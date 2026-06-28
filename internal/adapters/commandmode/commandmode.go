package commandmode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandview"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/adapters/terminallog"
	"github.com/Vibe-Pwners/hovel/internal/app/chainruntime"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/modules/pythonrpc"
	"github.com/akamensky/argparse"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewApp().Run(ctx, args, stdout, stderr)
}

type App struct {
	registry commands.Registry
	logs     terminallog.Renderer
}

func NewApp() App {
	return NewAppWithRuntime(defaultRuntime(nil))
}

func NewAppWithRuntime(runtime commands.Runtime) App {
	return App{
		registry: commands.HovelRegistry(runtime),
		logs:     terminallog.NewRenderer(),
	}
}

func NewAppWithSession(session commands.OperatorSession) App {
	return NewAppWithRuntime(defaultRuntime(session))
}

func NewAppWithSessionAndModules(session commands.OperatorSession, modules modulecatalog.Catalog) App {
	return NewAppWithRuntime(defaultRuntimeWithCatalog(session, modules))
}

func defaultRuntime(session commands.OperatorSession) commands.Runtime {
	return defaultRuntimeWithCatalog(session, pythonrpc.MustConfiguredCatalog())
}

func defaultRuntimeWithCatalog(session commands.OperatorSession, catalog modulecatalog.Catalog) commands.Runtime {
	store := filesystem.NewWorkspaceStore()
	pythonSessions := pythonrpc.NewSessionBroker()
	stepProcesses := pythonrpc.NewStepProcessBroker()
	stepRunner := pythonrpc.StepRuntimeRunner{Runner: pythonrpc.Runner{
		Events:        discardEvents{},
		IDs:           randomIDs{},
		Clock:         systemClock{},
		Sessions:      pythonSessions,
		StepProcesses: stepProcesses,
	}}
	return commands.Runtime{
		Workspaces: services.NewWorkspaceService(
			store,
			discardEvents{},
			randomIDs{},
			systemClock{},
		),
		Daemons:            services.NewDaemonService(store),
		Runs:               daemonRunClients{},
		CapabilityChains:   capabilityChainExecutor{catalog: catalog, runner: stepRunner},
		Plans:              store,
		Throws:             store,
		Confirmations:      store,
		Artifacts:          store,
		ArtifactRecords:    store,
		Events:             store,
		EventRecords:       store,
		ThrowConfirmations: store,
		ThrowPlans:         store,
		ChainFiles:         chainFileDiskStore{},
		Session:            session,
		Modules:            catalog,
		ModuleChecks:       moduleChecker{},
		Payloads:           store,
		PayloadProviders:   payloadProviderService{daemons: services.NewDaemonService(store), runs: daemonRunClients{}, modules: catalog},
	}
}

func NewAppWithRegistry(registry commands.Registry) App {
	return App{registry: registry, logs: terminallog.NewRenderer()}
}

func (a App) Registry() commands.Registry {
	return a.registry
}

func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return a.run(ctx, args, stdout, stderr, false)
}

func (a App) run(ctx context.Context, args []string, stdout, stderr io.Writer, echoConfirmationAnswer bool) int {
	args = normalizeLeadingConfig(args)
	if len(args) == 0 || topLevelHelpRequested(args) {
		parser := a.rootParser()
		if topLevelHelpRequested(args) {
			fmt.Fprint(stdout, parser.Usage(nil))
			return 0
		}
		fmt.Fprint(stderr, parser.Usage("command is required"))
		return 2
	}

	definition, commandArgs, ok := a.matchDefinition(args)
	if !ok {
		if group, rest, groupOK := a.matchGroup(args); groupOK && helpRequested(rest) {
			fmt.Fprint(stdout, a.groupParser(group).Usage(nil))
			return 0
		}
		fmt.Fprint(stderr, a.rootParser().Usage(fmt.Sprintf("unknown command %q", strings.Join(commandPath(args), " "))))
		return 2
	}
	return a.runDefinition(ctx, definition, commandArgs, stdout, stderr, echoConfirmationAnswer)
}

func normalizeLeadingConfig(args []string) []string {
	if len(args) < 2 {
		return args
	}
	switch {
	case args[0] == "--config":
		if len(args) < 3 {
			return args
		}
		out := append([]string(nil), args[2:]...)
		return append(out, "--config", args[1])
	case strings.HasPrefix(args[0], "--config="):
		out := append([]string(nil), args[1:]...)
		return append(out, "--config", strings.TrimPrefix(args[0], "--config="))
	default:
		return args
	}
}

func (a App) ExecuteLine(ctx context.Context, line string, stdout, stderr io.Writer) int {
	fields, err := splitCommandLine(line)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(fields) == 0 {
		return 0
	}
	return a.run(ctx, fields, stdout, stderr, true)
}

func splitCommandLine(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	var quote rune
	inField := false

	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote != 0:
			if r == '\\' && i+1 < len(runes) && (runes[i+1] == quote || runes[i+1] == '\\') {
				i++
				current.WriteRune(runes[i])
				inField = true
				continue
			}
			if r == quote {
				quote = 0
				inField = true
				continue
			}
			current.WriteRune(r)
			inField = true
		case r == '\'' || r == '"':
			quote = r
			inField = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inField {
				fields = append(fields, current.String())
				current.Reset()
				inField = false
			}
		default:
			current.WriteRune(r)
			inField = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	if inField {
		fields = append(fields, current.String())
	}
	return fields, nil
}

func (a App) runDefinition(ctx context.Context, definition commands.Definition, args []string, stdout, stderr io.Writer, echoConfirmationAnswer bool) int {
	parser, bindings := commandParser(definition)
	if helpRequested(args) {
		fmt.Fprint(stdout, usage(definition, parser, nil))
		return 0
	}

	parsed, ok, code := parseDefinition(definition, parser, bindings, args, stderr)
	if !ok {
		return code
	}
	parsed.Input = terminalInput{in: os.Stdin, out: stdout, echoAnswer: echoConfirmationAnswer}
	parsed.Output = stdout
	parsed.NonInteractive = stdinNonInteractive()
	if !echoConfirmationAnswer && definition.PathString() == "throw" && !parsed.Flag("json") {
		renderer := a.logs
		if parsed.Flag("no-color") {
			renderer = terminallog.NewPlainRenderer()
		}
		var renderMu sync.Mutex
		parsed.StreamLog = func(entry operatorlog.Entry) {
			rendered := renderer.Render(operatorlog.New("", "", []operatorlog.Entry{entry}))
			if rendered == "" {
				return
			}
			renderMu.Lock()
			defer renderMu.Unlock()
			fmt.Fprintln(stdout, rendered)
		}
	}
	result, err := definition.Execute(ctx, parsed)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if parsed.Flag("json") {
		if err := json.NewEncoder(stdout).Encode(result.JSON); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return resultCode(result)
	}
	if !result.Log.Empty() {
		renderer := a.logs
		if parsed.Flag("no-color") {
			renderer = terminallog.NewPlainRenderer()
		}
		fmt.Fprintln(stdout, renderer.Render(result.Log))
		return resultCode(result)
	}
	if len(result.Raw) > 0 {
		if _, err := stdout.Write(result.Raw); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return resultCode(result)
	}
	if result.Human != "" {
		human := result.Human
		if !parsed.Flag("no-color") && terminalOutput(stdout) {
			if rendered, ok := commandview.New(terminalWidth(stdout)).Render(result); ok {
				human = rendered
			}
		}
		fmt.Fprintln(stdout, human)
	}
	return resultCode(result)
}

func resultCode(result commands.Result) int {
	if result.ExitCode != 0 {
		return result.ExitCode
	}
	return 0
}

func stdinNonInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return true
	}
	return info.Mode()&os.ModeCharDevice == 0
}

func terminalOutput(writer io.Writer) bool {
	return terminalWidth(writer) > 0
}

func terminalWidth(writer io.Writer) int {
	file, ok := writer.(interface{ Fd() uintptr })
	if !ok {
		return 0
	}
	width, _, err := term.GetSize(file.Fd())
	if err != nil {
		return 0
	}
	return width
}

type terminalInput struct {
	in         io.Reader
	out        io.Writer
	echoAnswer bool
}

func (c terminalInput) Confirm(ctx context.Context, prompt commands.ConfirmationPrompt) (commands.ConfirmationAnswer, error) {
	if err := ctx.Err(); err != nil {
		return commands.ConfirmationAnswer{}, err
	}
	if c.out != nil {
		fmt.Fprintf(c.out, "%s\n", confirmationPromptTextBlock(prompt))
		fmt.Fprintf(c.out, "%s ", confirmationPromptText(prompt))
	}
	restoreTerminal, terminalEchoEnabled := func() (func() error, bool) {
		if !c.echoAnswer {
			return nil, false
		}
		return enableTerminalEcho()
	}()
	if restoreTerminal != nil {
		defer restoreTerminal()
	}
	var answer string
	if _, err := fmt.Fscan(c.in, &answer); err != nil {
		return commands.ConfirmationAnswer{}, fmt.Errorf("read confirmation: %w", err)
	}
	if c.echoAnswer && !terminalEchoEnabled && c.out != nil {
		fmt.Fprintln(c.out, answer)
	}
	return commands.ConfirmationAnswer{Value: answer}, nil
}

func confirmationPromptText(prompt commands.ConfirmationPrompt) string {
	action := strings.TrimSpace(prompt.Action)
	if action == "" {
		action = "throw"
	}
	required := strings.TrimSpace(prompt.RequiredLiteral)
	if required == "" {
		required = "yes"
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#facc15")).Bold(true).Render("Type ") +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e")).Bold(true).Render(required) +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#facc15")).Bold(true).Render(" to "+action+":")
}

func confirmationPromptTextBlock(prompt commands.ConfirmationPrompt) string {
	return confirmationPromptRenderer{}.Render(prompt)
}

type confirmationPromptRenderer struct{}

func (confirmationPromptRenderer) Render(prompt commands.ConfirmationPrompt) string {
	titleText := strings.TrimSpace(prompt.Title)
	if titleText == "" {
		titleText = "CONFIRM"
	}
	title := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0033")).Bold(true).Render(titleText)
	subtitle := lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")).Render(prompt.Plan.ID)
	lines := []string{strings.TrimSpace(title + " " + subtitle), ""}
	for _, field := range prompt.Fields {
		lines = append(lines, reviewRow(field))
	}
	body := strings.Join(lines, "\n")
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00e5ff")).
		Padding(1, 2).
		Width(76).
		Render(body)
}

func reviewRow(field commands.ConfirmationField) string {
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true).Width(13)
	valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Bold(true)
	if field.Muted {
		valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af"))
	}
	values := strings.Split(field.Value, "\n")
	if len(values) == 0 {
		values = []string{""}
	}
	lines := []string{labelStyle.Render(field.Label) + " " + valueStyle.Render(values[0])}
	for _, value := range values[1:] {
		lines = append(lines, labelStyle.Render("")+" "+valueStyle.Render(value))
	}
	return strings.Join(lines, "\n")
}

func (a App) matchDefinition(args []string) (commands.Definition, []string, bool) {
	for i := len(args); i > 0; i-- {
		definition, ok := a.registry.Find(args[:i]...)
		if ok {
			return definition, args[i:], true
		}
	}
	return commands.Definition{}, nil, false
}

func (a App) matchGroup(args []string) ([]string, []string, bool) {
	for i := len(args); i > 0; i-- {
		prefix := args[:i]
		if len(a.registry.Children(prefix...)) > 0 {
			return prefix, args[i:], true
		}
	}
	return nil, nil, false
}

func (a App) rootParser() *argparse.Parser {
	parser := argparse.NewParser("hovel command", "Run one Hovel command from the shell.")
	for _, definition := range a.registry.FirstSegments() {
		parser.NewCommand(definition.Path[0], definition.Summary)
	}
	return parser
}

func (a App) groupParser(prefix []string) *argparse.Parser {
	name := "hovel command " + strings.Join(prefix, " ")
	parser := argparse.NewParser(name, "Run a grouped Hovel command.")
	for _, definition := range a.registry.Children(prefix...) {
		parser.NewCommand(definition.Path[len(definition.Path)-1], definition.Summary)
	}
	return parser
}

type commandParserBindings struct {
	positionals map[string]*string
	options     map[string]*string
	flags       map[string]*bool
}

func commandParser(definition commands.Definition) (*argparse.Parser, commandParserBindings) {
	parser := argparse.NewParser("hovel command "+definition.PathString(), definition.Summary)
	bindings := commandParserBindings{
		positionals: make(map[string]*string, len(definition.Positionals)),
		options:     make(map[string]*string),
		flags:       make(map[string]*bool),
	}
	for _, positional := range definition.Positionals {
		bindings.positionals[positional.Name] = parser.StringPositional(&argparse.Options{
			Required: positional.Required,
			Help:     positional.Help,
		})
	}
	for _, option := range definition.Options {
		options := &argparse.Options{
			Required: option.Required,
			Help:     option.Help,
		}
		switch option.Kind {
		case commands.OptionBool:
			bindings.flags[option.Name] = parser.Flag(option.Short, option.Name, options)
		default:
			bindings.options[option.Name] = parser.String(option.Short, option.Name, options)
		}
	}
	return parser, bindings
}

func parseDefinition(definition commands.Definition, parser *argparse.Parser, bindings commandParserBindings, args []string, stderr io.Writer) (commands.Invocation, bool, int) {
	parser.ExitOnHelp(false)
	if err := parser.Parse(append([]string{"hovel"}, args...)); err != nil {
		fmt.Fprint(stderr, usage(definition, parser, err))
		return commands.Invocation{}, false, 2
	}

	invocation := commands.Invocation{
		Positionals: map[string]string{},
		Options:     map[string]string{},
		Flags:       map[string]bool{},
	}
	for _, positional := range definition.Positionals {
		invocation.Positionals[positional.Name] = strings.TrimSpace(*bindings.positionals[positional.Name])
	}
	for _, option := range definition.Options {
		switch option.Kind {
		case commands.OptionBool:
			invocation.Flags[option.Name] = *bindings.flags[option.Name]
		default:
			invocation.Options[option.Name] = strings.TrimSpace(*bindings.options[option.Name])
		}
	}
	return invocation, true, 0
}

func usage(definition commands.Definition, parser *argparse.Parser, msg any) string {
	out := parser.Usage(msg)
	parserName := "hovel command " + definition.PathString()
	generatedUsage := regexp.MustCompile(`\[_positionalArg_[\s\S]*?_\d+\s+"<value>"\]`)
	for i, positional := range definition.Positionals {
		out = replaceFirst(out, generatedUsage, "<"+positional.Name+">")
		generated := fmt.Sprintf("_positionalArg_%s_%d", parserName, i+1)
		out = strings.ReplaceAll(out, fmt.Sprintf(`[%s "<value>"]`, generated), "<"+positional.Name+">")
		out = strings.ReplaceAll(out, "--"+generated, positional.Name)
		out = strings.ReplaceAll(out, generated, positional.Name)
		wrapped := regexp.MustCompile(`\[` + regexp.QuoteMeta(positional.Name) + `\s+"<value>"\]`)
		out = wrapped.ReplaceAllString(out, "<"+positional.Name+">")
	}
	return out
}

func replaceFirst(text string, pattern *regexp.Regexp, replacement string) string {
	location := pattern.FindStringIndex(text)
	if location == nil {
		return text
	}
	return text[:location[0]] + replacement + text[location[1]:]
}

func topLevelHelpRequested(args []string) bool {
	return len(args) == 1 && isHelpArg(args[0])
}

func helpRequested(args []string) bool {
	return slices.ContainsFunc(args, isHelpArg)
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help"
}

func commandPath(args []string) []string {
	var path []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			break
		}
		path = append(path, arg)
	}
	return path
}

type daemonRunClients struct{}

type capabilityChainExecutor struct {
	catalog modulecatalog.Catalog
	runner  chainruntime.StepRunner
}

func (e capabilityChainExecutor) ExecuteCapabilityChain(ctx context.Context, req commands.CapabilityChainRequest) (commands.CapabilityChainResponse, error) {
	result, err := chainruntime.New(e.catalog, e.runner).Execute(ctx, chainruntime.Request{
		RunID: req.RunID,
		Steps: capabilityStepRefsFromCommand(req.Steps, mergeStepConfig(req.ChainConfig, req.TargetConfig)),
	})
	if err != nil {
		return commands.CapabilityChainResponse{
			RunID:             req.RunID,
			Target:            req.Target,
			State:             result.Status,
			Capabilities:      capabilitiesToCommand(result.Capabilities),
			Evidence:          evidenceToCommand(result.Evidence),
			Sessions:          sessionsFromRun(result.Sessions),
			InstalledPayloads: installedPayloadsFromRun(result.InstalledPayloads),
		}, err
	}
	return commands.CapabilityChainResponse{
		RunID:             req.RunID,
		Target:            req.Target,
		State:             result.Status,
		Summary:           "capability chain completed",
		Capabilities:      capabilitiesToCommand(result.Capabilities),
		Evidence:          evidenceToCommand(result.Evidence),
		Sessions:          sessionsFromRun(result.Sessions),
		InstalledPayloads: installedPayloadsFromRun(result.InstalledPayloads),
	}, nil
}

func capabilityStepRefsFromCommand(steps []commands.CapabilityChainStepRef, config map[string]any) []chainruntime.StepRef {
	out := make([]chainruntime.StepRef, 0, len(steps))
	for _, step := range steps {
		out = append(out, chainruntime.StepRef{
			ModuleID: step.ModuleID,
			StepID:   step.StepID,
			Config:   cloneAnyMap(config),
		})
	}
	return out
}

func mergeStepConfig(chainConfig, targetConfig map[string]string) map[string]any {
	if len(chainConfig) == 0 && len(targetConfig) == 0 {
		return nil
	}
	out := make(map[string]any, len(chainConfig)+len(targetConfig))
	for key, value := range chainConfig {
		out[key] = value
	}
	for key, value := range targetConfig {
		out[key] = value
	}
	return out
}

func capabilitiesToCommand(capabilities []modulecatalog.Capability) []commands.CapabilityPayload {
	out := make([]commands.CapabilityPayload, 0, len(capabilities))
	for _, capability := range capabilities {
		out = append(out, commands.CapabilityPayload{
			ID:             capability.ID,
			Type:           string(capability.Type),
			SchemaVersion:  capability.SchemaVersion,
			State:          capability.State,
			ProducerStepID: capability.ProducerStepID,
			Attributes:     cloneAnyMap(capability.Attributes),
			Extensions:     cloneAnyMap(capability.Extensions),
		})
	}
	return out
}

func evidenceToCommand(evidence []chainruntime.Evidence) []commands.CapabilityEvidence {
	out := make([]commands.CapabilityEvidence, 0, len(evidence))
	for _, item := range evidence {
		out = append(out, commands.CapabilityEvidence{
			ID:           item.ID,
			Level:        item.Level,
			Kind:         item.Kind,
			SourceStepID: item.SourceStepID,
			Message:      item.Message,
			Details:      cloneAnyMap(item.Details),
		})
	}
	return out
}

func sessionsFromRun(sessions []run.SessionRef) []commands.SessionRef {
	out := make([]commands.SessionRef, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, commands.SessionRef{
			ID:                 session.ID,
			RunID:              session.RunID,
			ModuleID:           session.ModuleID,
			Target:             session.Target,
			Name:               session.Name,
			Kind:               session.Kind,
			State:              session.State,
			Transport:          session.Transport,
			InstalledPayloadID: session.InstalledPayloadID,
			Capabilities:       append([]string(nil), session.Capabilities...),
		})
	}
	return out
}

func installedPayloadsFromRun(payloads []run.InstalledPayloadDescriptor) []commands.InstalledPayloadDescriptor {
	out := make([]commands.InstalledPayloadDescriptor, 0, len(payloads))
	for _, payload := range payloads {
		out = append(out, commands.InstalledPayloadDescriptor{
			Provider:                 payload.Provider,
			PayloadID:                payload.PayloadID,
			PayloadVersion:           payload.PayloadVersion,
			Target:                   payload.Target,
			TargetID:                 payload.TargetID,
			State:                    payload.State,
			Transport:                payload.Transport,
			Endpoint:                 payload.Endpoint,
			InstanceKey:              payload.InstanceKey,
			StampID:                  payload.StampID,
			ArtifactIDs:              append([]string(nil), payload.ArtifactIDs...),
			SupportsReconnect:        payload.SupportsReconnect,
			SupportsMultipleSessions: payload.SupportsMultipleSessions,
			Reconnect:                payloadProviderRecordFromRun(payload.Reconnect),
			Cleanup:                  payloadProviderRecordFromRun(payload.Cleanup),
			Metadata:                 cloneStringMap(payload.Metadata),
		})
	}
	return out
}

func payloadProviderRecordFromRun(record *run.PayloadProviderRecord) *commands.PayloadProviderRecord {
	if record == nil {
		return nil
	}
	return &commands.PayloadProviderRecord{
		ProviderID:    record.ProviderID,
		Schema:        record.Schema,
		SchemaVersion: record.SchemaVersion,
		Descriptor:    cloneAnyMap(record.Descriptor),
	}
}

func payloadProviderRecordToRun(record *commands.PayloadProviderRecord) *run.PayloadProviderRecord {
	if record == nil {
		return nil
	}
	return &run.PayloadProviderRecord{
		ProviderID:    record.ProviderID,
		Schema:        record.Schema,
		SchemaVersion: record.SchemaVersion,
		Descriptor:    cloneAnyMap(record.Descriptor),
	}
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (daemonRunClients) DialRunClient(socketPath string) (commands.RunClient, error) {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return nil, err
	}
	return daemonRunClient{client: client}, nil
}

type payloadProviderService struct {
	daemons commands.DaemonStatusProvider
	runs    commands.RunClientFactory
	modules modulecatalog.Catalog
}

func (s payloadProviderService) ListAvailablePayloads(ctx context.Context) ([]commands.AvailablePayload, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var payloads []commands.AvailablePayload
	for _, module := range s.modules.ByType(modulecatalog.TypePayloadProvider) {
		payloads = append(payloads, commands.AvailablePayload{
			Provider:  module.Name,
			PayloadID: module.ID,
			Name:      module.Name,
			Version:   module.Version,
		})
	}
	return payloads, nil
}

func (s payloadProviderService) ConnectInstalledPayload(ctx context.Context, record commands.InstalledPayloadRecord) (commands.SessionRef, error) {
	if s.daemons == nil || s.runs == nil {
		return commands.SessionRef{}, fmt.Errorf("daemon run service is not configured")
	}
	moduleID := payloadProviderModuleID(s.modules, record.Provider)
	if moduleID == "" {
		return commands.SessionRef{}, fmt.Errorf("payload provider %s is not configured", record.Provider)
	}
	status, err := s.daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: record.Workspace})
	if err != nil {
		return commands.SessionRef{}, err
	}
	if status.State != daemon.StateRunning {
		return commands.SessionRef{}, fmt.Errorf("daemon is not running for workspace %s", status.WorkspacePath)
	}
	client, err := s.runs.DialRunClient(status.Identity.SocketPath)
	if err != nil {
		return commands.SessionRef{}, err
	}
	defer client.Close()
	config := installedPayloadReconnectConfig(record)
	result, err := client.RunMockExploit(ctx, commands.RunMockExploitRequest{
		Operation:    record.Operation,
		Chain:        record.Chain,
		ModuleID:     moduleID,
		Target:       firstNonEmpty(record.TargetID, record.Target),
		ChainConfig:  config,
		TargetConfig: map[string]string{"target.host": record.Target},
	})
	if err != nil {
		return commands.SessionRef{}, err
	}
	if result.State != "succeeded" {
		return commands.SessionRef{}, fmt.Errorf("payload reconnect failed: %s", result.Summary)
	}
	if len(result.Sessions) == 0 {
		return commands.SessionRef{}, fmt.Errorf("payload reconnect returned no session")
	}
	session := result.Sessions[0]
	if session.InstalledPayloadID == "" {
		session.InstalledPayloadID = record.Handle
	}
	return session, nil
}

func (s payloadProviderService) CleanupInstalledPayload(context.Context, commands.InstalledPayloadRecord, string) error {
	return fmt.Errorf("provider cleanup is not wired for commandmode yet; use payloads mark-removed after manual cleanup")
}

func (s payloadProviderService) RefreshInstalledPayload(_ context.Context, record commands.InstalledPayloadRecord) (commands.InstalledPayloadRecord, error) {
	return record, nil
}

func (s payloadProviderService) ListPayloadCommands(ctx context.Context, record commands.InstalledPayloadRecord) ([]commands.PayloadCommand, error) {
	client, moduleID, closeClient, err := s.payloadCommandClient(ctx, record)
	if err != nil {
		return nil, err
	}
	defer closeClient()
	return client.ListPayloadCommands(ctx, moduleID, commandsPayloadListRequest(record))
}

func (s payloadProviderService) RunPayloadCommand(ctx context.Context, record commands.InstalledPayloadRecord, request commands.PayloadCommandRequest) (commands.PayloadCommandResult, error) {
	client, moduleID, closeClient, err := s.payloadCommandClient(ctx, record)
	if err != nil {
		return commands.PayloadCommandResult{}, err
	}
	defer closeClient()
	base := commandsPayloadCommandRequest(record)
	base.Command = request.Command
	base.Args = append([]string(nil), request.Args...)
	base.InputPath = request.InputPath
	base.InputData = request.InputData
	base.InputEncoding = request.InputEncoding
	if request.Config != nil {
		base.Config = cloneStringMap(request.Config)
	}
	if request.Reconnect != nil {
		base.Reconnect = request.Reconnect
	}
	return client.RunPayloadCommand(ctx, commands.RunPayloadCommandRunRequest{
		Operation: record.Operation,
		Chain:     record.Chain,
		ModuleID:  moduleID,
		Request:   base,
	})
}

func (s payloadProviderService) payloadCommandClient(ctx context.Context, record commands.InstalledPayloadRecord) (commands.RunClient, string, func(), error) {
	if s.daemons == nil || s.runs == nil {
		return nil, "", func() {}, fmt.Errorf("daemon run service is not configured")
	}
	moduleID := payloadProviderModuleID(s.modules, record.Provider)
	if moduleID == "" {
		return nil, "", func() {}, fmt.Errorf("payload provider %s is not configured", record.Provider)
	}
	status, err := s.daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: record.Workspace})
	if err != nil {
		return nil, "", func() {}, err
	}
	if status.State != daemon.StateRunning {
		return nil, "", func() {}, fmt.Errorf("daemon is not running for workspace %s", status.WorkspacePath)
	}
	client, err := s.runs.DialRunClient(status.Identity.SocketPath)
	if err != nil {
		return nil, "", func() {}, err
	}
	return client, moduleID, func() { _ = client.Close() }, nil
}

func commandsPayloadListRequest(record commands.InstalledPayloadRecord) commands.RunPayloadCommandListRequest {
	return commands.RunPayloadCommandListRequest{
		InstalledPayloadID: record.Handle,
		Target:             record.Target,
		PayloadID:          record.PayloadID,
		Config:             installedPayloadReconnectConfig(record),
		Reconnect:          payloadProviderRecordToRun(record.Reconnect),
	}
}

func commandsPayloadCommandRequest(record commands.InstalledPayloadRecord) commands.PayloadCommandRequest {
	return commands.PayloadCommandRequest{
		InstalledPayloadID: record.Handle,
		Target:             record.Target,
		PayloadID:          record.PayloadID,
		Config:             installedPayloadReconnectConfig(record),
		Reconnect:          payloadProviderRecordToRun(record.Reconnect),
	}
}

func payloadProviderModuleID(modules modulecatalog.Catalog, provider string) string {
	if module, ok := modules.Find(provider); ok && module.Type == modulecatalog.TypePayloadProvider {
		return module.ID
	}
	for _, module := range modules.ByType(modulecatalog.TypePayloadProvider) {
		if strings.EqualFold(module.Name, provider) || strings.EqualFold(module.ID, provider) {
			return module.ID
		}
	}
	return ""
}

func installedPayloadReconnectConfig(record commands.InstalledPayloadRecord) map[string]string {
	config := map[string]string{}
	if record.Reconnect != nil {
		for key, value := range record.Reconnect.Descriptor {
			text := fmt.Sprint(value)
			if text != "" {
				config[key] = text
			}
		}
	}
	if record.Transport != "" {
		config["payload.transport"] = record.Transport
	}
	if record.Target != "" {
		config["target.host"] = record.Target
	}
	return config
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type daemonRunClient struct {
	client *daemonrpc.Client
}

func (c daemonRunClient) Close() error {
	return c.client.Close()
}

func (c daemonRunClient) RunMockExploit(ctx context.Context, req commands.RunMockExploitRequest) (commands.RunMockExploitResponse, error) {
	result, err := c.client.RunMockExploit(ctx, daemonrpc.RunMockExploitRequest{
		Operation:    req.Operation,
		Chain:        req.Chain,
		ModuleID:     req.ModuleID,
		Target:       req.Target,
		Inputs:       req.Inputs,
		ChainConfig:  req.ChainConfig,
		TargetConfig: req.TargetConfig,
		ThrowStarted: req.ThrowStarted,
	})
	if err != nil {
		return commands.RunMockExploitResponse{}, err
	}
	return commands.RunMockExploitResponse{
		RunID:             result.RunID,
		ModuleID:          result.ModuleID,
		Target:            result.Target,
		State:             result.State,
		Summary:           result.Summary,
		Findings:          findingsFromRPC(result.Findings),
		Artifacts:         artifactsFromRPC(result.Artifacts),
		Logs:              logsFromRPC(result.Logs),
		Sessions:          sessionsFromRPC(result.Sessions),
		InstalledPayloads: installedPayloadsFromRun(result.InstalledPayloads),
	}, nil
}

func (c daemonRunClient) ListPayloadCommands(ctx context.Context, moduleID string, req commands.RunPayloadCommandListRequest) ([]commands.PayloadCommand, error) {
	resp, err := c.client.ListPayloadCommands(ctx, daemonrpc.PayloadCommandListRequest{
		ModuleID: moduleID,
		Request:  req,
	})
	if err != nil {
		return nil, err
	}
	return append([]commands.PayloadCommand(nil), resp.Commands...), nil
}

func (c daemonRunClient) RunPayloadCommand(ctx context.Context, req commands.RunPayloadCommandRunRequest) (commands.PayloadCommandResult, error) {
	resp, err := c.client.RunPayloadCommand(ctx, daemonrpc.PayloadCommandRunRequest{
		Operation: req.Operation,
		Chain:     req.Chain,
		ModuleID:  req.ModuleID,
		Request:   req.Request,
	})
	if err != nil {
		return commands.PayloadCommandResult{}, err
	}
	return resp, nil
}

func (c daemonRunClient) PollOperationChainLogs(ctx context.Context, operation, chain string, since uint64) (commands.RunLogPollResult, error) {
	result, err := c.client.PollOperationChainLogs(ctx, operation, chain, since)
	if err != nil {
		return commands.RunLogPollResult{}, err
	}
	return commands.RunLogPollResult{
		Last: result.Last,
		Logs: publishedLogsFromRPC(result.Logs),
	}, nil
}

func (c daemonRunClient) ListSessions(ctx context.Context) ([]commands.SessionRef, error) {
	sessions, err := c.client.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	return sessionsFromRPC(sessions), nil
}

func (c daemonRunClient) ReadSession(ctx context.Context, sessionID string, timeout time.Duration) (commands.SessionChunk, error) {
	chunk, err := c.client.ReadSession(ctx, sessionID, timeout)
	if err != nil {
		return commands.SessionChunk{}, err
	}
	return commands.SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}, nil
}

func (c daemonRunClient) TailSession(ctx context.Context, sessionID string, options commands.SessionTailOptions) (commands.SessionChunk, error) {
	chunk, err := c.client.TailSession(ctx, sessionID, run.SessionTailOptions{
		MaxBytes: options.MaxBytes,
		MaxLines: options.MaxLines,
		Consume:  options.Consume,
	})
	if err != nil {
		return commands.SessionChunk{}, err
	}
	return commands.SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}, nil
}

func (c daemonRunClient) WriteSession(ctx context.Context, sessionID string, data []byte) error {
	return c.client.WriteSession(ctx, sessionID, data)
}

func (c daemonRunClient) CloseSession(ctx context.Context, sessionID string) error {
	return c.client.CloseSession(ctx, sessionID)
}

func findingsFromRPC(findings []daemonrpc.Finding) []commands.Finding {
	out := make([]commands.Finding, 0, len(findings))
	for _, finding := range findings {
		out = append(out, commands.Finding{
			Title:    finding.Title,
			Severity: finding.Severity,
			Detail:   finding.Detail,
		})
	}
	return out
}

func sessionsFromRPC(sessions []daemonrpc.SessionRef) []commands.SessionRef {
	out := make([]commands.SessionRef, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, commands.SessionRef{
			ID:                 session.ID,
			RunID:              session.RunID,
			ModuleID:           session.ModuleID,
			Target:             session.Target,
			Name:               session.Name,
			Kind:               session.Kind,
			State:              session.State,
			Transport:          session.Transport,
			InstalledPayloadID: session.InstalledPayloadID,
			Capabilities:       append([]string(nil), session.Capabilities...),
		})
	}
	return out
}

func logsFromRPC(logs []daemonrpc.LogEntry) []commands.LogEntry {
	out := make([]commands.LogEntry, 0, len(logs))
	for _, log := range logs {
		out = append(out, commands.LogEntry{
			ID:             log.ID,
			Time:           log.Time,
			Topic:          log.Topic,
			Kind:           log.Kind,
			Level:          log.Level,
			Source:         log.Source,
			Message:        log.Message,
			Logger:         log.Logger,
			ChainID:        log.ChainID,
			ChainName:      log.ChainName,
			RunID:          log.RunID,
			Target:         log.Target,
			ModuleID:       log.ModuleID,
			ElapsedSeconds: cloneFloat64(log.ElapsedSeconds),
			Fields:         cloneStringMap(log.Fields),
			Attributes:     cloneStringMap(log.Attributes),
		})
	}
	return out
}

func publishedLogsFromRPC(logs []daemonrpc.PublishedLog) []commands.RunPublishedLog {
	out := make([]commands.RunPublishedLog, 0, len(logs))
	for _, log := range logs {
		out = append(out, commands.RunPublishedLog{
			Seq:       log.Seq,
			Operation: log.Operation,
			Chain:     log.Chain,
			Entry:     operatorLogEntryFromRPC(log.Entry),
		})
	}
	return out
}

func operatorLogEntryFromRPC(entry daemonrpc.OperatorLogEntry) operatorlog.Entry {
	timestamp, _ := time.Parse(time.RFC3339Nano, entry.Time)
	return operatorlog.Entry{
		ID:             entry.ID,
		Time:           timestamp,
		Topic:          entry.Topic,
		Kind:           operatorlog.Kind(entry.Kind),
		Level:          operatorlog.Level(entry.Level),
		Source:         entry.Source,
		Message:        entry.Message,
		ChainID:        entry.ChainID,
		ChainName:      entry.ChainName,
		RunID:          entry.RunID,
		Target:         entry.Target,
		ModuleID:       entry.ModuleID,
		ElapsedSeconds: cloneFloat64(entry.ElapsedSeconds),
		Fields:         fieldsFromMap(entry.Fields),
		Attributes:     cloneStringMap(entry.Attributes),
	}
}

func fieldsFromMap(values map[string]string) []operatorlog.Field {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	fields := make([]operatorlog.Field, 0, len(keys))
	for _, key := range keys {
		fields = append(fields, operatorlog.Field{Name: key, Value: values[key]})
	}
	return fields
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func artifactsFromRPC(artifacts []daemonrpc.Artifact) []commands.Artifact {
	out := make([]commands.Artifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		out = append(out, commands.Artifact{
			Name: artifact.Name,
			Kind: artifact.Kind,
			Data: artifact.Data,
			Path: artifact.Path,
		})
	}
	return out
}

type discardEvents struct{}

func (discardEvents) Append(context.Context, event.Event) error {
	return nil
}

type randomIDs struct{}

func (randomIDs) NewID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("id-%d", time.Now().UnixNano())
	}
	return "id-" + hex.EncodeToString(bytes[:])
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}
