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

	"github.com/akamensky/argparse"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/vibepwners/hovel/internal/adapters/commandview"
	"github.com/vibepwners/hovel/internal/adapters/daemonrpc"
	"github.com/vibepwners/hovel/internal/adapters/storage/filesystem"
	"github.com/vibepwners/hovel/internal/adapters/terminallog"
	"github.com/vibepwners/hovel/internal/app/chainruntime"
	"github.com/vibepwners/hovel/internal/app/commands"
	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	"github.com/vibepwners/hovel/internal/app/operatorlog"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/domain/daemon"
	"github.com/vibepwners/hovel/internal/domain/event"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/moduleruntime/pythonrpc"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewApp().Run(ctx, args, stdout, stderr)
}

type App struct {
	registry commands.Registry
	logs     terminallog.Renderer
}

type usageSurface struct {
	rootName         string
	commandPrefix    string
	rootDescription  string
	groupDescription string
}

var (
	shellUsageSurface = usageSurface{
		rootName:         "hovel command",
		commandPrefix:    "hovel command",
		rootDescription:  "Run one Hovel command from the shell.",
		groupDescription: "Run a grouped Hovel command.",
	}
	interactiveUsageSurface = usageSurface{
		rootName:         "command",
		rootDescription:  "Run one command in the Hovel CLI.",
		groupDescription: "Run a grouped command in the Hovel CLI.",
	}
)

func (s usageSurface) commandName(path []string) string {
	name := strings.Join(path, " ")
	if name == "" {
		return s.rootName
	}
	if s.commandPrefix == "" {
		return name
	}
	return s.commandPrefix + " " + name
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

func NewAppWithSessionModulesAndWorkspace(session commands.OperatorSession, modules modulecatalog.Catalog, workspacePath string) App {
	return NewAppWithRuntime(defaultRuntimeWithCatalogAndWorkspace(session, modules, workspacePath))
}

func defaultRuntime(session commands.OperatorSession) commands.Runtime {
	return defaultRuntimeWithCatalog(session, pythonrpc.MustConfiguredCatalog())
}

func defaultRuntimeWithCatalog(session commands.OperatorSession, catalog modulecatalog.Catalog) commands.Runtime {
	return defaultRuntimeWithCatalogAndWorkspace(session, catalog, "")
}

func defaultRuntimeWithCatalogAndWorkspace(session commands.OperatorSession, catalog modulecatalog.Catalog, workspacePath string) commands.Runtime {
	store := filesystem.NewWorkspaceStore()
	pythonSessions := pythonrpc.NewSessionBroker()
	stepProcesses := pythonrpc.NewStepProcessBroker()
	runner := pythonrpc.Runner{
		Events:        discardEvents{},
		IDs:           randomIDs{},
		Clock:         systemClock{},
		Sessions:      pythonSessions,
		StepProcesses: stepProcesses,
		WorkspacePath: workspacePath,
	}
	stepRunner := pythonrpc.StepRuntimeRunner{Runner: runner}
	return commands.Runtime{
		WorkspacePath: workspacePath,
		Workspaces: services.NewWorkspaceService(
			store,
			discardEvents{},
			randomIDs{},
			systemClock{},
		),
		Daemons:            services.NewDaemonService(store),
		PendingThrows:      daemonPendingThrows{},
		LaunchKeyPolicies:  daemonLaunchKeyPolicies{},
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
		ModuleInspector:    moduleInspector{runner: runner},
		Payloads:           store,
		PayloadProviders:   payloadProviderService{daemons: services.NewDaemonService(store), runs: daemonRunClients{}, modules: catalog, payloads: runner},
	}
}

func NewAppWithRegistry(registry commands.Registry) App {
	return App{registry: registry, logs: terminallog.NewRenderer()}
}

func (a App) Registry() commands.Registry {
	return a.registry
}

func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return a.run(ctx, args, stdout, stderr, false, shellUsageSurface)
}

// Validate checks command structure and arguments without executing the command handler.
// Daemon-owning front ends use it before acquiring runtime resources.
func (a App) Validate(args []string, stderr io.Writer) (bool, int) {
	return a.validate(args, stderr, shellUsageSurface)
}

// ValidateInteractive checks command structure while keeping usage local to
// the interactive shell, where operators enter commands without a binary or
// role prefix.
func (a App) ValidateInteractive(args []string, stderr io.Writer) (bool, int) {
	return a.validate(args, stderr, interactiveUsageSurface)
}

func (a App) validate(args []string, stderr io.Writer, surface usageSurface) (bool, int) {
	args = normalizeLeadingConfig(args)
	if len(args) == 0 {
		writeCommandText(stderr, a.rootParser(surface).Usage("command is required"))
		return false, 2
	}
	if topLevelHelpRequested(args) {
		return true, 0
	}
	definition, commandArgs, ok := a.matchDefinition(args)
	if !ok {
		if group, rest, groupOK := a.matchGroup(args); groupOK {
			if helpRequested(rest) {
				return true, 0
			}
			message := "subcommand is required"
			if len(rest) > 0 {
				message = fmt.Sprintf("unknown subcommand %q for %q", strings.Join(rest, " "), strings.Join(group, " "))
			}
			writeCommandText(stderr, a.groupParser(group, surface).Usage(message))
			return false, 2
		}
		writeCommandText(stderr, a.rootParser(surface).Usage(fmt.Sprintf("unknown command %q", strings.Join(commandPath(args), " "))))
		return false, 2
	}
	if commandHelpRequested(definition, commandArgs) {
		return true, 0
	}
	parserName := surface.commandName(definition.Path)
	parser, bindings := commandParser(definition, parserName)
	_, ok, code := parseDefinition(definition, parser, parserName, bindings, commandArgs, stderr)
	return ok, code
}

func (a App) run(ctx context.Context, args []string, stdout, stderr io.Writer, echoConfirmationAnswer bool, surface usageSurface) int {
	args = normalizeLeadingConfig(args)
	if len(args) == 0 || topLevelHelpRequested(args) {
		parser := a.rootParser(surface)
		if topLevelHelpRequested(args) {
			writeCommandText(stdout, parser.Usage(nil))
			return 0
		}
		writeCommandText(stderr, parser.Usage("command is required"))
		return 2
	}

	definition, commandArgs, ok := a.matchDefinition(args)
	if !ok {
		if group, rest, groupOK := a.matchGroup(args); groupOK {
			if helpRequested(rest) {
				writeCommandText(stdout, a.groupParser(group, surface).Usage(nil))
				return 0
			}
			message := "subcommand is required"
			if len(rest) > 0 {
				message = fmt.Sprintf("unknown subcommand %q for %q", strings.Join(rest, " "), strings.Join(group, " "))
			}
			writeCommandText(stderr, a.groupParser(group, surface).Usage(message))
			return 2
		}
		writeCommandText(stderr, a.rootParser(surface).Usage(fmt.Sprintf("unknown command %q", strings.Join(commandPath(args), " "))))
		return 2
	}
	return a.runDefinition(ctx, definition, commandArgs, stdout, stderr, echoConfirmationAnswer, surface)
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
	fields, err := SplitCommandLine(line)
	if err != nil {
		writeCommandLine(stderr, err)
		return 2
	}
	if len(fields) == 0 {
		return 0
	}
	return a.run(ctx, fields, stdout, stderr, true, interactiveUsageSurface)
}

// SplitCommandLine tokenizes one interactive command using the same quoting
// rules as ExecuteLine.
func SplitCommandLine(line string) ([]string, error) {
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

func (a App) runDefinition(ctx context.Context, definition commands.Definition, args []string, stdout, stderr io.Writer, echoConfirmationAnswer bool, surface usageSurface) int {
	parserName := surface.commandName(definition.Path)
	parser, bindings := commandParser(definition, parserName)
	if commandHelpRequested(definition, args) {
		writeCommandText(stdout, usage(definition, parser, parserName, nil))
		return 0
	}

	parsed, ok, code := parseDefinition(definition, parser, parserName, bindings, args, stderr)
	if !ok {
		return code
	}
	parsed.Input = terminalInput{in: os.Stdin, out: stdout, echoAnswer: echoConfirmationAnswer}
	parsed.Output = stdout
	parsed.NonInteractive = stdinNonInteractive()
	if installProgressCommand(definition) && !parsed.Flag("json") {
		parsed.InstallProgress = newInstallProgressRenderer(stdout, terminalWidth(stdout), !parsed.Flag("no-color")).Handle
	}
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
			writeCommandLine(stdout, rendered)
		}
	}
	result, err := definition.Execute(ctx, parsed)
	if err != nil {
		writeCommandLine(stderr, err)
		return 1
	}
	if parsed.Flag("json") {
		if err := json.NewEncoder(stdout).Encode(result.JSON); err != nil {
			writeCommandLine(stderr, err)
			return 1
		}
		return resultCode(result)
	}
	if !result.Log.Empty() {
		renderer := a.logs
		if parsed.Flag("no-color") {
			renderer = terminallog.NewPlainRenderer()
		}
		writeCommandLine(stdout, renderer.Render(result.Log))
		return resultCode(result)
	}
	if len(result.Raw) > 0 {
		if _, err := stdout.Write(result.Raw); err != nil {
			writeCommandLine(stderr, err)
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
		writeCommandLine(stdout, human)
	}
	return resultCode(result)
}

func installProgressCommand(definition commands.Definition) bool {
	switch definition.PathString() {
	case "chain add", "chains add", "module install", "modules install", "module bulk-install", "modules bulk-install":
		return true
	default:
		return false
	}
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
		writeCommandFormat(c.out, "%s\n", confirmationPromptTextBlock(prompt))
		writeCommandFormat(c.out, "%s ", confirmationPromptText(prompt))
	}
	restoreTerminal, terminalEchoEnabled := func() (func() error, bool) {
		if !c.echoAnswer {
			return nil, false
		}
		return enableTerminalEcho()
	}()
	if restoreTerminal != nil {
		defer func() { logCommandModeError("restore terminal echo", restoreTerminal()) }()
	}
	var answer string
	if _, err := fmt.Fscan(c.in, &answer); err != nil {
		return commands.ConfirmationAnswer{}, fmt.Errorf("read confirmation: %w", err)
	}
	if c.echoAnswer && !terminalEchoEnabled && c.out != nil {
		writeCommandLine(c.out, answer)
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

func (a App) rootParser(surface usageSurface) *argparse.Parser {
	parser := argparse.NewParser(surface.rootName, surface.rootDescription)
	for _, definition := range a.registry.FirstSegments() {
		parser.NewCommand(definition.Path[0], definition.Summary)
	}
	return parser
}

func (a App) groupParser(prefix []string, surface usageSurface) *argparse.Parser {
	parser := argparse.NewParser(surface.commandName(prefix), surface.groupDescription)
	for _, definition := range a.registry.Children(prefix...) {
		parser.NewCommand(definition.Path[len(definition.Path)-1], definition.Summary)
	}
	return parser
}

type commandParserBindings struct {
	positionals map[string]*string
	options     map[string]*string
	optionLists map[string]*[]string
	flags       map[string]*bool
}

func commandParser(definition commands.Definition, parserName string) (*argparse.Parser, commandParserBindings) {
	parser := argparse.NewParser(parserName, definition.Summary)
	bindings := commandParserBindings{
		positionals: make(map[string]*string, len(definition.Positionals)),
		options:     make(map[string]*string),
		optionLists: make(map[string]*[]string),
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
		case commands.OptionStringList:
			bindings.optionLists[option.Name] = parser.StringList(option.Short, option.Name, options)
		default:
			bindings.options[option.Name] = parser.String(option.Short, option.Name, options)
		}
	}
	return parser, bindings
}

func parseDefinition(definition commands.Definition, parser *argparse.Parser, parserName string, bindings commandParserBindings, args []string, stderr io.Writer) (commands.Invocation, bool, int) {
	parser.ExitOnHelp(false)
	parseArgs, passthrough := splitPassthrough(definition, args)
	if err := validateDefinitionOptions(definition, parseArgs); err != nil {
		writeCommandText(stderr, usage(definition, parser, parserName, err))
		return commands.Invocation{}, false, 2
	}
	parserArgs, escapedPositionals := escapeEndOfOptions(parseArgs)
	if err := parser.Parse(append([]string{"hovel"}, parserArgs...)); err != nil {
		writeCommandText(stderr, usage(definition, parser, parserName, err))
		return commands.Invocation{}, false, 2
	}
	for _, positional := range definition.Positionals {
		value := unescapeEndOfOptions(*bindings.positionals[positional.Name], escapedPositionals)
		if positional.Required && strings.TrimSpace(value) == "" {
			writeCommandText(stderr, usage(definition, parser, parserName, positional.Name+" is required"))
			return commands.Invocation{}, false, 2
		}
	}
	if definition.Passthrough.Required && len(passthrough) == 0 {
		writeCommandText(stderr, usage(definition, parser, parserName, definition.Passthrough.Name+" after -- is required"))
		return commands.Invocation{}, false, 2
	}

	invocation := commands.Invocation{
		Positionals: map[string]string{},
		Options:     map[string]string{},
		OptionLists: map[string][]string{},
		Flags:       map[string]bool{},
		Passthrough: append([]string(nil), passthrough...),
	}
	for _, positional := range definition.Positionals {
		value := unescapeEndOfOptions(*bindings.positionals[positional.Name], escapedPositionals)
		invocation.Positionals[positional.Name] = strings.TrimSpace(value)
	}
	for _, option := range definition.Options {
		switch option.Kind {
		case commands.OptionBool:
			invocation.Flags[option.Name] = *bindings.flags[option.Name]
		case commands.OptionStringList:
			invocation.OptionLists[option.Name] = append([]string(nil), *bindings.optionLists[option.Name]...)
		default:
			invocation.Options[option.Name] = strings.TrimSpace(*bindings.options[option.Name])
		}
	}
	return invocation, true, 0
}

const escapedPositionalPrefix = "\x1ehovel-positional-"

func escapeEndOfOptions(args []string) ([]string, map[string]string) {
	delimiter := slices.Index(args, "--")
	if delimiter < 0 {
		return args, nil
	}
	escaped := make(map[string]string, len(args)-delimiter-1)
	result := append([]string(nil), args[:delimiter]...)
	for index, arg := range args[delimiter+1:] {
		if strings.HasPrefix(arg, "-") {
			placeholder := fmt.Sprintf("%s%d", escapedPositionalPrefix, index)
			escaped[placeholder] = arg
			arg = placeholder
		}
		result = append(result, arg)
	}
	return result, escaped
}

func unescapeEndOfOptions(value string, escaped map[string]string) string {
	if original, ok := escaped[value]; ok {
		return original
	}
	return value
}

func validateDefinitionOptions(definition commands.Definition, args []string) error {
	for index := 0; index < len(args); index++ {
		token := args[index]
		if token == "--" {
			return nil
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			continue
		}
		name := token
		_, attachedValue, attached := strings.Cut(token, "=")
		if attached {
			name = token[:len(token)-len(attachedValue)-1]
		}
		if strings.HasPrefix(name, "--") {
			matched, ok := definitionOptionByLongName(definition, name)
			if !ok {
				return fmt.Errorf("unknown option %q", name)
			}
			if matched.Kind == commands.OptionBool {
				if attached {
					return fmt.Errorf("option %q does not take a value", name)
				}
				continue
			}
			if attached {
				continue
			}
			if index+1 >= len(args) {
				return fmt.Errorf("option %q requires a value", name)
			}
			index++
			continue
		}
		consumesNext, err := validateShortOptionCluster(definition, name, attached)
		if err != nil {
			return err
		}
		if consumesNext {
			if index+1 >= len(args) {
				return fmt.Errorf("option %q requires a value", name)
			}
			index++
		}
	}
	return nil
}

func definitionOptionByLongName(definition commands.Definition, name string) (commands.Option, bool) {
	for _, option := range definition.Options {
		if name == "--"+option.Name {
			return option, true
		}
	}
	return commands.Option{}, false
}

func validateShortOptionCluster(definition commands.Definition, name string, attached bool) (bool, error) {
	cluster := strings.TrimPrefix(name, "-")
	if cluster == "" || strings.HasPrefix(cluster, "-") {
		return false, fmt.Errorf("unknown option %q", name)
	}
	shorts := []rune(cluster)
	for index, short := range shorts {
		var matched commands.Option
		found := false
		for _, option := range definition.Options {
			if option.Short == string(short) {
				matched, found = option, true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("unknown option %q in %q", "-"+string(short), name)
		}
		if matched.Kind == commands.OptionBool {
			continue
		}
		if index != len(shorts)-1 {
			return false, fmt.Errorf("option %q must be last in %q because it takes a value", "-"+string(short), name)
		}
		return !attached, nil
	}
	if attached {
		return false, fmt.Errorf("option %q does not take a value", name)
	}
	return false, nil
}

func commandHelpRequested(definition commands.Definition, args []string) bool {
	parseArgs, _ := splitPassthrough(definition, args)
	return helpRequested(parseArgs)
}

func splitPassthrough(definition commands.Definition, args []string) ([]string, []string) {
	if definition.Passthrough.Name == "" {
		return args, nil
	}
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func usage(definition commands.Definition, parser *argparse.Parser, parserName string, msg any) string {
	out := parser.Usage(msg)
	generatedUsage := regexp.MustCompile(`\[_positionalArg_[\s\S]*?_\d+\s+"<value>"\]`)
	for i, positional := range definition.Positionals {
		placeholder := "<" + positional.Name + ">"
		if !positional.Required {
			placeholder = "[" + placeholder + "]"
		}
		out = replaceFirst(out, generatedUsage, placeholder)
		generated := fmt.Sprintf("_positionalArg_%s_%d", parserName, i+1)
		out = strings.ReplaceAll(out, fmt.Sprintf(`[%s "<value>"]`, generated), placeholder)
		out = strings.ReplaceAll(out, "--"+generated, positional.Name)
		out = strings.ReplaceAll(out, generated, positional.Name)
		wrapped := regexp.MustCompile(`\[` + regexp.QuoteMeta(positional.Name) + `\s+"<value>"\]`)
		out = wrapped.ReplaceAllString(out, placeholder)
	}
	if definition.Passthrough.Name != "" {
		requirement := "optional"
		if definition.Passthrough.Required {
			requirement = "required"
		}
		out = strings.TrimRight(out, "\n") + fmt.Sprintf("\n\nPassthrough:\n\n  -- <%s>...  %s (%s)\n", definition.Passthrough.Name, definition.Passthrough.Help, requirement)
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

type daemonPendingThrows struct{}
type daemonLaunchKeyPolicies struct{}

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

func (daemonPendingThrows) CreatePendingThrow(ctx context.Context, socketPath string, req commands.PendingThrowCreateRequest) (commands.PendingThrowSnapshot, error) {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return commands.PendingThrowSnapshot{}, err
	}
	defer func() { logCommandModeError("close pending throw daemon client", client.Close()) }()
	resp, err := client.CreatePendingThrow(ctx, daemonrpc.CreatePendingThrowRequest{
		ID:             req.ID,
		Operation:      req.Operation,
		Chain:          req.Chain,
		PlanHash:       req.PlanHash,
		AllowDangerous: req.AllowDangerous,
		NowBypass:      req.NowBypass,
	})
	if err != nil {
		return commands.PendingThrowSnapshot{}, err
	}
	return pendingThrowSnapshot(resp), nil
}

func (daemonPendingThrows) RequirePendingThrowReady(ctx context.Context, socketPath, id string) (commands.PendingThrowSnapshot, error) {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return commands.PendingThrowSnapshot{}, err
	}
	defer func() { logCommandModeError("close pending throw daemon client", client.Close()) }()
	resp, err := client.RequirePendingThrowReady(ctx, daemonrpc.PendingThrowRequest{ID: id})
	if err != nil {
		return pendingThrowSnapshot(resp), err
	}
	return pendingThrowSnapshot(resp), nil
}

func (daemonPendingThrows) CancelPendingThrow(ctx context.Context, socketPath, id string) error {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return err
	}
	defer func() { logCommandModeError("close daemon client", client.Close()) }()
	return client.CancelPendingThrow(ctx, daemonrpc.PendingThrowRequest{ID: id})
}

func pendingThrowSnapshot(resp daemonrpc.PendingThrowResponse) commands.PendingThrowSnapshot {
	return commands.PendingThrowSnapshot{
		ID:                  resp.ID,
		Operation:           resp.Operation,
		Chain:               resp.Chain,
		PlanHash:            resp.PlanHash,
		AllowDangerous:      resp.AllowDangerous,
		NowBypass:           resp.NowBypass,
		Ready:               resp.Ready,
		RequiredApproverIDs: append([]string(nil), resp.RequiredApproverIDs...),
		MissingApproverIDs:  append([]string(nil), resp.MissingApproverIDs...),
	}
}

func (daemonLaunchKeyPolicies) GetLaunchKeyPolicy(ctx context.Context, socketPath, operation string) (commands.LaunchKeyPolicySnapshot, error) {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return commands.LaunchKeyPolicySnapshot{}, err
	}
	defer func() { logCommandModeError("close daemon client", client.Close()) }()
	resp, err := client.GetLaunchKeyPolicy(ctx, daemonrpc.LaunchKeyPolicyRequest{Operation: operation})
	if err != nil {
		return commands.LaunchKeyPolicySnapshot{}, err
	}
	return launchKeyPolicySnapshot(resp), nil
}

func (daemonLaunchKeyPolicies) SetLaunchKeyPolicy(ctx context.Context, socketPath string, req commands.LaunchKeyPolicySetRequest) (commands.LaunchKeyPolicySnapshot, error) {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return commands.LaunchKeyPolicySnapshot{}, err
	}
	defer func() { logCommandModeError("close daemon client", client.Close()) }()
	resp, err := client.SetLaunchKeyPolicy(ctx, daemonrpc.SetLaunchKeyPolicyRequest{
		Operation:        req.Operation,
		Mode:             req.Mode,
		Quorum:           req.Quorum,
		HeartbeatTimeout: req.HeartbeatTimeout,
	})
	if err != nil {
		return commands.LaunchKeyPolicySnapshot{}, err
	}
	return launchKeyPolicySnapshot(resp), nil
}

func launchKeyPolicySnapshot(resp daemonrpc.LaunchKeyPolicyResponse) commands.LaunchKeyPolicySnapshot {
	return commands.LaunchKeyPolicySnapshot{
		Operation:        resp.Operation,
		Mode:             resp.Policy.Mode,
		Quorum:           resp.Policy.Quorum,
		HeartbeatTimeout: resp.Policy.HeartbeatTimeout,
	}
}

type payloadProviderService struct {
	daemons  commands.DaemonStatusProvider
	runs     commands.RunClientFactory
	modules  modulecatalog.Catalog
	payloads payloadMetadataLister
}

type payloadMetadataLister interface {
	ListPayloads(context.Context, string, run.PayloadQuery) ([]run.PayloadInfo, error)
}

func (s payloadProviderService) ListAvailablePayloads(ctx context.Context) ([]commands.AvailablePayload, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var payloads []commands.AvailablePayload
	for _, module := range s.modules.ByType(modulecatalog.TypePayloadProvider) {
		listed, err := s.listProviderPayloads(ctx, module)
		if err != nil || len(listed) == 0 {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			payloads = append(payloads, catalogAvailablePayload(module))
			continue
		}
		payloads = append(payloads, listed...)
	}
	return payloads, nil
}

func (s payloadProviderService) listProviderPayloads(ctx context.Context, module modulecatalog.Module) ([]commands.AvailablePayload, error) {
	if s.payloads == nil {
		return nil, fmt.Errorf("payload metadata runner is not configured")
	}
	infos, err := s.payloads.ListPayloads(ctx, module.ID, run.PayloadQuery{})
	if err != nil {
		return nil, err
	}
	payloads := make([]commands.AvailablePayload, 0, len(infos))
	for _, info := range infos {
		payloads = append(payloads, availablePayloadFromInfo(module, info))
	}
	return payloads, nil
}

func availablePayloadFromInfo(module modulecatalog.Module, info run.PayloadInfo) commands.AvailablePayload {
	return commands.AvailablePayload{
		Provider:     firstNonEmpty(module.Name, info.Name, module.ID),
		PayloadID:    firstNonEmpty(info.ID, module.ID),
		Name:         firstNonEmpty(info.Name, module.Name),
		Version:      firstNonEmpty(info.Version, module.Version),
		Kind:         info.Kind,
		Platform:     info.Platform,
		OS:           firstNonEmpty(info.OS, info.Platform),
		Arch:         info.Arch,
		Formats:      append([]string(nil), info.Formats...),
		Tags:         append([]string(nil), info.Tags...),
		Capabilities: append([]string(nil), info.Capabilities...),
		Transport:    info.Transport.Kind,
	}
}

func catalogAvailablePayload(module modulecatalog.Module) commands.AvailablePayload {
	return commands.AvailablePayload{
		Provider:  module.Name,
		PayloadID: module.ID,
		Name:      module.Name,
		Version:   module.Version,
	}
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
	defer func() { logCommandModeError("close daemon client", client.Close()) }()
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
		for key, value := range request.Config {
			base.Config[key] = value
		}
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
	return client, moduleID, func() { logCommandModeError("close daemon client", client.Close()) }, nil
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

func pkiRPCContext(scope commands.PKIRequestScope) daemonrpc.PKIRequestContext {
	return daemonrpc.PKIRequestContext{
		ActorID: scope.ActorID, OperationID: scope.OperationID, CorrelationID: scope.CorrelationID,
		ApproveSigningLease: scope.ApproveSigningLease, ApprovePrivateKeyExport: scope.ApprovePrivateKeyExport,
	}
}

func (c daemonRunClient) PKIStatus(ctx context.Context) (apppki.WorkspaceStatus, error) {
	return c.client.PKIStatus(ctx)
}

func (c daemonRunClient) InitializePKI(ctx context.Context, scope commands.PKIRequestScope, confirmed bool) (apppki.WorkspaceStatus, error) {
	return c.client.InitializePKI(ctx, daemonrpc.PKIInitializeRequest{Context: pkiRPCContext(scope), Confirmed: confirmed})
}

func (c daemonRunClient) ListPKIBackends(ctx context.Context) ([]domainpki.BackendDescriptor, error) {
	result, err := c.client.ListPKIBackends(ctx)
	return result.Backends, err
}

func (c daemonRunClient) ListPKIProfiles(ctx context.Context) ([]domainpki.Profile, error) {
	result, err := c.client.ListPKIProfiles(ctx)
	return result.Profiles, err
}

func (c daemonRunClient) ListPKIAuthorities(ctx context.Context) ([]domainpki.Authority, error) {
	result, err := c.client.ListPKIAuthorities(ctx)
	return result.Authorities, err
}

func (c daemonRunClient) InspectPKIAuthority(ctx context.Context, id domainpki.AuthorityID) (apppki.AuthorityInspection, error) {
	result, err := c.client.InspectPKIAuthority(ctx, daemonrpc.PKIAuthorityRequest{ID: id})
	return apppki.AuthorityInspection{Authority: result.Authority, ActiveGeneration: result.ActiveGeneration}, err
}

func (c daemonRunClient) CreatePKIAuthority(ctx context.Context, scope commands.PKIRequestScope, request apppki.CreateAuthorityRequest) (apppki.CreateAuthorityResult, error) {
	return c.client.CreatePKIAuthority(ctx, daemonrpc.PKIAuthorityCreateRequest{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) UnlockPKIAuthority(ctx context.Context, scope commands.PKIRequestScope, id domainpki.AuthorityID, duration time.Duration) (apppki.SigningLease, error) {
	value := ""
	if duration != 0 {
		value = duration.String()
	}
	return c.client.UnlockPKIAuthority(ctx, daemonrpc.PKIAuthorityLeaseRequest{Context: pkiRPCContext(scope), ID: id, Duration: value})
}

func (c daemonRunClient) LockPKIAuthority(ctx context.Context, scope commands.PKIRequestScope, id domainpki.AuthorityID) error {
	return c.client.LockPKIAuthority(ctx, daemonrpc.PKIAuthorityLockRequest{Context: pkiRPCContext(scope), ID: id})
}

func (c daemonRunClient) ListPKICertificates(ctx context.Context) ([]domainpki.CertificateGeneration, error) {
	result, err := c.client.ListPKICertificates(ctx)
	return result.Certificates, err
}

func (c daemonRunClient) InspectPKICertificate(ctx context.Context, id domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	return c.client.InspectPKICertificate(ctx, daemonrpc.PKICertificateRequest{ID: id})
}

func (c daemonRunClient) IssuePKICertificate(ctx context.Context, scope commands.PKIRequestScope, request apppki.IssueCertificateRequest) (domainpki.CertificateGeneration, error) {
	return c.client.IssuePKICertificate(ctx, daemonrpc.PKICertificateIssueRequest{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) RenewPKICertificate(ctx context.Context, scope commands.PKIRequestScope, request apppki.RenewCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	return c.client.RenewPKICertificate(ctx, daemonrpc.PKIMutationRequest[apppki.RenewCertificateRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) RotatePKICertificate(ctx context.Context, scope commands.PKIRequestScope, request apppki.RotateCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	return c.client.RotatePKICertificate(ctx, daemonrpc.PKIMutationRequest[apppki.RotateCertificateRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) RevokePKICertificate(ctx context.Context, scope commands.PKIRequestScope, request apppki.RevokeCertificateRequest) (apppki.CertificateRevocationResult, error) {
	return c.client.RevokePKICertificate(ctx, daemonrpc.PKIMutationRequest[apppki.RevokeCertificateRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) InspectPKIRevocation(ctx context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	return c.client.InspectPKIRevocation(ctx, daemonrpc.PKIRevocationRequest{ID: id})
}

func (c daemonRunClient) InspectPKIGenerationRevocation(ctx context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	return c.client.InspectPKIGenerationRevocation(ctx, daemonrpc.PKICertificateRequest{ID: id})
}

func (c daemonRunClient) ListPKIRevocations(ctx context.Context, authorityID domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	result, err := c.client.ListPKIRevocations(ctx, daemonrpc.PKIRevocationListRequest{AuthorityID: authorityID})
	return result.Revocations, err
}

func (c daemonRunClient) PublishPKICRL(ctx context.Context, scope commands.PKIRequestScope, request apppki.PublishCRLRequest) (apppki.CRLPublicationResult, error) {
	return c.client.PublishPKICRL(ctx, daemonrpc.PKIMutationRequest[apppki.PublishCRLRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) InspectPKICRL(ctx context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	return c.client.InspectPKICRL(ctx, daemonrpc.PKICRLRequest{ID: id})
}

func (c daemonRunClient) ListPKICRLs(ctx context.Context, authorityID domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	result, err := c.client.ListPKICRLs(ctx, daemonrpc.PKICRLListRequest{AuthorityID: authorityID})
	return result.CRLs, err
}

func (c daemonRunClient) ListPKIAssignments(ctx context.Context) ([]domainpki.Assignment, error) {
	result, err := c.client.ListPKIAssignments(ctx)
	return result.Assignments, err
}

func (c daemonRunClient) InspectPKIAssignment(ctx context.Context, id domainpki.AssignmentID) (apppki.AssignmentInspection, error) {
	return c.client.InspectPKIAssignment(ctx, daemonrpc.PKIAssignmentRequest{ID: id})
}

func (c daemonRunClient) BindPKIAssignment(ctx context.Context, scope commands.PKIRequestScope, request apppki.BindAssignmentRequest) (domainpki.Assignment, error) {
	return c.client.BindPKIAssignment(ctx, daemonrpc.PKIMutationRequest[apppki.BindAssignmentRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) StagePKIAssignment(ctx context.Context, scope commands.PKIRequestScope, request apppki.StageAssignmentRequest) (apppki.AssignmentInspection, error) {
	return c.client.StagePKIAssignment(ctx, daemonrpc.PKIMutationRequest[apppki.StageAssignmentRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) ActivatePKIAssignment(ctx context.Context, scope commands.PKIRequestScope, request apppki.ActivateAssignmentRequest) (apppki.AssignmentInspection, error) {
	return c.client.ActivatePKIAssignment(ctx, daemonrpc.PKIMutationRequest[apppki.ActivateAssignmentRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) UnbindPKIAssignment(ctx context.Context, scope commands.PKIRequestScope, request apppki.UnbindAssignmentRequest) (domainpki.Assignment, error) {
	return c.client.UnbindPKIAssignment(ctx, daemonrpc.PKIMutationRequest[apppki.UnbindAssignmentRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) ListPKITrustSets(ctx context.Context) ([]domainpki.TrustSet, error) {
	result, err := c.client.ListPKITrustSets(ctx)
	return result.TrustSets, err
}

func (c daemonRunClient) InspectPKITrustSet(ctx context.Context, id domainpki.TrustSetID) (apppki.TrustSetInspection, error) {
	return c.client.InspectPKITrustSet(ctx, daemonrpc.PKITrustSetRequest{ID: id})
}

func (c daemonRunClient) CreatePKITrustSet(ctx context.Context, scope commands.PKIRequestScope, request apppki.CreateTrustSetRequest) (domainpki.TrustSet, error) {
	return c.client.CreatePKITrustSet(ctx, daemonrpc.PKIMutationRequest[apppki.CreateTrustSetRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) StagePKITrustSet(ctx context.Context, scope commands.PKIRequestScope, request apppki.StageTrustSetRequest) (apppki.TrustSetInspection, error) {
	return c.client.StagePKITrustSet(ctx, daemonrpc.PKIMutationRequest[apppki.StageTrustSetRequest]{Context: pkiRPCContext(scope), Request: request})
}

func (c daemonRunClient) ActivatePKITrustSet(ctx context.Context, scope commands.PKIRequestScope, request apppki.ActivateTrustSetRequest) (apppki.TrustSetInspection, error) {
	return c.client.ActivatePKITrustSet(ctx, daemonrpc.PKIMutationRequest[apppki.ActivateTrustSetRequest]{Context: pkiRPCContext(scope), Request: request})
}

var _ commands.PKIControlClient = daemonRunClient{}

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

func (c daemonRunClient) GeneratePayload(ctx context.Context, moduleID string, req commands.GeneratePayloadRequest) (commands.PayloadArtifactSet, error) {
	return c.client.GeneratePayload(ctx, daemonrpc.PayloadGenerateRequest{
		ModuleID: moduleID,
		Request:  req,
	})
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

func (c daemonRunClient) ListSessionCommands(ctx context.Context, sessionID string, req commands.RunSessionCommandListRequest) ([]commands.PayloadCommand, error) {
	resp, err := c.client.ListSessionCommands(ctx, daemonrpc.SessionCommandListRequest{
		SessionID: sessionID,
		Request:   req,
	})
	if err != nil {
		return nil, err
	}
	return append([]commands.PayloadCommand(nil), resp.Commands...), nil
}

func (c daemonRunClient) RunSessionCommand(ctx context.Context, req commands.RunSessionCommandRunRequest) (commands.PayloadCommandResult, error) {
	return c.client.RunSessionCommand(ctx, daemonrpc.SessionCommandRunRequest{
		SessionID: req.SessionID,
		Request:   req.Request,
	})
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
	timestamp, err := time.Parse(time.RFC3339Nano, entry.Time)
	logCommandModeError("parse operator log timestamp", err)
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
