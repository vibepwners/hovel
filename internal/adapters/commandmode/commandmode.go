package commandmode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/adapters/terminallog"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/modules/pythonrpc"
	"github.com/akamensky/argparse"
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

func defaultRuntime(session commands.OperatorSession) commands.Runtime {
	store := filesystem.NewWorkspaceStore()
	return commands.Runtime{
		Workspaces: services.NewWorkspaceService(
			store,
			discardEvents{},
			randomIDs{},
			systemClock{},
		),
		Daemons: services.NewDaemonService(store),
		Runs:    daemonRunClients{},
		Plans:   store,
		Session: session,
		Modules: pythonrpc.MustConfiguredCatalog(),
	}
}

func NewAppWithRegistry(registry commands.Registry) App {
	return App{registry: registry, logs: terminallog.NewRenderer()}
}

func (a App) Registry() commands.Registry {
	return a.registry
}

func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
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
	return a.runDefinition(ctx, definition, commandArgs, stdout, stderr)
}

func (a App) ExecuteLine(ctx context.Context, line string, stdout, stderr io.Writer) int {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0
	}
	return a.Run(ctx, fields, stdout, stderr)
}

func (a App) runDefinition(ctx context.Context, definition commands.Definition, args []string, stdout, stderr io.Writer) int {
	parser := commandParser(definition)
	if helpRequested(args) {
		fmt.Fprint(stdout, usage(definition, parser, nil))
		return 0
	}

	parsed, ok, code := parseDefinition(definition, parser, args, stdout, stderr)
	if !ok {
		return code
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
		return 0
	}
	if !result.Log.Empty() {
		renderer := a.logs
		if parsed.Flag("no-color") {
			renderer = terminallog.NewPlainRenderer()
		}
		fmt.Fprintln(stdout, renderer.Render(result.Log))
		return 0
	}
	if result.Human != "" {
		fmt.Fprintln(stdout, result.Human)
	}
	return 0
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

func commandParser(definition commands.Definition) *argparse.Parser {
	parser := argparse.NewParser("hovel command "+definition.PathString(), definition.Summary)
	for _, positional := range definition.Positionals {
		parser.StringPositional(&argparse.Options{
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
			parser.Flag(option.Short, option.Name, options)
		default:
			parser.String(option.Short, option.Name, options)
		}
	}
	return parser
}

func parseDefinition(definition commands.Definition, parser *argparse.Parser, args []string, stdout, stderr io.Writer) (commands.Invocation, bool, int) {
	parser.ExitOnHelp(false)
	positionals := make(map[string]*string, len(definition.Positionals))
	options := make(map[string]*string)
	flags := make(map[string]*bool)

	parser = argparse.NewParser("hovel command "+definition.PathString(), definition.Summary)
	for _, positional := range definition.Positionals {
		positionals[positional.Name] = parser.StringPositional(&argparse.Options{
			Required: positional.Required,
			Help:     positional.Help,
		})
	}
	for _, option := range definition.Options {
		optionsForArgparse := &argparse.Options{
			Required: option.Required,
			Help:     option.Help,
		}
		switch option.Kind {
		case commands.OptionBool:
			flags[option.Name] = parser.Flag(option.Short, option.Name, optionsForArgparse)
		default:
			options[option.Name] = parser.String(option.Short, option.Name, optionsForArgparse)
		}
	}

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
		invocation.Positionals[positional.Name] = strings.TrimSpace(*positionals[positional.Name])
	}
	for _, option := range definition.Options {
		switch option.Kind {
		case commands.OptionBool:
			invocation.Flags[option.Name] = *flags[option.Name]
		default:
			invocation.Options[option.Name] = strings.TrimSpace(*options[option.Name])
		}
	}
	return invocation, true, 0
}

func usage(definition commands.Definition, parser *argparse.Parser, msg interface{}) string {
	out := parser.Usage(msg)
	parserName := "hovel command " + definition.PathString()
	for i, positional := range definition.Positionals {
		generated := fmt.Sprintf("_positionalArg_%s_%d", parserName, i+1)
		out = strings.ReplaceAll(out, fmt.Sprintf(`[%s "<value>"]`, generated), "<"+positional.Name+">")
		out = strings.ReplaceAll(out, "--"+generated, positional.Name)
		out = strings.ReplaceAll(out, generated, positional.Name)
		wrapped := regexp.MustCompile(`\[` + regexp.QuoteMeta(positional.Name) + `\s+"<value>"\]`)
		out = wrapped.ReplaceAllString(out, "<"+positional.Name+">")
	}
	return out
}

func topLevelHelpRequested(args []string) bool {
	return len(args) == 1 && isHelpArg(args[0])
}

func helpRequested(args []string) bool {
	for _, arg := range args {
		if isHelpArg(arg) {
			return true
		}
	}
	return false
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

func (daemonRunClients) DialRunClient(socketPath string) (commands.RunClient, error) {
	client, err := daemonrpc.Dial(socketPath)
	if err != nil {
		return nil, err
	}
	return daemonRunClient{client: client}, nil
}

type daemonRunClient struct {
	client *daemonrpc.Client
}

func (c daemonRunClient) Close() error {
	return c.client.Close()
}

func (c daemonRunClient) RunMockExploit(ctx context.Context, req commands.RunMockExploitRequest) (commands.RunMockExploitResponse, error) {
	result, err := c.client.RunMockExploit(ctx, daemonrpc.RunMockExploitRequest{
		ModuleID:     req.ModuleID,
		Target:       req.Target,
		Inputs:       req.Inputs,
		ChainConfig:  req.ChainConfig,
		TargetConfig: req.TargetConfig,
	})
	if err != nil {
		return commands.RunMockExploitResponse{}, err
	}
	return commands.RunMockExploitResponse{
		RunID:     result.RunID,
		ModuleID:  result.ModuleID,
		Target:    result.Target,
		State:     result.State,
		Summary:   result.Summary,
		Findings:  findingsFromRPC(result.Findings),
		Artifacts: artifactsFromRPC(result.Artifacts),
		Logs:      logsFromRPC(result.Logs),
	}, nil
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

func logsFromRPC(logs []daemonrpc.LogEntry) []commands.LogEntry {
	out := make([]commands.LogEntry, 0, len(logs))
	for _, log := range logs {
		out = append(out, commands.LogEntry{
			Level:   log.Level,
			Message: log.Message,
			Logger:  log.Logger,
			Fields:  cloneStringMap(log.Fields),
		})
	}
	return out
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
