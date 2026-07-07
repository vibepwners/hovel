package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonlocal"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/storage/filesystem"
	"github.com/Vibe-Pwners/hovel/internal/adapters/terminallog"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/modulepackage"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/Vibe-Pwners/hovel/internal/domain/workspace"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonmanager"
	"github.com/Vibe-Pwners/hovel/internal/moduleruntime/pythonrpc"
	prompt "github.com/c-bata/go-prompt"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewApp().Run(ctx, args, stdout, stderr)
}

type App struct {
	commands      commandmode.App
	manager       daemonmanager.Manager
	theme         Theme
	session       commands.OperatorSession
	modules       modulecatalog.Catalog
	daemonClient  *daemonrpc.Client
	wizard        *interactiveConfigWizard
	moduleCount   int
	workspacePath string
	surface       *promptSurface
	workspaceIDs  map[string]bool
}

func NewApp() App {
	session := operatorsession.New()
	modules := pythonrpc.MustConfiguredCatalog()
	return newAppWithSessionAndModules(session, modules)
}

func newAppWithSessionAndModules(session commands.OperatorSession, modules modulecatalog.Catalog) App {
	return App{
		commands:    commandmode.NewAppWithSessionAndModules(session, modules),
		manager:     daemonlocal.NewManager(),
		theme:       DefaultTheme(),
		session:     session,
		modules:     modules,
		wizard:      newInteractiveConfigWizard(session, modules),
		moduleCount: len(modules.List()),
	}
}

func NewAppWithDependencies(commands commandmode.App, manager daemonmanager.Manager, theme Theme) App {
	modules := pythonrpc.MustConfiguredCatalog()
	return App{
		commands:    commands,
		manager:     manager,
		theme:       theme,
		modules:     modules,
		wizard:      newInteractiveConfigWizard(nil, modules),
		moduleCount: len(modules.List()),
	}
}

func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	workspacePath, ok, code := parseArgs(args, stdout, stderr)
	if !ok {
		return code
	}
	a.workspacePath = workspace.ResolvePath(workspacePath)

	session, err := a.EnsureDaemon(ctx, a.workspacePath)
	if err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	defer func() { logCLIError("close daemon manager session", session.Close()) }()

	daemonClient, err := daemonrpc.Dial(session.Status().Identity.SocketPath)
	if err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	defer func() { logCLIError("close daemon rpc client", daemonClient.Close()) }()
	a = a.withDaemonSession(ctx, daemonClient)
	if err := a.refreshWorkspaceModules(ctx); err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	a.surface = newPromptSurface(prompt.NewStdoutWriter())

	if cliWelcomeEnabled() {
		writeCLILine(stdout, a.WelcomeForWidth(session, terminalWidth(stdout)))
	}
	terminalState, err := capturePromptTerminalState()
	if err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	terminalRestored := false
	defer func() {
		if !terminalRestored {
			logCLIError("restore prompt terminal state", terminalState.Restore())
		}
	}()
	stopLogs := a.SubscribeLogs(ctx, daemonClient, a.surface, stdout)
	defer stopLogs()
	a.Prompt(ctx, stdout, stderr).Run()
	stopLogs()
	if err := finishPrompt(stdout, terminalState); err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	terminalRestored = true
	return 0
}

func (a App) EnsureDaemon(ctx context.Context, workspacePath string) (*daemonmanager.Session, error) {
	return a.manager.Ensure(ctx, workspacePath)
}

func (a App) withDaemonSession(ctx context.Context, client *daemonrpc.Client) App {
	session := daemonrpc.NewSessionClient(ctx, client)
	a.daemonClient = client
	a.session = session
	a.commands = commandmode.NewAppWithSessionModulesAndWorkspace(session, a.modules, a.workspacePath)
	a.wizard = newInteractiveConfigWizard(session, a.modules)
	return a
}

func (a *App) refreshWorkspaceModules(ctx context.Context) error {
	workspacePath := workspace.ResolvePath(a.workspacePath)
	installed, err := installedWorkspaceModules(ctx, workspacePath)
	if err != nil {
		return err
	}
	base := moduleCatalogWithoutIDs(a.modules, a.workspaceIDs)
	workspaceCatalog := modulecatalog.New(installed...)
	a.modules = mergeModuleCatalogs(base, workspaceCatalog)
	a.workspaceIDs = moduleIDSet(installed)
	a.commands = commandmode.NewAppWithSessionModulesAndWorkspace(a.session, a.modules, workspacePath)
	if a.wizard == nil {
		a.wizard = newInteractiveConfigWizard(a.session, a.modules)
	} else {
		a.wizard.session = a.session
		a.wizard.modules = a.modules
	}
	a.moduleCount = len(a.modules.List())
	return nil
}

func installedWorkspaceModules(ctx context.Context, workspacePath string) ([]modulecatalog.Module, error) {
	lock, err := modulepackage.LoadLock(filepath.Join(workspacePath, "module-lock.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	modules := make([]modulecatalog.Module, 0, len(lock.Modules))
	runner := pythonrpc.Runner{WorkspacePath: workspacePath, Timeout: 10 * time.Second}
	for _, record := range lock.Modules {
		pkg, err := modulepackage.LoadDir(record.Source)
		if err != nil {
			return nil, fmt.Errorf("load installed module %s@%s: %w", record.Name, record.Version, err)
		}
		launch, err := pkg.LaunchEntry(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return nil, fmt.Errorf("load installed module %s@%s launcher: %w", record.Name, record.Version, err)
		}
		module, err := runner.InspectEntry(ctx, pythonrpc.ModuleEntry{
			ID:         modulecatalog.CanonicalID(record.Name, record.Version),
			Runtime:    launch.Runtime,
			ProjectDir: launch.ProjectDir,
			Module:     launch.Module,
			Command:    append([]string(nil), launch.Command...),
		})
		if err != nil {
			return nil, fmt.Errorf("inspect installed module %s@%s: %w", record.Name, record.Version, err)
		}
		modules = append(modules, module)
	}
	return modules, nil
}

func mergeModuleCatalogs(catalogs ...modulecatalog.Catalog) modulecatalog.Catalog {
	var modules []modulecatalog.Module
	for _, catalog := range catalogs {
		modules = append(modules, catalog.List()...)
	}
	return modulecatalog.New(modules...)
}

func moduleCatalogWithoutIDs(catalog modulecatalog.Catalog, ids map[string]bool) modulecatalog.Catalog {
	if len(ids) == 0 {
		return catalog
	}
	modules := catalog.List()
	filtered := modules[:0]
	for _, module := range modules {
		if !ids[module.ID] {
			filtered = append(filtered, module)
		}
	}
	return modulecatalog.New(filtered...)
}

func moduleIDSet(modules []modulecatalog.Module) map[string]bool {
	ids := make(map[string]bool, len(modules))
	for _, module := range modules {
		ids[module.ID] = true
	}
	return ids
}

func (a App) SubscribeLogs(ctx context.Context, client *daemonrpc.Client, surface *promptSurface, fallback io.Writer) func() {
	initial, err := client.PollLogs(ctx, 0)
	if err != nil {
		return func() {}
	}
	pollCtx, cancel := context.WithCancel(ctx)
	go func() {
		cursor := initial.Last
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		renderer := terminallog.NewRenderer()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				commandActive, renderCommandLogs := false, true
				if surface != nil {
					commandActive, renderCommandLogs = surface.CommandLogState()
				}
				state := a.session.Snapshot()
				operation := state.ActiveOperation
				chain := state.ActiveChain
				if chain == "" {
					result, err := client.PollLogs(pollCtx, cursor)
					if err != nil {
						continue
					}
					cursor = result.Last
					continue
				}
				result, err := client.PollOperationChainLogs(pollCtx, operation, chain, cursor)
				if err != nil {
					continue
				}
				cursor = result.Last
				if commandActive && !renderCommandLogs {
					continue
				}
				for _, log := range result.Logs {
					rendered := renderer.Render(operatorLog(log))
					if rendered != "" {
						if surface != nil {
							surface.WriteAsyncLog(rendered, a.PromptPrefix())
							continue
						}
						writeCLILine(fallback)
						writeCLILine(fallback, rendered)
					}
				}
			}
		}
	}()
	return cancel
}

func (a App) Prompt(ctx context.Context, stdout, stderr io.Writer) *prompt.Prompt {
	executor := func(line string) {
		if isExit(line) {
			return
		}
		a.ExecuteLine(ctx, line, stdout, stderr)
	}
	return prompt.New(
		executor,
		a.Completer,
		prompt.OptionWriter(a.promptWriter()),
		prompt.OptionTitle("hovel cli"),
		prompt.OptionPrefix(a.PromptPrefix()),
		prompt.OptionLivePrefix(func() (string, bool) {
			return a.PromptPrefix(), true
		}),
		prompt.OptionPrefixTextColor(prompt.Fuchsia),
		prompt.OptionInputTextColor(prompt.Turquoise),
		prompt.OptionSuggestionTextColor(prompt.White),
		prompt.OptionSuggestionBGColor(prompt.Black),
		prompt.OptionSelectedSuggestionTextColor(prompt.Black),
		prompt.OptionSelectedSuggestionBGColor(prompt.Fuchsia),
		prompt.OptionDescriptionTextColor(prompt.LightGray),
		prompt.OptionDescriptionBGColor(prompt.Black),
		prompt.OptionSelectedDescriptionTextColor(prompt.Black),
		prompt.OptionSelectedDescriptionBGColor(prompt.Turquoise),
		prompt.OptionScrollbarThumbColor(prompt.Turquoise),
		prompt.OptionScrollbarBGColor(prompt.Black),
		prompt.OptionMaxSuggestion(10),
		prompt.OptionSetExitCheckerOnInput(promptExitChecker),
	)
}

func (a App) promptWriter() prompt.ConsoleWriter {
	if a.surface != nil {
		return a.surface
	}
	return newPromptSurface(prompt.NewStdoutWriter())
}

func (a *App) ExecuteLine(ctx context.Context, line string, stdout, stderr io.Writer) int {
	if err := a.loadWorkspaceSession(ctx); err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	trimmed := strings.TrimSpace(line)
	if isExit(trimmed) {
		return 0
	}
	if a.wizard != nil && a.wizard.Active() {
		code := a.wizard.HandleLine(trimmed, stdout, stderr)
		if err := a.saveWorkspaceSession(ctx); err != nil {
			writeCLILine(stderr, err)
			return 1
		}
		return code
	}
	if trimmed == "" {
		return 0
	}
	if rewritten, ok := a.contextualCommand(trimmed); ok {
		trimmed = rewritten
	}
	if err := a.flowError(trimmed); err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	if trimmed == "chain config interactive" || trimmed == "chains config interactive" {
		code := a.ConfigureInteractive(ctx, stdout, stderr)
		if err := a.saveWorkspaceSession(ctx); err != nil {
			writeCLILine(stderr, err)
			return 1
		}
		return code
	}
	if isSessionConnectCommand(trimmed) {
		sessionID, options, err := parseSessionConnect(trimmed)
		if err != nil {
			writeCLILine(stderr, err)
			return 1
		}
		return a.executeSessionConnect(ctx, sessionID, options, stdout, stderr)
	}
	trimmed = a.withWorkspaceArgument(trimmed)
	if a.surface != nil {
		renderCommandLogs := !isJSONThrowExecutionCommand(trimmed)
		a.surface.SetCommandLogState(true, renderCommandLogs)
		defer func() {
			if renderCommandLogs && !isLiveThrowExecutionCommand(trimmed) {
				time.Sleep(200 * time.Millisecond)
			}
			a.surface.SetCommandLogState(false, false)
		}()
	}
	code := a.commands.ExecuteLine(ctx, trimmed, stdout, stderr)
	if code == 0 && moduleCatalogMutationCommand(trimmed) {
		if err := a.refreshWorkspaceModules(ctx); err != nil {
			writeCLILine(stderr, err)
			return 1
		}
	}
	if err := a.saveWorkspaceSession(ctx); err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	return code
}

func (a App) withWorkspaceArgument(line string) string {
	if commandLineHasWorkspaceArg(line) || !commandLineUsesWorkspace(line) {
		return line
	}
	return line + " --workspace " + quoteCommandArg(workspace.ResolvePath(a.workspacePath))
}

func commandLineHasWorkspaceArg(line string) bool {
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "--workspace" || field == "-w" {
			return i+1 < len(fields)
		}
		if strings.HasPrefix(field, "--workspace=") {
			return true
		}
	}
	return false
}

func commandLineUsesWorkspace(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "throw", "throws", "confirm", "review", "artifact", "artifacts", "session", "sessions", "module", "modules", "payload", "payloads":
		return true
	default:
		return false
	}
}

func moduleCatalogMutationCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case "module", "modules":
	default:
		return false
	}
	switch fields[1] {
	case "install", "bulk-install", "uninstall":
		return true
	default:
		return false
	}
}

func quoteCommandArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.HasPrefix(arg, "-") && !strings.ContainsAny(arg, " \t\r\n\"\\") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range arg {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

func isThrowExecutionCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != "throw" {
		return false
	}
	if len(fields) > 1 {
		switch fields[1] {
		case "list", "inspect":
			return false
		}
	}
	return true
}

func isAnimatedThrowExecutionCommand(line string) bool {
	if !isThrowExecutionCommand(line) {
		return false
	}
	fields := strings.Fields(line)
	for _, field := range fields[1:] {
		if field == "--now" || field == "-n" || strings.HasPrefix(field, "--now=") {
			return true
		}
	}
	return false
}

func isLiveThrowExecutionCommand(line string) bool {
	if !isThrowExecutionCommand(line) {
		return false
	}
	return !isJSONThrowExecutionCommand(line)
}

func isJSONThrowExecutionCommand(line string) bool {
	if !isThrowExecutionCommand(line) {
		return false
	}
	fields := strings.Fields(line)
	for _, field := range fields[1:] {
		if field == "--json" || field == "-j" || strings.HasPrefix(field, "--json=") {
			return true
		}
	}
	return false
}

func (a App) PromptPrefix() string {
	if a.session == nil {
		return a.theme.PromptPrefix("", "", 0, 0)
	}
	state := a.session.Snapshot()
	if a.wizard != nil && a.wizard.Active() {
		if prompt, ok := a.wizard.ValuePrompt(); ok {
			return a.theme.ConfigValuePromptPrefix(state.ActiveOperation, state.ActiveChain, len(state.Steps), len(state.Targets), prompt)
		}
		return a.theme.ConfigPromptPrefix(state.ActiveOperation, state.ActiveChain, len(state.Steps), len(state.Targets), a.wizard.PromptMode())
	}
	return a.theme.PromptPrefix(state.ActiveOperation, state.ActiveChain, len(state.Steps), len(state.Targets))
}

func (a *App) Completer(document prompt.Document) []prompt.Suggest {
	if a.surface != nil {
		a.surface.SetDocument(document)
	}
	return a.Suggestions(document.TextBeforeCursor())
}

func (a App) Suggestions(line string) []prompt.Suggest {
	if a.wizard != nil && a.wizard.Active() {
		return a.wizard.Suggestions(line)
	}

	line = strings.TrimLeft(line, " \t")
	fields := strings.Fields(line)
	endsWithSpace := strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t")
	registry := a.commands.Registry()

	if len(fields) == 0 {
		return a.rootSuggestions("")
	}

	if !endsWithSpace && len(fields) == 1 {
		return a.rootSuggestions(fields[0])
	}

	if rewritten, ok := a.contextualSuggestionLine(line); ok {
		return a.Suggestions(rewritten)
	}

	path := fields
	if !endsWithSpace {
		path = fields[:len(fields)-1]
	}
	if children := registry.Children(path...); len(children) > 0 {
		if !endsWithSpace && strings.HasPrefix(fields[len(fields)-1], "-") {
			if definition, commandWordCount, ok := matchDefinition(registry, fields); ok && commandWordCount == len(path) {
				return optionSuggestions(definition, fields[len(fields)-1])
			}
		}
		children = a.contextualChildren(path, children)
		prefix := ""
		if !endsWithSpace {
			prefix = fields[len(fields)-1]
		}
		suggestions := suggestionsFromDefinitions(children, prefix)
		if a.inChainContext() && (strings.Join(path, " ") == "chain config" || strings.Join(path, " ") == "chains config") {
			suggestions = appendSuggestion(suggestions, "interactive", "Interactively configure the active chain.", prefix)
		}
		return suggestions
	}

	definition, commandWordCount, ok := matchDefinition(registry, fields)
	if !ok {
		return nil
	}
	pathString := definition.PathString()
	if operationContextRequired(pathString) && !a.inOperationContext() {
		return nil
	}
	if chainContextRequired(pathString) && !a.inChainContext() {
		return nil
	}
	if suggestions, ok := a.positionalSuggestions(definition, commandWordCount, fields, endsWithSpace); ok {
		return suggestions
	}
	optionPrefix := ""
	if !endsWithSpace {
		last := fields[len(fields)-1]
		if strings.HasPrefix(last, "-") {
			optionPrefix = last
		}
	}
	if len(fields) >= commandWordCount {
		return optionSuggestions(definition, optionPrefix)
	}
	return nil
}

func (a App) rootSuggestions(prefix string) []prompt.Suggest {
	definitions := a.contextualRootDefinitions()
	suggestions := suggestionsFromDefinitions(definitions, prefix)
	if a.inChainContext() {
		for _, alias := range activeChainAliases {
			suggestions = appendSuggestion(suggestions, alias.text, alias.description, prefix)
		}
	}
	return suggestions
}

func (a App) contextualRootDefinitions() []commands.Definition {
	firstSegments := a.commands.Registry().FirstSegments()
	if a.inChainContext() {
		return firstSegments
	}
	if a.inOperationContext() {
		return filterDefinitions(firstSegments, map[string]bool{
			"chain":    true,
			"control":  true,
			"module":   true,
			"op":       true,
			"payload":  true,
			"payloads": true,
			"session":  true,
		})
	}
	return filterDefinitions(firstSegments, map[string]bool{
		"control":  true,
		"module":   true,
		"op":       true,
		"payload":  true,
		"payloads": true,
		"session":  true,
	})
}

func (a App) contextualChildren(path []string, children []commands.Definition) []commands.Definition {
	if a.inChainContext() {
		return children
	}
	if !a.inOperationContext() {
		switch strings.Join(path, " ") {
		case "chain", "chains", "chain config", "chains config", "target", "target config", "target set", "target group", "targets", "targets config", "targets set", "targets group":
			return nil
		default:
			return children
		}
	}
	switch strings.Join(path, " ") {
	case "chain", "chains":
		return filterDefinitions(children, map[string]bool{
			"create": true,
			"delete": true,
			"list":   true,
			"rename": true,
			"use":    true,
		})
	case "chain config", "chains config":
		return nil
	default:
		return children
	}
}

func (a App) flowError(line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	registry := a.commands.Registry()
	definition, _, ok := matchDefinition(registry, fields)
	path := ""
	if ok {
		path = definition.PathString()
	} else {
		path = strings.Join(fields, " ")
	}
	if operationContextRequired(path) && !a.inOperationContext() {
		return fmt.Errorf("select an operation first: op use <operation>")
	}
	if chainContextRequired(path) && !a.inChainContext() {
		return fmt.Errorf("select a chain first: chain use <chain>")
	}
	return nil
}

func operationContextRequired(path string) bool {
	fields := strings.Fields(path)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "chain", "chains", "target", "targets":
		return true
	case "throw":
		return len(fields) == 1
	default:
		return false
	}
}

func chainContextRequired(path string) bool {
	fields := strings.Fields(path)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "throw":
		return len(fields) == 1
	}
	return activeChainDefinition(path) || path == "chain config interactive" || path == "chains config interactive"
}

func activeChainDefinition(path string) bool {
	switch path {
	case "chain add",
		"chain config list",
		"chain config set",
		"chain config unset",
		"chain inspect",
		"chain logs",
		"chain validate",
		"chains add",
		"chains config list",
		"chains config set",
		"chains config unset",
		"chains inspect",
		"chains logs",
		"chains validate":
		return true
	default:
		return false
	}
}

func filterDefinitions(definitions []commands.Definition, allowed map[string]bool) []commands.Definition {
	filtered := make([]commands.Definition, 0, len(definitions))
	for _, definition := range definitions {
		if len(definition.Path) == 0 {
			continue
		}
		name := definition.Path[len(definition.Path)-1]
		if allowed[name] {
			filtered = append(filtered, definition)
		}
	}
	return filtered
}

func (a App) contextualSuggestionLine(line string) (string, bool) {
	if !a.inChainContext() {
		return "", false
	}
	trimmed := strings.TrimLeft(line, " \t")
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", false
	}
	if canonical, ok := contextualCommandAlias(fields, a.activeChain()); ok {
		if strings.HasSuffix(trimmed, " ") || strings.HasSuffix(trimmed, "\t") {
			canonical += " "
		}
		return canonical, true
	}
	return "", false
}

func (a App) contextualCommand(line string) (string, bool) {
	if !a.inChainContext() {
		return "", false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	return contextualCommandAlias(fields, a.activeChain())
}

func contextualCommandAlias(fields []string, activeChain string) (string, bool) {
	switch fields[0] {
	case "add":
		return joinCommand(append([]string{"chain", "add"}, fields[1:]...)...), true
	case "config":
		return joinCommand(append([]string{"chain", "config"}, fields[1:]...)...), true
	case "inspect":
		return joinCommand(append([]string{"chain", "inspect"}, fields[1:]...)...), true
	case "logs":
		return joinCommand(append([]string{"chain", "logs"}, fields[1:]...)...), true
	case "rename":
		if len(fields) == 2 {
			return joinCommand("chain", "rename", activeChain, fields[1]), true
		}
	case "validate":
		return joinCommand(append([]string{"chain", "validate"}, fields[1:]...)...), true
	}
	return "", false
}

func joinCommand(head ...string) string {
	return strings.Join(head, " ")
}

func (a App) inChainContext() bool {
	return a.activeChain() != ""
}

func (a App) inOperationContext() bool {
	if a.session == nil {
		return false
	}
	if a.activeChain() != "" {
		return true
	}
	if session, ok := a.session.(interface{ ActiveOperationSelected() bool }); ok {
		return session.ActiveOperationSelected()
	}
	state := a.session.Snapshot()
	return strings.TrimSpace(state.ActiveOperation) != "" && state.ActiveOperation != operatorsession.DefaultOperation
}

func (a App) activeChain() string {
	if a.session == nil {
		return ""
	}
	return a.session.Snapshot().ActiveChain
}

func (a App) positionalSuggestions(definition commands.Definition, commandWordCount int, fields []string, endsWithSpace bool) ([]prompt.Suggest, bool) {
	provided := len(fields) - commandWordCount
	prefix := ""
	if !endsWithSpace && len(fields) > 0 {
		prefix = fields[len(fields)-1]
	}

	switch definition.PathString() {
	case "op use", "operation use":
		return a.singlePositionalSuggestions(provided, prefix, endsWithSpace, a.operationSuggestions), true
	case "chain use", "chains use", "chain delete", "chains delete":
		return a.singlePositionalSuggestions(provided, prefix, endsWithSpace, a.chainSuggestions), true
	case "chain rename", "chains rename":
		if provided == 0 || provided == 1 && !endsWithSpace {
			return a.chainSuggestions(prefix), true
		}
		return nil, true
	case "chain add", "chains add", "module inspect", "modules inspect", "module check", "modules check":
		return a.singlePositionalSuggestions(provided, prefix, endsWithSpace, a.moduleSuggestions), true
	case "chain config set", "chains config set", "chain config unset", "chains config unset":
		if provided == 0 || provided == 1 && !endsWithSpace {
			return a.chainConfigKeySuggestions(prefix), true
		}
		return nil, true
	case "target config list", "targets config list", "target config set", "targets config set", "target config unset", "targets config unset":
		if provided == 0 || provided == 1 && !endsWithSpace {
			return a.targetSuggestions(prefix), true
		}
		if provided == 1 && endsWithSpace || provided == 2 && !endsWithSpace {
			return a.targetConfigKeySuggestions(prefix), true
		}
		return nil, true
	case "target set inspect", "targets set inspect", "target group inspect", "targets group inspect", "target set add", "targets set add", "target group add", "targets group add", "target set remove", "targets set remove", "target group remove", "targets group remove":
		if provided == 0 || provided == 1 && !endsWithSpace {
			return a.targetSetSuggestions(prefix), true
		}
		if strings.Contains(definition.PathString(), " add") || strings.Contains(definition.PathString(), " remove") {
			if provided == 1 && endsWithSpace || provided == 2 && !endsWithSpace {
				return a.targetSuggestions(prefix), true
			}
		}
		return nil, true
	case "session connect", "sessions connect", "session tail", "sessions tail", "session read", "sessions read", "session send", "sessions send", "session write", "sessions write", "session close", "sessions close",
		"session commands", "sessions commands", "session capabilities", "sessions capabilities":
		return a.singlePositionalSuggestions(provided, prefix, endsWithSpace, a.sessionSuggestions), true
	case "session call", "sessions call", "session command", "sessions command":
		if provided == 0 || provided == 1 && !endsWithSpace {
			return a.sessionSuggestions(prefix), true
		}
		if len(fields) > commandWordCount && (provided == 1 && endsWithSpace || provided == 2 && !endsWithSpace) {
			return a.sessionCapabilitySuggestions(fields[commandWordCount], prefix), true
		}
		return nil, true
	case "payloads inspect", "payload inspect", "payloads connect", "payload connect", "payloads cleanup", "payload cleanup",
		"payloads mark-removed", "payload mark-removed", "payloads refresh", "payload refresh", "payloads commands", "payload commands",
		"payloads capabilities", "payload capabilities", "payloads getfile", "payload getfile", "payloads putfile", "payload putfile",
		"payloads cmd", "payload cmd":
		return a.singlePositionalSuggestions(provided, prefix, endsWithSpace, a.payloadSuggestions), true
	case "payloads call", "payload call", "payloads command", "payload command":
		if provided == 0 || provided == 1 && !endsWithSpace {
			return a.payloadSuggestions(prefix), true
		}
		if len(fields) > commandWordCount && (provided == 1 && endsWithSpace || provided == 2 && !endsWithSpace) {
			return a.payloadCapabilitySuggestions(fields[commandWordCount], prefix), true
		}
		return nil, true
	default:
		return nil, false
	}
}

func (a App) singlePositionalSuggestions(provided int, prefix string, endsWithSpace bool, suggest func(string) []prompt.Suggest) []prompt.Suggest {
	if provided == 0 || provided == 1 && !endsWithSpace {
		return suggest(prefix)
	}
	return nil
}

func (a App) operationSuggestions(prefix string) []prompt.Suggest {
	if a.session == nil {
		return nil
	}
	state := a.session.Snapshot()
	suggestions := make([]prompt.Suggest, 0, len(state.Operations))
	for _, operation := range state.Operations {
		description := fmt.Sprintf("%d chain(s)", len(operation.Chains))
		if operation.Name == state.ActiveOperation {
			description = "active operation"
		}
		suggestions = append(suggestions, prompt.Suggest{Text: operation.Name, Description: description})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) chainSuggestions(prefix string) []prompt.Suggest {
	if a.session == nil {
		return nil
	}
	state := a.session.Snapshot()
	suggestions := make([]prompt.Suggest, 0, len(state.Chains))
	for _, chain := range state.Chains {
		description := fmt.Sprintf("%d step(s)", len(chain.Steps))
		if chain.Name == state.ActiveChain {
			description = "active chain"
		}
		suggestions = append(suggestions, prompt.Suggest{Text: chain.Name, Description: description})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) targetSuggestions(prefix string) []prompt.Suggest {
	if a.session == nil {
		return nil
	}
	state := a.session.Snapshot()
	targets := state.OperationTargets
	if len(targets) == 0 {
		targets = state.Targets
	}
	suggestions := make([]prompt.Suggest, 0, len(targets))
	for _, target := range targets {
		description := "target"
		if config := state.TargetConfigs[target]; len(config) > 0 {
			description = fmt.Sprintf("%d config value(s)", len(config))
		}
		suggestions = append(suggestions, prompt.Suggest{Text: target, Description: description})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) targetSetSuggestions(prefix string) []prompt.Suggest {
	if a.session == nil {
		return nil
	}
	state := a.session.Snapshot()
	suggestions := make([]prompt.Suggest, 0, len(state.TargetSets))
	for _, set := range state.TargetSets {
		suggestions = append(suggestions, prompt.Suggest{Text: set.Name, Description: fmt.Sprintf("%d target(s)", len(set.Targets))})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) chainConfigKeySuggestions(prefix string) []prompt.Suggest {
	if a.session == nil {
		return nil
	}
	state := a.session.Snapshot()
	requirements, _ := requirementMaps(a.modules, state)
	return configKeySuggestions(requirements, state.Config, prefix)
}

func (a App) targetConfigKeySuggestions(prefix string) []prompt.Suggest {
	if a.session == nil {
		return nil
	}
	state := a.session.Snapshot()
	_, requirements := requirementMaps(a.modules, state)
	existing := map[string]string{}
	for _, config := range state.TargetConfigs {
		for key, value := range config {
			existing[key] = value
		}
	}
	return configKeySuggestions(requirements, existing, prefix)
}

func (a App) sessionSuggestions(prefix string) []prompt.Suggest {
	sessions, ok := a.completionSessions()
	if !ok {
		return nil
	}
	suggestions := make([]prompt.Suggest, 0, len(sessions))
	for _, session := range sessions {
		description := strings.TrimSpace(strings.Join([]string{session.Kind, session.State, session.Target, session.Name}, " "))
		suggestions = append(suggestions, prompt.Suggest{Text: session.ID, Description: description})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) sessionCapabilitySuggestions(sessionRef, prefix string) []prompt.Suggest {
	if a.daemonClient == nil {
		return nil
	}
	sessionID, ok := a.resolveCompletionSessionID(sessionRef)
	if !ok {
		return nil
	}
	type sessionCommandResult struct {
		commands []run.PayloadCommand
		err      error
	}
	results := make(chan sessionCommandResult, 1)
	go func() {
		resp, err := a.daemonClient.ListSessionCommands(context.Background(), daemonrpc.SessionCommandListRequest{
			SessionID: sessionID,
			Request:   run.PayloadCommandListRequest{},
		})
		results <- sessionCommandResult{commands: resp.Commands, err: err}
	}()
	var sessionCommands []run.PayloadCommand
	select {
	case result := <-results:
		if result.err != nil {
			logCLIError("complete session command list", result.err)
			return nil
		}
		sessionCommands = result.commands
	case <-time.After(100 * time.Millisecond):
		return nil
	}
	suggestions := make([]prompt.Suggest, 0, len(sessionCommands))
	for _, command := range sessionCommands {
		description := command.Summary
		if len(command.Capabilities) > 0 {
			description = strings.TrimSpace(description + " " + strings.Join(command.Capabilities, ","))
		}
		suggestions = append(suggestions, prompt.Suggest{Text: command.Name, Description: description})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) resolveCompletionSessionID(sessionRef string) (string, bool) {
	sessionRef = strings.TrimSpace(sessionRef)
	switch sessionRef {
	case "latest", "@latest":
		sessions, ok := a.completionSessions()
		if !ok {
			return "", false
		}
		for i := len(sessions) - 1; i >= 0; i-- {
			session := sessions[i]
			if completionSessionIsActive(session) {
				return session.ID, true
			}
		}
		return "", false
	default:
		return sessionRef, sessionRef != ""
	}
}

func (a App) completionSessions() ([]daemonrpc.SessionRef, bool) {
	if a.daemonClient == nil {
		return nil, false
	}
	type sessionListResult struct {
		sessions []daemonrpc.SessionRef
		err      error
	}
	results := make(chan sessionListResult, 1)
	go func() {
		sessions, err := a.daemonClient.ListSessions(context.Background())
		results <- sessionListResult{sessions: sessions, err: err}
	}()
	select {
	case result := <-results:
		if result.err != nil {
			logCLIError("complete session list", result.err)
			return nil, false
		}
		return result.sessions, true
	case <-time.After(100 * time.Millisecond):
		return nil, false
	}
}

func completionSessionIsActive(session daemonrpc.SessionRef) bool {
	switch strings.ToLower(strings.TrimSpace(session.State)) {
	case "", "active", "open":
		return true
	default:
		return false
	}
}

func (a App) payloadSuggestions(prefix string) []prompt.Suggest {
	records, err := filesystem.NewWorkspaceStore().ListInstalledPayloads(context.Background(), workspace.ResolvePath(a.workspacePath), commands.InstalledPayloadFilter{})
	if err != nil {
		return nil
	}
	suggestions := make([]prompt.Suggest, 0, len(records))
	for _, record := range records {
		description := strings.TrimSpace(strings.Join([]string{record.State, record.Provider, record.Target, record.Transport}, " "))
		suggestions = append(suggestions, prompt.Suggest{Text: record.Handle, Description: description})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) payloadCapabilitySuggestions(payloadRef, prefix string) []prompt.Suggest {
	if a.daemonClient == nil {
		return nil
	}
	record, err := filesystem.NewWorkspaceStore().GetInstalledPayload(context.Background(), workspace.ResolvePath(a.workspacePath), payloadRef)
	if err != nil {
		return nil
	}
	moduleID := a.payloadProviderModuleID(record.Provider)
	if moduleID == "" {
		moduleID = record.Provider
	}
	type payloadCommandResult struct {
		commands []run.PayloadCommand
		err      error
	}
	results := make(chan payloadCommandResult, 1)
	go func() {
		resp, err := a.daemonClient.ListPayloadCommands(context.Background(), daemonrpc.PayloadCommandListRequest{
			ModuleID: moduleID,
			Request: run.PayloadCommandListRequest{
				InstalledPayloadID: record.Handle,
				Target:             record.Target,
				PayloadID:          record.PayloadID,
				Config:             cliInstalledPayloadConfig(record),
				Reconnect:          cliPayloadProviderRecordToRun(record.Reconnect),
			},
		})
		results <- payloadCommandResult{commands: resp.Commands, err: err}
	}()
	var payloadCommands []run.PayloadCommand
	select {
	case result := <-results:
		if result.err != nil {
			return nil
		}
		payloadCommands = result.commands
	case <-time.After(100 * time.Millisecond):
		return nil
	}
	suggestions := make([]prompt.Suggest, 0, len(payloadCommands))
	for _, command := range payloadCommands {
		description := command.Summary
		if len(command.Capabilities) > 0 {
			description = strings.TrimSpace(description + " " + strings.Join(command.Capabilities, ","))
		}
		suggestions = append(suggestions, prompt.Suggest{Text: command.Name, Description: description})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) payloadProviderModuleID(provider string) string {
	if module, ok := a.modules.Find(provider); ok && module.Type == modulecatalog.TypePayloadProvider {
		return module.ID
	}
	for _, module := range a.modules.ByType(modulecatalog.TypePayloadProvider) {
		if strings.EqualFold(module.Name, provider) || strings.EqualFold(module.ID, provider) {
			return module.ID
		}
	}
	return ""
}

func cliInstalledPayloadConfig(record commands.InstalledPayloadRecord) map[string]string {
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

func cliPayloadProviderRecordToRun(record *commands.PayloadProviderRecord) *run.PayloadProviderRecord {
	if record == nil {
		return nil
	}
	descriptor := make(map[string]any, len(record.Descriptor))
	for key, value := range record.Descriptor {
		descriptor[key] = value
	}
	return &run.PayloadProviderRecord{
		ProviderID:    record.ProviderID,
		Schema:        record.Schema,
		SchemaVersion: record.SchemaVersion,
		Descriptor:    descriptor,
	}
}

func configKeySuggestions(requirements map[string]modulecatalog.Requirement, existing map[string]string, prefix string) []prompt.Suggest {
	suggestions := make([]prompt.Suggest, 0, len(requirements)+len(existing))
	for _, key := range sortedKeys(requirements) {
		requirement := requirements[key]
		description := requirement.Description
		if description == "" {
			typeName := string(requirement.Type)
			if typeName == "" {
				typeName = "string"
			}
			description = typeName
		}
		suggestions = append(suggestions, prompt.Suggest{Text: key, Description: description})
	}
	for _, key := range sortedKeys(existing) {
		suggestions = append(suggestions, prompt.Suggest{Text: key, Description: "current value"})
	}
	return filterSuggestions(dedupeSuggestions(suggestions), prefix)
}

func (a App) moduleSuggestions(prefix string) []prompt.Suggest {
	var modules []modulecatalog.Module
	if strings.TrimSpace(prefix) == "" {
		modules = a.modules.List()
	} else {
		modules = a.modules.Search(prefix)
	}

	suggestions := make([]prompt.Suggest, 0, len(modules))
	for _, module := range modules {
		suggestions = append(suggestions, prompt.Suggest{
			Text:        module.ID,
			Description: fmt.Sprintf("%s %s", module.Type, module.Summary),
		})
	}
	return suggestions
}

func (a App) ConfigureInteractive(ctx context.Context, stdout, stderr io.Writer) int {
	if err := a.refreshWorkspaceModules(ctx); err != nil {
		writeCLILine(stderr, err)
		return 1
	}
	if shouldUseHuhConfig(stdout) {
		return a.runHuhConfigForm(ctx, stdout, stderr)
	}
	if a.wizard == nil {
		a.wizard = newInteractiveConfigWizard(a.session, a.modules)
	}
	return a.wizard.Start(stdout, stderr)
}

type configItem struct {
	Scope       modulecatalog.Scope
	Target      string
	Key         string
	Value       string
	Requirement modulecatalog.Requirement
}

func (i configItem) Label() string {
	value := modulecatalog.DisplayValue(i.Requirement, i.Value)
	if i.Value == "" {
		switch {
		case i.Requirement.Default != "":
			value = "default " + modulecatalog.DisplayValue(i.Requirement, i.Requirement.Default)
		case i.Requirement.Required:
			value = "required"
		default:
			value = "optional"
		}
	}
	if i.Scope == modulecatalog.ScopeTarget {
		return fmt.Sprintf("target %s %s=%s", i.Target, i.Key, value)
	}
	return fmt.Sprintf("chain %s=%s", i.Key, value)
}

func (i configItem) Prompt() string {
	typeName := string(i.Requirement.Type)
	if typeName == "" {
		typeName = "string"
	}
	current := ""
	if i.Value != "" {
		current = " [" + modulecatalog.DisplayValue(i.Requirement, i.Value) + "]"
	}
	if i.Scope == modulecatalog.ScopeTarget {
		return fmt.Sprintf("target %s %s (%s)%s: ", i.Target, i.Key, typeName, current)
	}
	return fmt.Sprintf("chain %s (%s)%s: ", i.Key, typeName, current)
}

func currentConfigItems(catalog modulecatalog.Catalog, state operatorsession.State) []configItem {
	chainRequirements, targetRequirements := requirementMaps(catalog, state)
	var items []configItem
	for _, key := range sortedKeys(state.Config) {
		items = append(items, configItem{
			Scope:       modulecatalog.ScopeChain,
			Key:         key,
			Value:       state.Config[key],
			Requirement: chainRequirements[key],
		})
	}
	for _, target := range sortedKeys(state.TargetConfigs) {
		for _, key := range sortedKeys(state.TargetConfigs[target]) {
			items = append(items, configItem{
				Scope:       modulecatalog.ScopeTarget,
				Target:      target,
				Key:         key,
				Value:       state.TargetConfigs[target][key],
				Requirement: targetRequirements[key],
			})
		}
	}
	return items
}

func availableConfigItems(catalog modulecatalog.Catalog, state operatorsession.State) []configItem {
	chainRequirements, targetRequirements := requirementMaps(catalog, state)
	var items []configItem
	for _, key := range sortedKeys(chainRequirements) {
		items = append(items, configItem{
			Scope:       modulecatalog.ScopeChain,
			Key:         key,
			Value:       state.Config[key],
			Requirement: chainRequirements[key],
		})
	}
	for _, target := range state.Targets {
		config := state.TargetConfigs[target]
		for _, key := range sortedKeys(targetRequirements) {
			items = append(items, configItem{
				Scope:       modulecatalog.ScopeTarget,
				Target:      target,
				Key:         key,
				Value:       config[key],
				Requirement: targetRequirements[key],
			})
		}
	}
	if len(items) == 0 {
		return currentConfigItems(catalog, state)
	}
	return items
}

func missingConfigItems(catalog modulecatalog.Catalog, state operatorsession.State) []configItem {
	chainRequirements, targetRequirements := requirementMaps(catalog, state)
	var items []configItem
	for _, key := range sortedKeys(chainRequirements) {
		requirement := chainRequirements[key]
		if !requirement.Required {
			continue
		}
		value := state.Config[key]
		if value == "" || validateConfigValue(requirement, value) != nil {
			items = append(items, configItem{
				Scope:       modulecatalog.ScopeChain,
				Key:         key,
				Value:       value,
				Requirement: requirement,
			})
		}
	}
	for _, target := range state.Targets {
		config := state.TargetConfigs[target]
		for _, key := range sortedKeys(targetRequirements) {
			requirement := targetRequirements[key]
			if !requirement.Required {
				continue
			}
			value := config[key]
			if value == "" || validateConfigValue(requirement, value) != nil {
				items = append(items, configItem{
					Scope:       modulecatalog.ScopeTarget,
					Target:      target,
					Key:         key,
					Value:       value,
					Requirement: requirement,
				})
			}
		}
	}
	return items
}

func requirementMaps(catalog modulecatalog.Catalog, state operatorsession.State) (map[string]modulecatalog.Requirement, map[string]modulecatalog.Requirement) {
	chainRequirements := map[string]modulecatalog.Requirement{}
	targetRequirements := map[string]modulecatalog.Requirement{}
	for _, step := range state.Steps {
		if step.StepID == "squatter.bind" || (step.StepID == "" && isSquatterTCPBindStep(catalog, step, state.Config)) {
			for _, requirement := range squatterTCPBindRequirements() {
				chainRequirements[requirement.Key] = requirement
			}
			continue
		}
		module, ok := catalog.Find(step.ModuleID)
		if !ok {
			continue
		}
		for _, requirement := range module.ChainConfig {
			chainRequirements[requirement.Key] = requirement
		}
		for _, requirement := range module.TargetConfig {
			targetRequirements[requirement.Key] = requirement
		}
	}
	return chainRequirements, targetRequirements
}

func isSquatterTCPBindStep(catalog modulecatalog.Catalog, step operatorsession.Step, config map[string]string) bool {
	module, ok := catalog.Find(step.ModuleID)
	if (!ok || !strings.EqualFold(module.Name, "squatter") || module.Type != modulecatalog.TypePayloadProvider) && !isSquatterProviderRef(step.ModuleID) {
		return false
	}
	mode := strings.TrimSpace(config["squatter.type"])
	return mode == "" || mode == "tcp-bind"
}

func isSquatterProviderRef(moduleID string) bool {
	ref := strings.ToLower(strings.TrimSpace(moduleID))
	return ref == "squatter" || ref == "squatter@v0.1.0"
}

func squatterTCPBindRequirements() []modulecatalog.Requirement {
	return []modulecatalog.Requirement{
		{
			Key:         "squatter.type",
			Type:        modulecatalog.ValueEnum,
			Required:    false,
			Default:     "tcp-bind",
			Allowed:     []string{"tcp-bind"},
			Description: "Squatter install/session mode.",
		},
		{
			Key:         "squatter.bind_port",
			Type:        modulecatalog.ValuePort,
			Required:    false,
			Default:     "9101",
			Description: "TCP bind port opened by the Squatter agent on the target.",
		},
		{
			Key:         "squatter.remote_path",
			Type:        modulecatalog.ValueString,
			Required:    false,
			Description: "Optional fixed target path used when the MS17-010 exploit installs the Squatter agent; unset auto-generates a fresh path.",
		},
	}
}

func validateConfigValue(requirement modulecatalog.Requirement, value string) error {
	if requirement.Type == "" {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("value is required")
		}
		return nil
	}
	return modulecatalog.ValidateValue(requirement, value)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (a App) Welcome(session *daemonmanager.Session) string {
	return a.WelcomeForWidth(session, 0)
}

func (a App) WelcomeForWidth(session *daemonmanager.Session, width int) string {
	status := session.Status()
	mode := "remote"
	if session.Owned() {
		mode = "managed"
	}
	return a.theme.Welcome(WelcomeInfo{
		ModuleCount:   a.moduleCount,
		DaemonAddress: status.Identity.SocketPath,
		DaemonMode:    mode,
		Health:        string(status.Identity.Health),
		TerminalWidth: width,
	})
}

type Theme struct {
	accent lipgloss.Style
	cyan   lipgloss.Style
	muted  lipgloss.Style
	label  lipgloss.Style
	panel  lipgloss.Style
}

func DefaultTheme() Theme {
	return Theme{
		accent: lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2bd6")).Bold(true),
		cyan:   lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		muted:  lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")),
		label:  lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")),
		panel: lipgloss.NewStyle().
			Border(thickRoundedBorder()).
			BorderForeground(lipgloss.Color("#ff2bd6")).
			Padding(0, 1),
	}
}

func (t Theme) PromptPrefix(operation, chain string, steps, targets int) string {
	operation = strings.TrimSpace(operation)
	chain = strings.TrimSpace(chain)
	if operation == "" || operation == operatorsession.DefaultOperation {
		if chain == "" {
			return "h0v3l> "
		}
		return fmt.Sprintf("h0v3l (%s | steps:%d targets:%d) > ", chain, steps, targets)
	}
	if chain == "" {
		return "h0v3l [op:" + operation + "]> "
	}
	return fmt.Sprintf("h0v3l [%s/%s | steps:%d targets:%d] > ", operation, chain, steps, targets)
}

func (t Theme) ConfigPromptPrefix(operation, chain string, steps, targets int, mode string) string {
	operation = strings.TrimSpace(operation)
	chain = strings.TrimSpace(chain)
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "config"
	}
	if operation == "" || operation == operatorsession.DefaultOperation {
		if chain == "" {
			return "h0v3l " + mode + "> "
		}
		return fmt.Sprintf("h0v3l (%s | steps:%d targets:%d) %s > ", chain, steps, targets, mode)
	}
	if chain == "" {
		return "h0v3l [" + operation + "] " + mode + " > "
	}
	return fmt.Sprintf("h0v3l [%s/%s | steps:%d targets:%d] %s > ", operation, chain, steps, targets, mode)
}

func (t Theme) ConfigValuePromptPrefix(operation, chain string, steps, targets int, prompt string) string {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return t.ConfigPromptPrefix(operation, chain, steps, targets, "config value")
	}
	operation = strings.TrimSpace(operation)
	chain = strings.TrimSpace(chain)
	if operation == "" || operation == operatorsession.DefaultOperation {
		if chain == "" {
			return "h0v3l " + prompt + " "
		}
		return fmt.Sprintf("h0v3l (%s | steps:%d targets:%d) %s ", chain, steps, targets, prompt)
	}
	if chain == "" {
		return "h0v3l [" + operation + "] " + prompt + " "
	}
	return fmt.Sprintf("h0v3l [%s/%s | steps:%d targets:%d] %s ", operation, chain, steps, targets, prompt)
}

type WelcomeInfo struct {
	ModuleCount   int
	DaemonAddress string
	DaemonMode    string
	Health        string
	TerminalWidth int
}

func (t Theme) Welcome(info WelcomeInfo) string {
	if info.TerminalWidth > 0 && info.TerminalWidth < wideMastheadColumns {
		details := []string{
			t.accent.Render(hovelCompactWordmark),
			"",
			t.detail("modules", strconv.Itoa(info.ModuleCount)),
			t.detail("hoveld", info.DaemonAddress),
			t.detail("mode", info.DaemonMode),
			t.detail("health", info.Health),
		}
		return strings.Join(details, "\n")
	}

	details := []string{
		t.accent.Render(hovelWordmark),
		"",
		t.detail("modules", strconv.Itoa(info.ModuleCount)),
		t.detail("hoveld", info.DaemonAddress),
		t.detail("mode", info.DaemonMode),
		t.detail("health", info.Health),
	}
	panel := t.panel.Render(strings.Join(details, "\n"))
	hut := centerBlock(t.cyan.Render(hovelASCII), lipgloss.Width(panel))
	return hut + "\n" + panel
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

func cliWelcomeEnabled() bool {
	value := strings.TrimSpace(os.Getenv("HOVEL_CLI_NO_WELCOME"))
	return value == "" || value == "0" || strings.EqualFold(value, "false")
}

func (t Theme) detail(label, value string) string {
	return t.label.Render(label+":") + " " + t.muted.Render(value)
}

func operatorLog(log daemonrpc.PublishedLog) operatorlog.Log {
	entry := operatorlog.Entry{
		ID:             log.Entry.ID,
		Kind:           operatorlog.Kind(log.Entry.Kind),
		Level:          operatorlog.Level(log.Entry.Level),
		Source:         log.Entry.Source,
		Message:        log.Entry.Message,
		ChainID:        log.Entry.ChainID,
		ChainName:      log.Entry.ChainName,
		RunID:          log.Entry.RunID,
		Target:         log.Entry.Target,
		ModuleID:       log.Entry.ModuleID,
		ElapsedSeconds: cloneFloat64(log.Entry.ElapsedSeconds),
		Fields:         fieldsFromMap(log.Entry.Fields),
		Attributes:     cloneStringMap(log.Entry.Attributes),
	}
	return operatorlog.New("", "", []operatorlog.Entry{entry})
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func fieldsFromMap(values map[string]string) []operatorlog.Field {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fields := make([]operatorlog.Field, 0, len(keys))
	for _, key := range keys {
		fields = append(fields, operatorlog.Field{Name: key, Value: values[key]})
	}
	return fields
}

func suggestionsFromDefinitions(definitions []commands.Definition, prefix string) []prompt.Suggest {
	var suggestions []prompt.Suggest
	for _, definition := range definitions {
		text := definition.Path[len(definition.Path)-1]
		if prefix != "" && !strings.HasPrefix(text, prefix) {
			continue
		}
		suggestions = append(suggestions, prompt.Suggest{Text: text, Description: definition.Summary})
	}
	return suggestions
}

func appendSuggestion(suggestions []prompt.Suggest, text, description, prefix string) []prompt.Suggest {
	if prefix != "" && !strings.HasPrefix(text, prefix) {
		return suggestions
	}
	for _, suggestion := range suggestions {
		if suggestion.Text == text {
			return suggestions
		}
	}
	return append(suggestions, prompt.Suggest{Text: text, Description: description})
}

type commandAlias struct {
	text        string
	description string
}

var activeChainAliases = []commandAlias{
	{text: "add", description: "Add a module to the active chain."},
	{text: "config", description: "Manage active chain configuration."},
	{text: "inspect", description: "Inspect the active chain."},
	{text: "logs", description: "Show logs for the active chain."},
	{text: "rename", description: "Rename the active chain."},
	{text: "validate", description: "Validate active chain configuration."},
}

func optionSuggestions(definition commands.Definition, prefix string) []prompt.Suggest {
	var suggestions []prompt.Suggest
	for _, option := range definition.Options {
		names := []string{"--" + option.Name}
		if option.Short != "" {
			names = append(names, "-"+option.Short)
		}
		for _, name := range names {
			if prefix != "" && !strings.HasPrefix(name, prefix) {
				continue
			}
			suggestions = append(suggestions, prompt.Suggest{Text: name, Description: option.Help})
		}
	}
	return suggestions
}

func matchDefinition(registry commands.Registry, fields []string) (commands.Definition, int, bool) {
	for i := len(fields); i > 0; i-- {
		definition, ok := registry.Find(fields[:i]...)
		if ok {
			return definition, i, true
		}
	}
	return commands.Definition{}, 0, false
}

func parseArgs(args []string, stdout, stderr io.Writer) (string, bool, int) {
	switch len(args) {
	case 0:
		return "", true, 0
	case 1:
		if args[0] == "-h" || args[0] == "--help" {
			writeCLIText(stdout, "Usage: hovel cli [--workspace <path>]\n\nLaunch the interactive Hovel prompt shell.\n")
			return "", false, 0
		}
	case 2:
		if args[0] == "--workspace" || args[0] == "-w" {
			return args[1], true, 0
		}
	}
	writeCLILine(stderr, "hovel cli starts the interactive shell; use hovel <command> for one-shot invocations")
	return "", false, 2
}

func isExit(line string) bool {
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "exit" || line == "quit"
}

func promptExitChecker(line string, breakline bool) bool {
	return breakline && isExit(line)
}

const hovelASCII = `          ~~~
        ~~   ~
           )
          (
        .-"""-.
     .-'       '-.
   .'   .-"""-.   '.
  /    /       \    \
 /____/_________\____\
 |   _           _   |
 |  (o)         (o)  |
 |        ___        |
 |       /   \       |
 |______|_____|______|
     ~~         ~~`

const hovelWordmark = ` █████   █████    ███████    █████   █████ ██████████ █████
░░███   ░░███   ███░░░░░███ ░░███   ░░███ ░░███░░░░░█░░███
 ░███    ░███  ███     ░░███ ░███    ░███  ░███  █ ░  ░███
 ░███████████ ░███      ░███ ░███    ░███  ░██████    ░███
 ░███░░░░░███ ░███      ░███ ░░███   ███   ░███░░█    ░███
 ░███    ░███ ░░███     ███   ░░░█████░    ░███ ░   █ ░███      █
 █████   █████ ░░░███████░      ░░███      ██████████ ███████████
░░░░░   ░░░░░    ░░░░░░░         ░░░      ░░░░░░░░░░ ░░░░░░░░░░░`

const hovelCompactWordmark = "                          \n" +
	"|   |,---..    ,,---.|    \n" +
	"|---||   ||    ||--- |    \n" +
	"|   ||   | \\  / |    |    \n" +
	"`   '`---'  `'  `---'`---'\n" +
	"                          "

const wideMastheadColumns = 69

func centerBlock(value string, width int) string {
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = lipgloss.PlaceHorizontal(width, lipgloss.Center, line)
	}
	return strings.Join(lines, "\n")
}

func thickRoundedBorder() lipgloss.Border {
	return lipgloss.Border{
		Top:         "━",
		Bottom:      "━",
		Left:        "┃",
		Right:       "┃",
		TopLeft:     "╭",
		TopRight:    "╮",
		BottomLeft:  "╰",
		BottomRight: "╯",
	}
}
