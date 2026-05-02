package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/adapters/terminallog"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonmanager"
	"github.com/Vibe-Pwners/hovel/internal/modules/pythonrpc"
	prompt "github.com/c-bata/go-prompt"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewApp().Run(ctx, args, stdout, stderr)
}

type App struct {
	commands    commandmode.App
	manager     daemonmanager.Manager
	theme       Theme
	session     commands.OperatorSession
	modules     modulecatalog.Catalog
	wizard      *interactiveConfigWizard
	moduleCount int
	sessionFile string
	surface     *promptSurface
}

func NewApp() App {
	session := operatorsession.New()
	modules := pythonrpc.MustConfiguredCatalog()
	return App{
		commands:    commandmode.NewAppWithSession(session),
		manager:     daemonmanager.New(),
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

	session, err := a.EnsureDaemon(ctx, workspacePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer session.Close()

	daemonClient, err := daemonrpc.Dial(session.Status().Identity.SocketPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer daemonClient.Close()
	a = a.withDaemonSession(ctx, daemonClient)
	a.surface = newPromptSurface(prompt.NewStdoutWriter())

	fmt.Fprintln(stdout, a.WelcomeForWidth(session, terminalWidth(stdout)))
	stopLogs := a.SubscribeLogs(ctx, daemonClient, a.surface, stdout)
	defer stopLogs()
	a.Prompt(ctx, stdout, stderr).Run()
	return 0
}

func (a App) EnsureDaemon(ctx context.Context, workspacePath string) (*daemonmanager.Session, error) {
	return a.manager.Ensure(ctx, workspacePath)
}

func (a App) withDaemonSession(ctx context.Context, client *daemonrpc.Client) App {
	session := daemonrpc.NewSessionClient(ctx, client)
	a.session = session
	a.commands = commandmode.NewAppWithSession(session)
	a.wizard = newInteractiveConfigWizard(session, a.modules)
	return a
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
				chain := a.session.Snapshot().ActiveChain
				if chain == "" {
					result, err := client.PollLogs(pollCtx, cursor)
					if err != nil {
						continue
					}
					cursor = result.Last
					continue
				}
				result, err := client.PollChainLogs(pollCtx, chain, cursor)
				if err != nil {
					continue
				}
				cursor = result.Last
				for _, log := range result.Logs {
					rendered := renderer.Render(operatorLog(log))
					if rendered != "" {
						if surface != nil {
							surface.WriteAsyncLog(rendered, a.PromptPrefix())
							continue
						}
						fmt.Fprintln(fallback)
						fmt.Fprintln(fallback, rendered)
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
		prompt.OptionSetExitCheckerOnInput(func(in string, _ bool) bool {
			return isExit(in)
		}),
	)
}

func (a App) promptWriter() prompt.ConsoleWriter {
	if a.surface != nil {
		return a.surface
	}
	return newPromptSurface(prompt.NewStdoutWriter())
}

func (a App) ExecuteLine(ctx context.Context, line string, stdout, stderr io.Writer) int {
	if err := a.loadWorkspaceSession(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	trimmed := strings.TrimSpace(line)
	if isExit(trimmed) {
		return 0
	}
	if a.wizard != nil && a.wizard.Active() {
		code := a.wizard.HandleLine(trimmed, stdout, stderr)
		if err := a.saveWorkspaceSession(ctx); err != nil {
			fmt.Fprintln(stderr, err)
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
	if trimmed == "chain config interactive" {
		code := a.ConfigureInteractive(stdout, stderr)
		if err := a.saveWorkspaceSession(ctx); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return code
	}
	code := a.commands.ExecuteLine(ctx, trimmed, stdout, stderr)
	if err := a.saveWorkspaceSession(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return code
}

func (a App) PromptPrefix() string {
	if a.session == nil {
		return a.theme.PromptPrefix("")
	}
	if a.wizard != nil && a.wizard.Active() {
		return a.theme.ConfigPromptPrefix(a.session.Snapshot().ActiveChain, a.wizard.PromptMode())
	}
	return a.theme.PromptPrefix(a.session.Snapshot().ActiveChain)
}

func (a App) Completer(document prompt.Document) []prompt.Suggest {
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
		children = a.contextualChildren(path, children)
		prefix := ""
		if !endsWithSpace {
			prefix = fields[len(fields)-1]
		}
		suggestions := suggestionsFromDefinitions(children, prefix)
		if a.inChainContext() && strings.Join(path, " ") == "chain config" {
			suggestions = appendSuggestion(suggestions, "interactive", "Interactively configure the active chain.", prefix)
		}
		return suggestions
	}

	definition, commandWordCount, ok := matchDefinition(registry, fields)
	if !ok {
		return nil
	}
	if !a.inChainContext() && activeChainDefinition(definition.PathString()) {
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
	return filterDefinitions(firstSegments, map[string]bool{
		"chain":   true,
		"control": true,
		"modules": true,
	})
}

func (a App) contextualChildren(path []string, children []commands.Definition) []commands.Definition {
	if a.inChainContext() {
		return children
	}
	switch strings.Join(path, " ") {
	case "chain":
		return filterDefinitions(children, map[string]bool{
			"create": true,
			"delete": true,
			"list":   true,
			"rename": true,
			"use":    true,
		})
	case "chain config", "targets", "targets config":
		return nil
	default:
		return children
	}
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
		"targets add",
		"targets clear",
		"targets config list",
		"targets config set",
		"targets config unset":
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

func (a App) activeChain() string {
	if a.session == nil {
		return ""
	}
	return a.session.Snapshot().ActiveChain
}

func (a App) positionalSuggestions(definition commands.Definition, commandWordCount int, fields []string, endsWithSpace bool) ([]prompt.Suggest, bool) {
	if definition.PathString() != "chain add" {
		return nil, false
	}

	provided := len(fields) - commandWordCount
	if endsWithSpace {
		if provided == 0 {
			return a.moduleSuggestions(""), true
		}
		return nil, true
	}
	if provided == 1 {
		return a.moduleSuggestions(fields[len(fields)-1]), true
	}
	return nil, false
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

func (a App) ConfigureInteractive(stdout, stderr io.Writer) int {
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

func configView(state operatorsession.State) modulecatalog.ConfigView {
	steps := make([]modulecatalog.StepRef, 0, len(state.Steps))
	for _, step := range state.Steps {
		steps = append(steps, modulecatalog.StepRef{ID: step.ID, ModuleID: step.ModuleID})
	}
	return modulecatalog.ConfigView{
		Steps:         steps,
		Targets:       append([]string(nil), state.Targets...),
		ChainConfig:   cloneStringMap(state.Config),
		TargetConfigs: cloneTargetConfigs(state.TargetConfigs),
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

func cloneTargetConfigs(values map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(values))
	for target, config := range values {
		out[target] = cloneStringMap(config)
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

func (t Theme) PromptPrefix(chain string) string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		return "h0v3l> "
	}
	return "h0v3l (" + chain + ") > "
}

func (t Theme) ConfigPromptPrefix(chain, mode string) string {
	chain = strings.TrimSpace(chain)
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "config"
	}
	if chain == "" {
		return "h0v3l " + mode + "> "
	}
	return "h0v3l (" + chain + ") " + mode + " > "
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
			fmt.Fprint(stdout, "Usage: hovel cli [--workspace <path>]\n\nLaunch the interactive Hovel prompt shell.\n")
			return "", false, 0
		}
	case 2:
		if args[0] == "--workspace" || args[0] == "-w" {
			return args[1], true, 0
		}
	}
	fmt.Fprintln(stderr, "hovel cli starts the interactive shell; use hovel <command> for one-shot invocations")
	return "", false, 2
}

func isExit(line string) bool {
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "exit" || line == "quit"
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

func splitStyledLines(values []string) []string {
	var lines []string
	for _, value := range values {
		lines = append(lines, strings.Split(value, "\n")...)
	}
	return lines
}

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

func joinColumns(left, right []string, gap int) string {
	width := 0
	for _, line := range left {
		if lipgloss.Width(line) > width {
			width = lipgloss.Width(line)
		}
	}
	var out []string
	rows := len(left)
	if len(right) > rows {
		rows = len(right)
	}
	spacer := strings.Repeat(" ", gap)
	for i := 0; i < rows; i++ {
		leftLine := ""
		if i < len(left) {
			leftLine = left[i]
		}
		rightLine := ""
		if i < len(right) {
			rightLine = right[i]
		}
		out = append(out, leftLine+strings.Repeat(" ", width-lipgloss.Width(leftLine))+spacer+rightLine)
	}
	return strings.Join(out, "\n")
}
