package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/adapters/commandmode"
	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/infra/daemonmanager"
	prompt "github.com/c-bata/go-prompt"
	"github.com/charmbracelet/lipgloss"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewApp().Run(ctx, args, stdout, stderr)
}

type App struct {
	commands    commandmode.App
	manager     daemonmanager.Manager
	theme       Theme
	session     *operatorsession.Session
	moduleCount int
}

func NewApp() App {
	session := operatorsession.New()
	return App{
		commands:    commandmode.NewAppWithSession(session),
		manager:     daemonmanager.New(),
		theme:       DefaultTheme(),
		session:     session,
		moduleCount: builtInModuleCount,
	}
}

func NewAppWithDependencies(commands commandmode.App, manager daemonmanager.Manager, theme Theme) App {
	return App{commands: commands, manager: manager, theme: theme, moduleCount: builtInModuleCount}
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

	fmt.Fprintln(stdout, a.Welcome(session))
	a.Prompt(ctx, stdout, stderr).Run()
	return 0
}

func (a App) EnsureDaemon(ctx context.Context, workspacePath string) (*daemonmanager.Session, error) {
	return a.manager.Ensure(ctx, workspacePath)
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

func (a App) ExecuteLine(ctx context.Context, line string, stdout, stderr io.Writer) int {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return 0
	}
	if isExit(trimmed) {
		return 0
	}
	return a.commands.ExecuteLine(ctx, trimmed, stdout, stderr)
}

func (a App) PromptPrefix() string {
	if a.session == nil {
		return a.theme.PromptPrefix("")
	}
	return a.theme.PromptPrefix(a.session.Snapshot().ActiveChain)
}

func (a App) Completer(document prompt.Document) []prompt.Suggest {
	return a.Suggestions(document.TextBeforeCursor())
}

func (a App) Suggestions(line string) []prompt.Suggest {
	line = strings.TrimLeft(line, " \t")
	fields := strings.Fields(line)
	endsWithSpace := strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t")
	registry := a.commands.Registry()

	if len(fields) == 0 {
		return suggestionsFromDefinitions(registry.FirstSegments(), "")
	}

	if !endsWithSpace && len(fields) == 1 {
		return suggestionsFromDefinitions(registry.FirstSegments(), fields[0])
	}

	path := fields
	if !endsWithSpace {
		path = fields[:len(fields)-1]
	}
	if children := registry.Children(path...); len(children) > 0 {
		prefix := ""
		if !endsWithSpace {
			prefix = fields[len(fields)-1]
		}
		return suggestionsFromDefinitions(children, prefix)
	}

	definition, commandWordCount, ok := matchDefinition(registry, fields)
	if !ok {
		return nil
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

func (a App) Welcome(session *daemonmanager.Session) string {
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
	return "h0v3l ( " + chain + " )> "
}

type WelcomeInfo struct {
	ModuleCount   int
	DaemonAddress string
	DaemonMode    string
	Health        string
}

func (t Theme) Welcome(info WelcomeInfo) string {
	details := []string{
		t.accent.Render(hovelWordmark),
		"",
		t.detail("modules", strconv.Itoa(info.ModuleCount)),
		t.detail("hoveld", info.DaemonAddress),
		t.detail("mode", info.DaemonMode),
		t.detail("health", info.Health),
	}
	return t.panel.Render(joinColumns(splitStyledLines([]string{t.cyan.Render(hovelASCII)}), splitStyledLines(details), 4))
}

func (t Theme) detail(label, value string) string {
	return t.label.Render(label+":") + " " + t.muted.Render(value)
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
	fmt.Fprintln(stderr, "hovel cli starts the interactive shell; use hovel command for one-shot invocations")
	return "", false, 2
}

func isExit(line string) bool {
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "exit" || line == "quit"
}

const builtInModuleCount = 1

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

const hovelWordmark = `░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒▒▓█▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░   ░▒▓██▓▒░  ░▒▓████████▓▒░▒▓████████▓▒░`

func splitStyledLines(values []string) []string {
	var lines []string
	for _, value := range values {
		lines = append(lines, strings.Split(value, "\n")...)
	}
	return lines
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
