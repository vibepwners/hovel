package terminallog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/charmbracelet/lipgloss"
)

const (
	defaultWidth = 88
	markerWidth  = 4
	sourceWidth  = 7
	levelWidth   = 7
	elapsedWidth = 6
	labelCore    = markerWidth + 1 + sourceWidth
	labelWidth   = labelCore + levelWidth + elapsedWidth
)

type Renderer struct {
	title         lipgloss.Style
	subtitle      lipgloss.Style
	throwTitle    lipgloss.Style
	throwSubtitle lipgloss.Style
	rail          lipgloss.Style
	label         lipgloss.Style
	level         lipgloss.Style
	elapsed       lipgloss.Style
	field         lipgloss.Style
	width         int
}

func NewRenderer() Renderer {
	return NewRendererWithWidth(defaultWidth)
}

func NewRendererWithWidth(width int) Renderer {
	if width <= 0 {
		width = defaultWidth
	}
	return Renderer{
		title:         lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2bd6")).Bold(true),
		subtitle:      lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")),
		throwTitle:    lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0033")).Bold(true),
		throwSubtitle: lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0033")).Bold(true),
		rail:          lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		label: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#7c3aed")).
			Bold(true).
			Inline(true),
		level: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffffff")).
			Bold(true).
			Inline(true).
			Width(levelWidth),
		elapsed: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0b1020")).
			Background(lipgloss.Color("#00e5ff")).
			Bold(true).
			Inline(true).
			Width(elapsedWidth),
		field: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#9ca3af")).
			Italic(true),
		width: width,
	}
}

func NewPlainRenderer() Renderer {
	return NewPlainRendererWithWidth(defaultWidth)
}

func NewPlainRendererWithWidth(width int) Renderer {
	if width <= 0 {
		width = defaultWidth
	}
	return Renderer{width: width}
}

func (r Renderer) Render(log operatorlog.Log) string {
	if log.Empty() {
		return ""
	}

	var lines []string
	if log.Title != "" || log.Subtitle != "" {
		lines = append(lines, r.renderHeader(log.Title, log.Subtitle))
		if len(log.Entries()) > 0 {
			lines = append(lines, r.renderRailLine(""))
		}
	}
	for _, entry := range log.Entries() {
		if entry.Kind == operatorlog.KindHeader {
			lines = append(lines, r.renderHeader(entry.Message, entry.ChainName), r.renderRailLine(""))
			continue
		}
		lines = append(lines, r.renderEntry(entry))
	}
	return strings.Join(lines, "\n")
}

func (r Renderer) renderHeader(title, subtitleText string) string {
	titleStyle, subtitleStyle := r.headerStyles(title)
	header := titleStyle.Render(title)
	if subtitleText != "" {
		header += " " + subtitleStyle.Render(subtitleText)
	}
	return r.renderRailLine(strings.TrimSpace(header))
}

func (r Renderer) headerStyles(title string) (lipgloss.Style, lipgloss.Style) {
	if title == "HOVEL//THROW" {
		return r.throwTitle, r.throwSubtitle
	}
	return r.title, r.subtitle
}

func (r Renderer) renderEntry(entry operatorlog.Entry) string {
	label := r.renderLabel(entry, r.marker(entry.Level))
	prefix := r.railPrefix() + label + " "
	continuationPrefix := r.railPrefix() + strings.Repeat(" ", labelWidth+1)
	lines := []string{wrapLine(prefix, continuationPrefix, entry.Message, r.width)}
	for _, line := range r.renderStructuredLines(entry) {
		if preformattedLine(line) {
			lines = append(lines, continuationPrefix+r.field.Render(line))
			continue
		}
		lines = append(lines, wrapLine(continuationPrefix, continuationPrefix, r.field.Render(line), r.width))
	}

	return strings.Join(lines, "\n")
}

func (r Renderer) renderStructuredLines(entry operatorlog.Entry) []string {
	var simple []string
	appendSimple := func(name, value string) {
		if value == "" {
			return
		}
		simple = append(simple, name+"="+value)
	}
	for _, name := range sortedAttributeNames(entry.Attributes) {
		appendSimple(name, entry.Attributes[name])
	}

	var lines []string
	for _, field := range entry.Fields {
		if pretty, ok := prettyJSON(field.Value); ok {
			if len(simple) > 0 {
				lines = append(lines, strings.Join(simple, "  "))
				simple = nil
			}
			lines = append(lines, field.Name+"=")
			lines = append(lines, strings.Split(pretty, "\n")...)
			continue
		}
		appendSimple(field.Name, field.Value)
	}
	if len(simple) > 0 {
		lines = append(lines, strings.Join(simple, "  "))
	}
	return lines
}

func sortedAttributeNames(attributes map[string]string) []string {
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func prettyJSON(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !(strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) || !json.Valid([]byte(trimmed)) {
		return "", false
	}
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(trimmed), "", "  "); err != nil {
		return "", false
	}
	return out.String(), true
}

func preformattedLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(line, " ") || trimmed == "{" || trimmed == "}" || trimmed == "[" || trimmed == "]"
}

func (r Renderer) renderLabel(entry operatorlog.Entry, marker string) string {
	core := fmt.Sprintf("%-*s", labelCore, marker+" "+entry.Source)
	level := r.renderLevel(entry.Level)
	if entry.ElapsedSeconds == nil {
		return r.label.Render(core) + level + r.renderElapsed("")
	}
	elapsed := fmt.Sprintf("%6.2f", *entry.ElapsedSeconds)
	return r.label.Render(core) + level + r.renderElapsed(elapsed)
}

func (r Renderer) renderElapsed(value string) string {
	if r.elapsed.GetWidth() == 0 {
		return fmt.Sprintf("%-*s", elapsedWidth, value)
	}
	return r.elapsed.Render(fmt.Sprintf("%-*s", elapsedWidth, value))
}

func (r Renderer) renderLevel(level operatorlog.Level) string {
	display := r.levelDisplay(level)
	if r.level.GetWidth() == 0 {
		return fmt.Sprintf("%-*s", levelWidth, display)
	}
	return r.levelStyle(level).Render(fmt.Sprintf("%-*s", levelWidth, display))
}

func (r Renderer) levelStyle(level operatorlog.Level) lipgloss.Style {
	style := r.level
	switch r.normalizedLevel(level) {
	case operatorlog.LevelError:
		return style.Background(lipgloss.Color("#dc2626")).Foreground(lipgloss.Color("#ffffff"))
	case operatorlog.LevelWarn:
		return style.Background(lipgloss.Color("#f59e0b")).Foreground(lipgloss.Color("#111827"))
	case operatorlog.LevelVerbose:
		return style.Background(lipgloss.Color("#a855f7")).Foreground(lipgloss.Color("#ffffff"))
	case operatorlog.LevelTrace:
		return style.Background(lipgloss.Color("#475569")).Foreground(lipgloss.Color("#ffffff"))
	default:
		return style.Background(lipgloss.Color("#0ea5e9")).Foreground(lipgloss.Color("#0b1020"))
	}
}

func (r Renderer) levelDisplay(level operatorlog.Level) string {
	normalized := r.normalizedLevel(level)
	if normalized == "" {
		normalized = operatorlog.LevelInfo
	}
	display := strings.ToUpper(string(normalized))
	if len(display) > levelWidth {
		return display[:levelWidth]
	}
	return display
}

func (r Renderer) normalizedLevel(level operatorlog.Level) operatorlog.Level {
	switch level {
	case operatorlog.LevelWarn, operatorlog.LevelFinding, operatorlog.Level("warning"):
		return operatorlog.LevelWarn
	case operatorlog.LevelError, operatorlog.Level("critical"), operatorlog.Level("fatal"):
		return operatorlog.LevelError
	case operatorlog.LevelVerbose, operatorlog.LevelArtifact, operatorlog.Level("debug"):
		return operatorlog.LevelVerbose
	case operatorlog.LevelTrace, operatorlog.LevelStage:
		return operatorlog.LevelTrace
	default:
		return operatorlog.LevelInfo
	}
}

func (r Renderer) renderRailLine(message string) string {
	return r.railPrefix() + message
}

func (r Renderer) railPrefix() string {
	return r.rail.Render("┃") + " "
}

func wrapLine(prefix, continuationPrefix, message string, width int) string {
	if message == "" {
		return strings.TrimRight(prefix, " ")
	}

	var lines []string
	current := prefix
	currentWidth := lipgloss.Width(prefix)
	for _, word := range strings.Fields(message) {
		wordWidth := lipgloss.Width(word)
		if currentWidth > lipgloss.Width(prefix) && currentWidth+1+wordWidth > width {
			lines = append(lines, current)
			current = continuationPrefix + word
			currentWidth = lipgloss.Width(continuationPrefix) + wordWidth
			continue
		}
		if currentWidth == lipgloss.Width(prefix) {
			current += word
			currentWidth += wordWidth
			continue
		}
		current += " " + word
		currentWidth += 1 + wordWidth
	}
	lines = append(lines, current)

	return strings.Join(lines, "\n")
}

func (r Renderer) marker(level operatorlog.Level) string {
	switch level {
	case operatorlog.LevelStage:
		return ">>"
	case operatorlog.LevelSuccess:
		return "++"
	case operatorlog.LevelFinding:
		return "##"
	case operatorlog.LevelArtifact:
		return "$$"
	default:
		return "::"
	}
}
