package terminallog

import (
	"fmt"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/charmbracelet/lipgloss"
)

const (
	defaultWidth = 88
	markerWidth  = 4
	sourceWidth  = 9
	elapsedWidth = 6
	labelCore    = markerWidth + 1 + sourceWidth
	labelWidth   = labelCore + 1 + elapsedWidth
)

type Renderer struct {
	title    lipgloss.Style
	subtitle lipgloss.Style
	rail     lipgloss.Style
	label    lipgloss.Style
	elapsed  lipgloss.Style
	field    lipgloss.Style
	width    int
}

func NewRenderer() Renderer {
	return NewRendererWithWidth(defaultWidth)
}

func NewRendererWithWidth(width int) Renderer {
	if width <= 0 {
		width = defaultWidth
	}
	return Renderer{
		title:    lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2bd6")).Bold(true),
		subtitle: lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")),
		rail:     lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		label: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#7c3aed")).
			Bold(true).
			Inline(true),
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
		header := r.title.Render(log.Title)
		if log.Subtitle != "" {
			header += " " + r.subtitle.Render(log.Subtitle)
		}
		lines = append(lines, r.renderRailLine(strings.TrimSpace(header)))
		if len(log.Entries()) > 0 {
			lines = append(lines, r.renderRailLine(""))
		}
	}
	for _, entry := range log.Entries() {
		if entry.Kind == operatorlog.KindHeader {
			header := strings.TrimSpace(entry.Message + " " + entry.ChainName)
			lines = append(lines, r.renderRailLine(header), r.renderRailLine(""))
			continue
		}
		lines = append(lines, r.renderEntry(entry))
	}
	return strings.Join(lines, "\n")
}

func (r Renderer) renderEntry(entry operatorlog.Entry) string {
	label := r.renderLabel(entry, r.marker(entry.Level))
	prefix := r.railPrefix() + label + " "
	continuationPrefix := r.railPrefix() + strings.Repeat(" ", labelWidth+1)
	lines := []string{wrapLine(prefix, continuationPrefix, entry.Message, r.width)}
	if len(entry.Fields) > 0 {
		fields := make([]string, 0, len(entry.Fields))
		for _, field := range entry.Fields {
			fields = append(fields, field.Name+"="+field.Value)
		}
		lines = append(lines, wrapLine(continuationPrefix, continuationPrefix, r.field.Render(strings.Join(fields, "  ")), r.width))
	}

	return strings.Join(lines, "\n")
}

func (r Renderer) renderLabel(entry operatorlog.Entry, marker string) string {
	core := fmt.Sprintf("%-*s", labelCore, marker+" "+entry.Source)
	if entry.ElapsedSeconds == nil {
		return r.label.Width(labelWidth).Render(fmt.Sprintf("%-*s", labelWidth, core))
	}
	elapsed := fmt.Sprintf("%6.2f", *entry.ElapsedSeconds)
	return r.label.Render(fmt.Sprintf("%-*s", labelCore+1, marker+" "+entry.Source)) + r.elapsed.Render(elapsed)
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
