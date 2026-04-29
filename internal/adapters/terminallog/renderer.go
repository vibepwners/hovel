package terminallog

import (
	"fmt"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/charmbracelet/lipgloss"
)

const (
	defaultWidth = 88
	sourceWidth  = 9
)

type Renderer struct {
	title    lipgloss.Style
	subtitle lipgloss.Style
	info     lipgloss.Style
	stage    lipgloss.Style
	success  lipgloss.Style
	finding  lipgloss.Style
	artifact lipgloss.Style
	source   lipgloss.Style
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
		info:     lipgloss.NewStyle().Foreground(lipgloss.Color("#d1d5db")),
		stage:    lipgloss.NewStyle().Foreground(lipgloss.Color("#facc15")).Bold(true),
		success:  lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		finding:  lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2bd6")).Bold(true),
		artifact: lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		source: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#7c3aed")).
			Bold(true).
			Padding(0, 1).
			Width(sourceWidth + 2),
		field: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#c4b5fd")).
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
		lines = append(lines, strings.TrimSpace(header))
	}
	for _, entry := range log.Entries() {
		lines = append(lines, r.renderEntry(entry))
	}
	return strings.Join(lines, "\n")
}

func (r Renderer) renderEntry(entry operatorlog.Entry) string {
	marker, markerStyle := r.marker(entry.Level)
	source := r.source.Render(fmt.Sprintf("%-*s", sourceWidth, entry.Source))
	prefix := fmt.Sprintf("%s %s ", markerStyle.Render(marker), source)
	message := entry.Message
	if len(entry.Fields) > 0 {
		fields := make([]string, 0, len(entry.Fields))
		for _, field := range entry.Fields {
			fields = append(fields, field.Name+"="+field.Value)
		}
		if message != "" {
			message += " "
		}
		message += r.field.Render(strings.Join(fields, " "))
	}

	return wrapLine(prefix, message, r.width)
}

func wrapLine(prefix, message string, width int) string {
	if message == "" {
		return strings.TrimRight(prefix, " ")
	}

	indent := strings.Repeat(" ", lipgloss.Width(prefix))
	var lines []string
	current := prefix
	currentWidth := lipgloss.Width(prefix)
	for _, word := range strings.Fields(message) {
		wordWidth := lipgloss.Width(word)
		if currentWidth > lipgloss.Width(prefix) && currentWidth+1+wordWidth > width {
			lines = append(lines, current)
			current = indent + word
			currentWidth = lipgloss.Width(indent) + wordWidth
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

func (r Renderer) marker(level operatorlog.Level) (string, lipgloss.Style) {
	switch level {
	case operatorlog.LevelStage:
		return "[>]", r.stage
	case operatorlog.LevelSuccess:
		return "[+]", r.success
	case operatorlog.LevelFinding:
		return "[#]", r.finding
	case operatorlog.LevelArtifact:
		return "[$]", r.artifact
	default:
		return "[*]", r.info
	}
}
