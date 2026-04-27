package terminallog

import (
	"fmt"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/charmbracelet/lipgloss"
)

type Renderer struct {
	title    lipgloss.Style
	subtitle lipgloss.Style
	info     lipgloss.Style
	success  lipgloss.Style
	finding  lipgloss.Style
	artifact lipgloss.Style
	field    lipgloss.Style
}

func NewRenderer() Renderer {
	return Renderer{
		title:    lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2bd6")).Bold(true),
		subtitle: lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")),
		info:     lipgloss.NewStyle().Foreground(lipgloss.Color("#d1d5db")),
		success:  lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		finding:  lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2bd6")).Bold(true),
		artifact: lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		field:    lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")),
	}
}

func (r Renderer) Render(log operatorlog.Log) string {
	if log.Empty() {
		return ""
	}

	var lines []string
	header := r.title.Render(log.Title)
	if log.Subtitle != "" {
		header += " " + r.subtitle.Render(log.Subtitle)
	}
	lines = append(lines, header)
	for _, entry := range log.Entries() {
		lines = append(lines, r.renderEntry(entry))
	}
	return strings.Join(lines, "\n")
}

func (r Renderer) renderEntry(entry operatorlog.Entry) string {
	marker, markerStyle := r.marker(entry.Level)
	line := fmt.Sprintf("%s %-9s %s", markerStyle.Render(marker), entry.Source, entry.Message)
	if len(entry.Fields) == 0 {
		return line
	}

	fields := make([]string, 0, len(entry.Fields))
	for _, field := range entry.Fields {
		fields = append(fields, field.Name+"="+field.Value)
	}
	return line + " " + r.field.Render(strings.Join(fields, " "))
}

func (r Renderer) marker(level operatorlog.Level) (string, lipgloss.Style) {
	switch level {
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
