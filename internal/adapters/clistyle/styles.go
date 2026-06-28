package clistyle

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

const DefaultWidth = 96

type Styles struct {
	Accent       lipgloss.Style
	Cyan         lipgloss.Style
	Muted        lipgloss.Style
	Success      lipgloss.Style
	Warning      lipgloss.Style
	Danger       lipgloss.Style
	Header       lipgloss.Style
	Subtle       lipgloss.Style
	Border       lipgloss.Style
	TableHeader  lipgloss.Style
	TableCell    lipgloss.Style
	TableOddCell lipgloss.Style
}

func Default() Styles {
	return Styles{
		Accent:       lipgloss.NewStyle().Foreground(lipgloss.Color("#ff2bd6")).Bold(true),
		Cyan:         lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true),
		Muted:        lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af")),
		Success:      lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e")).Bold(true),
		Warning:      lipgloss.NewStyle().Foreground(lipgloss.Color("#facc15")).Bold(true),
		Danger:       lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0033")).Bold(true),
		Header:       lipgloss.NewStyle().Foreground(lipgloss.Color("#ffffff")).Bold(true),
		Subtle:       lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280")),
		Border:       lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")),
		TableHeader:  lipgloss.NewStyle().Foreground(lipgloss.Color("#00e5ff")).Bold(true).Padding(0, 1),
		TableCell:    lipgloss.NewStyle().Foreground(lipgloss.Color("#e5e7eb")).Padding(0, 1),
		TableOddCell: lipgloss.NewStyle().Foreground(lipgloss.Color("#cbd5e1")).Padding(0, 1),
	}
}

func (s Styles) Badge(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "-"
	}
	return s.Cyan.Render(strings.ToUpper(value))
}

func (s Styles) Status(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "pass", "passed", "ok", "valid", "ready", "installed", "connected", "succeeded", "success", "healthy":
		return s.Success.Render(value)
	case "warn", "warning", "blocked", "unreachable", "required", "invalid":
		return s.Warning.Render(value)
	case "fail", "failed", "error", "removed", "danger", "destructive":
		return s.Danger.Render(value)
	default:
		return s.Muted.Render(value)
	}
}

func (s Styles) Panel(title, subtitle, body string, width int) string {
	title = strings.TrimSpace(title)
	subtitle = strings.TrimSpace(subtitle)
	body = strings.TrimSpace(body)
	heading := s.Header.Render(title)
	if subtitle != "" {
		heading += " " + s.Muted.Render(subtitle)
	}
	content := strings.TrimSpace(heading + "\n\n" + body)
	if width <= 0 {
		width = DefaultWidth
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00e5ff")).
		Padding(1, 2).
		Width(width).
		Render(content)
}

func (s Styles) Table(headers []string, rows [][]string, width int) string {
	t := table.New().
		Headers(headers...).
		Rows(rows...).
		Border(lipgloss.RoundedBorder()).
		BorderStyle(s.Border).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return s.TableHeader
			}
			if row%2 == 1 {
				return s.TableOddCell
			}
			return s.TableCell
		})
	if width > 0 {
		t.Width(width)
	}
	return t.String()
}

func (s Styles) KeyValue(rows [][2]string) string {
	if len(rows) == 0 {
		return ""
	}
	out := make([]string, 0, len(rows))
	width := 0
	for _, row := range rows {
		if lipgloss.Width(row[0]) > width {
			width = lipgloss.Width(row[0])
		}
	}
	for _, row := range rows {
		label := lipgloss.NewStyle().Width(width).Render(row[0])
		out = append(out, s.Cyan.Render(label)+"  "+row[1])
	}
	return strings.Join(out, "\n")
}
