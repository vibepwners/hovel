package commandmode

import (
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/adapters/clistyle"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/modulepackage"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/lipgloss"
)

type installProgressRenderer struct {
	out          io.Writer
	styles       clistyle.Styles
	width        int
	live         bool
	bar          progress.Model
	activeLine   bool
	activeSource string
}

func newInstallProgressRenderer(out io.Writer, width int, color bool) *installProgressRenderer {
	color = color && width > 0
	live := color
	if width <= 0 {
		width = clistyle.DefaultWidth
	}
	styles := clistyle.Default()
	if !color {
		styles = clistyle.Styles{}
	}
	barWidth := boundedInstallProgressWidth(width/2, 20, 48)
	return &installProgressRenderer{
		out:    out,
		styles: styles,
		width:  width,
		live:   live,
		bar: progress.New(
			progress.WithWidth(barWidth),
			progress.WithGradient("#00e5ff", "#ff2bd6"),
		),
	}
}

func (r *installProgressRenderer) Handle(event modulepackage.InstallProgress) {
	if r == nil || r.out == nil {
		return
	}
	switch event.Stage {
	case modulepackage.InstallProgressSetEntry:
		r.finishActiveLine()
		label := fmt.Sprintf("module %d/%d", event.Index, event.Count)
		r.println(r.styles.Accent.Render("module"), r.styles.Cyan.Render(label), displayInstallSource(event.Source))
	case modulepackage.InstallProgressDownloadCacheHit:
		r.finishActiveLine()
		r.println(r.styles.Success.Render("cache"), "using", displayInstallSource(firstNonEmptyProgress(event.Archive, event.Source)))
	case modulepackage.InstallProgressDownloadStart:
		r.finishActiveLine()
		r.activeSource = event.Source
		r.println(r.styles.Accent.Render("download"), displayInstallSource(event.Source), mutedProgress(formatInstallTotal(event.Total), r.styles))
	case modulepackage.InstallProgressDownloadProgress:
		r.renderProgress(event)
	case modulepackage.InstallProgressDownloadComplete:
		r.renderProgress(modulepackage.InstallProgress{
			Stage:  modulepackage.InstallProgressDownloadProgress,
			Source: event.Source,
			Bytes:  event.Bytes,
			Total:  firstPositive(event.Total, event.Bytes),
		})
		r.finishActiveLine()
		r.println(r.styles.Success.Render("downloaded"), displayInstallSource(event.Source), mutedProgress(formatInstallBytes(event.Bytes), r.styles))
	case modulepackage.InstallProgressDownloadVerified:
		r.finishActiveLine()
		if event.SHA256 != "" {
			r.println(r.styles.Success.Render("verified"), "sha256", mutedProgress(shortProgressSHA(event.SHA256), r.styles))
		}
	case modulepackage.InstallProgressDownloadCached:
		r.finishActiveLine()
		r.println(r.styles.Cyan.Render("cached"), displayInstallSource(event.Archive))
	case modulepackage.InstallProgressArchiveStart:
		r.finishActiveLine()
		r.println(r.styles.Accent.Render("install"), displayInstallSource(event.Archive))
	case modulepackage.InstallProgressArchiveComplete:
		r.finishActiveLine()
		ref := modulecatalog.CanonicalID(event.Name, event.Version)
		r.println(r.styles.Success.Render("installed"), ref)
	}
}

func (r *installProgressRenderer) renderProgress(event modulepackage.InstallProgress) {
	if event.Source == "" {
		event.Source = r.activeSource
	}
	if event.Total <= 0 || !r.live {
		return
	}
	percent := float64(event.Bytes) / float64(event.Total)
	if percent < 0 {
		percent = 0
	}
	if percent > 1 {
		percent = 1
	}
	prefix := r.styles.Cyan.Render("  " + displayInstallSource(event.Source))
	suffix := mutedProgress(formatInstallBytes(event.Bytes)+"/"+formatInstallBytes(event.Total), r.styles)
	available := r.width - lipgloss.Width(prefix) - lipgloss.Width(suffix) - 4
	if available < 12 {
		available = 12
	}
	if available > 56 {
		available = 56
	}
	r.bar.Width = available
	line := prefix + "  " + r.bar.ViewAs(percent) + "  " + suffix
	fmt.Fprintf(r.out, "\r\x1b[2K%s", line)
	r.activeLine = true
}

func (r *installProgressRenderer) finishActiveLine() {
	if r.activeLine {
		fmt.Fprintln(r.out)
		r.activeLine = false
	}
}

func (r *installProgressRenderer) println(parts ...string) {
	r.finishActiveLine()
	fmt.Fprintln(r.out, strings.Join(nonEmptyProgress(parts), " "))
}

func displayInstallSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "-"
	}
	if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		name := filepath.Base(parsed.Path)
		if name == "." || name == "/" || name == "" {
			name = parsed.Host
		}
		return parsed.Host + "/" + name
	}
	return filepath.Base(source)
}

func formatInstallTotal(total int64) string {
	if total <= 0 {
		return "size unknown"
	}
	return formatInstallBytes(total)
}

func formatInstallBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := int64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func shortProgressSHA(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func mutedProgress(value string, styles clistyle.Styles) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return styles.Muted.Render(value)
}

func nonEmptyProgress(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func firstNonEmptyProgress(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstPositive(values ...int64) int64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func boundedInstallProgressWidth(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
