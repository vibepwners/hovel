package progressview

import (
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/lipgloss"
	"github.com/vibepwners/hovel/internal/adapters/clistyle"
)

type TransferRenderer struct {
	out        io.Writer
	styles     clistyle.Styles
	width      int
	live       bool
	bar        progress.Model
	activeLine bool
	label      string
	doneLabel  string
	source     string
}

type TransferOptions struct {
	Label     string
	DoneLabel string
	Width     int
	Color     bool
}

func NewTransferRenderer(out io.Writer, opts TransferOptions) *TransferRenderer {
	color := opts.Color && opts.Width > 0
	width := opts.Width
	if width <= 0 {
		width = clistyle.DefaultWidth
	}
	styles := clistyle.Default()
	if !color {
		styles = clistyle.Styles{}
	}
	label := strings.TrimSpace(opts.Label)
	if label == "" {
		label = "transfer"
	}
	doneLabel := strings.TrimSpace(opts.DoneLabel)
	if doneLabel == "" {
		doneLabel = label + "ed"
	}
	return &TransferRenderer{
		out:       out,
		styles:    styles,
		width:     width,
		live:      color,
		bar:       progress.New(progress.WithWidth(boundedInstallProgressWidth(width/2, 20, 48)), progress.WithGradient("#00e5ff", "#ff2bd6")),
		label:     label,
		doneLabel: doneLabel,
	}
}

func (r *TransferRenderer) Start(source string, total int64) {
	if r == nil || r.out == nil {
		return
	}
	r.finishActiveLine()
	r.source = source
	r.println(r.styles.Accent.Render(r.label), DisplaySource(source), mutedProgress(formatTotal(total), r.styles))
}

func (r *TransferRenderer) Progress(source string, bytes, total int64) {
	if r == nil || r.out == nil {
		return
	}
	if source == "" {
		source = r.source
	}
	if total <= 0 || !r.live {
		return
	}
	percent := float64(bytes) / float64(total)
	if percent < 0 {
		percent = 0
	}
	if percent > 1 {
		percent = 1
	}
	prefix := r.styles.Cyan.Render("  " + DisplaySource(source))
	suffix := mutedProgress(FormatBytes(bytes)+"/"+FormatBytes(total), r.styles)
	available := r.width - lipgloss.Width(prefix) - lipgloss.Width(suffix) - 4
	if available < 12 {
		available = 12
	}
	if available > 56 {
		available = 56
	}
	r.bar.Width = available
	line := prefix + "  " + r.bar.ViewAs(percent) + "  " + suffix
	writeFormat(r.out, "\r\x1b[2K%s", line)
	r.activeLine = true
}

func (r *TransferRenderer) Complete(source string, bytes, total int64) {
	if r == nil || r.out == nil {
		return
	}
	if total <= 0 {
		total = bytes
	}
	r.Progress(source, total, total)
	r.finishActiveLine()
	r.println(r.styles.Success.Render(r.doneLabel), DisplaySource(source), mutedProgress(FormatBytes(bytes), r.styles))
}

func (r *TransferRenderer) finishActiveLine() {
	if r.activeLine {
		writeLine(r.out)
		r.activeLine = false
	}
}

func (r *TransferRenderer) println(parts ...string) {
	r.finishActiveLine()
	writeLine(r.out, strings.Join(nonEmptyProgress(parts), " "))
}
