package cli

import (
	"strings"

	prompt "github.com/c-bata/go-prompt"
)

type styledPromptWriter struct {
	prompt.ConsoleWriter
	fg   prompt.Color
	bg   prompt.Color
	bold bool
}

func newStyledPromptWriter(writer prompt.ConsoleWriter) prompt.ConsoleWriter {
	return &styledPromptWriter{
		ConsoleWriter: writer,
		fg:            prompt.DefaultColor,
		bg:            prompt.DefaultColor,
	}
}

func (w *styledPromptWriter) SetColor(fg, bg prompt.Color, bold bool) {
	w.fg = fg
	w.bg = bg
	w.bold = bold
	w.ConsoleWriter.SetColor(fg, bg, bold)
}

func (w *styledPromptWriter) WriteStr(data string) {
	if w.writeActiveChainPrefix(data) {
		return
	}
	w.ConsoleWriter.WriteStr(data)
}

func (w *styledPromptWriter) writeActiveChainPrefix(data string) bool {
	const prefix = "h0v3l ("
	if !strings.HasPrefix(data, prefix) {
		return false
	}
	end := strings.Index(data, ")")
	if end < len(prefix) {
		return false
	}

	w.ConsoleWriter.WriteStr(data[:len("h0v3l ")])
	w.ConsoleWriter.SetColor(prompt.Turquoise, w.bg, true)
	w.ConsoleWriter.WriteStr(data[len("h0v3l ") : end+1])
	w.ConsoleWriter.SetColor(w.fg, w.bg, w.bold)
	w.ConsoleWriter.WriteStr(data[end+1:])
	return true
}
