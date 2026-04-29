package cli

import (
	"strings"
	"sync"

	prompt "github.com/c-bata/go-prompt"
)

type promptSurface struct {
	mu       sync.Mutex
	writer   *styledPromptWriter
	document prompt.Document
}

func newPromptSurface(writer prompt.ConsoleWriter) *promptSurface {
	return &promptSurface{writer: newStyledPromptWriter(writer)}
}

func (w *promptSurface) SetDocument(document prompt.Document) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.document = document
}

func (w *promptSurface) WriteAsyncLog(rendered, prefix string) {
	if w == nil || strings.TrimSpace(rendered) == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	w.writer.HideCursor()
	defer w.writer.ShowCursor()
	w.writer.WriteRaw([]byte("\r"))
	w.writer.EraseDown()
	w.writer.WriteRawStr(rendered)
	w.writer.WriteRaw([]byte("\n"))
	w.writePromptLine(prefix)
	_ = w.writer.Flush()
}

func (w *promptSurface) writePromptLine(prefix string) {
	text := w.document.Text
	w.writer.SetColor(prompt.Fuchsia, prompt.DefaultColor, false)
	w.writer.WriteStr(prefix)
	w.writer.SetColor(prompt.Turquoise, prompt.DefaultColor, false)
	w.writer.WriteStr(text)
	w.writer.SetColor(prompt.DefaultColor, prompt.DefaultColor, false)
	afterCursor := w.document.TextAfterCursor()
	if afterWidth := len([]rune(afterCursor)); afterWidth > 0 {
		w.writer.CursorBackward(afterWidth)
	}
}

func (w *promptSurface) WriteRaw(data []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.WriteRaw(data)
}

func (w *promptSurface) Write(data []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.Write(data)
}

func (w *promptSurface) WriteRawStr(data string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.WriteRawStr(data)
}

func (w *promptSurface) WriteStr(data string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.WriteStr(data)
}

func (w *promptSurface) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Flush()
}

func (w *promptSurface) EraseScreen() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.EraseScreen()
}

func (w *promptSurface) EraseUp() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.EraseUp()
}

func (w *promptSurface) EraseDown() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.EraseDown()
}

func (w *promptSurface) EraseStartOfLine() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.EraseStartOfLine()
}

func (w *promptSurface) EraseEndOfLine() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.EraseEndOfLine()
}

func (w *promptSurface) EraseLine() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.EraseLine()
}

func (w *promptSurface) ShowCursor() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.ShowCursor()
}

func (w *promptSurface) HideCursor() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.HideCursor()
}

func (w *promptSurface) CursorGoTo(row, col int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.CursorGoTo(row, col)
}

func (w *promptSurface) CursorUp(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.CursorUp(n)
}

func (w *promptSurface) CursorDown(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.CursorDown(n)
}

func (w *promptSurface) CursorForward(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.CursorForward(n)
}

func (w *promptSurface) CursorBackward(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.CursorBackward(n)
}

func (w *promptSurface) AskForCPR() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.AskForCPR()
}

func (w *promptSurface) SaveCursor() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.SaveCursor()
}

func (w *promptSurface) UnSaveCursor() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.UnSaveCursor()
}

func (w *promptSurface) ScrollDown() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.ScrollDown()
}

func (w *promptSurface) ScrollUp() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.ScrollUp()
}

func (w *promptSurface) SetTitle(title string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.SetTitle(title)
}

func (w *promptSurface) ClearTitle() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.ClearTitle()
}

func (w *promptSurface) SetColor(fg, bg prompt.Color, bold bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writer.SetColor(fg, bg, bold)
}

type styledPromptWriter struct {
	prompt.ConsoleWriter
	fg   prompt.Color
	bg   prompt.Color
	bold bool
}

func newStyledPromptWriter(writer prompt.ConsoleWriter) *styledPromptWriter {
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
