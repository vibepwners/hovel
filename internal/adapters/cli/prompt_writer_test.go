package cli

import (
	"strings"
	"testing"

	prompt "github.com/c-bata/go-prompt"
)

func TestPromptSurfaceWritesAsyncLogsRaw(t *testing.T) {
	writer := &recordingConsoleWriter{}
	surface := newPromptSurface(writer)

	surface.WriteAsyncLog("\x1b[31mred\x1b[0m", "h0v3l> ")

	output := writer.String()
	if !strings.Contains(output, "\x1b[31mred\x1b[0m") {
		t.Fatalf("output = %q, want raw ANSI log", output)
	}
	if !strings.Contains(output, "h0v3l> ") {
		t.Fatalf("output = %q, want prompt redraw", output)
	}
}

func TestPromptSurfaceShowsThrowingAnimation(t *testing.T) {
	writer := &recordingConsoleWriter{}
	surface := newPromptSurface(writer)

	stop := surface.StartThrowing("h0v3l> ")
	surface.WriteAsyncLog("module log", "h0v3l> ")
	stop()

	output := writer.String()
	if !strings.Contains(output, "throwing") {
		t.Fatalf("output = %q, want throwing animation", output)
	}
	if !strings.Contains(output, "module log") {
		t.Fatalf("output = %q, want async log", output)
	}
	if !strings.Contains(output, "h0v3l> ") {
		t.Fatalf("output = %q, want prompt restored after stop", output)
	}
}

type recordingConsoleWriter struct {
	output strings.Builder
}

func (w *recordingConsoleWriter) String() string { return w.output.String() }
func (w *recordingConsoleWriter) WriteRaw(data []byte) {
	w.output.Write(data)
}
func (w *recordingConsoleWriter) Write(data []byte) {
	w.output.Write(data)
}
func (w *recordingConsoleWriter) WriteRawStr(data string) {
	w.output.WriteString(data)
}
func (w *recordingConsoleWriter) WriteStr(data string) {
	w.output.WriteString(data)
}
func (w *recordingConsoleWriter) Flush() error { return nil }
func (w *recordingConsoleWriter) EraseScreen() {
	w.output.WriteString("<erase-screen>")
}
func (w *recordingConsoleWriter) EraseUp() {
	w.output.WriteString("<erase-up>")
}
func (w *recordingConsoleWriter) EraseDown() {
	w.output.WriteString("<erase-down>")
}
func (w *recordingConsoleWriter) EraseStartOfLine() {
	w.output.WriteString("<erase-start>")
}
func (w *recordingConsoleWriter) EraseEndOfLine() {
	w.output.WriteString("<erase-end>")
}
func (w *recordingConsoleWriter) EraseLine() {
	w.output.WriteString("<erase-line>")
}
func (w *recordingConsoleWriter) ShowCursor() {}
func (w *recordingConsoleWriter) HideCursor() {}
func (w *recordingConsoleWriter) CursorGoTo(row, col int) {
	_, _ = row, col
}
func (w *recordingConsoleWriter) CursorUp(n int) {
	_ = n
}
func (w *recordingConsoleWriter) CursorDown(n int) {
	_ = n
}
func (w *recordingConsoleWriter) CursorForward(n int) {
	_ = n
}
func (w *recordingConsoleWriter) CursorBackward(n int) {
	_ = n
}
func (w *recordingConsoleWriter) AskForCPR()    {}
func (w *recordingConsoleWriter) SaveCursor()   {}
func (w *recordingConsoleWriter) UnSaveCursor() {}
func (w *recordingConsoleWriter) ScrollDown()   {}
func (w *recordingConsoleWriter) ScrollUp()     {}
func (w *recordingConsoleWriter) SetTitle(title string) {
	_ = title
}
func (w *recordingConsoleWriter) ClearTitle() {}
func (w *recordingConsoleWriter) SetColor(fg, bg prompt.Color, bold bool) {
	_, _, _ = fg, bg, bold
}
