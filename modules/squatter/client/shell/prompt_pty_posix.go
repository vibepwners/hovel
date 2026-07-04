//go:build !windows

package shell

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"syscall"

	prompt "github.com/c-bata/go-prompt"
	"github.com/charmbracelet/x/term"
)

const promptPTYReadSize = 1024

func newPromptPTYTerminal(input *os.File, output io.Writer) (promptTerminal, bool) {
	if input == nil || output == nil {
		return nil, false
	}
	return &promptPTYTerminal{
		parser: &promptPTYParser{file: input},
		writer: newPromptPTYWriter(output),
	}, true
}

type promptPTYTerminal struct {
	parser *promptPTYParser
	writer *promptPTYWriter
}

func (t *promptPTYTerminal) Setup() error {
	return t.parser.Setup()
}

func (t *promptPTYTerminal) TearDown() error {
	return t.parser.TearDown()
}

func (t *promptPTYTerminal) Read() ([]byte, error) {
	return t.parser.Read()
}

func (t *promptPTYTerminal) Writer() prompt.ConsoleWriter {
	return t.writer
}

type promptPTYParser struct {
	file  *os.File
	state *term.State
}

func (p *promptPTYParser) Setup() error {
	if p.file == nil {
		return io.ErrClosedPipe
	}
	state, err := term.MakeRaw(p.file.Fd())
	if err != nil {
		return err
	}
	p.state = state
	if err := syscall.SetNonblock(int(p.file.Fd()), true); err != nil {
		logShellError("restore prompt terminal after nonblock failure", term.Restore(p.file.Fd(), state))
		p.state = nil
		return err
	}
	return nil
}

func (p *promptPTYParser) TearDown() error {
	if p.file == nil {
		return nil
	}
	setErr := syscall.SetNonblock(int(p.file.Fd()), false)
	var restoreErr error
	if p.state != nil {
		restoreErr = term.Restore(p.file.Fd(), p.state)
		p.state = nil
	}
	if setErr != nil {
		return setErr
	}
	return restoreErr
}

func (p *promptPTYParser) GetWinSize() *prompt.WinSize {
	if p.file == nil {
		return &prompt.WinSize{Row: 24, Col: 80}
	}
	width, height, err := term.GetSize(p.file.Fd())
	if err != nil || width <= 0 || height <= 0 {
		return &prompt.WinSize{Row: 24, Col: 80}
	}
	return &prompt.WinSize{Row: uint16(height), Col: uint16(width)}
}

func (p *promptPTYParser) Read() ([]byte, error) {
	if p.file == nil {
		return nil, io.ErrClosedPipe
	}
	buf := make([]byte, promptPTYReadSize)
	n, err := syscall.Read(int(p.file.Fd()), buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

type promptPTYWriter struct {
	out    io.Writer
	buffer []byte
}

func newPromptPTYWriter(output io.Writer) *promptPTYWriter {
	return &promptPTYWriter{out: output}
}

func (w *promptPTYWriter) WriteRaw(data []byte) {
	w.buffer = append(w.buffer, data...)
}

func (w *promptPTYWriter) Write(data []byte) {
	w.WriteRaw(bytes.ReplaceAll(data, []byte{0x1b}, []byte{'?'}))
}

func (w *promptPTYWriter) WriteRawStr(data string) {
	w.WriteRaw([]byte(data))
}

func (w *promptPTYWriter) WriteStr(data string) {
	w.Write([]byte(data))
}

func (w *promptPTYWriter) Flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	if err := writeFully(w.out, w.buffer); err != nil {
		return err
	}
	w.buffer = w.buffer[:0]
	return nil
}

func (w *promptPTYWriter) EraseScreen() {
	w.WriteRaw([]byte{0x1b, '[', '2', 'J'})
}

func (w *promptPTYWriter) EraseUp() {
	w.WriteRaw([]byte{0x1b, '[', '1', 'J'})
}

func (w *promptPTYWriter) EraseDown() {
	w.WriteRaw([]byte{0x1b, '[', 'J'})
}

func (w *promptPTYWriter) EraseStartOfLine() {
	w.WriteRaw([]byte{0x1b, '[', '1', 'K'})
}

func (w *promptPTYWriter) EraseEndOfLine() {
	w.WriteRaw([]byte{0x1b, '[', 'K'})
}

func (w *promptPTYWriter) EraseLine() {
	w.WriteRaw([]byte{0x1b, '[', '2', 'K'})
}

func (w *promptPTYWriter) ShowCursor() {
	w.WriteRaw([]byte{0x1b, '[', '?', '1', '2', 'l', 0x1b, '[', '?', '2', '5', 'h'})
}

func (w *promptPTYWriter) HideCursor() {
	w.WriteRaw([]byte{0x1b, '[', '?', '2', '5', 'l'})
}

func (w *promptPTYWriter) CursorGoTo(row, col int) {
	if row == 0 && col == 0 {
		w.WriteRaw([]byte{0x1b, '[', 'H'})
		return
	}
	w.WriteRaw([]byte{0x1b, '['})
	w.WriteRawStr(strconv.Itoa(row))
	w.WriteRaw([]byte{';'})
	w.WriteRawStr(strconv.Itoa(col))
	w.WriteRaw([]byte{'H'})
}

func (w *promptPTYWriter) CursorUp(n int) {
	switch {
	case n == 0:
		return
	case n < 0:
		w.CursorDown(-n)
	default:
		w.moveCursor(n, 'A')
	}
}

func (w *promptPTYWriter) CursorDown(n int) {
	switch {
	case n == 0:
		return
	case n < 0:
		w.CursorUp(-n)
	default:
		w.moveCursor(n, 'B')
	}
}

func (w *promptPTYWriter) CursorForward(n int) {
	switch {
	case n == 0:
		return
	case n < 0:
		w.CursorBackward(-n)
	default:
		w.moveCursor(n, 'C')
	}
}

func (w *promptPTYWriter) CursorBackward(n int) {
	switch {
	case n == 0:
		return
	case n < 0:
		w.CursorForward(-n)
	default:
		w.moveCursor(n, 'D')
	}
}

func (w *promptPTYWriter) moveCursor(n int, command byte) {
	w.WriteRaw([]byte{0x1b, '['})
	w.WriteRawStr(strconv.Itoa(n))
	w.WriteRaw([]byte{command})
}

func (w *promptPTYWriter) AskForCPR() {
	w.WriteRaw([]byte{0x1b, '[', '6', 'n'})
}

func (w *promptPTYWriter) SaveCursor() {
	w.WriteRaw([]byte{0x1b, '[', 's'})
}

func (w *promptPTYWriter) UnSaveCursor() {
	w.WriteRaw([]byte{0x1b, '[', 'u'})
}

func (w *promptPTYWriter) ScrollDown() {
	w.WriteRaw([]byte{0x1b, 'D'})
}

func (w *promptPTYWriter) ScrollUp() {
	w.WriteRaw([]byte{0x1b, 'M'})
}

func (w *promptPTYWriter) SetTitle(title string) {
	titleBytes := bytes.ReplaceAll([]byte(title), []byte{0x13}, nil)
	titleBytes = bytes.ReplaceAll(titleBytes, []byte{0x07}, nil)
	w.WriteRaw([]byte{0x1b, ']', '2', ';'})
	w.WriteRaw(titleBytes)
	w.WriteRaw([]byte{0x07})
}

func (w *promptPTYWriter) ClearTitle() {
	w.WriteRaw([]byte{0x1b, ']', '2', ';', 0x07})
}

func (w *promptPTYWriter) SetColor(fg, bg prompt.Color, bold bool) {
	attr := "0"
	if bold {
		attr = "1"
	}
	w.WriteRaw([]byte{0x1b, '['})
	w.WriteRawStr(attr)
	w.WriteRaw([]byte{';'})
	w.WriteRawStr(promptPTYForegroundColor(fg))
	w.WriteRaw([]byte{';'})
	w.WriteRawStr(promptPTYBackgroundColor(bg))
	w.WriteRaw([]byte{'m'})
}

func promptPTYForegroundColor(color prompt.Color) string {
	if value, ok := promptPTYForegroundColors[color]; ok {
		return value
	}
	return promptPTYForegroundColors[prompt.DefaultColor]
}

func promptPTYBackgroundColor(color prompt.Color) string {
	if value, ok := promptPTYBackgroundColors[color]; ok {
		return value
	}
	return promptPTYBackgroundColors[prompt.DefaultColor]
}

var promptPTYForegroundColors = map[prompt.Color]string{
	prompt.DefaultColor: "39",
	prompt.Black:        "30",
	prompt.DarkRed:      "31",
	prompt.DarkGreen:    "32",
	prompt.Brown:        "33",
	prompt.DarkBlue:     "34",
	prompt.Purple:       "35",
	prompt.Cyan:         "36",
	prompt.LightGray:    "37",
	prompt.DarkGray:     "90",
	prompt.Red:          "91",
	prompt.Green:        "92",
	prompt.Yellow:       "93",
	prompt.Blue:         "94",
	prompt.Fuchsia:      "95",
	prompt.Turquoise:    "96",
	prompt.White:        "97",
}

var promptPTYBackgroundColors = map[prompt.Color]string{
	prompt.DefaultColor: "49",
	prompt.Black:        "40",
	prompt.DarkRed:      "41",
	prompt.DarkGreen:    "42",
	prompt.Brown:        "43",
	prompt.DarkBlue:     "44",
	prompt.Purple:       "45",
	prompt.Cyan:         "46",
	prompt.LightGray:    "47",
	prompt.DarkGray:     "100",
	prompt.Red:          "101",
	prompt.Green:        "102",
	prompt.Yellow:       "103",
	prompt.Blue:         "104",
	prompt.Fuchsia:      "105",
	prompt.Turquoise:    "106",
	prompt.White:        "107",
}

var _ prompt.ConsoleParser = (*promptPTYParser)(nil)
var _ prompt.ConsoleWriter = (*promptPTYWriter)(nil)
