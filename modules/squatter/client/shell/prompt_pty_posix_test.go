//go:build !windows

package shell

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	prompt "github.com/c-bata/go-prompt"
)

func TestPromptPTYWriterFlushesVT100ToOutput(t *testing.T) {
	var output bytes.Buffer
	writer := newPromptPTYWriter(&output)
	writer.SetColor(prompt.Fuchsia, prompt.Black, true)
	writer.WriteStr("sq")
	writer.CursorBackward(2)
	writer.EraseEndOfLine()
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}

	got := output.String()
	for _, want := range []string{"\x1b[1;95;40m", "sq", "\x1b[2D", "\x1b[K"} {
		if !strings.Contains(got, want) {
			t.Fatalf("writer output missing %q: %q", want, got)
		}
	}
}

func TestPromptPTYWriterSanitizesEscapedText(t *testing.T) {
	var output bytes.Buffer
	writer := newPromptPTYWriter(&output)
	writer.Write([]byte{'a', 0x1b, 'b'})
	writer.WriteRaw([]byte{0x1b, '[', 'K'})
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}

	if got, want := output.String(), "a?b\x1b[K"; got != want {
		t.Fatalf("writer output = %q, want %q", got, want)
	}
}

func TestPromptPTYWriterImplementsAllTerminalOperations(t *testing.T) {
	var output bytes.Buffer
	writer := newPromptPTYWriter(&output)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	writer.EraseScreen()
	writer.EraseUp()
	writer.EraseDown()
	writer.EraseStartOfLine()
	writer.EraseEndOfLine()
	writer.EraseLine()
	writer.ShowCursor()
	writer.HideCursor()
	writer.CursorGoTo(0, 0)
	writer.CursorGoTo(2, 3)
	for _, n := range []int{0, 2, -2} {
		writer.CursorUp(n)
		writer.CursorDown(n)
		writer.CursorForward(n)
		writer.CursorBackward(n)
	}
	writer.AskForCPR()
	writer.SaveCursor()
	writer.UnSaveCursor()
	writer.ScrollDown()
	writer.ScrollUp()
	writer.SetTitle("safe\x13\x07title")
	writer.ClearTitle()
	writer.SetColor(prompt.DefaultColor, prompt.DefaultColor, false)
	writer.SetColor(prompt.Color(255), prompt.Color(255), true)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "\x1b[2J") || !strings.Contains(got, "safetitle") {
		t.Fatalf("writer output = %q", got)
	}
}

func TestPromptPTYTerminalNilAndPipeBehavior(t *testing.T) {
	if terminal, ok := newPromptPTYTerminal(nil, io.Discard); ok || terminal != nil {
		t.Fatalf("newPromptPTYTerminal(nil) = %#v, %v", terminal, ok)
	}
	if terminal, ok := newPromptPTYTerminal(os.Stdin, nil); ok || terminal != nil {
		t.Fatalf("newPromptPTYTerminal(nil output) = %#v, %v", terminal, ok)
	}

	parser := &promptPTYParser{}
	if err := parser.Setup(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Setup nil error = %v", err)
	}
	if err := parser.TearDown(); err != nil {
		t.Fatalf("TearDown nil error = %v", err)
	}
	if _, err := parser.Read(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read nil error = %v", err)
	}
	if size := parser.GetWinSize(); size.Row != 24 || size.Col != 80 {
		t.Fatalf("nil size = %#v", size)
	}

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
	parser.file = read
	if size := parser.GetWinSize(); size.Row != 24 || size.Col != 80 {
		t.Fatalf("pipe size = %#v", size)
	}
	if _, err := write.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	data, err := parser.Read()
	if err != nil || string(data) != "x" {
		t.Fatalf("Read pipe = %q, %v", data, err)
	}
}

func TestAttachTerminalHelpersCoverPipeAndNonblockingReads(t *testing.T) {
	restore := enterAttachTerminal(nil)
	restore()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close(); _ = write.Close() })
	restore = enterAttachTerminal(read)
	restore()
	if _, err := write.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, wouldBlock, err := readAttachTerminal(read, buf)
	if err != nil || wouldBlock || string(buf[:n]) != "abc" {
		t.Fatalf("readAttachTerminal = %d, %v, %v, %q", n, wouldBlock, err, buf[:n])
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	if _, wouldBlock, err := readAttachTerminal(read, buf); err == nil || wouldBlock {
		t.Fatalf("closed writer read = wouldBlock %v, err %v", wouldBlock, err)
	}
}
