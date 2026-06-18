//go:build !windows

package shell

import (
	"bytes"
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
