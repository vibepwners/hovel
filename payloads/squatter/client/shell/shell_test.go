package shell

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/wire"
	prompt "github.com/c-bata/go-prompt"
)

func TestClientRunDrivesEchoOverWire(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		kind, sid, _, err := wire.ReadFrame(serverConn)
		if err != nil || kind != wire.KindOpen {
			return
		}
		_ = wire.WriteFrame(serverConn, wire.KindData, sid, []byte("argc=2 echo hello"))
		_ = wire.WriteFrame(serverConn, wire.KindControl, sid, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventInteractive}))
		kind, sid, payload, err := wire.ReadFrame(serverConn)
		if err != nil || kind != wire.KindData {
			return
		}
		_ = wire.WriteFrame(serverConn, wire.KindData, sid, payload)
		_, sid, _, _ = wire.ReadFrame(serverConn)
		_ = wire.WriteFrame(serverConn, wire.KindClose, sid, nil)
	}()

	input := strings.NewReader("echo hello\nEND\n")
	var output bytes.Buffer
	New(clientConn).Run(input, &output)
	<-done

	text := output.String()
	for _, want := range []string{"squatter shell", "squatter> ", "argc=2 echo hello", "echo> ", "END"} {
		if !strings.Contains(text, want) {
			t.Fatalf("shell output missing %q:\n%s", want, text)
		}
	}
}

func TestClientRunDrivesCmdAsOneShot(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		kind, sid, _, err := wire.ReadFrame(serverConn)
		if err != nil || kind != wire.KindOpen {
			return
		}
		_ = wire.WriteFrame(serverConn, wire.KindData, sid, []byte("hello from cmd\n"))
		_ = wire.WriteFrame(serverConn, wire.KindControl, sid, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventExited}))
		_ = wire.WriteFrame(serverConn, wire.KindClose, sid, nil)
	}()

	input := strings.NewReader("cmd echo hello\nquit\n")
	var output bytes.Buffer
	New(clientConn).Run(input, &output)
	<-done

	text := output.String()
	for _, want := range []string{"hello from cmd", "squatter> "} {
		if !strings.Contains(text, want) {
			t.Fatalf("shell output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "exit=0") {
		t.Fatalf("cmd exit status should not be emitted as DATA:\n%s", text)
	}
	if strings.Contains(text, "cmd> ") {
		t.Fatalf("cmd should be one-shot, got active prompt:\n%s", text)
	}
}

func TestClientRunDrivesCmdInteractive(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		kind, sid, _, err := wire.ReadFrame(serverConn)
		if err != nil || kind != wire.KindOpen {
			return
		}
		_ = wire.WriteFrame(serverConn, wire.KindControl, sid,
			wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventInteractive, Code: streamInteractiveRaw}))
		kind, sid, payload, err := wire.ReadFrame(serverConn)
		if err != nil || kind != wire.KindData {
			return
		}
		if string(payload) != "echo hello\n" {
			return
		}
		_ = wire.WriteFrame(serverConn, wire.KindData, sid, []byte("hello"))
		kind, sid, payload, err = wire.ReadFrame(serverConn)
		if err != nil || kind != wire.KindData {
			return
		}
		if string(payload) != "exit\n" {
			return
		}
		_ = wire.WriteFrame(serverConn, wire.KindClose, sid, nil)
	}()

	input := strings.NewReader("cmd\necho hello\nexit\n")
	var output bytes.Buffer
	New(clientConn).Run(input, &output)
	<-done

	text := output.String()
	for _, want := range []string{"hello"} {
		if !strings.Contains(text, want) {
			t.Fatalf("shell output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "cmd> ") {
		t.Fatalf("interactive cmd should attach without a frontend prompt:\n%s", text)
	}
	if strings.Contains(text, "cmd ready") {
		t.Fatalf("cmd startup marker should not be emitted as DATA:\n%s", text)
	}
}

func TestClientRunRendersOpenStreamError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		kind, sid, _, err := wire.ReadFrame(serverConn)
		if err != nil || kind != wire.KindOpen {
			return
		}
		_ = wire.WriteFrame(serverConn, wire.KindControl, sid,
			wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventError, Message: "no such module: dir"}))
		_ = wire.WriteFrame(serverConn, wire.KindClose, sid, nil)
	}()

	input := strings.NewReader("dir\nquit\n")
	var output bytes.Buffer
	New(clientConn).Run(input, &output)
	<-done

	if got := output.String(); !strings.Contains(got, "[dir error: no such module: dir]") {
		t.Fatalf("shell output missing open error:\n%s", got)
	}
}

func TestCmdArgsFromLinePreservesRawRemainder(t *testing.T) {
	got := cmdArgsFromLine(`cmd echo "hello there" && cd`)
	if len(got) != 1 || got[0] != `echo "hello there" && cd` {
		t.Fatalf("cmd args = %#v", got)
	}

	got = cmdArgsFromLine(`cmd --interactive echo "hello there" && cd`)
	if len(got) != 2 || got[0] != "--interactive" || got[1] != `echo "hello there" && cd` {
		t.Fatalf("interactive cmd args = %#v", got)
	}
}

func TestEchoAttachInputEchoesPrintableEditingBytes(t *testing.T) {
	var output bytes.Buffer
	if err := echoAttachInput(&output, []byte{'d', 'i', 'r', '\r', 0x7f, 'x', '\t', 0x03}); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "dir\r\n\b \bx\t"; got != want {
		t.Fatalf("echo output = %q, want %q", got, want)
	}
}

func TestWriteFullyHandlesPartialWrites(t *testing.T) {
	writer := &partialWriter{limit: 2}
	if err := writeFully(writer, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if got, want := writer.String(), "abcdef"; got != want {
		t.Fatalf("written = %q, want %q", got, want)
	}
}

type partialWriter struct {
	bytes.Buffer
	limit int
}

func (w *partialWriter) Write(payload []byte) (int, error) {
	if len(payload) > w.limit {
		payload = payload[:w.limit]
	}
	return w.Buffer.Write(payload)
}

func TestSuggestionsCoverTopLevelAndActiveModule(t *testing.T) {
	top := Suggestions("", "")
	if !hasSuggestion(top, "cmd") || !hasSuggestion(top, "echo") || !hasSuggestion(top, "getfile") || !hasSuggestion(top, "putfile") {
		t.Fatalf("top suggestions = %#v", top)
	}
	filtered := Suggestions("", "pu")
	if len(filtered) != 1 || filtered[0].Text != "putfile" {
		t.Fatalf("filtered suggestions = %#v, want putfile", filtered)
	}
	active := Suggestions("echo", "")
	if !hasSuggestion(active, "END") || !hasSuggestion(active, "detach") {
		t.Fatalf("active suggestions = %#v", active)
	}
}

func TestParseCLISupportsSMBNamedPipe(t *testing.T) {
	opts, err := ParseCLI([]string{
		"192.0.2.10",
		"--smb",
		"--pipe", `\pipe\squatter`,
		"--domain", "LAB",
		"--user", "alice",
		"--password", "secret",
		"--smb-port", "445",
		"--demo",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !opts.SMB {
		t.Fatal("SMB = false, want true")
	}
	if opts.Host != "192.0.2.10" || opts.Pipe != `\pipe\squatter` {
		t.Fatalf("host/pipe = %q/%q", opts.Host, opts.Pipe)
	}
	if opts.Domain != "LAB" || opts.Username != "alice" || opts.Password != "secret" {
		t.Fatalf("credentials = %#v", opts)
	}
	if opts.SMBPort != 445 {
		t.Fatalf("SMBPort = %d, want 445", opts.SMBPort)
	}
	if opts.Mode != ModeDemo {
		t.Fatalf("Mode = %q, want demo", opts.Mode)
	}
}

func TestParseCLIRejectsInvalidNumericFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--streams", "nope"},
		{"--streams", "0"},
		{"--smb-port", "nope"},
		{"--smb-port", "70000"},
	} {
		if _, err := ParseCLI(args); err == nil {
			t.Fatalf("ParseCLI(%#v) returned nil error", args)
		}
	}
}

func hasSuggestion(suggestions []prompt.Suggest, text string) bool {
	for _, suggestion := range suggestions {
		if suggestion.Text == text {
			return true
		}
	}
	return false
}
