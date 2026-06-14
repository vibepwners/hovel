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
		_ = wire.WriteFrame(serverConn, wire.KindData, sid, []byte("hello from cmd"))
		_ = wire.WriteFrame(serverConn, wire.KindData, sid, []byte("exit=0"))
		_ = wire.WriteFrame(serverConn, wire.KindClose, sid, nil)
	}()

	input := strings.NewReader("cmd echo hello\nquit\n")
	var output bytes.Buffer
	New(clientConn).Run(input, &output)
	<-done

	text := output.String()
	for _, want := range []string{"hello from cmd", "exit=0", "squatter> "} {
		if !strings.Contains(text, want) {
			t.Fatalf("shell output missing %q:\n%s", want, text)
		}
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
		_ = wire.WriteFrame(serverConn, wire.KindData, sid, []byte("cmd ready"))
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
	for _, want := range []string{"cmd ready", "cmd> ", "hello"} {
		if !strings.Contains(text, want) {
			t.Fatalf("shell output missing %q:\n%s", want, text)
		}
	}
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
	opts := ParseCLI([]string{
		"192.0.2.10",
		"--smb",
		"--pipe", `\pipe\squatter`,
		"--domain", "LAB",
		"--user", "alice",
		"--password", "secret",
		"--smb-port", "445",
		"--demo",
	})

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

func hasSuggestion(suggestions []prompt.Suggest, text string) bool {
	for _, suggestion := range suggestions {
		if suggestion.Text == text {
			return true
		}
	}
	return false
}
