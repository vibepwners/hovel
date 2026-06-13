package shell

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/wire"
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
