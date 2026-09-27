package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/adapters/daemonrpc"
	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/infra/daemonruntime"
	"github.com/vibepwners/hovel/internal/testsupport"
)

func TestSessionConnectRestoresPresentation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controlling PTY regression requires Linux")
	}
	for _, scenario := range []string{"detach", "read-error", "plain", "redirected", "embedded"} {
		t.Run(scenario, func(t *testing.T) {
			broker := &presentationSessionBroker{fail: scenario == "read-error", plain: scenario == "plain"}
			broker.sessions = []run.SessionRef{{ID: "presentation", State: "active", Capabilities: []string{sessionCapabilityTerminalPTY}}}
			fixture := testsupport.StartDaemon(t, daemonruntime.Args{
				ModuleRunner: fakeCompletionModuleRunner{}, ModuleSessions: broker,
			})
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "python3", "-c", sessionPresentationPTY, executable, fixture.SocketPath, scenario)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("PTY regression: %v\n%s", err, output)
			}
			broker.mu.Lock()
			defer broker.mu.Unlock()
			if got := broker.input.String(); got != "x\r\x03" {
				t.Errorf("remote input = %q, want unchanged raw input/Ctrl-C and no local cleanup", got)
			}
			if broker.closed {
				t.Error("attachment closed the retained session")
			}
		})
	}
}

// The subprocess must own a controlling TTY so RunSessionConnect uses /dev/tty.
func TestSessionConnectPresentationHelper(t *testing.T) {
	socket := os.Getenv("HOVEL_PRESENTATION_SOCKET")
	if socket == "" {
		return
	}
	client, err := daemonrpc.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { logCLIError("close test client", client.Close()) }()
	code := RunSessionConnect(t.Context(), client, "presentation", defaultSessionConnectOptions(), os.Stdout, os.Stderr)
	want := 0
	if os.Getenv("HOVEL_PRESENTATION_SCENARIO") == "read-error" {
		want = 1
	}
	if code != want {
		t.Fatalf("session connect exit = %d, want %d", code, want)
	}
	if _, err := io.WriteString(os.Stdout, "ATTACHMENT_RETURNED\n"); err != nil {
		t.Fatal(err)
	}
}

type presentationSessionBroker struct {
	fakeCompletionSessionBroker
	mu     sync.Mutex
	input  bytes.Buffer
	fail   bool
	plain  bool
	closed bool
}

func (b *presentationSessionBroker) TailSession(context.Context, string, run.SessionTailOptions) (run.SessionChunk, error) {
	if b.plain {
		return run.SessionChunk{Data: []byte("RESTORE_PROBE")}, nil
	}
	return run.SessionChunk{Data: []byte("\x1b[?1049h\x1b[?25l\x1b[2J\x1b[HRESTORE_PROBE")}, nil
}

func (b *presentationSessionBroker) ReadSession(ctx context.Context, _ string, wait time.Duration) (run.SessionChunk, error) {
	select {
	case <-ctx.Done():
		return run.SessionChunk{}, ctx.Err()
	case <-time.After(wait):
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail && bytes.Contains(b.input.Bytes(), []byte{3}) {
		return run.SessionChunk{}, errors.New("presentation read failed")
	}
	return run.SessionChunk{}, nil
}

func (b *presentationSessionBroker) WriteSession(_ context.Context, _ string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.input.Write(data)
	return err
}

func (b *presentationSessionBroker) CloseSession(context.Context, string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

const sessionPresentationPTY = `
import fcntl
import os
import pty
import select
import subprocess
import sys
import tempfile
import termios
import time

master, slave = pty.openpty()
before = termios.tcgetattr(slave)
scenario = sys.argv[3]
env = dict(os.environ, HOVEL_PRESENTATION_SOCKET=sys.argv[2], HOVEL_PRESENTATION_SCENARIO=scenario,
           COLORFGBG="15;0", TERM="xterm-256color")
output_master, output_slave = master, slave
capture = None
if scenario == "redirected":
    capture = tempfile.TemporaryFile()
    output_slave = capture
elif scenario == "embedded":
    # The output PTY represents an embedded terminal. The controlling terminal
    # belongs to its enclosing frontend and must not receive presentation resets.
    output_master, output_slave = pty.openpty()
    os.write(slave, b"\x1b[?1049h\x1b[?25lOUTER_FRONTEND")

def controlling_tty():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)

child = subprocess.Popen([sys.argv[1], "-test.run=^TestSessionConnectPresentationHelper$"],
                         stdin=slave, stdout=output_slave, stderr=output_slave, env=env,
                         preexec_fn=controlling_tty)
output = bytearray()
outer_output = bytearray()
sent = False
deadline = time.monotonic() + 8
try:
    while time.monotonic() < deadline:
        if capture is not None:
            output = bytearray(os.pread(capture.fileno(), 65536, 0))
            time.sleep(0.01)
        else:
            if select.select([output_master], [], [], 0.05)[0]:
                output.extend(os.read(output_master, 65536))
        if output_master != master and select.select([master], [], [], 0)[0]:
            outer_output.extend(os.read(master, 65536))
        if b"RESTORE_PROBE" in output and not sent:
            os.write(master, b"x\r\x03" + (b"" if scenario == "read-error" else b"\x1d"))
            sent = True
        if child.poll() is not None and (capture is not None or not select.select([output_master], [], [], 0)[0]):
            if capture is not None:
                output = bytearray(os.pread(capture.fileno(), 65536, 0))
            break
    assert child.poll() == 0, (child.poll(), bytes(output))
    assert termios.tcgetattr(slave) == before, "termios was not restored"
    assert b"ATTACHMENT_RETURNED" in output, bytes(output)
    if scenario == "redirected":
        for reset in (b"\x1b[?1049l", b"\x1b[?25h", b"\x1b[0m"):
            assert reset not in output, ("cleanup added to redirected output", bytes(output))
        assert not select.select([master], [], [], 0)[0], "cleanup written to controlling terminal"
    else:
        assert output.rfind(b"\x1b[?1049l") > output.rfind(b"\x1b[?1049h"), ("alternate screen left active", bytes(output))
        assert output.rfind(b"\x1b[?25h") > output.rfind(b"\x1b[?25l"), ("cursor left hidden", bytes(output))
    if scenario == "read-error":
        assert output.index(b"\x1b[?1049l") < output.index(b"presentation read failed"), bytes(output)
    else:
        assert b"Detached from session presentation" in output, bytes(output)
    if scenario == "embedded":
        assert outer_output == b"\x1b[?1049h\x1b[?25lOUTER_FRONTEND", bytes(outer_output)
finally:
    if child.poll() is None:
        child.kill()
    child.wait()
    os.close(slave)
    os.close(master)
    if capture is not None:
        capture.close()
    elif scenario == "embedded":
        os.close(output_slave)
        os.close(output_master)
`
