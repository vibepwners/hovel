package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/charmbracelet/x/term"
)

const sessionDetachByte byte = 0x1d

func (a App) executeSessionConnect(ctx context.Context, sessionID string, stdout, stderr io.Writer) int {
	if a.daemonClient == nil {
		fmt.Fprintln(stderr, "session connect needs an interactive daemon session; run hovel cli")
		return 1
	}
	input, cleanup, rawOutput, err := openSessionConnectInput()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer cleanup()
	output := stdout
	if rawOutput {
		output = crlfWriter{writer: stdout}
	}
	if err := ConnectSession(ctx, a.daemonClient, sessionID, input, output); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func ConnectSession(ctx context.Context, client *daemonrpc.Client, sessionID string, input io.Reader, output io.Writer) error {
	if client == nil {
		return errors.New("daemon client is not configured")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("session is required")
	}

	fmt.Fprintf(output, "Connected to session %s. Press Ctrl-] to detach.\n", sessionID)

	stopOutput := make(chan struct{})
	outputDone := make(chan struct{})
	events := make(chan sessionConnectEvent, 2)

	go readSessionOutput(ctx, client, sessionID, output, stopOutput, outputDone, events)
	go writeSessionInput(ctx, client, sessionID, input, events)

	event := <-events
	close(stopOutput)
	<-outputDone

	switch {
	case event.err != nil:
		return event.err
	case event.closed:
		fmt.Fprintf(output, "\nSession closed: %s\n", sessionID)
		return nil
	default:
		if err := drainSessionOutput(ctx, client, sessionID, output); err != nil {
			return err
		}
		fmt.Fprintf(output, "\nDetached from session %s\n", sessionID)
		return nil
	}
}

type sessionConnectEvent struct {
	err    error
	closed bool
}

func readSessionOutput(ctx context.Context, client *daemonrpc.Client, sessionID string, output io.Writer, stop <-chan struct{}, done chan<- struct{}, events chan<- sessionConnectEvent) {
	defer close(done)
	for {
		select {
		case <-stop:
			return
		default:
		}

		chunk, err := client.ReadSession(ctx, sessionID, 50*time.Millisecond)
		if err != nil {
			sendSessionConnectEvent(events, sessionConnectEvent{err: err})
			return
		}
		if len(chunk.Data) > 0 {
			if _, err := output.Write(chunk.Data); err != nil {
				sendSessionConnectEvent(events, sessionConnectEvent{err: err})
				return
			}
		}
		if chunk.Closed {
			sendSessionConnectEvent(events, sessionConnectEvent{closed: true})
			return
		}
	}
}

func writeSessionInput(ctx context.Context, client *daemonrpc.Client, sessionID string, input io.Reader, events chan<- sessionConnectEvent) {
	reader := bufio.NewReader(input)
	lastWasCarriageReturn := false
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				sendSessionConnectEvent(events, sessionConnectEvent{})
				return
			}
			sendSessionConnectEvent(events, sessionConnectEvent{err: err})
			return
		}
		if b == sessionDetachByte {
			sendSessionConnectEvent(events, sessionConnectEvent{})
			return
		}
		if b == '\n' && lastWasCarriageReturn {
			lastWasCarriageReturn = false
			continue
		}
		if b == '\r' {
			b = '\n'
			lastWasCarriageReturn = true
		} else {
			lastWasCarriageReturn = false
		}
		if err := client.WriteSession(ctx, sessionID, []byte{b}); err != nil {
			sendSessionConnectEvent(events, sessionConnectEvent{err: err})
			return
		}
	}
}

func drainSessionOutput(ctx context.Context, client *daemonrpc.Client, sessionID string, output io.Writer) error {
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		chunk, err := client.ReadSession(ctx, sessionID, 25*time.Millisecond)
		if err != nil {
			return err
		}
		if len(chunk.Data) > 0 {
			if _, err := output.Write(chunk.Data); err != nil {
				return err
			}
			deadline = time.Now().Add(50 * time.Millisecond)
		}
		if chunk.Closed {
			return nil
		}
	}
	return nil
}

func sendSessionConnectEvent(events chan<- sessionConnectEvent, event sessionConnectEvent) {
	select {
	case events <- event:
	default:
	}
}

func isSessionConnectCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	if fields[0] != "session" && fields[0] != "sessions" {
		return false
	}
	if fields[1] != "connect" {
		return false
	}
	return !sessionConnectHelpRequested(fields[2:])
}

func sessionConnectHelpRequested(fields []string) bool {
	for _, field := range fields {
		if field == "-h" || field == "--help" {
			return true
		}
	}
	return false
}

func parseSessionConnectID(line string) (string, error) {
	fields := strings.Fields(line)
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "-w", "--workspace":
			i++
			continue
		default:
			if strings.HasPrefix(fields[i], "-") {
				continue
			}
			return fields[i], nil
		}
	}
	return "", errors.New("session is required")
}

func openSessionConnectInput() (io.Reader, func(), bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return os.Stdin, func() {}, false, nil
	}
	state, err := term.MakeRaw(tty.Fd())
	if err != nil {
		_ = tty.Close()
		return nil, nil, false, fmt.Errorf("enter session terminal mode: %w", err)
	}
	cleanup := func() {
		_ = term.Restore(tty.Fd(), state)
		_ = tty.Close()
	}
	return tty, cleanup, true, nil
}

type crlfWriter struct {
	writer io.Writer
}

func (w crlfWriter) Write(p []byte) (int, error) {
	for i, b := range p {
		if b == '\n' && (i == 0 || p[i-1] != '\r') {
			if _, err := w.writer.Write([]byte{'\r'}); err != nil {
				return i, err
			}
		}
		if _, err := w.writer.Write([]byte{b}); err != nil {
			return i, err
		}
	}
	return len(p), nil
}
