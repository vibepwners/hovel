package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/daemonrpc"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	"github.com/charmbracelet/x/term"
)

const sessionDetachByte byte = 0x1d

type SessionConnectOptions struct {
	HistoryLines       int
	HistoryBytes       int
	NoHistory          bool
	HistoryLimitChosen bool
}

func defaultSessionConnectOptions() SessionConnectOptions {
	return SessionConnectOptions{HistoryLines: 20}
}

func (a App) executeSessionConnect(ctx context.Context, sessionID string, options SessionConnectOptions, stdout, stderr io.Writer) int {
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
	if err := ConnectSession(ctx, a.daemonClient, sessionID, input, output, options); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func ConnectSession(ctx context.Context, client *daemonrpc.Client, sessionID string, input io.Reader, output io.Writer, connectOptions ...SessionConnectOptions) error {
	if client == nil {
		return errors.New("daemon client is not configured")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("session is required")
	}

	options := defaultSessionConnectOptions()
	if len(connectOptions) > 0 {
		options = connectOptions[0]
	}

	fmt.Fprintf(output, "Connected to session %s. Press Ctrl-] to detach.\n", sessionID)
	ptySession := sessionHasCapability(ctx, client, sessionID, sessionCapabilityTerminalPTY)
	if err := printSessionConnectHistory(ctx, client, sessionID, output, ptySession, options); err != nil {
		return err
	}

	stopOutput := make(chan struct{})
	outputDone := make(chan struct{})
	events := make(chan sessionConnectEvent, 2)

	go readSessionOutput(ctx, client, sessionID, output, stopOutput, outputDone, events)
	go writeSessionInput(ctx, client, sessionID, input, events, sessionInputOptions{Raw: ptySession})

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

func printSessionConnectHistory(ctx context.Context, client *daemonrpc.Client, sessionID string, output io.Writer, ptySession bool, options SessionConnectOptions) error {
	if options.NoHistory {
		return nil
	}
	tailOptions := run.SessionTailOptions{Consume: true}
	if ptySession && !options.HistoryLimitChosen {
		chunk, err := client.TailSession(ctx, sessionID, tailOptions)
		if err != nil {
			return err
		}
		return writeSessionHistory(output, chunk.Data)
	}
	switch {
	case options.HistoryBytes > 0:
		tailOptions.MaxBytes = options.HistoryBytes
	case options.HistoryLines > 0:
		tailOptions.MaxLines = options.HistoryLines
	default:
		return nil
	}
	chunk, err := client.TailSession(ctx, sessionID, tailOptions)
	if err != nil {
		return err
	}
	return writeSessionHistory(output, chunk.Data)
}

const sessionCapabilityTerminalPTY = "terminal.pty"

func sessionHasCapability(ctx context.Context, client *daemonrpc.Client, sessionID, capability string) bool {
	sessions, err := client.ListSessions(ctx)
	if err != nil {
		return false
	}
	for _, session := range sessions {
		if session.ID != sessionID {
			continue
		}
		for _, candidate := range session.Capabilities {
			if candidate == capability {
				return true
			}
		}
	}
	return false
}

func writeSessionHistory(output io.Writer, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	_, err := output.Write(data)
	return err
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

type sessionInputOptions struct {
	Raw bool
}

type sessionInputWriter interface {
	WriteSession(context.Context, string, []byte) error
}

func writeSessionInput(ctx context.Context, client sessionInputWriter, sessionID string, input io.Reader, events chan<- sessionConnectEvent, options sessionInputOptions) {
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
		if !options.Raw {
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
	sessionID, _, err := parseSessionConnect(line)
	return sessionID, err
}

func parseSessionConnect(line string) (string, SessionConnectOptions, error) {
	fields := strings.Fields(line)
	options := defaultSessionConnectOptions()
	var sessionID string
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "-w", "--workspace":
			i++
			continue
		case "--history-lines":
			value, ok := nextSessionConnectValue(fields, &i)
			if !ok {
				return "", SessionConnectOptions{}, errors.New("--history-lines requires a value")
			}
			count, err := parseSessionConnectCount("--history-lines", value)
			if err != nil {
				return "", SessionConnectOptions{}, err
			}
			options.HistoryLines = count
			options.HistoryBytes = 0
			options.HistoryLimitChosen = true
		case "--history-bytes":
			value, ok := nextSessionConnectValue(fields, &i)
			if !ok {
				return "", SessionConnectOptions{}, errors.New("--history-bytes requires a value")
			}
			count, err := parseSessionConnectCount("--history-bytes", value)
			if err != nil {
				return "", SessionConnectOptions{}, err
			}
			options.HistoryBytes = count
			options.HistoryLines = 0
			options.HistoryLimitChosen = true
		case "--no-history":
			options.NoHistory = true
		default:
			if strings.HasPrefix(fields[i], "-") {
				continue
			}
			if sessionID == "" {
				sessionID = fields[i]
			}
		}
	}
	if sessionID == "" {
		return "", SessionConnectOptions{}, errors.New("session is required")
	}
	return sessionID, options, nil
}

func nextSessionConnectValue(fields []string, index *int) (string, bool) {
	if *index+1 >= len(fields) {
		return "", false
	}
	*index = *index + 1
	return fields[*index], true
}

func parseSessionConnectCount(option, value string) (int, error) {
	count, err := strconv.Atoi(value)
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", option)
	}
	return count, nil
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
