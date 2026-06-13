// Package shell implements the interactive Squatter client shell shared by
// squatterctl and the Hovel Squatter provider session frontend.
package shell

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/wire"
	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/xfer"
)

type Client struct {
	conn net.Conn
	r    *bufio.Reader
	sid  uint64
}

func New(conn net.Conn) *Client {
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

// RunDemo executes the scripted echo walkthrough used by squatterctl.
func (c *Client) RunDemo(out io.Writer) {
	_ = c.openStream(1, "echo", []string{"alpha", "beta", "gamma"})
	_, _, p, _ := wire.ReadFrame(c.r)
	emit(out, p)
	for _, msg := range []string{"hello", "world", "the quick brown fox"} {
		_ = wire.WriteFrame(c.conn, wire.KindData, 1, []byte(msg))
		_, _, p, _ = wire.ReadFrame(c.r)
		emit(out, p)
	}
	_ = wire.WriteFrame(c.conn, wire.KindData, 1, []byte("END"))
	k, _, _, _ := wire.ReadFrame(c.r)
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
		if err := wire.WriteFrame(c.conn, wire.KindData, sid, []byte(line)); err != nil {
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

type Mode string

const (
	ModeShell   Mode = "shell"
	ModeDemo    Mode = "demo"
	ModeStreams Mode = "streams"
)

type CLIOptions struct {
	Mode    Mode
	Streams int
	Host    string
	Port    string
}

func ParseCLI(args []string) CLIOptions {
	opts := CLIOptions{Mode: ModeShell, Streams: 3, Host: "127.0.0.1", Port: "9100"}
	if len(args) > 0 && args[0] == "--demo" {
		opts.Mode, args = ModeDemo, args[1:]
	} else if len(args) > 1 && args[0] == "--streams" {
		opts.Mode = ModeStreams
		opts.Streams, _ = strconv.Atoi(args[1])
		args = args[2:]
	}
	if len(args) > 0 {
		opts.Host = args[0]
	}
	if len(args) > 1 {
		opts.Port = args[1]
	}
	return opts
}
