// Command squatterctl is the client/shell for the squatter mux server.
//
// At the prompt you invoke a module by name (e.g. "echo a b") and talk to it
// directly; getfile/putfile stream files of any size through a fixed buffer.
//
//	squatterctl [host] [port]           # the shell (default)
//	squatterctl --demo [host] [port]    # scripted echo walkthrough
//	squatterctl --streams N [host] [port]
package main

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

type client struct {
	conn net.Conn
	r    *bufio.Reader
	sid  uint64
}

func (c *client) nextSID() uint64 { c.sid++; return c.sid }

func emit(payload []byte) {
	os.Stdout.Write(payload)
	os.Stdout.Write([]byte{'\n'})
}

// runModule talks to a just-opened interactive module (e.g. echo): print what
// it sends, forward what the user types, until it closes (echo: on "END").
func (c *client) runModule(sid uint64, module string, in *bufio.Reader) bool {
	kind, _, payload, err := wire.ReadFrame(c.r)
	if err != nil {
		fmt.Println("[disconnected]")
		return false
	}
	if kind == wire.KindClose {
		fmt.Printf("[no such module: %s]\n", module)
		return true
	}
	emit(payload)

	for {
		fmt.Printf("%s> ", module)
		line, err := in.ReadString('\n')
		if err == io.EOF {
			fmt.Println()
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
			fmt.Println("[disconnected]")
			return false
		}
		kind, _, payload, err := wire.ReadFrame(c.r)
		if err != nil {
			fmt.Println("[disconnected]")
			return false
		}
		if kind == wire.KindClose {
			return true
		}
		emit(payload)
	}
}

func (c *client) cmdGetfile(sid uint64, args []string) bool {
	if len(args) < 1 {
		fmt.Println("usage: getfile <remote-path> [local-path]")
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
		fmt.Printf("[cannot create %s: %v]\n", local, err)
		return true
	}
	defer f.Close()
	n, err := xfer.GetFile(c.conn, c.r, sid, remote, f)
	if err != nil {
		fmt.Printf("[getfile failed: %v]\n", err)
		return c.conn != nil
	}
	fmt.Printf("got %s: %d bytes\n", local, n)
	return true
}

func (c *client) cmdPutfile(sid uint64, args []string) bool {
	if len(args) < 2 {
		fmt.Println("usage: putfile <local-path> <remote-path>")
		return true
	}
	local, remote := args[0], args[1]
	f, err := os.Open(local)
	if err != nil {
		fmt.Printf("[cannot open %s: %v]\n", local, err)
		return true
	}
	defer f.Close()
	sent, ack, err := xfer.PutFile(c.conn, c.r, sid, f, remote)
	if err != nil {
		fmt.Printf("[putfile failed: %v]\n", err)
		return false
	}
	if ack != "" {
		fmt.Println(ack)
	}
	fmt.Printf("put %s -> %s: %d bytes\n", local, remote, sent)
	return true
}

func (c *client) shell() {
	in := bufio.NewReader(os.Stdin)
	fmt.Println("squatter shell -- run a module: <name> [args...]   (e.g. 'echo a b')")
	fmt.Println("  echo <args...>                  open the echo module (interactive)")
	fmt.Println("  getfile <remote> [local]        download a file (fixed memory)")
	fmt.Println("  putfile <local> <remote>        upload a file (fixed memory)")
	fmt.Println("  quit                            exit; inside a module, Ctrl-D detaches")
	for {
		fmt.Print("squatter> ")
		line, err := in.ReadString('\n')
		if err == io.EOF {
			fmt.Println()
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
			alive = c.cmdGetfile(sid, parts[1:])
		case "putfile":
			alive = c.cmdPutfile(sid, parts[1:])
		default:
			if err := c.openStream(sid, parts[0], parts[1:]); err != nil {
				fmt.Println("[disconnected]")
				return
			}
			alive = c.runModule(sid, parts[0], in)
		}
		if !alive {
			return
		}
	}
}

func (c *client) openStream(sid uint64, module string, args []string) error {
	return wire.WriteFrame(c.conn, wire.KindOpen, sid, wire.EncodeOpen(module, args))
}

func (c *client) demo() {
	_ = c.openStream(1, "echo", []string{"alpha", "beta", "gamma"})
	_, _, p, _ := wire.ReadFrame(c.r)
	emit(p)
	for _, msg := range []string{"hello", "world", "the quick brown fox"} {
		_ = wire.WriteFrame(c.conn, wire.KindData, 1, []byte(msg))
		_, _, p, _ := wire.ReadFrame(c.r)
		emit(p)
	}
	_ = wire.WriteFrame(c.conn, wire.KindData, 1, []byte("END"))
	k, _, _, _ := wire.ReadFrame(c.r)
	if k == wire.KindClose {
		fmt.Println("[closed]")
	}
}

func (c *client) streams(n int) {
	for s := 0; s < n; s++ {
		_ = c.openStream(uint64(100+s), "echo", []string{fmt.Sprintf("task%d", s)})
	}
	for i := 0; i < n; i++ {
		_, sid, p, _ := wire.ReadFrame(c.r)
		fmt.Printf("stream %d: %s\n", sid, p)
	}
	for s := 0; s < n; s++ {
		_ = wire.WriteFrame(c.conn, wire.KindData, uint64(100+s), []byte(fmt.Sprintf("msg-%d", s)))
	}
	for i := 0; i < n; i++ {
		_, sid, p, _ := wire.ReadFrame(c.r)
		fmt.Printf("stream %d echoed %q\n", sid, p)
	}
	for s := 0; s < n; s++ {
		_ = wire.WriteFrame(c.conn, wire.KindData, uint64(100+s), []byte("END"))
	}
}

func main() {
	args := os.Args[1:]
	mode := "shell"
	nstreams := 3
	if len(args) > 0 && args[0] == "--demo" {
		mode, args = "demo", args[1:]
	} else if len(args) > 1 && args[0] == "--streams" {
		mode = "streams"
		nstreams, _ = strconv.Atoi(args[1])
		args = args[2:]
	}
	host := "127.0.0.1"
	port := "9100"
	if len(args) > 0 {
		host = args[0]
	}
	if len(args) > 1 {
		port = args[1]
	}

	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer conn.Close()
	c := &client{conn: conn, r: bufio.NewReader(conn)}

	switch mode {
	case "demo":
		c.demo()
	case "streams":
		c.streams(nstreams)
	default:
		c.shell()
	}
}
