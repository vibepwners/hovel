// pipeprobe is a Windows-side black-box client for Squatter's named-pipe
// transport. It is built for both PE ABIs and run in the same Wine prefix as
// the payload so the Docker functional suite crosses the real Win32 pipe API.
package main

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pipeprobe.exe \\\\.\\pipe\\name")
		os.Exit(2)
	}
	pipe, err := openPipe(os.Args[1], 30*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = pipe.Close() }()

	reader := bufio.NewReader(pipe)
	if err := wire.WriteFrame(pipe, wire.KindOpen, 73, wire.EncodeOpen("echo", []string{"named-pipe"})); err != nil {
		fatal(err)
	}
	if err := expectData(reader, "argc=2 echo named-pipe"); err != nil {
		fatal(err)
	}
	if err := wire.WriteFrame(pipe, wire.KindData, 73, []byte("named-pipe-payload")); err != nil {
		fatal(err)
	}
	if err := expectData(reader, "named-pipe-payload"); err != nil {
		fatal(err)
	}
	if err := wire.WriteFrame(pipe, wire.KindData, 73, []byte("END")); err != nil {
		fatal(err)
	}
	for {
		kind, streamID, _, err := wire.ReadFrame(reader)
		if err != nil {
			fatal(err)
		}
		if kind == wire.KindClose && streamID == 73 {
			break
		}
	}
	fmt.Println("E2E transport=smb-named-pipe real Win32 pipe echo session passed")
}

func openPipe(path string, timeout time.Duration) (*os.File, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			return file, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("open named pipe %q: %w", path, lastErr)
}

func expectData(reader *bufio.Reader, want string) error {
	for {
		kind, streamID, payload, err := wire.ReadFrame(reader)
		if err != nil {
			return err
		}
		if streamID != 73 {
			return fmt.Errorf("response stream = %d, want 73", streamID)
		}
		if kind == wire.KindControl {
			continue
		}
		if kind != wire.KindData || string(payload) != want {
			return fmt.Errorf("response kind=%d payload=%q, want DATA %q", kind, payload, want)
		}
		return nil
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
