package cli

import (
	"fmt"
	"io"
)

type promptTerminalRestorer interface {
	Restore() error
}

func finishPrompt(stdout io.Writer, terminal promptTerminalRestorer) error {
	if terminal != nil {
		if err := terminal.Restore(); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(stdout)
	return err
}
