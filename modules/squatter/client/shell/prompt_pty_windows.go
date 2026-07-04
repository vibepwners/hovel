//go:build windows

package shell

import (
	"io"
	"os"
)

func newPromptPTYTerminal(input *os.File, output io.Writer) (promptTerminal, bool) {
	return nil, false
}
