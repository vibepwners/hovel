package commandmode

import (
	"fmt"
	"io"
	"log"
)

func writeCommandText(out io.Writer, text string) {
	if _, err := fmt.Fprint(out, text); err != nil {
		log.Printf("hovel command mode: write text: %v", err)
	}
}

func writeCommandLine(out io.Writer, args ...any) {
	if _, err := fmt.Fprintln(out, args...); err != nil {
		log.Printf("hovel command mode: write line: %v", err)
	}
}

func writeCommandFormat(out io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(out, format, args...); err != nil {
		log.Printf("hovel command mode: write formatted text: %v", err)
	}
}

func logCommandModeError(action string, err error) {
	if err != nil {
		log.Printf("hovel command mode: %s: %v", action, err)
	}
}
