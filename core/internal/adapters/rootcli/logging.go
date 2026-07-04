package rootcli

import (
	"fmt"
	"io"
	"log"
)

func writeRootLine(out io.Writer, args ...any) {
	if _, err := fmt.Fprintln(out, args...); err != nil {
		log.Printf("hovel root cli: write line: %v", err)
	}
}

func writeRootText(out io.Writer, text string) {
	if _, err := fmt.Fprint(out, text); err != nil {
		log.Printf("hovel root cli: write text: %v", err)
	}
}

func writeRootFormat(out io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(out, format, args...); err != nil {
		log.Printf("hovel root cli: write formatted text: %v", err)
	}
}

func logRootError(action string, err error) {
	if err != nil {
		log.Printf("hovel root cli: %s: %v", action, err)
	}
}
