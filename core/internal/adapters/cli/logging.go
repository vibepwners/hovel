package cli

import (
	"fmt"
	"io"
	"log"
)

func writeCLILine(out io.Writer, args ...any) {
	if _, err := fmt.Fprintln(out, args...); err != nil {
		log.Printf("hovel cli: write line: %v", err)
	}
}

func writeCLIText(out io.Writer, text string) {
	if _, err := fmt.Fprint(out, text); err != nil {
		log.Printf("hovel cli: write text: %v", err)
	}
}

func writeCLIFormat(out io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(out, format, args...); err != nil {
		log.Printf("hovel cli: write formatted text: %v", err)
	}
}

func logCLIError(action string, err error) {
	if err != nil {
		log.Printf("hovel cli: %s: %v", action, err)
	}
}
