package uicatalog

import (
	"fmt"
	"io"
	"log"
)

func writeText(out io.Writer, text string) {
	if _, err := fmt.Fprint(out, text); err != nil {
		log.Printf("hovel ui catalog: write text: %v", err)
	}
}

func writeLine(out io.Writer, args ...any) {
	if _, err := fmt.Fprintln(out, args...); err != nil {
		log.Printf("hovel ui catalog: write line: %v", err)
	}
}
