package main

import (
	"context"
	"os"

	"github.com/Vibe-Pwners/hovel/internal/adapters/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
