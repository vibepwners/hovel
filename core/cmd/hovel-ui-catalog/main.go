package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vibepwners/hovel/internal/adapters/uicatalog"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(uicatalog.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
