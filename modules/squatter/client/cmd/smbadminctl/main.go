package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/vibepwners/hovel/payloads/squatter/client/smbpipe"
)

func main() {
	var opts smbpipe.Options
	var command string
	var readPath string
	var outPath string
	var delay time.Duration
	flag.StringVar(&opts.Domain, "domain", "", "SMB domain or local machine name")
	flag.StringVar(&opts.Username, "user", "", "SMB username")
	flag.StringVar(&opts.Password, "password", "", "SMB password")
	flag.IntVar(&opts.Port, "port", 445, "SMB port")
	flag.StringVar(&command, "schedule", "", "command to schedule through ATSVC")
	flag.StringVar(&readPath, "read", "", "remote admin path to read")
	flag.StringVar(&outPath, "out", "", "local file to write read data")
	flag.DurationVar(&delay, "delay", 20*time.Second, "ATSVC schedule delay")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: smbadminctl [flags] HOST")
		os.Exit(2)
	}
	opts.Host = flag.Arg(0)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if command != "" {
		status, jobID, err := smbpipe.ScheduleCommand(ctx, opts, command, delay)
		if err != nil {
			fmt.Fprintf(os.Stderr, "schedule: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("scheduled status=0x%08x job_id=%d\n", status, jobID)
	}
	if readPath != "" {
		body, err := smbpipe.ReadAdminFile(ctx, opts, readPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			os.Exit(1)
		}
		if outPath != "" {
			if err := os.WriteFile(outPath, body, 0600); err != nil {
				fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
				os.Exit(1)
			}
			fmt.Printf("read %d bytes to %s\n", len(body), outPath)
			return
		}
		fmt.Print(string(body))
	}
}
