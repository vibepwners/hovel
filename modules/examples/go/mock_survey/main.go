// Command mock-survey-go is an example Hovel survey module written in Go.
//
// It mirrors the Python example in examples/python/mock_survey: it collects a
// couple of "facts" about a target without touching anything real. Run it
// through the daemon by registering it in a modules config with a "command"
// entry that points at the built binary.
package main

import (
	"fmt"
	"time"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

// MockSurvey reports example facts about a target.
type MockSurvey struct{}

func (MockSurvey) Info() hovel.Info {
	return hovel.Info{
		Name:        "mock-survey-go",
		Version:     "v0.0.0-example",
		Type:        hovel.TypeSurvey,
		Summary:     "Collect example target facts.",
		Description: "Example Go survey module for the Hovel stdio JSON-RPC runtime.",
		Tags:        []string{"example", "survey", "go"},
	}
}

func (MockSurvey) Schema() hovel.Schema {
	return hovel.Schema{
		TargetConfig: []hovel.Requirement{
			hovel.Req("target.host", "host", "Target host name or IP address."),
			hovel.Req("target.port", "port", "Target TCP port."),
		},
	}
}

func (MockSurvey) Run(ctx *hovel.Context) (hovel.Result, error) {
	host := ctx.InputString("target.host", ctx.Target)
	port := ctx.InputString("target.port", "unknown")
	ctx.Log.Info("connecting to target", "host", host, "port", port)
	time.Sleep(500 * time.Millisecond)
	ctx.Log.Info("connected to target, surveying ...", "host", host, "port", port)
	time.Sleep(1500 * time.Millisecond)
	ctx.Log.Info("example survey completed", "host", host, "port", port)
	return hovel.Ok(
		map[string]any{"facts": map[string]any{"host": host, "port": port, "reachable": true}},
		hovel.WithSummary(fmt.Sprintf("example survey reached %s:%s", host, port)),
	), nil
}

func main() {
	hovel.Serve(MockSurvey{})
}
