package uicatalog

import (
	"context"
	"io"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/terminallog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

const defaultLogDelay = 500 * time.Millisecond

func logsDemo() Demo {
	return Demo{
		Name:     "logs",
		Summary:  "operator log rail with structured fields, pretty JSON, and elapsed labels",
		Animated: true,
		Render: func(ctx context.Context, opts Options, out io.Writer) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			renderer := terminallog.NewRendererWithWidth(opts.Width)
			if !opts.Color {
				renderer = terminallog.NewPlainRendererWithWidth(opts.Width)
			}
			log := demoLog()
			if opts.Animate {
				if err := streamLog(ctx, renderer, log, logDelay(opts), out); err != nil {
					return err
				}
				return nil
			}
			writeLine(out, renderer.Render(log))
			return nil
		},
	}
}

func demoLog() operatorlog.Log {
	elapsed := []float64{0.04, 0.31, 1.28, 1.74, 2.03, 2.18, 2.26}
	topic := "operation/default/chain/mock-survey-exploit/logs"
	return operatorlog.New("HOVEL//RUN", "mock-survey -> mock://alpha", []operatorlog.Entry{
		operatorlog.Stage(
			"Preparing target survey",
			operatorlog.Field{Name: "topic", Value: topic},
			operatorlog.Field{Name: "chain", Value: "mock-survey-exploit"},
			operatorlog.Field{Name: "run", Value: "run-2026-07-05T01:31Z"},
			operatorlog.Field{Name: "targets", Value: "3"},
			operatorlog.Field{Name: "workspace", Value: "lab-west"},
		).WithElapsed(elapsed[0]).WithTopic(topic).WithChain("mock-survey-exploit").WithRun("run-2026-07-05T01:31Z"),
		operatorlog.Info(
			"survey",
			"Resolved hostname and selected an exploit path based on open service metadata.",
			operatorlog.Field{Name: "target", Value: "mock://alpha"},
			operatorlog.Field{Name: "module", Value: "mock-survey-go@v0.0.0-example"},
			operatorlog.Field{Name: "service", Value: "smb"},
			operatorlog.Field{Name: "port", Value: "445/tcp"},
		).WithElapsed(elapsed[1]).WithTopic(topic).WithTarget("mock://alpha").WithModule("mock-survey-go@v0.0.0-example"),
		operatorlog.Info(
			"event",
			"Captured structured module event payload",
			operatorlog.Field{Name: "event", Value: `{"host":"mock-alpha","service":{"name":"smb","port":445},"tags":["lab","authorized"],"evidence":{"banner":"SMB mock service","confidence":0.91}}`},
		).WithElapsed(elapsed[2]).WithAttributes(map[string]string{"source": "jsonrpc-stdio", "schema": "hovel.module.event/v1"}),
		operatorlog.Finding(
			"survey",
			"Potential credential reuse found for operator review",
			operatorlog.Field{Name: "target", Value: "mock://alpha"},
			operatorlog.Field{Name: "module", Value: "mock-survey-go@v0.0.0-example"},
			operatorlog.Field{Name: "severity", Value: "medium"},
			operatorlog.Field{Name: "matched_users", Value: `["svc-backup","operator.demo"]`},
		).WithElapsed(elapsed[3]).WithTarget("mock://alpha").WithModule("mock-survey-go@v0.0.0-example"),
		operatorlog.Artifact(
			"artifact",
			"Wrote normalized survey report",
			operatorlog.Field{Name: "path", Value: "artifacts/survey.json"},
			operatorlog.Field{Name: "sha256", Value: "7d7f1f4f0f3d6c2a9b8e1a0c3e5f6a2d"},
		).WithElapsed(elapsed[4]).WithAttributes(map[string]string{"content_type": "application/json", "retention": "workspace"}),
		operatorlog.Error(
			"policy",
			"Rejected unauthenticated probe and kept the run scoped",
			operatorlog.Field{Name: "policy", Value: "authorized-lab-only"},
			operatorlog.Field{Name: "decision", Value: "blocked"},
			operatorlog.Field{Name: "retryable", Value: "false"},
		).WithElapsed(elapsed[5]).WithAttributes(map[string]string{"reason": "missing approval token"}),
		operatorlog.Success(
			"run",
			"Completed chain mock-survey-exploit",
			operatorlog.Field{Name: "chain", Value: "mock-survey-exploit"},
			operatorlog.Field{Name: "run", Value: "run-2026-07-05T01:31Z"},
		).WithElapsed(elapsed[6]).WithChain("mock-survey-exploit").WithRun("run-2026-07-05T01:31Z"),
	})
}

func logDelay(opts Options) time.Duration {
	if opts.DelaySet {
		return opts.Delay
	}
	return defaultLogDelay
}

func streamLog(ctx context.Context, renderer terminallog.Renderer, log operatorlog.Log, delay time.Duration, out io.Writer) error {
	writeLine(out, renderer.Render(operatorlog.New(log.Title, log.Subtitle, nil)))
	for index, entry := range log.Entries() {
		writeLine(out, renderer.Render(operatorlog.New("", "", []operatorlog.Entry{entry})))
		if index == len(log.Entries())-1 || delay == 0 {
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
