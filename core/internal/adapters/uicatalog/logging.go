package uicatalog

import (
	"context"
	"io"

	"github.com/Vibe-Pwners/hovel/internal/adapters/terminallog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

func logsDemo() Demo {
	return Demo{
		Name:    "logs",
		Summary: "operator log rail with stages, findings, artifacts, and elapsed labels",
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
			elapsed := []float64{0.04, 0.31, 1.28, 1.74, 2.03}
			log := operatorlog.New("HOVEL//RUN", "mock-survey -> mock://alpha", []operatorlog.Entry{
				operatorlog.Stage("Preparing target survey", operatorlog.Field{Name: "targets", Value: "3"}).WithElapsed(elapsed[0]),
				operatorlog.Info("survey", "Resolved hostname and selected an exploit path based on open service metadata.").WithElapsed(elapsed[1]),
				operatorlog.Finding("survey", "Potential credential reuse found for operator review", operatorlog.Field{Name: "severity", Value: "medium"}).WithElapsed(elapsed[2]),
				operatorlog.Artifact("artifact", "Wrote normalized survey report", operatorlog.Field{Name: "path", Value: "artifacts/survey.json"}).WithElapsed(elapsed[3]),
				operatorlog.Success("run", "Completed chain mock-survey-exploit").WithElapsed(elapsed[4]),
			})
			writeLine(out, renderer.Render(log))
			return nil
		},
	}
}
