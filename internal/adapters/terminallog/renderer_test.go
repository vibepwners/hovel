package terminallog

import (
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

func TestRendererFormatsOperatorLog(t *testing.T) {
	rendered := NewRenderer().Render(operatorlog.New("HOVEL//RUN", "mock-exploit -> mock://target", []operatorlog.Entry{
		operatorlog.Info("run", "module staged", operatorlog.Field{Name: "run", Value: "run-1"}),
		operatorlog.Finding("finding", "mock exploit path verified", operatorlog.Field{Name: "severity", Value: "info"}),
		operatorlog.Artifact("artifact", "mock-exploit-transcript.txt", operatorlog.Field{Name: "kind", Value: "text/plain"}),
		operatorlog.Success("run", "completed", operatorlog.Field{Name: "state", Value: "succeeded"}),
	}))

	for _, want := range []string{
		"HOVEL//RUN",
		"mock-exploit -> mock://target",
		"[*] run",
		"[#] finding",
		"[$] artifact",
		"[+] run",
		"severity=info",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered log missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "╭") || strings.Contains(rendered, "╰") {
		t.Fatalf("rendered log should not include a box border:\n%s", rendered)
	}
}

func TestRendererReturnsEmptyForEmptyLog(t *testing.T) {
	if got := NewRenderer().Render(operatorlog.Log{}); got != "" {
		t.Fatalf("empty render = %q", got)
	}
}
