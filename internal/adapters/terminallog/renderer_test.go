package terminallog

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

func TestRendererFormatsOperatorLog(t *testing.T) {
	rendered := NewRenderer().Render(operatorlog.New("HOVEL//RUN", "mock-exploit -> mock://target", []operatorlog.Entry{
		operatorlog.Stage("1/2 prepare"),
		operatorlog.Info("run", "module staged", operatorlog.Field{Name: "run", Value: "run-1"}),
		operatorlog.Finding("finding", "mock exploit path verified", operatorlog.Field{Name: "severity", Value: "info"}),
		operatorlog.Artifact("artifact", "mock-exploit-transcript.txt", operatorlog.Field{Name: "kind", Value: "text/plain"}),
		operatorlog.Success("run", "completed", operatorlog.Field{Name: "state", Value: "succeeded"}),
	}))

	plain := stripANSI(rendered)
	for _, want := range []string{
		"HOVEL//RUN",
		"mock-exploit -> mock://target",
		"┃",
		":: run",
		">> stage",
		"## finding",
		"$$ artifact",
		"++ run",
		"severity=info",
	} {
		if !strings.Contains(plain, want) {
			t.Fatalf("rendered log missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "╭") || strings.Contains(rendered, "╰") {
		t.Fatalf("rendered log should not include a box border:\n%s", rendered)
	}
}

func TestRendererWrapsContinuationLinesAtMessageIndent(t *testing.T) {
	rendered := NewRendererWithWidth(44).Render(operatorlog.New("HOVEL//RUN", "", []operatorlog.Entry{
		operatorlog.Info("log", "this is a really long message that should wrap inline to the message indentation"),
	}))

	lines := strings.Split(stripANSI(rendered), "\n")
	if len(lines) < 3 {
		t.Fatalf("rendered log did not wrap:\n%s", rendered)
	}
	if !strings.HasPrefix(lines[2], "┃ :: log                this is a really") {
		t.Fatalf("first log line has wrong prefix:\n%s", rendered)
	}
	if !strings.HasPrefix(lines[3], "┃                       long message that") {
		t.Fatalf("wrapped line did not align with message column:\n%s", rendered)
	}
}

func TestRendererDisplaysThrowElapsedInLabel(t *testing.T) {
	rendered := NewRenderer().Render(operatorlog.New("HOVEL//THROW", "", []operatorlog.Entry{
		operatorlog.Info("module", "mock exploit started").WithElapsed(0.02),
	}))

	plain := stripANSI(rendered)
	if !strings.Contains(plain, ":: module        0.02") {
		t.Fatalf("rendered log missing elapsed label:\n%s", rendered)
	}
}

func TestRendererCanRenderEntriesWithoutHeader(t *testing.T) {
	rendered := NewRenderer().Render(operatorlog.New("", "", []operatorlog.Entry{
		operatorlog.Info("chain", "module added"),
	}))

	if strings.Contains(rendered, "HOVEL//") {
		t.Fatalf("rendered log should not include a synthetic header:\n%s", rendered)
	}
	if plain := stripANSI(rendered); !strings.Contains(plain, ":: chain") || !strings.Contains(plain, "module added") {
		t.Fatalf("rendered log missing entry:\n%s", rendered)
	}
}

func TestRendererReturnsEmptyForEmptyLog(t *testing.T) {
	if got := NewRenderer().Render(operatorlog.Log{}); got != "" {
		t.Fatalf("empty render = %q", got)
	}
}

func stripANSI(value string) string {
	return ansiPattern.ReplaceAllString(value, "")
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
