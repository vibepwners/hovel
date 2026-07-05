package terminallog

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/charmbracelet/lipgloss"
)

func TestRendererFormatsOperatorLog(t *testing.T) {
	rendered := NewRenderer().Render(operatorlog.New("HOVEL//RUN", "mock-exploit -> mock://target", []operatorlog.Entry{
		operatorlog.Stage("1/2 prepare"),
		operatorlog.Info("run", "module staged", operatorlog.Field{Name: "run", Value: "run-1"}),
		operatorlog.Finding("finding", "mock exploit path verified", operatorlog.Field{Name: "severity", Value: "info"}),
		operatorlog.Artifact("artifact", "mock-exploit-transcript.txt", operatorlog.Field{Name: "kind", Value: "text/plain"}),
		operatorlog.Error("policy", "blocked unauthenticated probe"),
		operatorlog.Success("run", "completed", operatorlog.Field{Name: "state", Value: "succeeded"}),
	}))

	plain := stripANSI(rendered)
	for _, want := range []string{
		"HOVEL//RUN",
		"mock-exploit -> mock://target",
		"┃",
		"INFO",
		"WARN",
		"VERBOSE",
		"TRACE",
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
	if !strings.HasPrefix(lines[2], "┃ :: log      INFO          this is a really") {
		t.Fatalf("first log line has wrong prefix:\n%s", rendered)
	}
	if !strings.HasPrefix(lines[3], "┃                           long message") {
		t.Fatalf("wrapped line did not align with message column:\n%s", rendered)
	}
}

func TestRendererDisplaysThrowElapsedInLabel(t *testing.T) {
	rendered := NewRenderer().Render(operatorlog.New("HOVEL//THROW", "", []operatorlog.Entry{
		operatorlog.Info("module", "mock exploit started").WithElapsed(0.02),
	}))

	plain := stripANSI(rendered)
	if !strings.Contains(plain, ":: module   INFO     0.02") {
		t.Fatalf("rendered log missing elapsed label:\n%s", rendered)
	}
}

func TestRendererDisplaysLevelBlocks(t *testing.T) {
	rendered := NewPlainRenderer().Render(operatorlog.New("HOVEL//RUN", "", []operatorlog.Entry{
		operatorlog.Info("module", "info"),
		operatorlog.Warn("module", "warn"),
		operatorlog.Error("module", "error"),
		operatorlog.Verbose("module", "verbose"),
		operatorlog.Trace("module", "trace"),
	}))

	for _, want := range []string{"INFO", "WARN", "ERROR", "VERBOSE", "TRACE"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered log missing level %q:\n%s", want, rendered)
		}
	}
}

func TestRendererDisplaysStructuredMetadataAndPrettyJSON(t *testing.T) {
	rendered := NewPlainRendererWithWidth(120).Render(operatorlog.New("HOVEL//RUN", "", []operatorlog.Entry{
		operatorlog.Info("event", "captured structured payload",
			operatorlog.Field{Name: "topic", Value: "operation/default/chain/mock/logs"},
			operatorlog.Field{Name: "chain", Value: "mock"},
			operatorlog.Field{Name: "run", Value: "run-1"},
			operatorlog.Field{Name: "target", Value: "mock://alpha"},
			operatorlog.Field{Name: "module", Value: "mock-survey"},
			operatorlog.Field{Name: "payload", Value: `{"host":"mock-alpha","service":{"name":"smb","port":445},"tags":["lab","authorized"]}`},
			operatorlog.Field{Name: "severity", Value: "info"},
		).WithAttributes(map[string]string{"schema": "hovel.module.event/v1"}),
	}))

	for _, want := range []string{
		"topic=operation/default/chain/mock/logs",
		"chain=mock",
		"run=run-1",
		"target=mock://alpha",
		"module=mock-survey",
		"schema=hovel.module.event/v1",
		"payload=",
		`"service": {`,
		`"port": 445`,
		`"tags": [`,
		"severity=info",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered log missing %q:\n%s", want, rendered)
		}
	}
}

func TestRendererStylesThrowHeaderBoldRed(t *testing.T) {
	renderer := NewRenderer()
	title, subtitle := renderer.headerStyles("HOVEL//THROW")

	requireBoldRedStyle(t, "title", title)
	requireBoldRedStyle(t, "subtitle", subtitle)

	rendered := renderer.Render(operatorlog.New("HOVEL//THROW", "new", []operatorlog.Entry{
		operatorlog.Info("throw", "started"),
	}))
	if !strings.Contains(stripANSI(rendered), "HOVEL//THROW new") {
		t.Fatalf("rendered throw header missing chain name:\n%s", rendered)
	}
}

func TestRendererStylesStreamedThrowHeaderBoldRed(t *testing.T) {
	renderer := NewRenderer()
	rendered := renderer.Render(operatorlog.New("", "", []operatorlog.Entry{{
		Kind:      operatorlog.KindHeader,
		Message:   "HOVEL//THROW",
		ChainName: "new",
	}}))

	if !strings.Contains(stripANSI(rendered), "HOVEL//THROW new") {
		t.Fatalf("rendered streamed throw header missing chain name:\n%s", rendered)
	}
	if !strings.Contains(rendered, renderer.throwTitle.Render("HOVEL//THROW")) {
		t.Fatalf("rendered streamed throw header missing styled title:\n%s", rendered)
	}
	if !strings.Contains(rendered, renderer.throwSubtitle.Render("new")) {
		t.Fatalf("rendered streamed throw header missing styled chain name:\n%s", rendered)
	}
}

func requireBoldRedStyle(t *testing.T, name string, style lipgloss.Style) {
	t.Helper()
	if !style.GetBold() {
		t.Fatalf("%s style is not bold", name)
	}
	if color, ok := style.GetForeground().(lipgloss.Color); !ok || color != lipgloss.Color("#ff0033") {
		t.Fatalf("%s style foreground = %#v, want #ff0033", name, style.GetForeground())
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
