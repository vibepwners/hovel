package progressview

import (
	"bytes"
	"strings"
	"testing"
)

func TestTransferRendererPlainUploadOutput(t *testing.T) {
	var out bytes.Buffer
	renderer := NewTransferRenderer(&out, TransferOptions{Label: "upload", DoneLabel: "uploaded"})
	renderer.Start("artifacts/report.json", 2048)
	renderer.Complete("artifacts/report.json", 2048, 2048)

	text := out.String()
	for _, want := range []string{"upload report.json", "uploaded report.json"} {
		if !strings.Contains(text, want) {
			t.Fatalf("transfer output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("plain transfer output contains ANSI escapes:\n%q", text)
	}
}

func TestTransferRendererLiveOutputReachesComplete(t *testing.T) {
	var out bytes.Buffer
	renderer := NewTransferRenderer(&out, TransferOptions{Label: "upload", DoneLabel: "uploaded", Width: 80, Color: true})
	renderer.Progress("artifacts/report.json", 4096, 4096)
	renderer.Complete("artifacts/report.json", 4096, 4096)

	text := out.String()
	if !strings.Contains(text, "100%") {
		t.Fatalf("transfer output did not reach 100%%:\n%q", text)
	}
	if !strings.Contains(text, "uploaded report.json") {
		t.Fatalf("transfer output missing completion line:\n%q", text)
	}
}
