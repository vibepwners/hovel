package pythonrpc

import (
	"strings"
	"testing"
)

func TestFrameDecoderRejectsOversizedModuleNotification(t *testing.T) {
	var frame strings.Builder
	err := writeFrame(&frame, map[string]any{
		"jsonrpc": "2.0",
		"method":  "module/log",
		"params": map[string]any{
			"message": strings.Repeat("x", maxModuleNotificationBytes),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = newFrameDecoder(strings.NewReader(frame.String())).read()
	if err == nil || !strings.Contains(err.Error(), "module/log params size") {
		t.Fatalf("error = %v, want module notification size error", err)
	}
}

func TestCapturedStderrRetainsBoundedTail(t *testing.T) {
	stderr := newCapturedStderr()
	wantTail := strings.Repeat("z", maxCapturedStderrBytes)
	if _, err := stderr.Write([]byte("discarded" + wantTail)); err != nil {
		t.Fatal(err)
	}

	got := stderr.String()
	if len(got) != maxCapturedStderrBytes {
		t.Fatalf("captured stderr bytes = %d, want %d", len(got), maxCapturedStderrBytes)
	}
	if !strings.HasPrefix(got, stderrTruncationMarker) {
		t.Fatalf("captured stderr missing truncation marker: %q", got[:len(stderrTruncationMarker)])
	}
	if !strings.HasSuffix(got, strings.Repeat("z", maxCapturedStderrBytes-len(stderrTruncationMarker))) {
		t.Fatal("captured stderr did not retain the newest bytes")
	}
}

func TestRPCClientRejectsExcessBufferedModuleLogs(t *testing.T) {
	client := &rpcClient{}
	for index := 0; index < maxBufferedModuleLogs; index++ {
		if err := client.handleNotification(rpcMessage{Method: "module/log"}); err != nil {
			t.Fatalf("handle module log %d: %v", index+1, err)
		}
	}
	if got := len(client.logsSnapshot()); got != maxBufferedModuleLogs {
		t.Fatalf("buffered module logs = %d, want %d", got, maxBufferedModuleLogs)
	}
	err := client.handleNotification(rpcMessage{Method: "module/log"})
	if err == nil || !strings.Contains(err.Error(), "notification count exceeds maximum") {
		t.Fatalf("error = %v, want buffered module log limit error", err)
	}
}
