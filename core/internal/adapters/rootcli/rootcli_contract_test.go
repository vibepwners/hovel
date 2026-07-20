package rootcli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

func TestDaemonOwningRoutesValidateBeforeWorkspaceStartup(t *testing.T) {
	for _, test := range []struct {
		name          string
		args          func(string) []string
		want          string
		wantUsage     string
		forbidUnknown bool
	}{
		{
			name: "run missing required positional",
			args: func(workspace string) []string {
				return []string{"run", "--workspace", workspace, "module", "inspect"}
			},
			want:          "module is required",
			wantUsage:     "usage: hovel command module inspect",
			forbidUnknown: true,
		},
		{
			name: "one-shot throw unknown option",
			args: func(workspace string) []string {
				return []string{"throw", "demo.chain.yaml", "--workspace", workspace, "--not-an-option"}
			},
			want: "not-an-option",
		},
		{
			name: "direct session connect unknown option",
			args: func(workspace string) []string {
				return []string{"session", "connect", "session-1", "--workspace", workspace, "--not-an-option"}
			},
			want: "unknown option",
		},
		{
			name: "direct session connect missing required positional",
			args: func(workspace string) []string {
				return []string{"session", "connect", "--workspace", workspace}
			},
			want:          "session is required",
			wantUsage:     "usage: hovel command session connect",
			forbidUnknown: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspacePath := t.TempDir()
			var stdout, stderr bytes.Buffer

			code := Run(context.Background(), test.args(workspacePath), &stdout, &stderr)

			if code != 2 {
				t.Fatalf("exit code = %d, want 2; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr missing %q: %s", test.want, stderr.String())
			}
			if test.wantUsage != "" && !strings.Contains(stderr.String(), test.wantUsage) {
				t.Fatalf("stderr missing command-local usage %q: %s", test.wantUsage, stderr.String())
			}
			if test.forbidUnknown && strings.Contains(stderr.String(), "unknown command") {
				t.Fatalf("registered command was mislabeled as unknown: %s", stderr.String())
			}
			entries, err := os.ReadDir(workspacePath)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("syntax error started workspace resources: %#v", entries)
			}
		})
	}
}

func TestDirectSessionConnectValidArgumentsReachDaemonLookup(t *testing.T) {
	workspacePath := t.TempDir()
	var stdout, stderr bytes.Buffer

	code := Run(context.Background(), []string{
		"session", "connect",
		"--workspace", workspacePath,
		"--history-lines", "12",
		"session-1",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout = %s; stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "daemon is not running") {
		t.Fatalf("valid session connect did not reach daemon lookup: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "usage:") || strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("valid session connect was rejected as malformed: %s", stderr.String())
	}
}
