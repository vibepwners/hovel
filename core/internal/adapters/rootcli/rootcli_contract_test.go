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
		name string
		args func(string) []string
		want string
	}{
		{
			name: "run missing required positional",
			args: func(workspace string) []string {
				return []string{"run", "--workspace", workspace, "module", "inspect"}
			},
			want: "module is required",
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
			want: "unknown session connect option",
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
