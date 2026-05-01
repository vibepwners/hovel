package cli

import (
	"bytes"
	"errors"
	"testing"
)

type promptTerminalRestorerFunc func() error

func (f promptTerminalRestorerFunc) Restore() error {
	return f()
}

func TestFinishPromptRestoresTerminalAndPrintsNewline(t *testing.T) {
	var stdout bytes.Buffer
	restored := false

	err := finishPrompt(&stdout, promptTerminalRestorerFunc(func() error {
		restored = true
		return nil
	}))

	if err != nil {
		t.Fatalf("finish prompt error = %v", err)
	}
	if !restored {
		t.Fatal("terminal was not restored")
	}
	if stdout.String() != "\n" {
		t.Fatalf("stdout = %q, want newline", stdout.String())
	}
}

func TestFinishPromptReturnsRestoreErrorBeforeNewline(t *testing.T) {
	var stdout bytes.Buffer
	restoreErr := errors.New("restore failed")

	err := finishPrompt(&stdout, promptTerminalRestorerFunc(func() error {
		return restoreErr
	}))

	if !errors.Is(err, restoreErr) {
		t.Fatalf("finish prompt error = %v, want %v", err, restoreErr)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want no newline after restore failure", stdout.String())
	}
}
