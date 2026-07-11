package pythonrpc

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	stubbornShutdownHelperEnv = "HOVEL_TEST_STUBBORN_MODULE_SHUTDOWN"
	shutdownTestTimeout       = 250 * time.Millisecond
)

func TestModuleProcessShutdownIsBounded(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestStubbornShutdownHelper")
	cmd.Env = append(os.Environ(), stubbornShutdownHelperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &moduleProcess{
		cmd:      cmd,
		client:   newClient(stdout, stdin),
		waitDone: make(chan struct{}),
	}

	shutdownErr, waitErr := process.shutdownAndWait(context.Background(), shutdownTestTimeout)
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want deadline exceeded", shutdownErr)
	}
	if !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("wait error = %v, want deadline exceeded", waitErr)
	}
	if process.cmd.ProcessState == nil {
		t.Fatalf("process state = %#v, want reaped process", process.cmd.ProcessState)
	}
}

func TestStubbornShutdownHelper(t *testing.T) {
	if os.Getenv(stubbornShutdownHelperEnv) != "1" {
		return
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}
