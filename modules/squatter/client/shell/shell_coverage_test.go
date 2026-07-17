package shell

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	prompt "github.com/c-bata/go-prompt"
	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
)

func TestClientRunDemoAndStreams(t *testing.T) {
	demoResponses := shellFrames(t,
		shellFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventStarted})},
		shellFrame{wire.KindData, []byte("argc=3")},
		shellFrame{wire.KindData, []byte("hello")},
		shellFrame{wire.KindData, []byte("world")},
		shellFrame{wire.KindData, []byte("the quick brown fox")},
		shellFrame{wire.KindClose, nil},
	)
	demoConn := newMemoryConn(demoResponses)
	var demoOut bytes.Buffer
	New(demoConn).RunDemo(&demoOut)
	for _, want := range []string{"argc=3", "hello", "world", "quick brown fox", "[closed]"} {
		if !strings.Contains(demoOut.String(), want) {
			t.Fatalf("demo output missing %q: %q", want, demoOut.String())
		}
	}

	streamResponses := shellFrames(t,
		shellFrame{wire.KindData, []byte("task0")},
		shellFrame{wire.KindData, []byte("task1")},
		shellFrame{wire.KindData, []byte("msg-0")},
		shellFrame{wire.KindData, []byte("msg-1")},
	)
	streamConn := newMemoryConn(streamResponses)
	var streamOut bytes.Buffer
	New(streamConn).RunStreams(&streamOut, 2)
	if !strings.Contains(streamOut.String(), "stream 1") || !strings.Contains(streamOut.String(), "echoed") {
		t.Fatalf("streams output = %q", streamOut.String())
	}
}

func TestClientDemoAndStreamsReportTransportFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*Client, io.Writer)
	}{
		{name: "demo", run: func(c *Client, out io.Writer) { c.RunDemo(out) }},
		{name: "streams", run: func(c *Client, out io.Writer) { c.RunStreams(out, 1) }},
	} {
		t.Run(test.name+" write", func(t *testing.T) {
			conn := newMemoryConn(nil)
			conn.writeErr = errors.New("write failed")
			var out bytes.Buffer
			test.run(New(conn), &out)
		})
		t.Run(test.name+" read", func(t *testing.T) {
			var out bytes.Buffer
			test.run(New(newMemoryConn([]byte("short"))), &out)
		})
	}
}

func TestClientTransportHelpersAndStreamBranches(t *testing.T) {
	c := New(newMemoryConn(shellFrames(t,
		shellFrame{wire.KindControl, []byte{0x80}},
		shellFrame{wire.KindData, []byte("ready")},
		shellFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventError, Message: "bad"})},
		shellFrame{wire.KindClose, nil},
	)))
	var out bytes.Buffer
	start := c.startStream(&out, 7, "echo", nil)
	if start != (streamStart{alive: true}) || !strings.Contains(out.String(), "ready") || !strings.Contains(out.String(), "bad") {
		t.Fatalf("start = %#v, output = %q", start, out.String())
	}

	failing := New(&memoryConn{read: bytes.NewReader(nil), writeErr: errors.New("no transport")})
	out.Reset()
	if got := failing.startStream(&out, 1, "echo", nil); got.alive || !strings.Contains(out.String(), "disconnected") {
		t.Fatalf("failed start = %#v, output = %q", got, out.String())
	}

	closed := New(newMemoryConn(shellFrames(t, shellFrame{wire.KindClose, nil})))
	if closed.readActiveResponse(io.Discard) {
		t.Fatal("readActiveResponse returned alive for close")
	}
	broken := New(newMemoryConn([]byte("short")))
	if broken.readActiveResponse(io.Discard) {
		t.Fatal("readActiveResponse returned alive for truncated frame")
	}

	transport := New(newMemoryConn(nil))
	var sid uint64
	if err := transport.WithLockedTransport(func(_ io.Writer, _ *bufio.Reader, got uint64) error {
		sid = got
		return errors.New("callback")
	}); err == nil || sid != 1 {
		t.Fatalf("WithLockedTransport = sid %d, err %v", sid, err)
	}
}

func TestClientLineStreamAndDrainPaths(t *testing.T) {
	responses := shellFrames(t,
		shellFrame{wire.KindData, []byte("reply")},
		shellFrame{wire.KindClose, nil},
	)
	c := New(newMemoryConn(responses))
	var out bytes.Buffer
	if !c.runLineStream(&out, 3, "echo", bufio.NewReader(strings.NewReader("hello\n"))) {
		t.Fatalf("line stream failed: %q", out.String())
	}
	if !strings.Contains(out.String(), "reply") {
		t.Fatalf("line stream output = %q", out.String())
	}

	done := make(chan bool, 1)
	drain := New(newMemoryConn(shellFrames(t,
		shellFrame{wire.KindData, []byte("raw")},
		shellFrame{wire.KindControl, []byte{0x80}},
		shellFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventError, Message: "oops"})},
		shellFrame{wire.KindClose, nil},
	)))
	out.Reset()
	drain.drainStreamFrames(&out, done)
	if alive := <-done; !alive || !strings.Contains(out.String(), "raw") || !strings.Contains(out.String(), "oops") {
		t.Fatalf("drain = %v, %q", alive, out.String())
	}

	done = make(chan bool, 1)
	New(newMemoryConn([]byte("short"))).drainStreamFrames(io.Discard, done)
	if <-done {
		t.Fatal("truncated drain reported alive")
	}
}

func TestClientGetAndPutFileCommands(t *testing.T) {
	dir := t.TempDir()
	download := filepath.Join(dir, "download.bin")
	getResponses := shellFrames(t,
		shellFrame{wire.KindData, []byte("SOK")},
		shellFrame{wire.KindData, []byte("Dcontents")},
		shellFrame{wire.KindClose, nil},
	)
	var out bytes.Buffer
	if !New(newMemoryConn(getResponses)).cmdGetfile(&out, 1, []string{"remote.bin", download}) {
		t.Fatal("cmdGetfile returned false")
	}
	data, err := os.ReadFile(download)
	if err != nil || string(data) != "contents" {
		t.Fatalf("download = %q, %v", data, err)
	}

	upload := filepath.Join(dir, "upload.bin")
	if err := os.WriteFile(upload, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	putResponses := shellFrames(t,
		shellFrame{wire.KindData, []byte("SOK")},
		shellFrame{wire.KindData, []byte("SOK 7")},
		shellFrame{wire.KindClose, nil},
	)
	out.Reset()
	if !New(newMemoryConn(putResponses)).cmdPutfile(&out, 2, []string{upload, `C:\temp\upload.bin`}) {
		t.Fatalf("cmdPutfile failed: %q", out.String())
	}
	if !strings.Contains(out.String(), "OK 7") || !strings.Contains(out.String(), "7 bytes") {
		t.Fatalf("put output = %q", out.String())
	}

	out.Reset()
	c := New(newMemoryConn(nil))
	if !c.cmdGetfile(&out, 3, nil) || !c.cmdPutfile(&out, 4, nil) {
		t.Fatal("usage errors should keep shell alive")
	}
	if !c.cmdGetfile(&out, 5, []string{"remote", filepath.Join(dir, "missing", "file")}) {
		t.Fatal("create error should keep shell alive")
	}
	if !c.cmdPutfile(&out, 6, []string{filepath.Join(dir, "missing"), "remote"}) {
		t.Fatal("open error should keep shell alive")
	}
}

func TestInteractiveShellStateExecutionAndFallbackLoop(t *testing.T) {
	conn := newMemoryConn(shellFrames(t,
		shellFrame{wire.KindData, []byte("done")},
		shellFrame{wire.KindClose, nil},
	))
	var out bytes.Buffer
	s := &interactiveShell{client: New(conn), out: &out, title: "mesh node"}
	s.printBanner()
	s.printHelp()
	s.runTerminalPromptLoop(strings.NewReader("help\nquit\n"))
	if !s.done || !strings.Contains(out.String(), "mesh node") || !strings.Contains(out.String(), "commands") {
		t.Fatalf("shell state = done %v, output %q", s.done, out.String())
	}

	s.done = false
	s.setActive("echo", 9, false, false)
	s.executeActive("hello")
	if active, _, _ := s.activeState(); active != "echo" {
		t.Fatalf("active = %q after data response", active)
	}
	s.executeActive("detach")
	if active, _, _ := s.activeState(); active != "" {
		t.Fatalf("active = %q after detach", active)
	}

	s.setActive("cmd", 10, true, false)
	s.executeActive("whoami")
	if active, _, raw := s.activeState(); active != "cmd" || !raw {
		t.Fatalf("raw active state = %q, %v", active, raw)
	}
	s.executeActive("quit")
	if !s.done {
		t.Fatal("active quit did not finish shell")
	}

	s.done = false
	s.execute("?")
	s.execute("   ")
	s.execute("exit")
	if !s.done {
		t.Fatal("top-level exit did not finish shell")
	}
}

func TestInteractiveShellExecutesInactiveActiveRawAndFailureBranches(t *testing.T) {
	var out bytes.Buffer
	nonActive := &interactiveShell{
		client: New(newMemoryConn(shellFrames(t, shellFrame{wire.KindClose, nil}))),
		out:    &out,
	}
	nonActive.execute("wininfo")
	if nonActive.done {
		t.Fatal("completed one-shot stream ended shell")
	}

	activeConn := newMemoryConn(shellFrames(t,
		shellFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventInteractive})},
		shellFrame{wire.KindData, []byte("response")},
		shellFrame{wire.KindClose, nil},
	))
	active := &interactiveShell{client: New(activeConn), out: &out}
	active.execute("echo hello")
	if module, _, raw := active.activeState(); module != "echo" || raw {
		t.Fatalf("active state = %q, %v", module, raw)
	}
	active.execute("next")
	active.execute("next-again")
	if module, _, _ := active.activeState(); module != "" {
		t.Fatalf("closed active state = %q", module)
	}

	rawConn := newMemoryConn(shellFrames(t,
		shellFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventInteractive, Code: streamInteractiveRaw})},
	))
	raw := &interactiveShell{client: New(rawConn), out: &out}
	raw.execute("cmd")
	raw.execute("whoami")
	if module, _, isRaw := raw.activeState(); module != "cmd" || !isRaw {
		t.Fatalf("raw state = %q, %v", module, isRaw)
	}
	raw.execute("detach")

	failedConn := newMemoryConn(nil)
	failedConn.writeErr = errors.New("write failed")
	failed := &interactiveShell{client: New(failedConn), out: &out}
	failed.execute("echo")
	if !failed.done {
		t.Fatal("failed stream did not end shell")
	}

	usage := &interactiveShell{client: New(newMemoryConn(nil)), out: &out}
	usage.execute("getfile")
	usage.execute("putfile")
	if usage.done {
		t.Fatal("usage errors ended shell")
	}
	if usage.prefix() != "sq> " || usage.renderedPrefix() == "" || usage.output() != &out {
		t.Fatal("shell rendering helpers failed")
	}
}

func TestPTYPromptLoopSubmissionExitAndSetupFailure(t *testing.T) {
	var out bytes.Buffer
	s := &interactiveShell{client: New(newMemoryConn(nil)), out: &out}
	terminal := &fakePromptTerminal{
		writer: newPromptPTYWriter(&out),
		reads:  [][]byte{[]byte("quit\n")},
	}
	if !s.runPTYPrompt(terminal) || !s.done || terminal.setupCalls == 0 || terminal.tearDownCalls == 0 {
		t.Fatalf("PTY prompt = done %v setup %d teardown %d", s.done, terminal.setupCalls, terminal.tearDownCalls)
	}

	failing := &fakePromptTerminal{writer: newPromptPTYWriter(io.Discard), setupErr: errors.New("setup")}
	if (&interactiveShell{client: New(newMemoryConn(nil)), out: io.Discard}).runPTYPrompt(failing) {
		t.Fatal("PTY prompt accepted setup failure")
	}
}

func TestClientRunBlankQuitEOFAndAdditionalFailurePaths(t *testing.T) {
	var out bytes.Buffer
	New(newMemoryConn(nil)).Run(strings.NewReader("\nquit\n"), &out)
	New(newMemoryConn(nil)).Run(strings.NewReader(""), &out)

	dataThenBroken := newMemoryConn(shellFrames(t, shellFrame{wire.KindData, []byte("ready")}))
	client := New(dataThenBroken)
	if start := client.startStream(errorOutput{err: errors.New("out")}, 1, "echo", nil); start.alive {
		t.Fatalf("output failure start = %#v", start)
	}
	if client.drainUntilClose() {
		t.Fatal("truncated drain returned true")
	}

	if got := cmdArgsFromLine("not-cmd"); got != nil {
		t.Fatalf("non-cmd args = %#v", got)
	}
	for _, line := range []string{"cmd ", "cmd -i", "cmd --debug", "cmd -i whoami", "cmd --debug whoami"} {
		_ = cmdArgsFromLine(line)
	}
	if module, args := moduleArgsFromLine("", nil); module != "" || args != nil {
		t.Fatalf("empty module args = %q, %#v", module, args)
	}
}

func TestShellPromptUIEditingHistoryCompletionAndRendering(t *testing.T) {
	var output bytes.Buffer
	s := &interactiveShell{client: New(newMemoryConn(nil)), out: &output}
	w := newPromptPTYWriter(&output)
	ui := newShellPromptUI(s, w)

	if _, _, ok := ui.consume(nil); ok {
		t.Fatal("empty input was consumed")
	}
	for _, input := range [][]byte{
		[]byte("ec"),
		{0x01},
		{0x05},
		{0x1b, '[', 'D'},
		{0x1b, '[', 'C'},
		{0x7f},
		[]byte("h"),
		{'\t'},
	} {
		pending := input
		for len(pending) > 0 {
			_, rest, ok := ui.consume(pending)
			if !ok {
				t.Fatalf("input %x was incomplete", pending)
			}
			pending = rest
		}
	}
	if event, _, ok := ui.consume([]byte{'\n'}); !ok || event.kind != promptUISubmit {
		t.Fatalf("submit event = %#v, %v", event, ok)
	}
	ui.resetInput()
	ui.historyOlder()
	ui.historyOlder()
	ui.historyNewer()
	ui.historyNewer()
	ui.backspace()
	ui.deleteAtCursor()
	ui.setLine("abc")
	ui.cursor = 1
	ui.deleteAtCursor()
	ui.backspace()
	ui.replaceCurrentWord("echo")

	for _, input := range [][]byte{
		{0x1b},
		{0x1b, 'x', 'z'},
		{0x1b, '[', 'H'},
		{0x1b, '[', 'F'},
		{0x1b, '[', '3'},
		{0x1b, '[', '3', '~'},
		{0x03},
		{0x04},
		{0x00},
	} {
		_, _, _ = ui.consume(input)
	}

	ui.completions = append(topLevelSuggestions(), topLevelSuggestions()...)
	ui.completionIndex = 1
	ui.renderedCompletionRows = 2
	if err := ui.render(); err != nil {
		t.Fatal(err)
	}
	if err := ui.breakLine(); err != nil {
		t.Fatal(err)
	}
	if output.Len() == 0 {
		t.Fatal("prompt rendering produced no output")
	}

	s.setActive("cmd", 2, true, false)
	if got := ui.activeModule(); got != "" {
		t.Fatalf("raw active module = %q", got)
	}
	if got := s.complete(prompt.Document{}); got != nil {
		t.Fatalf("raw completions = %#v", got)
	}
}

func TestSuggestionsAndCLIParsingCoverAllShapes(t *testing.T) {
	commands := []string{"getfile", "putfile", "echo", "cmd", "process.run", "process.run_as_user", "file.stat", "registry.query", "eventlog.query"}
	for _, command := range commands {
		if got := Suggestions("", command+" "); len(got) == 0 {
			t.Fatalf("Suggestions(%q) = nil", command)
		}
	}
	if got := Suggestions("", "unknown "); got != nil {
		t.Fatalf("unknown suggestions = %#v", got)
	}
	if got := Suggestions("echo", "d"); len(got) != 1 || got[0].Text != "detach" {
		t.Fatalf("active filtered suggestions = %#v", got)
	}
	if currentPrefix(nil, false) != "" || currentPrefix([]string{"x"}, true) != "" || currentPrefix([]string{"x"}, false) != "x" {
		t.Fatal("currentPrefix cases failed")
	}

	opts, err := ParseCLI([]string{"--streams", "4", "--smb", "--domain", "LAB", "--username", "alice", "--password", "pw", "--pipe", "sq", "--smb-port", "1445", "host", "9999"})
	if err != nil || opts.Mode != ModeStreams || opts.Streams != 4 || opts.Host != "host" || opts.Port != "9999" || opts.Username != "alice" {
		t.Fatalf("ParseCLI = %#v, %v", opts, err)
	}
	defaults, err := ParseCLI(nil)
	if err != nil || defaults.Mode != ModeShell || defaults.Host != "127.0.0.1" {
		t.Fatalf("ParseCLI defaults = %#v, %v", defaults, err)
	}
	for _, flag := range []string{"--streams", "--domain", "--user", "--username", "--password", "--pipe", "--smb-port"} {
		if _, err := ParseCLI([]string{flag}); err == nil {
			t.Fatalf("ParseCLI(%q) returned nil error", flag)
		}
	}
}

func TestWriteAndEchoHelpersPropagateErrors(t *testing.T) {
	want := errors.New("output failed")
	for _, fn := range []func(io.Writer) error{
		func(w io.Writer) error { return emit(w, []byte("x")) },
		func(w io.Writer) error { return emitRaw(w, []byte("x")) },
		func(w io.Writer) error { return echoAttachInput(w, []byte("x\r\b\t")) },
	} {
		if err := fn(errorOutput{err: want}); !errors.Is(err, want) {
			t.Fatalf("helper error = %v, want %v", err, want)
		}
	}
	if err := writeFully(zeroOutput{}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeFully zero error = %v", err)
	}
}

func TestShellStreamAndOutputFailureMatrix(t *testing.T) {
	want := errors.New("shell failure")
	writeLine(errorOutput{err: want}, "line")
	writeText(errorOutput{err: want}, "text")
	writeFormat(errorOutput{err: want}, "%s", "format")
	logShellError("expected test failure", want)
	retrying := &retryOutput{}
	if err := writeFully(retrying, []byte("retry")); err != nil || retrying.calls != 2 {
		t.Fatalf("retryable write = calls %d, %v", retrying.calls, err)
	}

	var out bytes.Buffer
	if start := New(newMemoryConn([]byte("short"))).startStream(&out, 1, "echo", nil); start.alive {
		t.Fatalf("truncated start response = %#v", start)
	}
	if New(newMemoryConn(nil)).runLineStream(&out, 1, "echo", bufio.NewReader(errorReader{err: want})) {
		t.Fatal("line stream reader failure reported alive")
	}
	writeBroken := newMemoryConn(nil)
	writeBroken.writeErr = want
	if New(writeBroken).runLineStream(&out, 1, "echo", bufio.NewReader(strings.NewReader("hello\n"))) {
		t.Fatal("line stream writer failure reported alive")
	}
	emptyLine := New(newMemoryConn(shellFrames(t, shellFrame{wire.KindClose, nil})))
	if !emptyLine.runLineStream(&out, 1, "echo", bufio.NewReader(strings.NewReader("\n"))) {
		t.Fatal("empty line followed by detach reported dead")
	}

	dataResponse := New(newMemoryConn(shellFrames(t, shellFrame{wire.KindData, []byte("data")})))
	if dataResponse.readActiveResponse(errorOutput{err: want}) {
		t.Fatal("active response output failure reported alive")
	}
	controlResponse := New(newMemoryConn(shellFrames(t,
		shellFrame{wire.KindControl, wire.EncodeStreamEvent(wire.StreamEvent{Kind: wire.EventError, Message: "failed"})},
		shellFrame{wire.KindClose, nil},
	)))
	out.Reset()
	if controlResponse.readActiveResponse(&out) || !strings.Contains(out.String(), "stream error") {
		t.Fatalf("control response = %q", out.String())
	}
	done := make(chan bool, 1)
	New(newMemoryConn(shellFrames(t, shellFrame{wire.KindData, []byte("data")}))).drainStreamFrames(errorOutput{err: want}, done)
	if <-done {
		t.Fatal("drain output failure reported alive")
	}
	raw := New(newMemoryConn(shellFrames(t, shellFrame{wire.KindClose, nil})))
	if !raw.runRawLines(io.Discard, 1, bufio.NewReader(strings.NewReader(""))) {
		t.Fatal("raw EOF detach reported dead")
	}

	dir := t.TempDir()
	upload := filepath.Join(dir, "upload.bin")
	if err := os.WriteFile(upload, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if New(newMemoryConn([]byte("short"))).cmdPutfile(&out, 1, []string{upload, "remote"}) {
		t.Fatal("failed putfile reported alive")
	}
	download := filepath.Join(dir, "download.bin")
	if !New(newMemoryConn([]byte("short"))).cmdGetfile(&out, 2, []string{"remote", download}) {
		t.Fatal("failed getfile should preserve a connected shell")
	}

	activeConn := newMemoryConn(nil)
	activeConn.writeErr = want
	active := &interactiveShell{client: New(activeConn), out: &out}
	active.setActive("echo", 1, false, false)
	active.executeActive("hello")
	if !active.done {
		t.Fatal("active stream write failure did not end shell")
	}
	completionShell := &interactiveShell{client: New(newMemoryConn(nil)), out: &out}
	if got := completionShell.complete(prompt.Document{}); len(got) == 0 {
		t.Fatal("non-raw completion returned no suggestions")
	}
}

func TestPromptLoopFailureAndExitMatrix(t *testing.T) {
	want := errors.New("prompt failure")
	if (&interactiveShell{client: New(newMemoryConn(nil)), out: io.Discard}).runPTYPrompt(&fakePromptTerminal{
		writer:  newPromptPTYWriter(errorOutput{err: want}),
		readErr: want,
	}) {
		t.Fatal("PTY accepted initial render failure")
	}
	for name, terminal := range map[string]*fakePromptTerminal{
		"read": {
			writer: newPromptPTYWriter(io.Discard), readErr: want,
		},
		"empty_then_read": {
			writer: newPromptPTYWriter(io.Discard), reads: [][]byte{nil}, readErr: want,
		},
		"incomplete_then_read": {
			writer: newPromptPTYWriter(io.Discard), reads: [][]byte{{0x1b}}, readErr: want,
		},
		"teardown": {
			writer: newPromptPTYWriter(io.Discard), reads: [][]byte{[]byte("help\n")}, tearDownErr: want,
		},
		"second_setup": {
			writer: newPromptPTYWriter(io.Discard), reads: [][]byte{[]byte("help\n")}, failSetupAt: 2, setupErr: want,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := &interactiveShell{client: New(newMemoryConn(nil)), out: io.Discard}
			if s.runPTYPrompt(terminal) {
				t.Fatal("PTY failure returned true")
			}
		})
	}
	exit := &interactiveShell{client: New(newMemoryConn(nil)), out: io.Discard}
	if !exit.runPTYPrompt(&fakePromptTerminal{
		writer: newPromptPTYWriter(io.Discard), reads: [][]byte{{0x04}},
	}) || !exit.done {
		t.Fatal("PTY Ctrl-D did not exit")
	}

	(&interactiveShell{client: New(newMemoryConn(nil)), out: errorOutput{err: want}}).runTerminalPromptLoop(strings.NewReader("quit\n"))
	var out bytes.Buffer
	(&interactiveShell{client: New(newMemoryConn(nil)), out: &out}).runTerminalPromptLoop(errorReader{err: want})
	if !strings.Contains(out.String(), "disconnected") {
		t.Fatalf("terminal reader failure output = %q", out.String())
	}

	nilOutput := &interactiveShell{}
	if nilOutput.output() != os.Stdout {
		t.Fatal("nil shell output did not default to stdout")
	}
	nilOutput.setActive("cmd", 1, true, false)
	if nilOutput.prefix() != "" || nilOutput.renderedPrefix() != "" {
		t.Fatal("raw shell rendered a prompt")
	}
}

func TestPromptUIAdditionalNavigationAndFailures(t *testing.T) {
	var out bytes.Buffer
	s := &interactiveShell{client: New(newMemoryConn(nil)), out: &out}
	ui := newShellPromptUI(s, newPromptPTYWriter(&out))
	ui.history = []string{"one", "two"}
	ui.historyIndex = len(ui.history)
	ui.setLine("scratch")
	for _, input := range [][]byte{{0x1b, '[', 'A'}, {0x1b, '[', 'A'}, {0x1b, '[', 'B'}} {
		if _, _, ok := ui.consume(input); !ok {
			t.Fatalf("navigation input %x was incomplete", input)
		}
	}
	if string(ui.line) != "two" {
		t.Fatalf("history line = %q", ui.line)
	}
	ui.completions = topLevelSuggestions()
	ui.completionIndex = 0
	ui.complete()
	ui.setLine("prefix word")
	ui.cursor = len(ui.line)
	ui.replaceCurrentWord("replacement")
	if !strings.Contains(string(ui.line), "replacement") {
		t.Fatalf("replacement line = %q", ui.line)
	}
	broken := newShellPromptUI(s, newPromptPTYWriter(errorOutput{err: errors.New("flush failed")}))
	if err := broken.breakLine(); err == nil {
		t.Fatal("breakLine flush failure returned nil")
	}
}

type shellFrame struct {
	kind    uint16
	payload []byte
}

func shellFrames(t *testing.T, values ...shellFrame) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, value := range values {
		if err := wire.WriteFrame(&out, value.kind, 1, value.payload); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

type memoryConn struct {
	read     *bytes.Reader
	writes   bytes.Buffer
	writeErr error
}

func newMemoryConn(input []byte) *memoryConn { return &memoryConn{read: bytes.NewReader(input)} }

func (c *memoryConn) Read(p []byte) (int, error) { return c.read.Read(p) }

func (c *memoryConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.writes.Write(p)
}

func (*memoryConn) Close() error { return nil }

type errorOutput struct{ err error }

func (w errorOutput) Write([]byte) (int, error) { return 0, w.err }

type zeroOutput struct{}

func (zeroOutput) Write([]byte) (int, error) { return 0, nil }

type retryOutput struct{ calls int }

func (w *retryOutput) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return 0, syscall.EAGAIN
	}
	return len(p), nil
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type fakePromptTerminal struct {
	writer        prompt.ConsoleWriter
	reads         [][]byte
	setupErr      error
	readErr       error
	tearDownErr   error
	failSetupAt   int
	setupCalls    int
	tearDownCalls int
}

func (t *fakePromptTerminal) Setup() error {
	t.setupCalls++
	if t.failSetupAt > 0 && t.setupCalls == t.failSetupAt {
		return t.setupErr
	}
	if t.failSetupAt > 0 {
		return nil
	}
	return t.setupErr
}

func (t *fakePromptTerminal) TearDown() error {
	t.tearDownCalls++
	return t.tearDownErr
}

func (t *fakePromptTerminal) Read() ([]byte, error) {
	if len(t.reads) == 0 {
		return nil, t.readErr
	}
	read := t.reads[0]
	t.reads = t.reads[1:]
	return read, nil
}

func (t *fakePromptTerminal) Writer() prompt.ConsoleWriter { return t.writer }

var _ prompt.ConsoleWriter = (*promptPTYWriter)(nil)
