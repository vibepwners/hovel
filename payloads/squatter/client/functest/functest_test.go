// Package functest is a black-box functional harness: it launches the actual
// squatter.exe under wine and drives it over TCP with the real wire protocol.
//
// One server is started for the whole package (TestMain) in a fresh working
// directory, so the file-transfer test can inspect what the server wrote.
package functest

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"

	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/wire"
	"github.com/Vibe-Pwners/hovel/payloads/squatter/client/xfer"
)

var (
	serverPort int
	serverDir  string
)

func findSquatter() (string, error) {
	rf, err := runfiles.New()
	if err != nil {
		return "", err
	}
	// //payloads/squatter/windows/src:squatter_all produces
	// squatter_all-x86_64.exe (a PE32+).
	return rf.Rlocation("_main/payloads/squatter/windows/src/squatter_all-x86_64.exe")
}

func wineEnv() []string {
	prefix := filepath.Join(os.TempDir(), "sq-functest-wine")
	xdg := filepath.Join(os.TempDir(), "sq-functest-xdg")
	_ = os.MkdirAll(prefix, 0o755)
	_ = os.MkdirAll(xdg, 0o700)
	// Force a UTF-8 unix locale: wine derives its unix filesystem codepage from
	// the locale, and the test sandbox scrubs LANG. Without this, wine maps
	// wide (UTF-16) filenames through an ASCII/POSIX codepage and CreateFileW on
	// a non-ASCII name fails (ERROR_FILE_NOT_FOUND). The in-memory UTF-16<->UTF-8
	// path (argv, payloads) is unaffected by the locale.
	return append(os.Environ(),
		"WINEPREFIX="+prefix,
		"WINEDEBUG=-all",
		"XDG_RUNTIME_DIR="+xdg,
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
	)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitListen(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func findWine() (string, error) {
	if override := os.Getenv("HOVEL_SQUATTER_WINE"); override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", err
		}
		return override, nil
	}
	return exec.LookPath("wine")
}

func TestMain(m *testing.M) {
	exe, err := findSquatter()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot find squatter.exe:", err)
		os.Exit(2)
	}
	wine, err := findWine()
	if err != nil {
		if os.Getenv("HOVEL_SQUATTER_REQUIRE_WINE") != "" {
			fmt.Fprintln(os.Stderr, "wine is required for squatter functest:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "skipping squatter functest: wine not found")
		os.Exit(0)
	}

	serverDir, err = os.MkdirTemp("", "sq-functest-srv")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	serverPort, err = freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	cmd := exec.Command(wine, exe, strconv.Itoa(serverPort))
	cmd.Dir = serverDir // the server's cwd: putfile/getfile resolve relative to here
	cmd.Env = wineEnv()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start wine:", err)
		os.Exit(2)
	}
	// First wine boot can be slow; give it room.
	if !waitListen(serverPort, 60*time.Second) {
		_ = cmd.Process.Kill()
		fmt.Fprintln(os.Stderr, "squatter did not start listening")
		os.Exit(2)
	}

	code := m.Run()

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	os.RemoveAll(serverDir)
	os.Exit(code)
}

func dial(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, bufio.NewReader(conn)
}

func readSkippingControl(t *testing.T, r *bufio.Reader) (uint16, uint64, []byte) {
	t.Helper()
	for {
		kind, sid, payload, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		if kind != wire.KindControl {
			return kind, sid, payload
		}
	}
}

func readData(t *testing.T, r *bufio.Reader) (uint64, []byte) {
	t.Helper()
	kind, sid, payload := readSkippingControl(t, r)
	if kind != wire.KindData {
		t.Fatalf("frame kind = %d, want DATA", kind)
	}
	return sid, payload
}

func TestEcho(t *testing.T) {
	conn, r := dial(t)
	if err := wire.WriteFrame(conn, wire.KindOpen, 1, wire.EncodeOpen("echo", []string{"a", "b"})); err != nil {
		t.Fatal(err)
	}
	_, p := readData(t, r)
	if got := string(p); got != "argc=3 echo a b" {
		t.Fatalf("argv echo = %q", got)
	}

	_ = wire.WriteFrame(conn, wire.KindData, 1, []byte("hello world"))
	_, p = readData(t, r)
	if got := string(p); got != "hello world" {
		t.Fatalf("echo = %q", got)
	}

	_ = wire.WriteFrame(conn, wire.KindData, 1, []byte("END"))
	k, _, _ := readSkippingControl(t, r)
	if k != wire.KindClose {
		t.Fatalf("expected CLOSE, got kind %d", k)
	}
}

// TestEchoUnicode proves the wide (UTF-16) pipeline end to end: non-ASCII argv
// and payload bytes survive UTF-8 wire -> MultiByteToWideChar -> wide module ->
// WideCharToMultiByte round-trips byte-for-byte. The emoji is a supplementary-
// plane code point (a UTF-16 surrogate pair), so it also exercises surrogates.
func TestEchoUnicode(t *testing.T) {
	conn, r := dial(t)

	args := []string{"café", "日本語", "🚀"}
	if err := wire.WriteFrame(conn, wire.KindOpen, 1, wire.EncodeOpen("echo", args)); err != nil {
		t.Fatal(err)
	}
	_, p := readData(t, r)
	if got, want := string(p), "argc=4 echo café 日本語 🚀"; got != want {
		t.Fatalf("unicode argv echo = %q, want %q", got, want)
	}

	// Raw DATA is a byte passthrough; arbitrary UTF-8 must return unchanged.
	payload := []byte("Ünïcödé ☃ \U0001F4E6")
	_ = wire.WriteFrame(conn, wire.KindData, 1, payload)
	_, p = readData(t, r)
	if !bytes.Equal(p, payload) {
		t.Fatalf("unicode data echo = %q, want %q", p, payload)
	}

	_ = wire.WriteFrame(conn, wire.KindData, 1, []byte("END"))
	if k, _, _ := readSkippingControl(t, r); k != wire.KindClose {
		t.Fatalf("expected CLOSE, got kind %d", k)
	}
}

func TestCmdInteractiveEcho(t *testing.T) {
	conn, r := dial(t)
	if tcp, ok := conn.(*net.TCPConn); ok {
		t.Cleanup(func() { _ = tcp.SetDeadline(time.Time{}) })
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := wire.WriteFrame(conn, wire.KindOpen, 1, wire.EncodeOpen("cmd", nil)); err != nil {
		t.Fatal(err)
	}

	sawInteractive := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		kind, _, p, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("read cmd startup: %v", err)
		}
		if kind == wire.KindControl {
			event, err := wire.DecodeStreamEvent(p)
			if err != nil {
				t.Fatalf("decode startup control: %v", err)
			}
			if event.Kind == wire.EventInteractive {
				sawInteractive = true
				break
			}
			continue
		}
		if kind != wire.KindData {
			t.Fatalf("startup frame kind = %d, want DATA or CONTROL", kind)
		}
	}
	if !sawInteractive {
		t.Fatal("cmd did not report interactive state")
	}

	if err := wire.WriteFrame(conn, wire.KindData, 1, []byte("echo squatter-interactive-wine-ok\r\n")); err != nil {
		t.Fatal(err)
	}
	sawEcho := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		kind, _, p, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("read cmd echo: %v", err)
		}
		if kind == wire.KindClose {
			break
		}
		if kind != wire.KindData {
			t.Fatalf("echo frame kind = %d, want DATA", kind)
		}
		if bytes.Contains(p, []byte("squatter-interactive-wine-ok")) {
			sawEcho = true
			break
		}
	}
	if !sawEcho {
		t.Fatal("cmd did not return interactive echo output")
	}

	_ = wire.WriteFrame(conn, wire.KindData, 1, []byte("exit\r\n"))
}

func TestCmdInteractiveDebug(t *testing.T) {
	conn, r := dial(t)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := wire.WriteFrame(conn, wire.KindOpen, 1, wire.EncodeOpen("cmd", []string{"--debug"})); err != nil {
		t.Fatal(err)
	}

	sawDebug := false
	sawInteractive := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && (!sawDebug || !sawInteractive); {
		kind, _, p, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("read debug startup: %v", err)
		}
		if kind != wire.KindControl {
			continue
		}
		event, err := wire.DecodeStreamEvent(p)
		if err != nil {
			t.Fatalf("decode debug startup: %v", err)
		}
		sawDebug = sawDebug || event.Kind == wire.EventDebug
		sawInteractive = sawInteractive || event.Kind == wire.EventInteractive
	}
	if !sawDebug {
		t.Fatal("cmd --debug did not emit diagnostic control frames")
	}
	if !sawInteractive {
		t.Fatal("cmd --debug did not report interactive state")
	}

	if err := wire.WriteFrame(conn, wire.KindData, 1, []byte("echo squatter-debug-ok\r\n")); err != nil {
		t.Fatal(err)
	}
	sawEcho := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		kind, _, p, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("read debug echo: %v", err)
		}
		if kind == wire.KindClose {
			break
		}
		if bytes.Contains(p, []byte("squatter-debug-ok")) {
			sawEcho = true
			break
		}
	}
	if !sawEcho {
		t.Fatal("cmd --debug did not return echo output")
	}

	_ = wire.WriteFrame(conn, wire.KindData, 1, []byte("exit\r\n"))
}

// TestFileTransferUnicodeName proves CreateFileW path handling: a file named
// with non-ASCII code points round-trips through put/get and lands on disk under
// that exact name.
func TestFileTransferUnicodeName(t *testing.T) {
	conn, r := dial(t)

	name := "café-日本-🚀.bin"
	data := []byte("unicode filename payload \U0001F680")

	sent, ack, err := xfer.PutFile(conn, r, 1, bytes.NewReader(data), name)
	if err != nil {
		t.Fatalf("putfile: %v", err)
	}
	if sent != int64(len(data)) {
		t.Fatalf("putfile sent %d, want %d", sent, len(data))
	}
	if want := fmt.Sprintf("OK %d", len(data)); ack != want {
		t.Fatalf("putfile ack = %q, want %q", ack, want)
	}

	onServer, err := os.ReadFile(filepath.Join(serverDir, name))
	if err != nil {
		t.Fatalf("read server file by unicode name: %v", err)
	}
	if !bytes.Equal(onServer, data) {
		t.Fatalf("server-side file differs (got %d bytes)", len(onServer))
	}

	var buf bytes.Buffer
	recv, err := xfer.GetFile(conn, r, 2, name, &buf)
	if err != nil {
		t.Fatalf("getfile: %v", err)
	}
	if recv != int64(len(data)) || !bytes.Equal(buf.Bytes(), data) {
		t.Fatalf("downloaded %d bytes, mismatch", recv)
	}
}

func TestManyStreams(t *testing.T) {
	conn, r := dial(t)
	const n = 5
	for s := 0; s < n; s++ {
		_ = wire.WriteFrame(conn, wire.KindOpen, uint64(10+s), wire.EncodeOpen("echo", []string{fmt.Sprintf("s%d", s)}))
	}
	// argv echoes, bucketed by stream id (they may interleave)
	argv := map[uint64]string{}
	for i := 0; i < n; i++ {
		sid, p := readData(t, r)
		argv[sid] = string(p)
	}
	for s := 0; s < n; s++ {
		want := fmt.Sprintf("argc=2 echo s%d", s)
		if got := argv[uint64(10+s)]; got != want {
			t.Fatalf("stream %d argv = %q, want %q", 10+s, got, want)
		}
	}
	// interleaved data, each must come back on its own stream
	for s := 0; s < n; s++ {
		_ = wire.WriteFrame(conn, wire.KindData, uint64(10+s), []byte(fmt.Sprintf("p%d", s)))
	}
	echoed := map[uint64]string{}
	for i := 0; i < n; i++ {
		sid, p := readData(t, r)
		echoed[sid] = string(p)
	}
	for s := 0; s < n; s++ {
		if got := echoed[uint64(10+s)]; got != fmt.Sprintf("p%d", s) {
			t.Fatalf("stream %d echoed %q", 10+s, got)
		}
	}
}

func TestFileTransferRoundTrip(t *testing.T) {
	conn, r := dial(t)

	// A few MB of deterministic data.
	data := make([]byte, 4*1024*1024)
	for i := range data {
		data[i] = byte(i*131 + 7)
	}

	sent, ack, err := xfer.PutFile(conn, r, 1, bytes.NewReader(data), "uploaded.bin")
	if err != nil {
		t.Fatalf("putfile: %v", err)
	}
	if sent != int64(len(data)) {
		t.Fatalf("putfile sent %d, want %d", sent, len(data))
	}
	if want := fmt.Sprintf("OK %d", len(data)); ack != want {
		t.Fatalf("putfile ack = %q, want %q", ack, want)
	}

	// The server wrote it into its cwd; verify on disk.
	onServer, err := os.ReadFile(filepath.Join(serverDir, "uploaded.bin"))
	if err != nil {
		t.Fatalf("read server file: %v", err)
	}
	if !bytes.Equal(onServer, data) {
		t.Fatalf("server-side file differs (got %d bytes)", len(onServer))
	}

	// Download it back and compare.
	var buf bytes.Buffer
	recv, err := xfer.GetFile(conn, r, 2, "uploaded.bin", &buf)
	if err != nil {
		t.Fatalf("getfile: %v", err)
	}
	if recv != int64(len(data)) || !bytes.Equal(buf.Bytes(), data) {
		t.Fatalf("downloaded %d bytes, mismatch", recv)
	}
}

func TestGetfileMissingErrors(t *testing.T) {
	conn, r := dial(t)
	var buf bytes.Buffer
	_, err := xfer.GetFile(conn, r, 1, "does_not_exist_99.bin", &buf)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
