// Package functest is a black-box functional harness: it launches the actual
// squatter.exe under wine and drives it over TCP with the real wire protocol.
//
// One server is started for the whole package (TestMain) in a fresh working
// directory, so the file-transfer test can inspect what the server wrote.
package functest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/bazelbuild/rules_go/go/runfiles"

	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
	"github.com/vibepwners/hovel/payloads/squatter/client/xfer"
)

var (
	serverPort  int
	serverDir   string
	squatterExe string
	wineCommand string
)

var featureModules = []string{
	"acl.stat",
	"cmd",
	"drive.list",
	"echo",
	"eventlog.query",
	"file.stat",
	"getfile",
	"payload.cleanup",
	"payload.status",
	"process.kill",
	"process.list",
	"process.run",
	"process.run_as_user",
	"putfile",
	"registry.query",
	"share.list",
	"wininfo",
}

func findSquatter() (string, error) {
	if override := os.Getenv("HOVEL_SQUATTER_EXE"); override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", err
		}
		return override, nil
	}
	rf, err := runfiles.New()
	if err != nil {
		return "", err
	}
	// //modules/squatter/windows/src:squatter_all produces
	// squatter_all-x86_64.exe (a PE32+).
	return rf.Rlocation("_main/modules/squatter/windows/src/squatter_all-x86_64.exe")
}

func findPipeProbe() (string, error) {
	if override := os.Getenv("HOVEL_SQUATTER_PIPE_PROBE"); override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", err
		}
		return override, nil
	}
	rf, err := runfiles.New()
	if err != nil {
		return "", err
	}
	return rf.Rlocation("_main/modules/squatter/client/pipeprobe/pipeprobe_all-x86_64.exe")
}

func findModuleSurface() (string, error) {
	if override := os.Getenv("HOVEL_SQUATTER_MODULE_SURFACE"); override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", err
		}
		return override, nil
	}
	rf, err := runfiles.New()
	if err != nil {
		return "", err
	}
	return rf.Rlocation("_main/modules/squatter/windows/module_surface.json")
}

func wineEnv() []string {
	prefix := filepath.Join(os.TempDir(), "sq-functest-wine")
	xdg := filepath.Join(os.TempDir(), "sq-functest-xdg")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "create wine prefix:", err)
	}
	if err := os.MkdirAll(xdg, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "create wine runtime dir:", err)
	}
	// Force a UTF-8 unix locale: wine derives its unix filesystem codepage from
	// the locale, and the test sandbox scrubs LANG. Without this, wine maps
	// wide (UTF-16) filenames through an ASCII/POSIX codepage and CreateFileW on
	// a non-ASCII name fails (ERROR_FILE_NOT_FOUND). The in-memory UTF-16<->UTF-8
	// path (argv, payloads) is unaffected by the locale.
	return append(os.Environ(),
		"WINEPREFIX="+prefix,
		"WINEDEBUG=-all",
		"XDG_RUNTIME_DIR="+xdg,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := l.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close free-port listener:", err)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitListen(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			if err := c.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "close wait-listen probe:", err)
			}
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
	squatterExe = exe
	wineCommand = wine

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
		if err := cmd.Process.Kill(); err != nil {
			fmt.Fprintln(os.Stderr, "kill wine:", err)
		}
		fmt.Fprintln(os.Stderr, "squatter did not start listening")
		os.Exit(2)
	}

	code := m.Run()

	if err := cmd.Process.Kill(); err != nil {
		fmt.Fprintln(os.Stderr, "kill wine:", err)
	}
	if _, err := cmd.Process.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "wait wine:", err)
	}
	if err := os.RemoveAll(serverDir); err != nil {
		fmt.Fprintln(os.Stderr, "remove squatter functest server dir:", err)
	}
	os.Exit(code)
}

func dial(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("close squatter functest connection: %v", err)
		}
	})
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

func writeTestFrame(t *testing.T, w io.Writer, kind uint16, sid uint64, payload []byte) {
	t.Helper()
	if err := wire.WriteFrame(w, kind, sid, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

const (
	transportReverseTCP = 1
	transportSMBPipe    = 2
	transportTCPBind    = 3
)

func patchedPayload(t *testing.T, name string, kind uint32, port int, pipeName string) string {
	t.Helper()
	body, err := os.ReadFile(squatterExe)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("SQCFG001")
	offset := bytes.Index(body, marker)
	if offset < 0 || bytes.Index(body[offset+len(marker):], marker) >= 0 {
		t.Fatalf("payload has an invalid embedded transport marker count")
	}
	if offset+18+(128*2) > len(body) {
		t.Fatal("payload embedded transport configuration is truncated")
	}
	binary.LittleEndian.PutUint32(body[offset+8:], kind)
	copy(body[offset+12:offset+16], []byte{127, 0, 0, 1})
	binary.LittleEndian.PutUint16(body[offset+16:], uint16(port))
	if pipeName != "" {
		field := body[offset+18 : offset+18+(128*2)]
		clear(field)
		encoded := utf16.Encode([]rune(pipeName))
		if len(encoded) >= 128 {
			t.Fatalf("named pipe is too long: %q", pipeName)
		}
		for i, value := range encoded {
			binary.LittleEndian.PutUint16(field[i*2:], value)
		}
	}
	path := filepath.Join(serverDir, name)
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func startWinePayload(t *testing.T, exe string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(wineCommand, append([]string{exe}, args...)...)
	cmd.Dir = serverDir
	cmd.Env = wineEnv()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Wine payload: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	return cmd
}

func wineWindowsPath(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return `Z:` + strings.ReplaceAll(absolute, `/`, `\`)
}

func runWineUtility(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(wineCommand, args...)
	cmd.Dir = serverDir
	cmd.Env = wineEnv()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wine %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func exerciseEchoConnection(t *testing.T, conn net.Conn, label string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	writeTestFrame(t, conn, wire.KindOpen, 41, wire.EncodeOpen("echo", []string{label}))
	kind, sid, payload := readSkippingControl(t, r)
	if kind != wire.KindData || sid != 41 || string(payload) != "argc=2 echo "+label {
		t.Fatalf("%s echo startup: kind=%d sid=%d payload=%q", label, kind, sid, payload)
	}
	writeTestFrame(t, conn, wire.KindData, 41, []byte(label+"-payload"))
	sid, payload = readData(t, r)
	if sid != 41 || string(payload) != label+"-payload" {
		t.Fatalf("%s echo data: sid=%d payload=%q", label, sid, payload)
	}
	writeTestFrame(t, conn, wire.KindData, 41, []byte("END"))
	for {
		kind, sid, _, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("%s echo close: %v", label, err)
		}
		if kind == wire.KindClose && sid == 41 {
			break
		}
	}
	t.Logf("E2E transport=%s real PE echo session passed", label)
}

type moduleResult struct {
	Data      []byte
	Events    []wire.StreamEvent
	CloseCode uint32
}

func runModule(t *testing.T, module string, args ...string) moduleResult {
	t.Helper()
	conn, r := dial(t)
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeTestFrame(t, conn, wire.KindOpen, 1, wire.EncodeOpen(module, args))

	var result moduleResult
	for {
		kind, sid, payload, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("%s read: %v", module, err)
		}
		if sid != 1 {
			t.Fatalf("%s response stream = %d, want 1", module, sid)
		}
		switch kind {
		case wire.KindData:
			result.Data = append(result.Data, payload...)
		case wire.KindControl:
			event, err := wire.DecodeStreamEvent(payload)
			if err != nil {
				t.Fatalf("%s decode control: %v", module, err)
			}
			result.Events = append(result.Events, event)
		case wire.KindClose:
			result.CloseCode, err = wire.DecodeClose(payload)
			if err != nil {
				t.Fatalf("%s decode close: %v", module, err)
			}
			t.Logf("E2E module=%s args=%q close=%d events=%+v data=%s", module, args, result.CloseCode, result.Events, strings.TrimSpace(string(result.Data)))
			return result
		default:
			t.Fatalf("%s response kind = %d", module, kind)
		}
	}
}

func requireModuleSuccess(t *testing.T, module string, result moduleResult) {
	t.Helper()
	for _, event := range result.Events {
		if event.Kind == wire.EventError {
			t.Fatalf("%s error event: code=%d message=%q", module, event.Code, event.Message)
		}
	}
	if result.CloseCode != 0 {
		t.Fatalf("%s close code = %d, want 0", module, result.CloseCode)
	}
}

func runJSONModule(t *testing.T, module string, args ...string) map[string]any {
	t.Helper()
	result := runModule(t, module, args...)
	requireModuleSuccess(t, module, result)
	var value map[string]any
	if err := json.Unmarshal(result.Data, &value); err != nil {
		t.Fatalf("%s JSON: %v; data=%q", module, err, result.Data)
	}
	return value
}

func runJSONArrayModule(t *testing.T, module string, args ...string) []map[string]any {
	t.Helper()
	result := runModule(t, module, args...)
	requireModuleSuccess(t, module, result)
	var value []map[string]any
	if err := json.Unmarshal(result.Data, &value); err != nil {
		t.Fatalf("%s JSON: %v; data=%q", module, err, result.Data)
	}
	return value
}

func TestFeatureSurfaceManifest(t *testing.T) {
	manifest, err := findModuleSurface()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	if err := json.Unmarshal(body, &declared); err != nil {
		t.Fatal(err)
	}
	got := append([]string(nil), featureModules...)
	want := append([]string(nil), declared...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("functional module surface changed:\n got %q\nwant %q", got, want)
	}
	t.Logf("E2E feature manifest covers all %d Squatter runtime modules: %s", len(got), strings.Join(got, ", "))
}

func TestConfiguredTCPBindTransport(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	exe := patchedPayload(t, "squatter-configured-bind.exe", transportTCPBind, port, "")
	startWinePayload(t, exe)
	if !waitListen(port, 30*time.Second) {
		t.Fatalf("configured TCP bind transport did not listen on %d", port)
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	exerciseEchoConnection(t, conn, "tcp-bind-config")
}

func TestConfiguredReverseTCPTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if tcp, ok := listener.(*net.TCPListener); ok {
		if err := tcp.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	port := listener.Addr().(*net.TCPAddr).Port
	exe := patchedPayload(t, "squatter-configured-callback.exe", transportReverseTCP, port, "")
	startWinePayload(t, exe)
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept reverse TCP callback: %v", err)
	}
	defer func() { _ = conn.Close() }()
	exerciseEchoConnection(t, conn, "tcp-callback-config")
}

func TestConfiguredNamedPipeTransport(t *testing.T) {
	probe, err := findPipeProbe()
	if err != nil {
		t.Fatalf("find named-pipe probe: %v", err)
	}
	pipeName := fmt.Sprintf(`\\.\pipe\hovel-squatter-e2e-%d`, serverPort)
	exe := patchedPayload(t, "squatter-configured-pipe.exe", transportSMBPipe, 0, pipeName)
	startWinePayload(t, exe)
	cmd := exec.Command(wineCommand, probe, pipeName)
	cmd.Dir = serverDir
	cmd.Env = wineEnv()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("named-pipe probe: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("real Win32 pipe echo session passed")) {
		t.Fatalf("named-pipe probe did not report evidence: %s", output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func TestServiceInvocationFallsBackToConfiguredServer(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	startWinePayload(t, squatterExe, "--service", "HovelSquatterE2E", strconv.Itoa(port))
	if !waitListen(port, 30*time.Second) {
		t.Fatalf("service invocation fallback did not listen on %d", port)
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	exerciseEchoConnection(t, conn, "service-invocation")
	t.Log("E2E lifecycle=service-console-fallback dispatcher-error-to-configured-server passed")
}

func TestServiceControlManagerLifecycle(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	serviceName := fmt.Sprintf("HovelSquatterE2E%d", port)
	imagePath := fmt.Sprintf(`"%s" --service %s %d`, wineWindowsPath(t, squatterExe), serviceName, port)
	runWineUtility(t, "sc.exe", "create", serviceName, "binPath=", imagePath, "start=", "demand")
	t.Cleanup(func() {
		cmd := exec.Command(wineCommand, "sc.exe", "stop", serviceName)
		cmd.Dir = serverDir
		cmd.Env = wineEnv()
		_ = cmd.Run()
		cmd = exec.Command(wineCommand, "sc.exe", "delete", serviceName)
		cmd.Dir = serverDir
		cmd.Env = wineEnv()
		_ = cmd.Run()
	})
	runWineUtility(t, "sc.exe", "start", serviceName)
	if !waitListen(port, 30*time.Second) {
		t.Fatalf("SCM-started service did not listen on %d", port)
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	exerciseEchoConnection(t, conn, "service-scm")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	runWineUtility(t, "sc.exe", "stop", serviceName)
	t.Log("E2E lifecycle=service-scm start/control-stop real PE passed")
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

	writeTestFrame(t, conn, wire.KindData, 1, []byte("hello world"))
	_, p = readData(t, r)
	if got := string(p); got != "hello world" {
		t.Fatalf("echo = %q", got)
	}

	writeTestFrame(t, conn, wire.KindData, 1, []byte("END"))
	k, _, _ := readSkippingControl(t, r)
	if k != wire.KindClose {
		t.Fatalf("expected CLOSE, got kind %d", k)
	}
	t.Log("E2E module=echo interactive argv/data/close passed")
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
	writeTestFrame(t, conn, wire.KindData, 1, payload)
	_, p = readData(t, r)
	if !bytes.Equal(p, payload) {
		t.Fatalf("unicode data echo = %q, want %q", p, payload)
	}

	writeTestFrame(t, conn, wire.KindData, 1, []byte("END"))
	if k, _, _ := readSkippingControl(t, r); k != wire.KindClose {
		t.Fatalf("expected CLOSE, got kind %d", k)
	}
}

func TestCmdInteractiveEcho(t *testing.T) {
	conn, r := dial(t)
	if tcp, ok := conn.(*net.TCPConn); ok {
		t.Cleanup(func() {
			if err := tcp.SetDeadline(time.Time{}); err != nil {
				t.Logf("clear TCP deadline: %v", err)
			}
		})
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

	writeTestFrame(t, conn, wire.KindData, 1, []byte("exit\r\n"))
	for {
		kind, _, _, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("wait for cmd close: %v", err)
		}
		if kind == wire.KindClose {
			break
		}
	}
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

	writeTestFrame(t, conn, wire.KindData, 1, []byte("exit\r\n"))
	for {
		kind, _, _, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("wait for debug cmd close: %v", err)
		}
		if kind == wire.KindClose {
			break
		}
	}
}

func TestCmdOneShot(t *testing.T) {
	result := runModule(t, "cmd", "echo", "squatter-one-shot-ok")
	requireModuleSuccess(t, "cmd", result)
	if !bytes.Contains(result.Data, []byte("squatter-one-shot-ok")) {
		t.Fatalf("cmd output = %q", result.Data)
	}
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
		writeTestFrame(t, conn, wire.KindOpen, uint64(10+s), wire.EncodeOpen("echo", []string{fmt.Sprintf("s%d", s)}))
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
		writeTestFrame(t, conn, wire.KindData, uint64(10+s), []byte(fmt.Sprintf("p%d", s)))
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
	for s := 0; s < n; s++ {
		writeTestFrame(t, conn, wire.KindData, uint64(10+s), []byte("END"))
	}
	closed := make(map[uint64]bool, n)
	for len(closed) < n {
		kind, sid, _, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatalf("read multiplexed close: %v", err)
		}
		if kind == wire.KindClose {
			closed[sid] = true
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
	t.Logf("E2E module=putfile bytes=%d ack=%q passed", sent, ack)
	t.Logf("E2E module=getfile bytes=%d round-trip passed", recv)
}

func TestGetfileMissingErrors(t *testing.T) {
	conn, r := dial(t)
	var buf bytes.Buffer
	_, err := xfer.GetFile(conn, r, 1, "does_not_exist_99.bin", &buf)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestEvidenceFileStat(t *testing.T) {
	const name = "evidence-café-日本.bin"
	data := []byte("squatter file.stat Wine evidence\n")
	if err := os.WriteFile(filepath.Join(serverDir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	value := runJSONModule(t, "file.stat", name)
	if got := int(value["size"].(float64)); got != len(data) {
		t.Fatalf("file.stat size = %d, want %d", got, len(data))
	}
	wantHash := sha256.Sum256(data)
	if got := value["sha256"]; got != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("file.stat sha256 = %v", got)
	}
}

func TestEvidenceACLStat(t *testing.T) {
	const name = "acl-evidence.txt"
	if err := os.WriteFile(filepath.Join(serverDir, name), []byte("acl"), 0o600); err != nil {
		t.Fatal(err)
	}
	value := runJSONModule(t, "acl.stat", name)
	if value["path"] != name || strings.TrimSpace(fmt.Sprint(value["sddl"])) == "" {
		t.Fatalf("acl.stat result = %#v", value)
	}
}

func TestEvidenceDriveList(t *testing.T) {
	drives := runJSONArrayModule(t, "drive.list")
	if len(drives) == 0 {
		t.Fatal("drive.list returned no drives")
	}
	foundC := false
	for _, drive := range drives {
		foundC = foundC || strings.EqualFold(fmt.Sprint(drive["path"]), `C:\`)
	}
	if !foundC {
		t.Fatalf("drive.list did not include C: %#v", drives)
	}
}

func TestEvidenceRegistryQuery(t *testing.T) {
	const key = `Software\HovelSquatterE2E`
	const valueName = "UnicodeValue"
	const valueData = "café-日本-🚀"
	setup := runModule(t, "process.run", `reg.exe add HKCU\`+key+` /v `+valueName+` /t REG_SZ /d "`+valueData+`" /f`)
	requireModuleSuccess(t, "process.run", setup)
	value := runJSONModule(t, "registry.query", "HKCU", key, valueName)
	if value["data"] != valueData {
		t.Fatalf("registry.query data = %v, want %q", value["data"], valueData)
	}
}

func TestEvidenceEventLogQuery(t *testing.T) {
	events := runJSONArrayModule(t, "eventlog.query", "Application", "5")
	if len(events) > 5 {
		t.Fatalf("eventlog.query returned %d records, limit 5", len(events))
	}
}

func TestEvidenceShareList(t *testing.T) {
	shares := runJSONArrayModule(t, "share.list")
	for _, share := range shares {
		if strings.TrimSpace(fmt.Sprint(share["name"])) == "" {
			t.Fatalf("share.list returned nameless share: %#v", share)
		}
	}
}

func TestProcessList(t *testing.T) {
	processes := runJSONArrayModule(t, "process.list")
	found := false
	for _, process := range processes {
		found = found || strings.Contains(strings.ToLower(fmt.Sprint(process["imageName"])), "squatter")
	}
	if !found {
		t.Fatalf("process.list did not include squatter.exe: %#v", processes)
	}
}

func TestProcessRun(t *testing.T) {
	value := runJSONModule(t, "process.run", `cmd.exe /c "echo squatter-stdout-ok&echo squatter-stderr-ok 1>&2&exit /b 7"`)
	if value["exitCode"] != float64(7) || value["timedOut"] != false {
		t.Fatalf("process.run result = %#v", value)
	}
	if !strings.Contains(fmt.Sprint(value["stdout"]), "squatter-stdout-ok") ||
		!strings.Contains(fmt.Sprint(value["stderr"]), "squatter-stderr-ok") {
		t.Fatalf("process.run capture = %#v", value)
	}
}

func TestProcessRunAsUser(t *testing.T) {
	status := runJSONModule(t, "payload.status")
	payloadPID := strconv.FormatUint(uint64(status["pid"].(float64)), 10)
	value := runJSONModule(t, "process.run_as_user", `cmd.exe /c exit 0`, "", payloadPID)
	if value["sourcePid"] != status["pid"] || value["command"] != `cmd.exe /c exit 0` {
		t.Fatalf("process.run_as_user result = %#v", value)
	}
}

func TestProcessKill(t *testing.T) {
	before := processIDs(t)
	fixture := exec.Command(wineCommand, "cmd.exe", "/c", "ping.exe", "127.0.0.1", "-n", "10")
	fixture.Env = wineEnv()
	fixture.Stdout = io.Discard
	fixture.Stderr = io.Discard
	if err := fixture.Start(); err != nil {
		t.Fatalf("start process.kill fixture: %v", err)
	}
	t.Cleanup(func() {
		if fixture.Process != nil {
			_ = fixture.Process.Kill()
			_, _ = fixture.Process.Wait()
		}
	})

	var victim uint64
	deadline := time.Now().Add(10 * time.Second)
	for victim == 0 && time.Now().Before(deadline) {
		for pid, image := range processIDs(t) {
			_, existed := before[pid]
			if !existed && strings.EqualFold(image, "PING.EXE") {
				victim = pid
				break
			}
		}
		if victim == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if victim == 0 {
		t.Fatal("process.kill fixture did not appear in process.list")
	}
	value := runJSONModule(t, "process.kill", strconv.FormatUint(victim, 10))
	if value["pid"] != float64(victim) || value["killed"] != true {
		t.Fatalf("process.kill result = %#v", value)
	}
}

func processIDs(t *testing.T) map[uint64]string {
	t.Helper()
	result := make(map[uint64]string)
	for _, process := range runJSONArrayModule(t, "process.list") {
		pid, ok := process["pid"].(float64)
		if ok {
			result[uint64(pid)] = fmt.Sprint(process["imageName"])
		}
	}
	return result
}

func TestPayloadStatus(t *testing.T) {
	value := runJSONModule(t, "payload.status")
	if value["pid"].(float64) <= 0 || !strings.Contains(strings.ToLower(fmt.Sprint(value["imagePath"])), "squatter") {
		t.Fatalf("payload.status result = %#v", value)
	}
}

func TestPayloadCleanupNoStop(t *testing.T) {
	value := runJSONModule(t, "payload.cleanup", "--no-stop")
	if value["stopScheduled"] != false || value["deleteFileRequested"] != false {
		t.Fatalf("payload.cleanup result = %#v", value)
	}
	if !waitListen(serverPort, 3*time.Second) {
		t.Fatal("payload.cleanup --no-stop stopped the payload")
	}
}

func TestWininfo(t *testing.T) {
	value := runJSONModule(t, "wininfo")
	if strings.TrimSpace(fmt.Sprint(value["hostname"])) == "" || strings.TrimSpace(fmt.Sprint(value["arch"])) == "" {
		t.Fatalf("wininfo result = %#v", value)
	}
}

func TestUnknownModuleLifecycle(t *testing.T) {
	result := runModule(t, "not.a.real.squatter.module")
	if result.CloseCode != 0 || len(result.Events) != 1 || result.Events[0].Kind != wire.EventError ||
		!strings.Contains(result.Events[0].Message, "no such module") {
		t.Fatalf("unknown module lifecycle = %#v", result)
	}
}
