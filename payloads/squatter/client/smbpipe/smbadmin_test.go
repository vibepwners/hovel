package smbpipe

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestAdminSharePathMapsWindowsPaths(t *testing.T) {
	tests := []struct {
		path      string
		wantShare string
		wantPath  string
	}{
		{path: `C:\Windows\Temp\a.exe`, wantShare: "ADMIN$", wantPath: `Temp\a.exe`},
		{path: `C:\WINNT\Temp\a.exe`, wantShare: "ADMIN$", wantPath: `Temp\a.exe`},
		{path: `C:\Tools\a.exe`, wantShare: "C$", wantPath: `Tools\a.exe`},
		{path: `\Windows\Temp\a.exe`, wantShare: "ADMIN$", wantPath: `Windows\Temp\a.exe`},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			share, path := adminSharePath(tt.path)
			if share != tt.wantShare || path != tt.wantPath {
				t.Fatalf("adminSharePath(%q) = %q, %q; want %q, %q", tt.path, share, path, tt.wantShare, tt.wantPath)
			}
		})
	}
}

func TestServiceBinaryPathQuotesRemotePathAndAppendsArgs(t *testing.T) {
	got := serviceBinaryPath(`C:\Windows\Temp\a.exe`, "svc123", `--flag value`)
	want := `"C:\Windows\Temp\a.exe" --service svc123 --flag value`
	if got != want {
		t.Fatalf("binary path = %q, want %q", got, want)
	}
}

func TestScheduledBinaryPathDoesNotAddServiceArg(t *testing.T) {
	got := scheduledBinaryPath(`C:\Windows\Temp\a.exe`, `--flag value`)
	want := `"C:\Windows\Temp\a.exe" --flag value`
	if got != want {
		t.Fatalf("scheduled binary path = %q, want %q", got, want)
	}
}

func TestNDRWideStringIncludesNullTerminatorAndAlignment(t *testing.T) {
	got := ndrWString("svc")
	if len(got)%4 != 0 {
		t.Fatalf("NDR string length = %d, want 4-byte aligned", len(got))
	}
	if got[0] != 4 || got[8] != 4 {
		t.Fatalf("NDR conformant counts = % x", got[:12])
	}
}

func TestCreateServiceHandleFromReplyUsesLeadingContextHandle(t *testing.T) {
	reply := make([]byte, serviceHandleLen+8)
	for i := 0; i < serviceHandleLen; i++ {
		reply[4+i] = byte(i + 1)
	}
	binary.LittleEndian.PutUint32(reply[serviceHandleLen+4:], 0)

	handle, status, err := createServiceHandleFromReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		t.Fatalf("status = 0x%x, want success", status)
	}
	for i, b := range handle {
		if b != byte(i+1) {
			t.Fatalf("handle[%d] = 0x%x, want 0x%x", i, b, byte(i+1))
		}
	}
}

func TestServiceStatusFromXPStyleReply(t *testing.T) {
	reply := make([]byte, 28)
	binary.LittleEndian.PutUint32(reply[0:], serviceInteractive)
	binary.LittleEndian.PutUint32(reply[4:], 4)
	binary.LittleEndian.PutUint32(reply[12:], 0)

	status, err := serviceStatusFromReply(reply)
	if err != nil {
		t.Fatal(err)
	}
	if status.CurrentState != 4 || status.Win32ExitCode != 0 {
		t.Fatalf("status = state 0x%x exit 0x%x", status.CurrentState, status.Win32ExitCode)
	}
}

func TestATInfoEncodesCurrentDateNonInteractiveCommand(t *testing.T) {
	when := time.Date(2026, 6, 14, 1, 2, 3, 0, time.UTC)
	got := atInfo(`C:\Windows\System32\a.exe`, when)
	if jobTime := binary.LittleEndian.Uint32(got[0:4]); jobTime != 3780000 {
		t.Fatalf("job time = %d", jobTime)
	}
	if got[9] != jobAddCurrentDate|jobNonInteractive {
		t.Fatalf("flags = 0x%x", got[9])
	}
	if !containsBytes(got, utf16le(`C:\Windows\System32\a.exe`)) {
		t.Fatalf("encoded command missing from AT_INFO")
	}
}

func TestFiletimeToTime(t *testing.T) {
	got := filetimeToTime(116444736000000000)
	if !got.IsZero() {
		t.Fatalf("epoch boundary = %s, want zero guard", got)
	}
	got = filetimeToTime(116444736010000000)
	want := time.Unix(1, 0)
	if !got.Equal(want) {
		t.Fatalf("filetime = %s, want %s", got, want)
	}
}

func TestCurrentServerTimeAppliesSMBTimezone(t *testing.T) {
	c := &pipeConn{
		serverTime:      time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC),
		serverTimeSeen:  time.Now(),
		serverTZMinutes: 240,
	}
	got := c.currentServerTime()
	if got.Hour() != 12 {
		t.Fatalf("server local hour = %d, want 12", got.Hour())
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		matches := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}
