package smbpipe

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

func TestNormalizePipePathForIPCShare(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "bare", in: "alpha", want: `alpha`},
		{name: "local", in: `\\.\pipe\alpha`, want: `alpha`},
		{name: "remote", in: `\\target\pipe\alpha`, want: `alpha`},
		{name: "nested remote", in: `\\target\pipe\alpha\beta`, want: `alpha\beta`},
		{name: "slash trimmed", in: `\alpha`, want: `alpha`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizePipePath(tc.in); got != tc.want {
				t.Fatalf("NormalizePipePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOptionsDefaultSMBPortAndTimeout(t *testing.T) {
	opts := Options{Host: "target", Username: "u", Password: "p"}
	normalized := opts.normalized()

	if normalized.Port != 445 {
		t.Fatalf("port = %d, want 445", normalized.Port)
	}
	if normalized.Timeout != 10*time.Second {
		t.Fatalf("timeout = %s, want 10s", normalized.Timeout)
	}
}

func TestDialerRejectsMissingHostPipeAndUsername(t *testing.T) {
	d := Dialer{}
	for _, opts := range []Options{
		{Pipe: "pipe", Username: "u", Password: "p"},
		{Host: "target", Username: "u", Password: "p"},
		{Host: "target", Pipe: "pipe", Password: "p"},
	} {
		if _, err := d.Dial(context.Background(), opts); err == nil {
			t.Fatalf("Dial(%#v) succeeded, want validation error", opts)
		}
	}
}

func TestBuildNegotiateRequestUsesSMB1Dialect(t *testing.T) {
	c := &pipeConn{pid: 0x1111, mid: 1}
	req := buildSMB(cmdNegotiate, c, 0, nil, []byte{0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0})
	body := req[4:]

	if string(body[:4]) != "\xffSMB" {
		t.Fatalf("protocol = %q", body[:4])
	}
	if body[4] != cmdNegotiate {
		t.Fatalf("command = 0x%x, want negotiate", body[4])
	}
	if got := body[smbHeaderLen]; got != 0 {
		t.Fatalf("word count = %d, want 0", got)
	}
	if !hasDialect(body[smbHeaderLen+3:], "NT LM 0.12") {
		t.Fatalf("negotiate request missing NT LM 0.12 dialect: %x", body)
	}
}

func TestOpenPipeRequestUsesIPCNamedPipePath(t *testing.T) {
	c := &pipeConn{pid: 0x1111, mid: 1, tid: 2, uid: 3}
	name := `\pipe\` + NormalizePipePath(`\\target\pipe\squatter`)
	encoded := utf16le(name)
	params := make([]byte, 48)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[5:], uint16(len(encoded)-2))
	binary.LittleEndian.PutUint32(params[15:], pipeAccess)
	req := buildSMB(cmdNTCreateAndX, c, 24, params, encoded)
	body := req[4:]
	requestParams := body[smbHeaderLen+1 : smbHeaderLen+1+48]

	if body[4] != cmdNTCreateAndX {
		t.Fatalf("command = 0x%x, want NT_CREATE_ANDX", body[4])
	}
	if got := binary.LittleEndian.Uint16(body[24:26]); got != 2 {
		t.Fatalf("tid = %d, want 2", got)
	}
	if got := binary.LittleEndian.Uint16(body[28:30]); got != 3 {
		t.Fatalf("uid = %d, want 3", got)
	}
	if got := decodeUTF16LE(body[len(body)-len(encoded):]); got != `\pipe\squatter` {
		t.Fatalf("pipe path = %q", got)
	}
	if got := binary.LittleEndian.Uint32(requestParams[11:15]); got != 0 {
		t.Fatalf("root directory fid = 0x%x, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(requestParams[15:19]); got != pipeAccess {
		t.Fatalf("desired access = 0x%x, want 0x%x", got, pipeAccess)
	}
}

func TestLegacySessionSetupRequestDoesNotAdvertiseExtendedSecurity(t *testing.T) {
	c := &pipeConn{pid: 0x1111, mid: 1, auth: authNTLMv1}
	params := make([]byte, 26)
	params[0] = 0xff
	data := append(make([]byte, 48), utf16le("user")...)
	req := buildSMB(cmdSessionSetup, c, 13, params, data)
	body := req[4:]

	if body[4] != cmdSessionSetup {
		t.Fatalf("command = 0x%x, want session setup", body[4])
	}
	if got := binary.LittleEndian.Uint16(body[10:12]); got&flags2ExtSecurity != 0 {
		t.Fatalf("legacy flags2 includes extended security: 0x%x", got)
	}
	if got := body[smbHeaderLen]; got != 13 {
		t.Fatalf("word count = %d, want 13", got)
	}
}

func TestNTLMv1AndLMResponsesMatchKnownVector(t *testing.T) {
	challenge := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	ntResp, err := ntlmv1Response("Password", challenge)
	if err != nil {
		t.Fatalf("ntlmv1Response: %v", err)
	}
	if got := hex.EncodeToString(ntResp); got != "67c43011f30298a2ad35ece64f16331c44bdbed927841f94" {
		t.Fatalf("NTLMv1 response = %s", got)
	}

	lmResp, err := lmResponse("Password", challenge)
	if err != nil {
		t.Fatalf("lmResponse: %v", err)
	}
	if got := hex.EncodeToString(lmResp); got != "98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13" {
		t.Fatalf("LM response = %s", got)
	}
}

func hasDialect(data []byte, dialect string) bool {
	want := append([]byte{0x02}, append([]byte(dialect), 0)...)
	for i := 0; i+len(want) <= len(data); i++ {
		if string(data[i:i+len(want)]) == string(want) {
			return true
		}
	}
	return false
}

func decodeUTF16LE(data []byte) string {
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		value := binary.LittleEndian.Uint16(data[i:])
		if value == 0 {
			break
		}
		runes = append(runes, rune(value))
	}
	return string(runes)
}
