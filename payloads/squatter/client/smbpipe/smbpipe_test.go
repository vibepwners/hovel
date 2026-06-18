package smbpipe

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
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
	data := append(make([]byte, 48), oemString("user")...)
	req := buildSMB(cmdSessionSetup, c, 13, params, data)
	body := req[4:]

	if body[4] != cmdSessionSetup {
		t.Fatalf("command = 0x%x, want session setup", body[4])
	}
	if got := binary.LittleEndian.Uint16(body[10:12]); got&flags2ExtSecurity != 0 {
		t.Fatalf("legacy flags2 includes extended security: 0x%x", got)
	}
	if got := binary.LittleEndian.Uint16(body[10:12]); got&flags2Unicode != 0 {
		t.Fatalf("legacy flags2 includes unicode: 0x%x", got)
	}
	if got := binary.LittleEndian.Uint16(body[10:12]); got&flags2EAS != 0 {
		t.Fatalf("legacy flags2 includes EAS: 0x%x", got)
	}
	if got := body[smbHeaderLen]; got != 13 {
		t.Fatalf("word count = %d, want 13", got)
	}
}

func TestLegacySessionSetupUsesOEMStringsAndCapabilities(t *testing.T) {
	c := &pipeConn{pid: 0x1111, mid: 1, auth: authNTLMv1}
	opts := Options{Username: "user", Domain: "LAB", Password: "password123"}
	lmResp := bytesOf(0x11, 24)
	ntResp := bytesOf(0x22, 24)
	params := make([]byte, 26)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[14:], uint16(len(lmResp)))
	binary.LittleEndian.PutUint16(params[16:], uint16(len(ntResp)))
	binary.LittleEndian.PutUint32(params[22:], clientCapabilities(c.legacy()))

	data := make([]byte, 0, 64)
	data = append(data, lmResp...)
	data = append(data, ntResp...)
	data = append(data, oemString(opts.Username)...)
	data = append(data, oemString(opts.Domain)...)
	data = append(data, oemString("Unix")...)
	data = append(data, oemString("Hovel")...)
	req := buildSMB(cmdSessionSetup, c, 13, params, data)
	body := req[4:]

	requestParams := body[smbHeaderLen+1 : smbHeaderLen+1+26]
	if got := binary.LittleEndian.Uint32(requestParams[22:26]); got&capUnicode != 0 {
		t.Fatalf("legacy capabilities include unicode: 0x%x", got)
	}
	if got := binary.LittleEndian.Uint32(requestParams[22:26]); got != capNT_SMBS|capNTStatus {
		t.Fatalf("legacy capabilities = 0x%x", got)
	}
	if got := string(body[len(body)-len("user\x00LAB\x00Unix\x00Hovel\x00"):]); got != "user\x00LAB\x00Unix\x00Hovel\x00" {
		t.Fatalf("legacy strings = %q", got)
	}
}

func TestAnonymousSessionSetupMatchesXPNullSessionShape(t *testing.T) {
	c := &pipeConn{pid: 0x1111, mid: 1, auth: authAnon}
	params := make([]byte, 26)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[4:], 4356)
	binary.LittleEndian.PutUint16(params[6:], 10)
	binary.LittleEndian.PutUint32(params[22:], clientCapabilities(true))
	data := []byte{0, 0}
	data = append(data, oemString("Unix")...)
	data = append(data, oemString("Hovel")...)
	req := buildSMB(cmdSessionSetup, c, 13, params, data)
	body := req[4:]

	if got := body[smbHeaderLen]; got != 13 {
		t.Fatalf("word count = %d, want 13", got)
	}
	if got := binary.LittleEndian.Uint16(body[10:12]); got != flags2LongNames|flags2NTStatus {
		t.Fatalf("anonymous flags2 = 0x%x", got)
	}
	if got := string(body[len(body)-len("\x00\x00Unix\x00Hovel\x00"):]); got != "\x00\x00Unix\x00Hovel\x00" {
		t.Fatalf("anonymous data suffix = %q", got)
	}
}

func TestWriteAndXParamsEncodeFileOffset(t *testing.T) {
	params := writeAndXParams(0x1200, 0x10203040, 4096, 64, 0)
	if got := binary.LittleEndian.Uint16(params[4:]); got != 0x1200 {
		t.Fatalf("fid = 0x%x", got)
	}
	if got := binary.LittleEndian.Uint32(params[6:]); got != 0x10203040 {
		t.Fatalf("offset = 0x%x", got)
	}
	if got := binary.LittleEndian.Uint32(params[10:]); got != 0 {
		t.Fatalf("timeout = 0x%x, want zero", got)
	}
	if got := binary.LittleEndian.Uint16(params[20:]); got != 4096 {
		t.Fatalf("data length = %d", got)
	}
	if got := binary.LittleEndian.Uint16(params[22:]); got != 64 {
		t.Fatalf("data offset = %d", got)
	}
}

func TestExchangeDemuxesOutOfOrderResponsesByMID(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	c := &pipeConn{
		conn:    client,
		timeout: time.Second,
		pid:     0x1111,
		mid:     1,
		pending: make(map[uint16]chan exchangeResult),
	}
	go c.readResponses()
	defer c.Close()

	req1 := buildSMB(cmdRead, c, 0, nil, nil)
	req2 := buildSMB(cmdWriteAndX, c, 0, nil, nil)
	mid1 := binary.LittleEndian.Uint16(req1[4+30:])
	mid2 := binary.LittleEndian.Uint16(req2[4+30:])

	type result struct {
		name string
		res  *smbResponse
		err  error
	}
	results := make(chan result, 2)
	go func() {
		res, err := c.exchange(req1)
		results <- result{name: "first", res: res, err: err}
	}()
	go func() {
		res, err := c.exchange(req2)
		results <- result{name: "second", res: res, err: err}
	}()

	seen := map[uint16]bool{}
	for len(seen) < 2 {
		raw, err := readNBT(server)
		if err != nil {
			t.Fatalf("server read request: %v", err)
		}
		seen[binary.LittleEndian.Uint16(raw[30:32])] = true
	}
	if !seen[mid1] || !seen[mid2] {
		t.Fatalf("server saw MIDs %#v, want %d and %d", seen, mid1, mid2)
	}

	if _, err := server.Write(withNBT(testSMBResponse(cmdWriteAndX, mid2, []byte("second")))); err != nil {
		t.Fatalf("server write second response: %v", err)
	}
	if _, err := server.Write(withNBT(testSMBResponse(cmdRead, mid1, []byte("first")))); err != nil {
		t.Fatalf("server write first response: %v", err)
	}

	got := map[string]string{}
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("%s exchange failed: %v", result.name, result.err)
		}
		got[result.name] = string(result.res.data)
	}
	if got["first"] != "first" || got["second"] != "second" {
		t.Fatalf("responses = %#v", got)
	}
}

func TestPipeReadBlocksOnSMBReadAndAllowsConcurrentWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	c := &pipeConn{
		conn:    client,
		timeout: time.Second,
		pid:     0x1111,
		mid:     1,
		fid:     0x2222,
		pending: make(map[uint16]chan exchangeResult),
	}
	go c.readResponses()
	defer c.Close()

	readDone := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := c.Read(buf)
		readDone <- readResult{data: append([]byte(nil), buf[:n]...), err: err}
	}()

	readReq, err := readNBT(server)
	if err != nil {
		t.Fatalf("server read request: %v", err)
	}
	if got := readReq[4]; got != cmdRead {
		t.Fatalf("first request command = 0x%x, want SMB_COM_READ", got)
	}
	readMID := binary.LittleEndian.Uint16(readReq[30:32])

	writeDone := make(chan error, 1)
	go func() {
		frame := make([]byte, 16)
		_, err := c.Write(frame)
		writeDone <- err
	}()

	writeReq, err := readNBT(server)
	if err != nil {
		t.Fatalf("server write request: %v", err)
	}
	if got := writeReq[4]; got != cmdWriteAndX {
		t.Fatalf("second request command = 0x%x, want SMB_COM_WRITE_ANDX", got)
	}
	writeMID := binary.LittleEndian.Uint16(writeReq[30:32])
	if _, err := server.Write(withNBT(testWriteAndXResponse(writeMID, 16))); err != nil {
		t.Fatalf("server write write response: %v", err)
	}

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("client write failed while read was pending: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client write blocked behind pending pipe read")
	}

	if _, err := server.Write(withNBT(testReadResponse(readMID, []byte("abc")))); err != nil {
		t.Fatalf("server write read response: %v", err)
	}
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("client read failed: %v", result.err)
		}
		if string(result.data) != "abc" {
			t.Fatalf("client read = %q, want abc", result.data)
		}
	case <-time.After(time.Second):
		t.Fatal("client read did not complete after read response")
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

func bytesOf(value byte, count int) []byte {
	return bytes.Repeat([]byte{value}, count)
}

type readResult struct {
	data []byte
	err  error
}

func testSMBResponse(command byte, mid uint16, data []byte) []byte {
	raw := make([]byte, smbHeaderLen, smbHeaderLen+1+2+len(data))
	copy(raw, []byte{0xff, 'S', 'M', 'B'})
	raw[4] = command
	raw[9] = flagsReply
	binary.LittleEndian.PutUint16(raw[30:], mid)
	raw = append(raw, 0)
	raw = binary.LittleEndian.AppendUint16(raw, uint16(len(data)))
	raw = append(raw, data...)
	return raw
}

func testReadResponse(mid uint16, payload []byte) []byte {
	params := make([]byte, 2)
	binary.LittleEndian.PutUint16(params, uint16(len(payload)))
	data := []byte{0}
	data = binary.LittleEndian.AppendUint16(data, uint16(len(payload)))
	data = append(data, payload...)
	return testSMBParamResponse(cmdRead, mid, params, data)
}

func testWriteAndXResponse(mid uint16, written int) []byte {
	params := make([]byte, 6)
	binary.LittleEndian.PutUint16(params[4:], uint16(written))
	return testSMBParamResponse(cmdWriteAndX, mid, params, nil)
}

func testSMBParamResponse(command byte, mid uint16, params, data []byte) []byte {
	raw := make([]byte, smbHeaderLen, smbHeaderLen+1+len(params)+2+len(data))
	copy(raw, []byte{0xff, 'S', 'M', 'B'})
	raw[4] = command
	raw[9] = flagsReply
	binary.LittleEndian.PutUint16(raw[30:], mid)
	raw = append(raw, byte(len(params)/2))
	raw = append(raw, params...)
	raw = binary.LittleEndian.AppendUint16(raw, uint16(len(data)))
	raw = append(raw, data...)
	return raw
}
