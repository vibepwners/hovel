package smbpipe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMBPipeProtocolMethodsThroughExchangeBoundary(t *testing.T) {
	c := scriptedPipeConn(authNTLMv1)
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		switch requestCommand(req) {
		case cmdNegotiate:
			params := make([]byte, 34)
			binary.LittleEndian.PutUint32(params[15:], 0x12345678)
			binary.LittleEndian.PutUint32(params[19:], capNTStatus)
			binary.LittleEndian.PutUint64(params[23:], windowsFiletime(time.Now()))
			params[33] = 8
			return responseFor(req, statusOK, params, []byte("12345678")), nil
		case cmdSessionSetup:
			res := responseFor(req, statusOK, nil, nil)
			res.uid = 44
			return res, nil
		case cmdTreeConnectAndX:
			res := responseFor(req, statusOK, nil, nil)
			res.tid = 55
			return res, nil
		case cmdNTCreateAndX:
			params := make([]byte, 8)
			binary.LittleEndian.PutUint16(params[5:], 66)
			return responseFor(req, statusOK, params, nil), nil
		case cmdRead:
			params := make([]byte, 2)
			binary.LittleEndian.PutUint16(params, 3)
			return responseFor(req, statusOK, params, []byte{0, 3, 0, 'a', 'b', 'c'}), nil
		case cmdWriteAndX:
			params := make([]byte, 6)
			binary.LittleEndian.PutUint16(params[4:], 16)
			return responseFor(req, statusOK, params, nil), nil
		case cmdClose:
			return responseFor(req, statusOK, nil, nil), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}

	opts := Options{Host: "server", Domain: "LAB", Username: "alice", Password: "Password", Pipe: "squatter"}
	if err := c.handshake(opts); err != nil {
		t.Fatal(err)
	}
	if c.uid != 44 || len(c.serverChallenge) != 8 || c.sessionKey != 0x12345678 {
		t.Fatalf("negotiated state = uid %d challenge %x key %x", c.uid, c.serverChallenge, c.sessionKey)
	}
	if err := c.treeConnectShare("IPC$"); err != nil || c.tid != 55 {
		t.Fatalf("tree connect = tid %d, %v", c.tid, err)
	}
	if err := c.openPipe("squatter"); err != nil || c.fid != 66 {
		t.Fatalf("open pipe = fid %d, %v", c.fid, err)
	}
	data, err := c.readClassicWithTimeout(10, time.Millisecond)
	if err != nil || string(data) != "abc" {
		t.Fatalf("read = %q, %v", data, err)
	}
	if n, err := c.writeAndX(make([]byte, 16)); err != nil || n != 16 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if err := c.closeFID(); err != nil {
		t.Fatal(err)
	}
}

func TestSMBPipeExtendedAndAnonymousSessionSetup(t *testing.T) {
	for _, auth := range []authMode{authExtended, authAnon} {
		t.Run(string(auth), func(t *testing.T) {
			c := scriptedPipeConn(auth)
			c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
				res := responseFor(req, statusOK, nil, nil)
				res.uid = 9
				return res, nil
			}
			if err := c.sessionSetup(Options{Username: "alice", Password: "pw", Domain: "LAB"}); err != nil {
				t.Fatal(err)
			}
			if c.uid != 9 {
				t.Fatalf("uid = %d", c.uid)
			}
		})
	}

	c := scriptedPipeConn(authMode("bad"))
	c.serverChallenge = []byte("12345678")
	if err := c.sessionSetupLegacy(Options{}); err == nil {
		t.Fatal("unsupported legacy auth returned nil error")
	}
	c.serverChallenge = nil
	if err := c.sessionSetupLegacy(Options{}); err == nil {
		t.Fatal("missing challenge returned nil error")
	}
}

func TestSMBTransactionsAndResponseBounds(t *testing.T) {
	c := scriptedPipeConn(authExtended)
	c.fid = 7
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		return transactionResponse(req, []byte("parameter"), []byte("data")), nil
	}
	out, err := c.transactPipe([]byte("request"))
	if err != nil || string(out) != "parameterdata" {
		t.Fatalf("transactPipe = %q, %v", out, err)
	}
	if out, err := c.transaction(transWriteNmPipe, []byte("request"), 0); err != nil || out != nil {
		t.Fatalf("write transaction = %x, %v", out, err)
	}

	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		res := transactionResponse(req, []byte("x"), nil)
		binary.LittleEndian.PutUint16(res.params[8:10], 1)
		return res, nil
	}
	if _, err := c.transactPipe(nil); err == nil {
		t.Fatal("invalid transaction parameter bounds returned nil error")
	}
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		res := transactionResponse(req, nil, []byte("x"))
		binary.LittleEndian.PutUint16(res.params[14:16], 1)
		return res, nil
	}
	if _, err := c.transactPipe(nil); err == nil {
		t.Fatal("invalid transaction data bounds returned nil error")
	}
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		return responseFor(req, statusOK, nil, nil), nil
	}
	if _, err := c.transactPipe(nil); err == nil {
		t.Fatal("short transaction response returned nil error")
	}
}

func TestSMBResponseParsingPendingAndTimeoutFailures(t *testing.T) {
	valid := testSMBParamResponse(cmdRead, 7, []byte{1, 2}, []byte("data"))
	res, err := parseResponse(valid)
	if err != nil || res.mid != 7 || string(res.data) != "data" {
		t.Fatalf("parseResponse = %#v, %v", res, err)
	}
	for _, raw := range [][]byte{
		nil,
		bytes.Repeat([]byte{'x'}, smbHeaderLen+3),
		append(append([]byte{}, valid[:smbHeaderLen+1]...), 5),
		valid[:len(valid)-1],
	} {
		if _, err := parseResponse(raw); err == nil {
			t.Fatalf("parseResponse(%x) returned nil error", raw)
		}
	}
	for _, req := range [][]byte{nil, withNBT([]byte("not smb"))} {
		if _, err := requestMID(req); err == nil {
			t.Fatalf("requestMID(%x) returned nil error", req)
		}
	}

	c := scriptedPipeConn(authExtended)
	wait, err := c.registerPending(1)
	if err != nil || wait == nil {
		t.Fatalf("registerPending = %v, %v", wait, err)
	}
	if _, err := c.registerPending(1); err == nil {
		t.Fatal("duplicate MID returned nil error")
	}
	want := errors.New("reader stopped")
	c.failPending(want)
	if result := <-wait; !errors.Is(result.err, want) {
		t.Fatalf("pending error = %v", result.err)
	}
	c.failPending(errors.New("ignored"))
	if _, err := c.registerPending(2); !errors.Is(err, want) {
		t.Fatalf("closed registration error = %v", err)
	}

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	timed := scriptedPipeConn(authExtended)
	timed.conn = client
	req := buildSMB(cmdRead, timed, 0, nil, nil)
	done := make(chan error, 1)
	go func() {
		_, err := timed.exchangeWithTimeout(req, time.Millisecond)
		done <- err
	}()
	if _, err := readNBT(server); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestSMBHelpersAndErrorCases(t *testing.T) {
	if treeHost(Options{Host: "host", Domain: "LAB"}) != "LAB" || treeHost(Options{Host: "host", Domain: "WORKGROUP"}) != "host" {
		t.Fatal("treeHost cases failed")
	}
	if !filetimeToTime(0).IsZero() || filetimeToTime(windowsFiletime(time.Unix(10, 0))).Unix() != 10 {
		t.Fatal("filetime conversion failed")
	}
	params := make([]byte, 8)
	binary.LittleEndian.PutUint16(params[6:], 9)
	if got := sessionSetupBlob(&smbResponse{params: params, data: []byte("abc")}); string(got) != "abc" {
		t.Fatalf("session blob = %q", got)
	}
	if got := sessionSetupBlob(&smbResponse{}); got != nil {
		t.Fatalf("empty session blob = %x", got)
	}
	if clientCapabilities(true)&capExtSecurity != 0 || clientCapabilities(false)&capExtSecurity == 0 {
		t.Fatal("client capability modes failed")
	}
	c := scriptedPipeConn(authExtended)
	if c.flags2()&flags2Unicode == 0 || c.legacy() {
		t.Fatal("extended flags failed")
	}
	c.auth = authNTLMv1
	if c.flags2()&flags2Unicode != 0 || !c.legacy() {
		t.Fatal("legacy flags failed")
	}
	c.mid = 0xffff
	if c.nextMID() != 0xffff || c.mid != 1 {
		t.Fatalf("MID rollover = %d", c.mid)
	}

	if _, err := challengeResponse(nil, []byte("short")); err == nil {
		t.Fatal("short challenge returned nil error")
	}
	if _, _, err := ntlmv2Responses(Options{}, nil); err == nil {
		t.Fatal("short NTLMv2 challenge returned nil error")
	}
	if got := string(utf16le("a😀")); !strings.Contains(got, "?") {
		t.Fatalf("utf16 replacement = %x", got)
	}
	if got := string(oemString("abc")); got != "abc\x00" {
		t.Fatalf("OEM string = %q", got)
	}
	if !isStatus(smbStatusError("op", statusLogonFailure), statusLogonFailure) || isStatus(errors.New("x"), statusLogonFailure) {
		t.Fatal("status matching failed")
	}
	if err := checkStatus(&smbResponse{status: 1}, 0, "op"); err == nil || !strings.Contains(err.Error(), "NTSTATUS") {
		t.Fatalf("status error = %v", err)
	}
	if got, err := readNBT(bytes.NewReader([]byte{1, 0, 0, 0})); err == nil || got != nil {
		t.Fatalf("invalid NBT = %x, %v", got, err)
	}
	if got, err := readNBT(bytes.NewReader([]byte{0, 0, 0, 2, 1})); err == nil || len(got) != 2 {
		t.Fatalf("truncated NBT = %x, %v", got, err)
	}
}

func TestSMBAdministrativeFileAndServiceFlows(t *testing.T) {
	c := scriptedPipeConn(authExtended)
	writeSizes := []int{4096, 904}
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		switch requestCommand(req) {
		case cmdTreeConnectAndX:
			return responseFor(req, statusOK, nil, nil), nil
		case cmdNTCreateAndX:
			params := make([]byte, 8)
			binary.LittleEndian.PutUint16(params[5:], 8)
			return responseFor(req, statusOK, params, nil), nil
		case cmdWriteAndX:
			params := make([]byte, 6)
			binary.LittleEndian.PutUint16(params[4:], uint16(writeSizes[0]))
			writeSizes = writeSizes[1:]
			return responseFor(req, statusOK, params, nil), nil
		case cmdClose:
			return responseFor(req, statusOK, nil, nil), nil
		default:
			return nil, errors.New("unexpected upload command")
		}
	}
	written, err := c.uploadAdminFile(`C:\Windows\Temp\sq.exe`, bytes.Repeat([]byte{'x'}, 5000))
	if err != nil || written != 5000 {
		t.Fatalf("uploadAdminFile = %d, %v", written, err)
	}

	readChunks := [][]byte{bytes.Repeat([]byte{'a'}, 4096), []byte("tail")}
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		switch requestCommand(req) {
		case cmdTreeConnectAndX:
			return responseFor(req, statusOK, nil, nil), nil
		case cmdNTCreateAndX:
			params := make([]byte, 8)
			binary.LittleEndian.PutUint16(params[5:], 8)
			return responseFor(req, statusOK, params, nil), nil
		case cmdReadAndX:
			chunk := readChunks[0]
			readChunks = readChunks[1:]
			return readAndXResponse(req, chunk), nil
		case cmdClose:
			return responseFor(req, statusOK, nil, nil), nil
		default:
			return nil, errors.New("unexpected read command")
		}
	}
	data, err := c.readAdminFile(`C:\boot.ini`)
	if err != nil || len(data) != 4100 || !bytes.HasSuffix(data, []byte("tail")) {
		t.Fatalf("readAdminFile = %d bytes, %v", len(data), err)
	}

	transactions := serviceTransactionReplies()
	c.exchangeHook = commandScript(transactions)
	status, state, exitCode, queryError, err := c.startService("hovel", `"C:\sq.exe" --service hovel`)
	if err != nil || status != 0 || state != 4 || exitCode != 7 || queryError != "" {
		t.Fatalf("startService = %d, %d, %d, %q, %v", status, state, exitCode, queryError, err)
	}

	transactions = [][]byte{
		{5, 0, dcerpcBindAck},
		rpcResponseStub(append(binary.LittleEndian.AppendUint32(nil, 77), binary.LittleEndian.AppendUint32(nil, 0)...)),
	}
	c.exchangeHook = commandScript(transactions)
	status, jobID, err := c.scheduleATAt("cmd /c whoami", time.Now())
	if err != nil || status != 0 || jobID != 77 {
		t.Fatalf("scheduleATAt = %d, %d, %v", status, jobID, err)
	}
}

func TestAdministrativePublicOperationsThroughInjectedSession(t *testing.T) {
	original := openSMBSession
	t.Cleanup(func() { openSMBSession = original })

	newUploadSession := func() *pipeConn {
		c := scriptedPipeConn(authExtended)
		c.conn = stubNetConn{}
		writeSizes := []int{7}
		transactions := serviceTransactionReplies()
		c.exchangeHook = func(req []byte, timeout time.Duration) (*smbResponse, error) {
			switch requestCommand(req) {
			case cmdTreeConnectAndX:
				return responseFor(req, statusOK, nil, nil), nil
			case cmdNTCreateAndX:
				params := make([]byte, 8)
				binary.LittleEndian.PutUint16(params[5:], 7)
				return responseFor(req, statusOK, params, nil), nil
			case cmdWriteAndX:
				params := make([]byte, 6)
				binary.LittleEndian.PutUint16(params[4:], uint16(writeSizes[0]))
				writeSizes = writeSizes[1:]
				return responseFor(req, statusOK, params, nil), nil
			case cmdTransaction:
				payload := transactions[0]
				transactions = transactions[1:]
				return transactionResponse(req, nil, payload), nil
			case cmdClose:
				return responseFor(req, statusOK, nil, nil), nil
			default:
				return nil, errors.New("unexpected public operation command")
			}
		}
		return c
	}
	openSMBSession = func(context.Context, Options, authMode) (*pipeConn, error) {
		return newUploadSession(), nil
	}
	result, err := UploadAndStart(context.Background(), InstallOptions{
		Options:     Options{Host: "server", Port: 445, Username: "alice"},
		RemotePath:  `C:\Windows\Temp\sq.exe`,
		ServiceName: "hovel",
		Payload:     []byte("payload"),
	})
	if err != nil || result.BytesWritten != 7 || result.LaunchMethod != "svcctl" || result.ServiceState != 4 {
		t.Fatalf("UploadAndStart = %#v, %v", result, err)
	}

	openSMBSession = func(context.Context, Options, authMode) (*pipeConn, error) {
		c := scriptedPipeConn(authExtended)
		c.conn = stubNetConn{}
		transactions := [][]byte{
			{5, 0, dcerpcBindAck},
			rpcResponseStub(append(binary.LittleEndian.AppendUint32(nil, 12), binary.LittleEndian.AppendUint32(nil, 0)...)),
		}
		c.exchangeHook = commandScript(transactions)
		return c, nil
	}
	status, jobID, err := ScheduleCommand(context.Background(), Options{Host: "server"}, "whoami", time.Second)
	if err != nil || status != 0 || jobID != 12 {
		t.Fatalf("ScheduleCommand = %d, %d, %v", status, jobID, err)
	}

	openSMBSession = func(context.Context, Options, authMode) (*pipeConn, error) {
		c := scriptedPipeConn(authExtended)
		c.conn = stubNetConn{}
		chunks := [][]byte{[]byte("contents")}
		c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
			switch requestCommand(req) {
			case cmdTreeConnectAndX:
				return responseFor(req, statusOK, nil, nil), nil
			case cmdNTCreateAndX:
				params := make([]byte, 8)
				binary.LittleEndian.PutUint16(params[5:], 7)
				return responseFor(req, statusOK, params, nil), nil
			case cmdReadAndX:
				chunk := chunks[0]
				chunks = chunks[1:]
				return readAndXResponse(req, chunk), nil
			case cmdClose:
				return responseFor(req, statusOK, nil, nil), nil
			default:
				return nil, errors.New("unexpected read operation")
			}
		}
		return c, nil
	}
	data, err := ReadAdminFile(context.Background(), Options{Host: "server"}, `C:\boot.ini`)
	if err != nil || string(data) != "contents" {
		t.Fatalf("ReadAdminFile = %q, %v", data, err)
	}
}

func TestAdministrativeValidationAndCodecFailures(t *testing.T) {
	valid := InstallOptions{
		Options:     Options{Host: "server", Port: 445, Username: "alice"},
		RemotePath:  `C:\sq.exe`,
		ServiceName: "svc",
		Payload:     []byte("x"),
	}
	mutations := []func(*InstallOptions){
		func(v *InstallOptions) { v.Host = "" },
		func(v *InstallOptions) { v.Username = "" },
		func(v *InstallOptions) { v.Port = 0 },
		func(v *InstallOptions) { v.RemotePath = "" },
		func(v *InstallOptions) { v.ServiceName = "" },
		func(v *InstallOptions) { v.Payload = nil },
	}
	for i, mutate := range mutations {
		value := valid
		mutate(&value)
		if err := validateInstallOptions(value); err == nil {
			t.Fatalf("validation mutation %d returned nil error", i)
		}
	}
	if err := validateInstallOptions(valid); err != nil {
		t.Fatal(err)
	}

	for _, uuid := range []string{"bad", "00000000-0000-0000-0000-00000000000z", "000000000-0000-0000-0000-000000000000"} {
		if got := dcerpcUUID(uuid, 1); got != nil {
			t.Fatalf("dcerpcUUID(%q) = %x", uuid, got)
		}
	}
	if _, ok := parseHexByte("zz"); ok {
		t.Fatal("invalid hex byte accepted")
	}
	if handle, status, err := createServiceHandleFromReply(nil); err == nil || handle != nil || status != 0 {
		t.Fatalf("short create reply = %x, %d, %v", handle, status, err)
	}
	reply := make([]byte, serviceHandleLen+4)
	binary.LittleEndian.PutUint32(reply[len(reply)-4:], 5)
	if handle, status, err := createServiceHandleFromReply(reply); err != nil || handle != nil || status != 5 {
		t.Fatalf("failed create reply = %x, %d, %v", handle, status, err)
	}
	if _, err := serviceStatusFromReply(nil); err == nil {
		t.Fatal("short service status accepted")
	}
	statusReply := make([]byte, 32)
	binary.LittleEndian.PutUint32(statusReply[28:], 5)
	if _, err := serviceStatusFromReply(statusReply); err == nil {
		t.Fatal("failed service status accepted")
	}

	c := scriptedPipeConn(authExtended)
	if got := c.currentServerTime(); time.Since(got) > time.Second {
		t.Fatalf("current fallback time = %s", got)
	}
	if nameLen, payload, flags := c.fileNamePayload(`\path\file`); nameLen == 0 || len(payload) == 0 || flags&flags2Unicode == 0 {
		t.Fatalf("unicode filename = %d, %x, %x", nameLen, payload, flags)
	}
	c.auth = authNTLMv1
	if nameLen, payload, flags := c.fileNamePayload(`\path\file`); nameLen == 0 || len(payload) == 0 || flags&flags2Unicode != 0 {
		t.Fatalf("legacy filename = %d, %x, %x", nameLen, payload, flags)
	}
}

func TestSMBPipeOperationFailuresAndFallbacks(t *testing.T) {
	sentinel := errors.New("scripted SMB failure")
	c := scriptedPipeConn(authExtended)

	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return nil, sentinel }
	if err := c.handshake(Options{}); !errors.Is(err, sentinel) {
		t.Fatalf("handshake negotiate error = %v", err)
	}
	for name, response := range map[string]*smbResponse{
		"status":    {status: statusLogonFailure},
		"short":     {status: statusOK},
		"dialect":   {status: statusOK, params: append([]byte{0xff, 0xff}, make([]byte, 32)...)},
		"challenge": {status: statusOK, params: append(make([]byte, 33), 8), data: []byte("short")},
	} {
		t.Run("negotiate_"+name, func(t *testing.T) {
			c.auth = authNTLMv1
			c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return response, nil }
			if err := c.negotiate(); err == nil {
				t.Fatal("negotiate returned nil error")
			}
		})
	}

	c.auth = authNTLMv1
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return nil, sentinel }
	if err := c.sessionSetupLegacyWithResponses(Options{}, nil, nil); !errors.Is(err, sentinel) {
		t.Fatalf("legacy exchange error = %v", err)
	}
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) {
		return &smbResponse{status: statusLogonFailure}, nil
	}
	if err := c.sessionSetupLegacyWithResponses(Options{}, nil, nil); err == nil {
		t.Fatal("legacy status failure returned nil error")
	}
	c.auth = authAnon
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return nil, sentinel }
	if err := c.sessionSetupAnonymous(); !errors.Is(err, sentinel) {
		t.Fatalf("anonymous exchange error = %v", err)
	}
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) {
		return &smbResponse{status: statusLogonFailure}, nil
	}
	if err := c.sessionSetupAnonymous(); err == nil {
		t.Fatal("anonymous status failure returned nil error")
	}

	assertExchangeFailures := func(t *testing.T, operation func() error) {
		t.Helper()
		c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return nil, sentinel }
		if err := operation(); !errors.Is(err, sentinel) {
			t.Fatalf("exchange error = %v", err)
		}
		c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) {
			return &smbResponse{status: statusLogonFailure}, nil
		}
		if err := operation(); err == nil {
			t.Fatal("status failure returned nil error")
		}
	}
	c.auth = authExtended
	assertExchangeFailures(t, func() error { return c.treeConnectShare("IPC$") })
	assertExchangeFailures(t, func() error { return c.openPipePath(`\PIPE\squatter`) })
	assertExchangeFailures(t, func() error { return c.openPipePathASCII(`\PIPE\squatter`) })
	assertExchangeFailures(t, c.closeFID)

	for name, operation := range map[string]func() error{
		"unicode": func() error { return c.openPipePath(`\PIPE\squatter`) },
		"ascii":   func() error { return c.openPipePathASCII(`\PIPE\squatter`) },
	} {
		t.Run(name+"_short", func(t *testing.T) {
			c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) {
				return &smbResponse{status: statusOK}, nil
			}
			if err := operation(); err == nil {
				t.Fatal("short open response returned nil error")
			}
		})
	}

	unicodeAttempts := 0
	c.auth = authExtended
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		unicodeAttempts++
		if unicodeAttempts <= 6 {
			return responseFor(req, statusObjectNameNotFound, nil, nil), nil
		}
		params := make([]byte, 8)
		binary.LittleEndian.PutUint16(params[5:], 91)
		return responseFor(req, statusOK, params, nil), nil
	}
	if err := c.openPipe("squatter"); err != nil || c.fid != 91 || unicodeAttempts != 7 {
		t.Fatalf("unicode-to-ASCII fallback = fid %d attempts %d, %v", c.fid, unicodeAttempts, err)
	}
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		return responseFor(req, statusLogonFailure, nil, nil), nil
	}
	if err := c.openPipe("squatter"); err == nil {
		t.Fatal("non-retryable open pipe error returned nil")
	}

	readCases := []struct {
		name string
		res  *smbResponse
	}{
		{name: "status", res: &smbResponse{status: statusLogonFailure}},
		{name: "params", res: &smbResponse{status: statusOK}},
		{name: "data", res: &smbResponse{status: statusOK, params: []byte{1, 0}, data: nil}},
		{name: "bounds", res: &smbResponse{status: statusOK, params: []byte{1, 0}, data: []byte{0, 2, 0, 1}}},
	}
	for _, tc := range readCases {
		t.Run("read_"+tc.name, func(t *testing.T) {
			c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return tc.res, nil }
			if _, err := c.readClassicWithTimeout(8, time.Millisecond); err == nil {
				t.Fatal("invalid read response returned nil error")
			}
		})
	}
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return nil, sentinel }
	if _, err := c.readClassicWithTimeout(8, time.Millisecond); !errors.Is(err, sentinel) {
		t.Fatalf("read exchange error = %v", err)
	}

	for name, res := range map[string]*smbResponse{
		"status": {status: statusLogonFailure},
		"short":  {status: statusOK},
	} {
		t.Run("write_"+name, func(t *testing.T) {
			c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return res, nil }
			if _, err := c.writeAndX([]byte("frame")); err == nil {
				t.Fatal("invalid write response returned nil error")
			}
		})
	}
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return nil, sentinel }
	if _, err := c.writeAndX(nil); !errors.Is(err, sentinel) {
		t.Fatalf("write exchange error = %v", err)
	}
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) {
		return &smbResponse{status: statusLogonFailure}, nil
	}
	if _, err := c.transaction(transactNmPipe, nil, 0); err == nil {
		t.Fatal("transaction status failure returned nil error")
	}
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) { return nil, sentinel }
	if _, err := c.transaction(transactNmPipe, nil, 0); !errors.Is(err, sentinel) {
		t.Fatalf("transaction exchange error = %v", err)
	}
}

func TestSMBPipeFramingAndConnectionLifecycle(t *testing.T) {
	c := scriptedPipeConn(authExtended)
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty Read = %d, %v", n, err)
	}
	c.readBuf = []byte("buffered")
	buf := make([]byte, 3)
	if n, err := c.Read(buf); n != 3 || err != nil || string(buf) != "buf" {
		t.Fatalf("buffered Read = %d %q, %v", n, buf, err)
	}

	reads := 0
	c.readBuf = nil
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		reads++
		params := make([]byte, 2)
		if reads == 1 {
			return responseFor(req, statusOK, params, []byte{0, 0, 0}), nil
		}
		binary.LittleEndian.PutUint16(params, 2)
		return responseFor(req, statusOK, params, []byte{0, 2, 0, 'o', 'k'}), nil
	}
	buf = make([]byte, 8)
	if n, err := c.Read(buf); n != 2 || err != nil || string(buf[:n]) != "ok" || reads != 2 {
		t.Fatalf("pipe Read = %d %q reads=%d, %v", n, buf[:n], reads, err)
	}

	frame := make([]byte, 19)
	binary.LittleEndian.PutUint32(frame, 3)
	copy(frame[16:], "abc")
	writes := 0
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		writes++
		params := make([]byte, 6)
		binary.LittleEndian.PutUint16(params[4:], uint16(len(frame)))
		return responseFor(req, statusOK, params, nil), nil
	}
	if n, err := c.Write(frame[:8]); n != 8 || err != nil || writes != 0 {
		t.Fatalf("partial frame Write = %d writes=%d, %v", n, writes, err)
	}
	if n, err := c.Write(frame[8:]); n != 11 || err != nil || writes != 1 {
		t.Fatalf("complete frame Write = %d writes=%d, %v", n, writes, err)
	}

	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		params := make([]byte, 6)
		return responseFor(req, statusOK, params, nil), nil
	}
	if _, err := c.writeAll([]byte("no progress")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writeAll error = %v", err)
	}
	c.exchangeHook = func([]byte, time.Duration) (*smbResponse, error) {
		return nil, errors.New("write failed")
	}
	if _, err := c.writeAll([]byte("fail")); err == nil {
		t.Fatal("writeAll exchange failure returned nil")
	}

	closed := &lifecycleNetConn{closeErr: errors.New("close failed")}
	c = scriptedPipeConn(authExtended)
	c.conn = closed
	c.fid = 12
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		return responseFor(req, statusLogonFailure, nil, nil), nil
	}
	if err := c.Close(); err == nil || closed.closeCalls != 1 || c.fid != 0 {
		t.Fatalf("Close = calls %d fid %d, %v", closed.closeCalls, c.fid, err)
	}

	c = scriptedPipeConn(authExtended)
	c.conn = &lifecycleNetConn{}
	c.fid = 13
	c.pending[1] = make(chan exchangeResult, 1)
	if err := c.Close(); err != nil || c.fid != 13 {
		t.Fatalf("Close with pending request = fid %d, %v", c.fid, err)
	}
}

func TestSMBAdministrativeErrorPropagation(t *testing.T) {
	sentinel := errors.New("administrative exchange failed")

	for failAt := 1; failAt <= 7; failAt++ {
		t.Run("service_step_"+strconv.Itoa(failAt), func(t *testing.T) {
			c := scriptedPipeConn(authExtended)
			replies := serviceTransactionReplies()
			calls := 0
			base := commandScript(replies)
			c.exchangeHook = func(req []byte, timeout time.Duration) (*smbResponse, error) {
				calls++
				if calls == failAt {
					return nil, sentinel
				}
				return base(req, timeout)
			}
			_, _, _, queryError, err := c.startService("svc", `"C:\\sq.exe"`)
			if failAt == 7 {
				if err != nil || queryError == "" {
					t.Fatalf("query failure = query %q, %v", queryError, err)
				}
			} else if !errors.Is(err, sentinel) {
				t.Fatalf("service failure = %v", err)
			}
		})
	}

	for failAt := 1; failAt <= 4; failAt++ {
		t.Run("atsvc_step_"+strconv.Itoa(failAt), func(t *testing.T) {
			c := scriptedPipeConn(authExtended)
			replies := [][]byte{{5, 0, dcerpcBindAck}, rpcResponseStub(make([]byte, 8))}
			calls := 0
			base := commandScript(replies)
			c.exchangeHook = func(req []byte, timeout time.Duration) (*smbResponse, error) {
				calls++
				if calls == failAt {
					return nil, sentinel
				}
				return base(req, timeout)
			}
			if _, _, err := c.scheduleAT("whoami"); !errors.Is(err, sentinel) {
				t.Fatalf("ATSVC failure = %v", err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		call func(*pipeConn) error
	}{
		{name: "upload", call: func(c *pipeConn) error { _, err := c.uploadAdminFile(`C:\\sq.exe`, []byte("x")); return err }},
		{name: "read", call: func(c *pipeConn) error { _, err := c.readAdminFile(`C:\\boot.ini`); return err }},
	} {
		for failAt := 1; failAt <= 3; failAt++ {
			t.Run(tc.name+"_step_"+strconv.Itoa(failAt), func(t *testing.T) {
				c := scriptedPipeConn(authExtended)
				calls := 0
				c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
					calls++
					if calls == failAt {
						return nil, sentinel
					}
					switch requestCommand(req) {
					case cmdTreeConnectAndX:
						return responseFor(req, statusOK, nil, nil), nil
					case cmdNTCreateAndX:
						params := make([]byte, 8)
						binary.LittleEndian.PutUint16(params[5:], 7)
						return responseFor(req, statusOK, params, nil), nil
					case cmdWriteAndX:
						params := make([]byte, 6)
						binary.LittleEndian.PutUint16(params[4:], 1)
						return responseFor(req, statusOK, params, nil), nil
					case cmdReadAndX:
						return readAndXResponse(req, nil), nil
					case cmdClose:
						return responseFor(req, statusOK, nil, nil), nil
					default:
						return nil, errors.New("unexpected file command")
					}
				}
				if err := tc.call(c); !errors.Is(err, sentinel) {
					t.Fatalf("file operation failure = %v", err)
				}
			})
		}
	}

	c := scriptedPipeConn(authExtended)
	c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
		switch requestCommand(req) {
		case cmdTreeConnectAndX:
			return responseFor(req, statusOK, nil, nil), nil
		case cmdNTCreateAndX:
			params := make([]byte, 8)
			binary.LittleEndian.PutUint16(params[5:], 7)
			return responseFor(req, statusOK, params, nil), nil
		case cmdWriteAndX:
			return responseFor(req, statusOK, make([]byte, 6), nil), nil
		case cmdClose:
			return responseFor(req, statusOK, nil, nil), nil
		default:
			return nil, sentinel
		}
	}
	if _, err := c.uploadAdminFile(`C:\\sq.exe`, []byte("x")); err == nil {
		t.Fatal("zero-progress upload returned nil error")
	}
}

func TestAdministrativeRPCFailureResponses(t *testing.T) {
	sentinel := errors.New("RPC transport failed")
	c := scriptedPipeConn(authExtended)
	c.fid = 7
	setReply := func(reply []byte, err error) {
		c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
			if err != nil {
				return nil, err
			}
			return transactionResponse(req, nil, reply), nil
		}
	}

	setReply(nil, sentinel)
	if err := bindRPC(c, svcctlUUID, 2); !errors.Is(err, sentinel) {
		t.Fatalf("bind transport error = %v", err)
	}
	for _, reply := range [][]byte{nil, {5, 0, dcerpcResponse}} {
		setReply(reply, nil)
		if err := bindRPC(c, svcctlUUID, 2); err == nil {
			t.Fatal("invalid bind reply returned nil error")
		}
	}

	at := atService{client: c}
	for _, tc := range []struct {
		name  string
		reply []byte
		err   error
	}{
		{name: "transport", err: sentinel},
		{name: "short", reply: []byte{1}},
		{name: "type", reply: dcerpcHeader(dcerpcBindAck, 1, make([]byte, 8))},
	} {
		t.Run("at_request_"+tc.name, func(t *testing.T) {
			setReply(tc.reply, tc.err)
			if _, err := at.request(atOpJobAdd, nil); err == nil {
				t.Fatal("invalid ATSVC reply returned nil error")
			}
		})
	}
	setReply(rpcResponseStub([]byte{1}), nil)
	if _, _, err := at.jobAdd("whoami", time.Now()); err == nil {
		t.Fatal("short job-add response returned nil error")
	}

	svc := serviceControl{client: c}
	for _, tc := range []struct {
		name  string
		reply []byte
		err   error
	}{
		{name: "transport", err: sentinel},
		{name: "short", reply: []byte{1}},
		{name: "type", reply: dcerpcHeader(dcerpcBindAck, 1, make([]byte, 8))},
	} {
		t.Run("service_request_"+tc.name, func(t *testing.T) {
			setReply(tc.reply, tc.err)
			if _, err := svc.request(svcOpOpenSCM, nil); err == nil {
				t.Fatal("invalid SVCCTL reply returned nil error")
			}
		})
	}

	for name, reply := range map[string][]byte{
		"short":  rpcResponseStub([]byte{1}),
		"status": rpcResponseStub(append(make([]byte, serviceHandleLen), 1, 0, 0, 0)),
	} {
		t.Run("open_manager_"+name, func(t *testing.T) {
			setReply(reply, nil)
			if _, err := svc.openSCManager(); err == nil {
				t.Fatal("invalid open-manager reply returned nil error")
			}
		})
	}
	setReply(nil, sentinel)
	if _, err := svc.openSCManager(); err == nil {
		t.Fatal("open-manager transport error returned nil")
	}

	setReply(rpcResponseStub([]byte{1}), nil)
	if _, _, err := svc.tryCreateService(make([]byte, serviceHandleLen), "svc", "path"); err == nil {
		t.Fatal("short create-service reply returned nil error")
	}
	setReply(nil, sentinel)
	if _, _, err := svc.tryCreateService(make([]byte, serviceHandleLen), "svc", "path"); err == nil {
		t.Fatal("create-service transport error returned nil")
	}

	for _, reply := range [][]byte{rpcResponseStub([]byte{1}), rpcResponseStub(append(make([]byte, serviceHandleLen), 1, 0, 0, 0))} {
		setReply(reply, nil)
		if _, err := svc.openService(make([]byte, serviceHandleLen), "svc"); err == nil {
			t.Fatal("invalid open-service reply returned nil error")
		}
	}
	setReply(nil, sentinel)
	if _, err := svc.openService(make([]byte, serviceHandleLen), "svc"); err == nil {
		t.Fatal("open-service transport error returned nil")
	}

	setReply(nil, errors.New("write: i/o timeout"))
	if status, err := svc.startServiceWithStub(nil); status != 0x41d || err != nil {
		t.Fatalf("start timeout = %#x, %v", status, err)
	}
	setReply(nil, sentinel)
	if _, err := svc.startServiceWithStub(nil); err == nil {
		t.Fatal("start transport error returned nil")
	}
	setReply(rpcResponseStub([]byte{1}), nil)
	if _, err := svc.startServiceWithStub(nil); err == nil {
		t.Fatal("short start reply returned nil error")
	}

	setReply(nil, sentinel)
	if _, err := svc.queryServiceStatus(nil); err == nil {
		t.Fatal("query transport error returned nil")
	}
	if err := svc.deleteService(nil); err == nil {
		t.Fatal("delete transport error returned nil")
	}
	if err := svc.closeHandle(nil); err == nil {
		t.Fatal("close transport error returned nil")
	}
}

func TestAdministrativeServiceReplacementAndPublicFailures(t *testing.T) {
	statusStub := func(status uint32) []byte {
		return binary.LittleEndian.AppendUint32(nil, status)
	}
	handle := bytes.Repeat([]byte{0x55}, serviceHandleLen)
	createSuccess := append([]byte{0, 0, 0, 0}, handle...)
	createSuccess = append(createSuccess, make([]byte, 4)...)
	openSuccess := append(append([]byte{}, handle...), make([]byte, 4)...)

	for name, replies := range map[string][][]byte{
		"unexpected_status": {rpcResponseStub(statusStub(5))},
		"open_stale_fails":  {rpcResponseStub(statusStub(errorServiceExists)), rpcResponseStub([]byte{1})},
		"recreate_fails": {
			rpcResponseStub(statusStub(errorServiceExists)), rpcResponseStub(openSuccess),
			rpcResponseStub(nil), rpcResponseStub(nil), rpcResponseStub(statusStub(5)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := scriptedPipeConn(authExtended)
			c.exchangeHook = commandScript(replies)
			svc := serviceControl{client: c}
			if _, err := svc.createService(handle, "svc", "path"); err == nil {
				t.Fatal("failed service replacement returned nil error")
			}
		})
	}
	c := scriptedPipeConn(authExtended)
	c.exchangeHook = commandScript([][]byte{
		rpcResponseStub(statusStub(errorServiceExists)), rpcResponseStub(openSuccess),
		rpcResponseStub(nil), rpcResponseStub(nil), rpcResponseStub(createSuccess),
	})
	svc := serviceControl{client: c}
	if got, err := svc.createService(handle, "svc", "path"); err != nil || !bytes.Equal(got, handle) {
		t.Fatalf("service replacement = %x, %v", got, err)
	}

	original := openSMBSession
	t.Cleanup(func() { openSMBSession = original })
	sentinel := errors.New("dial failed")
	openSMBSession = func(context.Context, Options, authMode) (*pipeConn, error) { return nil, sentinel }
	valid := InstallOptions{
		Options:    Options{Host: "server", Port: 445, Username: "alice"},
		RemotePath: `C:\sq.exe`, ServiceName: "svc", Payload: []byte("x"),
	}
	if _, err := UploadAndStart(context.Background(), valid); !errors.Is(err, sentinel) {
		t.Fatalf("UploadAndStart dial error = %v", err)
	}
	if _, _, err := ScheduleCommand(context.Background(), valid.Options, "whoami", 0); !errors.Is(err, sentinel) {
		t.Fatalf("ScheduleCommand dial error = %v", err)
	}
	if _, err := ReadAdminFile(context.Background(), valid.Options, `C:\boot.ini`); !errors.Is(err, sentinel) {
		t.Fatalf("ReadAdminFile dial error = %v", err)
	}

	newInstallConn := func(transactions [][]byte) *pipeConn {
		conn := scriptedPipeConn(authExtended)
		conn.conn = stubNetConn{}
		administrative := commandScript(transactions)
		conn.exchangeHook = func(req []byte, timeout time.Duration) (*smbResponse, error) {
			if requestCommand(req) == cmdWriteAndX {
				params := make([]byte, 6)
				binary.LittleEndian.PutUint16(params[4:], 1)
				return responseFor(req, statusOK, params, nil), nil
			}
			return administrative(req, timeout)
		}
		return conn
	}
	openSMBSession = func(context.Context, Options, authMode) (*pipeConn, error) {
		conn := newInstallConn(nil)
		conn.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
			if requestCommand(req) == cmdTreeConnectAndX {
				return nil, sentinel
			}
			return responseFor(req, statusOK, nil, nil), nil
		}
		return conn, nil
	}
	if _, err := UploadAndStart(context.Background(), valid); !errors.Is(err, sentinel) {
		t.Fatalf("UploadAndStart upload error = %v", err)
	}

	serviceReplies := serviceTransactionReplies()
	openSMBSession = func(context.Context, Options, authMode) (*pipeConn, error) {
		conn := newInstallConn(serviceReplies)
		calls := 0
		base := conn.exchangeHook
		conn.exchangeHook = func(req []byte, timeout time.Duration) (*smbResponse, error) {
			calls++
			if calls == 8 {
				return nil, sentinel
			}
			return base(req, timeout)
		}
		return conn, nil
	}
	if _, err := UploadAndStart(context.Background(), valid); err == nil {
		t.Fatalf("UploadAndStart service error = %v", err)
	}

	startReplies := serviceTransactionReplies()
	startReplies[3] = rpcResponseStub(statusStub(5))
	atReplies := [][]byte{
		{5, 0, dcerpcBindAck},
		rpcResponseStub(append(binary.LittleEndian.AppendUint32(nil, 42), make([]byte, 4)...)),
	}
	openSMBSession = func(context.Context, Options, authMode) (*pipeConn, error) {
		return newInstallConn(append(startReplies, atReplies...)), nil
	}
	result, err := UploadAndStart(context.Background(), valid)
	if err != nil || result.LaunchMethod != "atsvc" || result.ATJobID != 42 {
		t.Fatalf("ATSVC fallback = %#v, %v", result, err)
	}
}

func TestSMBDialAuthenticationFallbacks(t *testing.T) {
	original := openSMBSession
	t.Cleanup(func() { openSMBSession = original })
	seen := make([]authMode, 0, 4)
	openSMBSession = func(_ context.Context, _ Options, mode authMode) (*pipeConn, error) {
		seen = append(seen, mode)
		if mode != authAnon {
			return nil, smbStatusError("logon", statusLogonFailure)
		}
		c := scriptedPipeConn(mode)
		c.conn = stubNetConn{}
		c.exchangeHook = func(req []byte, _ time.Duration) (*smbResponse, error) {
			if requestCommand(req) == cmdNTCreateAndX {
				params := make([]byte, 8)
				binary.LittleEndian.PutUint16(params[5:], 7)
				return responseFor(req, statusOK, params, nil), nil
			}
			return responseFor(req, statusOK, nil, nil), nil
		}
		return c, nil
	}
	if _, err := dial(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join([]string{string(seen[0]), string(seen[1]), string(seen[2]), string(seen[3])}, ","); got != "extended,ntlmv1,ntlmv2,anonymous" {
		t.Fatalf("dial auth order = %s", got)
	}

	seen = seen[:0]
	openSMBSession = func(_ context.Context, _ Options, mode authMode) (*pipeConn, error) {
		seen = append(seen, mode)
		if mode != authNTLMv2 {
			return nil, smbStatusError("logon", statusLogonFailure)
		}
		return &pipeConn{}, nil
	}
	if _, err := dialInstall(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[2] != authNTLMv2 {
		t.Fatalf("install auth order = %v", seen)
	}
}

func scriptedPipeConn(auth authMode) *pipeConn {
	return &pipeConn{
		auth:     auth,
		host:     "server",
		treeHost: "server",
		timeout:  time.Second,
		pid:      1,
		mid:      1,
		pending:  make(map[uint16]chan exchangeResult),
	}
}

func requestCommand(req []byte) byte {
	if len(req) < 9 {
		return 0xff
	}
	return req[8]
}

func responseFor(req []byte, status uint32, params, data []byte) *smbResponse {
	mid, _ := requestMID(req)
	raw := testSMBParamResponse(requestCommand(req), mid, params, data)
	binary.LittleEndian.PutUint32(raw[5:9], status)
	res, _ := parseResponse(raw)
	return res
}

func transactionResponse(req []byte, parameter, data []byte) *smbResponse {
	params := make([]byte, 20)
	raw := make([]byte, 96+len(parameter)+len(data))
	paramOffset := 64
	dataOffset := paramOffset + len(parameter)
	copy(raw[paramOffset:], parameter)
	copy(raw[dataOffset:], data)
	binary.LittleEndian.PutUint16(params[6:8], uint16(len(parameter)))
	binary.LittleEndian.PutUint16(params[8:10], uint16(paramOffset))
	binary.LittleEndian.PutUint16(params[12:14], uint16(len(data)))
	binary.LittleEndian.PutUint16(params[14:16], uint16(dataOffset))
	return &smbResponse{raw: raw, command: cmdTransaction, status: statusOK, params: params, mid: func() uint16 { mid, _ := requestMID(req); return mid }()}
}

func readAndXResponse(req []byte, data []byte) *smbResponse {
	params := make([]byte, 14)
	raw := make([]byte, 64+len(data))
	copy(raw[64:], data)
	binary.LittleEndian.PutUint16(params[10:12], uint16(len(data)))
	binary.LittleEndian.PutUint16(params[12:14], 64)
	return &smbResponse{raw: raw, status: statusOK, params: params, command: cmdReadAndX}
}

func serviceTransactionReplies() [][]byte {
	handle := bytes.Repeat([]byte{0x44}, serviceHandleLen)
	open := append(append([]byte{}, handle...), make([]byte, 4)...)
	create := make([]byte, 4)
	create = append(create, handle...)
	create = append(create, make([]byte, 4)...)
	status := make([]byte, 32)
	binary.LittleEndian.PutUint32(status[4:8], 4)
	binary.LittleEndian.PutUint32(status[12:16], 7)
	return [][]byte{
		{5, 0, dcerpcBindAck},
		rpcResponseStub(open),
		rpcResponseStub(create),
		rpcResponseStub(make([]byte, 4)),
		rpcResponseStub(status),
		rpcResponseStub(nil),
		rpcResponseStub(nil),
	}
}

func rpcResponseStub(stub []byte) []byte {
	body := append(make([]byte, 8), stub...)
	return dcerpcHeader(dcerpcResponse, 1, body)
}

func commandScript(transactions [][]byte) func([]byte, time.Duration) (*smbResponse, error) {
	return func(req []byte, _ time.Duration) (*smbResponse, error) {
		switch requestCommand(req) {
		case cmdTreeConnectAndX:
			return responseFor(req, statusOK, nil, nil), nil
		case cmdNTCreateAndX:
			params := make([]byte, 8)
			binary.LittleEndian.PutUint16(params[5:], 7)
			return responseFor(req, statusOK, params, nil), nil
		case cmdTransaction:
			if len(transactions) == 0 {
				return nil, errors.New("no transaction response")
			}
			payload := transactions[0]
			transactions = transactions[1:]
			return transactionResponse(req, nil, payload), nil
		case cmdClose:
			return responseFor(req, statusOK, nil, nil), nil
		default:
			return nil, errors.New("unexpected administrative command")
		}
	}
}

type stubNetConn struct{}

func (stubNetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (stubNetConn) Write(p []byte) (int, error)      { return len(p), nil }
func (stubNetConn) Close() error                     { return nil }
func (stubNetConn) LocalAddr() net.Addr              { return nil }
func (stubNetConn) RemoteAddr() net.Addr             { return nil }
func (stubNetConn) SetDeadline(time.Time) error      { return nil }
func (stubNetConn) SetReadDeadline(time.Time) error  { return nil }
func (stubNetConn) SetWriteDeadline(time.Time) error { return nil }

type lifecycleNetConn struct {
	closeErr   error
	closeCalls int
}

func (*lifecycleNetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*lifecycleNetConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *lifecycleNetConn) Close() error                   { c.closeCalls++; return c.closeErr }
func (*lifecycleNetConn) LocalAddr() net.Addr              { return nil }
func (*lifecycleNetConn) RemoteAddr() net.Addr             { return nil }
func (*lifecycleNetConn) SetDeadline(time.Time) error      { return nil }
func (*lifecycleNetConn) SetReadDeadline(time.Time) error  { return nil }
func (*lifecycleNetConn) SetWriteDeadline(time.Time) error { return nil }
