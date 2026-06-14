package smbpipe

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/spnego"
)

const (
	defaultPort    = 445
	defaultTimeout = 10 * time.Second

	smbHeaderLen = 32

	cmdClose           = 0x04
	cmdRead            = 0x0a
	cmdReadAndX        = 0x2e
	cmdWriteAndX       = 0x2f
	cmdTransaction     = 0x25
	cmdNegotiate       = 0x72
	cmdSessionSetup    = 0x73
	cmdTreeConnectAndX = 0x75
	cmdNTCreateAndX    = 0xa2

	statusOK                     = 0x00000000
	statusMoreProcessingRequired = 0xc0000016
	statusObjectNameNotFound     = 0xc0000034
	statusLogonFailure           = 0xc000006d

	flagsReply              = 0x80
	flagsCaseInsensitive    = 0x08
	flagsCanonicalizedPaths = 0x10
	flags2LongNames         = 0x0001
	flags2NTStatus          = 0x4000
	flags2Unicode           = 0x8000
	flags2ExtSecurity       = 0x0800
	flags2EAS               = 0x0002

	capRawMode        = 0x0001
	capMpxMode        = 0x0002
	capUnicode        = 0x0004
	capLargeFiles     = 0x0008
	capNTStatus       = 0x0040
	capNTFind         = 0x0200
	capExtSecurity    = 0x80000000
	capNT_SMBS        = 0x0010
	capLevelIIOplocks = 0x0080
	capLargeReadX     = 0x00004000
	capLargeWriteX    = 0x00008000

	fileReadData        = 0x00000001
	fileWriteData       = 0x00000002
	fileReadEA          = 0x00000008
	fileWriteEA         = 0x00000010
	fileReadAttributes  = 0x00000080
	fileWriteAttributes = 0x00000100
	readControl         = 0x00020000
	synchronize         = 0x00100000

	fileShareRead    = 0x00000001
	fileShareWrite   = 0x00000002
	pipeAccess       = 0x0002019f
	fileOpen         = 0x00000001
	fileNonDirectory = 0x00000040
	impersonation    = 0x00000002
	transactNmPipe   = 0x0026
	transReadNmPipe  = 0x0036
	transWriteNmPipe = 0x0037
)

type authMode string

const (
	authExtended authMode = "extended"
	authNTLMv1   authMode = "ntlmv1"
	authNTLMv2   authMode = "ntlmv2"
)

type Options struct {
	Host     string
	Port     int
	Domain   string
	Username string
	Password string
	Pipe     string
	Timeout  time.Duration
}

type Dialer struct{}

func (d Dialer) Dial(ctx context.Context, opts Options) (io.ReadWriteCloser, error) {
	opts = opts.normalized()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	done := make(chan dialResult, 1)
	go func() {
		conn, err := dial(ctx, opts)
		done <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		return result.conn, result.err
	}
}

func NormalizePipePath(pipe string) string {
	pipe = strings.TrimSpace(pipe)
	pipe = strings.TrimLeft(pipe, `\`)
	parts := strings.Split(pipe, `\`)
	if len(parts) >= 3 && parts[0] != "" && strings.EqualFold(parts[1], "pipe") {
		return strings.Join(parts[2:], `\`)
	}
	if len(parts) >= 3 && parts[0] == "." && strings.EqualFold(parts[1], "pipe") {
		return strings.Join(parts[2:], `\`)
	}
	if len(parts) >= 2 && strings.EqualFold(parts[0], "pipe") {
		return strings.Join(parts[1:], `\`)
	}
	return pipe
}

func (o Options) normalized() Options {
	if o.Port == 0 {
		o.Port = defaultPort
	}
	if o.Timeout == 0 {
		o.Timeout = defaultTimeout
	}
	o.Pipe = NormalizePipePath(o.Pipe)
	return o
}

func (o Options) validate() error {
	if strings.TrimSpace(o.Host) == "" {
		return fmt.Errorf("smb host is required")
	}
	if strings.TrimSpace(o.Pipe) == "" {
		return fmt.Errorf("smb pipe is required")
	}
	if strings.TrimSpace(o.Username) == "" {
		return fmt.Errorf("smb username is required")
	}
	if o.Port < 1 || o.Port > 65535 {
		return fmt.Errorf("smb port is invalid: %d", o.Port)
	}
	return nil
}

type dialResult struct {
	conn io.ReadWriteCloser
	err  error
}

func dial(ctx context.Context, opts Options) (io.ReadWriteCloser, error) {
	conn, err := dialMode(ctx, opts, authExtended)
	if isStatus(err, statusLogonFailure) {
		conn, err = dialMode(ctx, opts, authNTLMv1)
		if isStatus(err, statusLogonFailure) {
			return dialMode(ctx, opts, authNTLMv2)
		}
	}
	return conn, err
}

func dialMode(ctx context.Context, opts Options, auth authMode) (io.ReadWriteCloser, error) {
	dialer := net.Dialer{Timeout: opts.Timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port)))
	if err != nil {
		return nil, fmt.Errorf("smb1 connect %s:%d: %w", opts.Host, opts.Port, err)
	}
	c := &pipeConn{
		conn:     netConn,
		host:     opts.Host,
		treeHost: treeHost(opts),
		timeout:  opts.Timeout,
		pid:      0x484f,
		mid:      1,
	}
	c.auth = auth
	c.debug = os.Getenv("HOVEL_SMB_DEBUG") != ""
	if err := c.handshake(opts); err != nil {
		_ = netConn.Close()
		return nil, err
	}
	return c, nil
}

type pipeConn struct {
	mu       sync.Mutex
	conn     net.Conn
	host     string
	treeHost string
	timeout  time.Duration
	uid      uint16
	tid      uint16
	fid      uint16
	pid      uint16
	mid      uint16

	auth            authMode
	debug           bool
	serverCaps      uint32
	sessionKey      uint32
	serverChallenge []byte
	writeBuf        []byte
	readBuf         []byte
}

func (c *pipeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	data, err := c.readClassic(min(min(len(p), 16), 0xffff))
	if err != nil {
		return 0, err
	}
	return copy(p, data), nil
}

func (c *pipeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeBuf = append(c.writeBuf, p...)
	for {
		if len(c.writeBuf) < 16 {
			return len(p), nil
		}
		frameLen := 16 + int(binary.LittleEndian.Uint32(c.writeBuf[0:4]))
		if len(c.writeBuf) < frameLen {
			return len(p), nil
		}
		_, err := c.writeAll(c.writeBuf[:frameLen])
		if err != nil {
			return 0, err
		}
		c.writeBuf = c.writeBuf[frameLen:]
	}
}

func (c *pipeConn) writeAll(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		end := min(len(p), total+0xffff)
		n, err := c.writeAndX(p[total:end])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (c *pipeConn) transactPipe(data []byte) ([]byte, error) {
	return c.transaction(transactNmPipe, data, 0x1000)
}

func (c *pipeConn) writeNMPipe(data []byte) (int, error) {
	_, err := c.transaction(transWriteNmPipe, data, 0)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *pipeConn) readNMPipe(max int) ([]byte, error) {
	return c.transaction(transReadNmPipe, nil, uint16(max))
}

func (c *pipeConn) transaction(subcommand uint16, data []byte, maxData uint16) ([]byte, error) {
	const setupWords = 2
	name := []byte("\\PIPE\\\x00")
	paramLen := 28 + setupWords*2
	params := make([]byte, paramLen)
	binary.LittleEndian.PutUint16(params[2:], uint16(len(data)))
	binary.LittleEndian.PutUint16(params[6:], maxData)
	binary.LittleEndian.PutUint32(params[12:], uint32(c.timeout/time.Millisecond))
	binary.LittleEndian.PutUint16(params[22:], uint16(len(data)))
	cursor := smbHeaderLen + 1 + paramLen + 2 + len(name)
	padding := (4 - cursor%4) % 4
	if len(data) > 0 {
		dataOffset := cursor + padding
		binary.LittleEndian.PutUint16(params[24:], uint16(dataOffset))
	}
	params[26] = setupWords
	binary.LittleEndian.PutUint16(params[28:], subcommand)
	binary.LittleEndian.PutUint16(params[30:], c.fid)
	payload := append([]byte{}, name...)
	if len(data) > 0 {
		payload = append(payload, bytes.Repeat([]byte{0}, padding)...)
		payload = append(payload, data...)
	}
	c.debugf("transaction pipe subcommand=0x%04x fid=%d bytes=%d max=%d", subcommand, c.fid, len(data), maxData)
	req := buildSMB(cmdTransaction, c, byte(14+setupWords), params, payload)
	res, err := c.exchange(req)
	if err != nil {
		return nil, err
	}
	c.debugf("transaction pipe raw subcommand=0x%04x status=0x%08x params=%d data=%d", subcommand, res.status, len(res.params), len(res.data))
	if err := checkStatus(res, statusOK, "SMB1 named pipe transaction"); err != nil {
		return nil, err
	}
	if len(res.params) < 20 {
		return nil, fmt.Errorf("SMB1 transact response too short")
	}
	paramCount := int(binary.LittleEndian.Uint16(res.params[6:8]))
	paramOffset := int(binary.LittleEndian.Uint16(res.params[8:10]))
	dataCount := int(binary.LittleEndian.Uint16(res.params[12:14]))
	dataOffsetResp := int(binary.LittleEndian.Uint16(res.params[14:16]))
	c.debugf("transaction pipe counts subcommand=0x%04x paramCount=%d paramOffset=%d dataCount=%d dataOffset=%d raw=%d", subcommand, paramCount, paramOffset, dataCount, dataOffsetResp, len(res.raw))
	if subcommand == transWriteNmPipe {
		return nil, nil
	}
	out := make([]byte, 0, paramCount+dataCount)
	if paramCount > 0 {
		if paramOffset < smbHeaderLen || paramOffset+paramCount > len(res.raw) {
			return nil, fmt.Errorf("SMB1 transact response has invalid parameter bounds")
		}
		out = append(out, res.raw[paramOffset:paramOffset+paramCount]...)
	}
	if dataCount > 0 {
		if dataOffsetResp < smbHeaderLen || dataOffsetResp+dataCount > len(res.raw) {
			return nil, fmt.Errorf("SMB1 transact response has invalid data bounds")
		}
		out = append(out, res.raw[dataOffsetResp:dataOffsetResp+dataCount]...)
	}
	c.debugf("transaction pipe status=0x%08x bytes=%d", res.status, len(out))
	return out, nil
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fid != 0 {
		_ = c.closeFID()
		c.fid = 0
	}
	return c.conn.Close()
}

func (c *pipeConn) handshake(opts Options) error {
	c.debugf("handshake start auth=%s host=%s pipe=%s user=%s domain=%s", c.auth, opts.Host, opts.Pipe, opts.Username, opts.Domain)
	if err := c.negotiate(); err != nil {
		return err
	}
	if err := c.sessionSetup(opts); err != nil {
		return err
	}
	if err := c.treeConnect(); err != nil {
		return err
	}
	if err := c.openPipe(opts.Pipe); err != nil {
		return err
	}
	return nil
}

func (c *pipeConn) negotiate() error {
	var data []byte
	data = append(data, 0x02)
	data = append(data, []byte("NT LM 0.12\x00")...)
	req := buildSMB(cmdNegotiate, c, 0, nil, data)
	res, err := c.exchange(req)
	if err != nil {
		return err
	}
	if err := checkStatus(res, statusOK, "SMB1 negotiate"); err != nil {
		return err
	}
	if len(res.params) < 34 {
		return fmt.Errorf("SMB1 negotiate response too short")
	}
	if binary.LittleEndian.Uint16(res.params[0:2]) == 0xffff {
		return fmt.Errorf("SMB1 negotiate did not select NT LM 0.12")
	}
	c.sessionKey = binary.LittleEndian.Uint32(res.params[15:19])
	c.serverCaps = binary.LittleEndian.Uint32(res.params[19:23])
	challengeLen := int(res.params[33])
	c.debugf("negotiate status=0x%08x caps=0x%08x sessionKey=0x%08x challengeLen=%d flags2=0x%04x dataLen=%d", res.status, c.serverCaps, c.sessionKey, challengeLen, res.flags2, len(res.data))
	if !c.usesExtendedSecurity() && challengeLen > 0 {
		if len(res.data) < challengeLen {
			return fmt.Errorf("SMB1 negotiate challenge is truncated")
		}
		c.serverChallenge = append(c.serverChallenge[:0], res.data[:challengeLen]...)
	}
	return nil
}

func (c *pipeConn) sessionSetup(opts Options) error {
	if c.auth != authExtended {
		return c.sessionSetupLegacy(opts)
	}
	initiator := &spnego.NTLMInitiator{
		User:      opts.Username,
		Password:  opts.Password,
		Domain:    opts.Domain,
		LocalUser: opts.Domain == "",
	}
	spnegoClient, err := spnego.NewClient([]gss.Mechanism{initiator})
	if err != nil {
		return err
	}
	token, err := spnegoClient.InitSecContext(nil)
	if err != nil {
		return fmt.Errorf("SMB1 NTLM negotiate token: %w", err)
	}
	res, err := c.sessionSetupLeg(token)
	if err != nil {
		return err
	}
	c.debugf("session setup extended leg1 status=0x%08x uid=%d dataLen=%d", res.status, res.uid, len(res.data))
	if res.status != statusMoreProcessingRequired && res.status != statusOK {
		return smbStatusError("SMB1 session setup", res.status)
	}
	c.uid = res.uid
	if res.status == statusOK {
		return nil
	}
	challenge := sessionSetupBlob(res)
	auth, err := spnegoClient.InitSecContext(challenge)
	if err != nil {
		return fmt.Errorf("SMB1 NTLM authenticate token: %w", err)
	}
	res, err = c.sessionSetupLeg(auth)
	if err != nil {
		return err
	}
	c.debugf("session setup extended leg2 status=0x%08x uid=%d dataLen=%d", res.status, res.uid, len(res.data))
	if err := checkStatus(res, statusOK, "SMB1 session setup authenticate"); err != nil {
		return err
	}
	c.uid = res.uid
	return nil
}

func (c *pipeConn) sessionSetupLeg(token []byte) (*smbResponse, error) {
	params := make([]byte, 24)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[4:], 0xffff)
	binary.LittleEndian.PutUint16(params[6:], 2)
	binary.LittleEndian.PutUint16(params[8:], 1)
	binary.LittleEndian.PutUint16(params[14:], uint16(len(token)))
	binary.LittleEndian.PutUint32(params[20:], clientCapabilities(c.legacy()))
	data := append([]byte{}, token...)
	data = append(data, utf16le("Unix")...)
	data = append(data, utf16le("Hovel")...)
	req := buildSMB(cmdSessionSetup, c, 12, params, data)
	return c.exchange(req)
}

func (c *pipeConn) sessionSetupLegacy(opts Options) error {
	if len(c.serverChallenge) != 8 {
		return fmt.Errorf("SMB1 legacy session setup missing 8-byte server challenge")
	}
	var lmResp, ntResp []byte
	var err error
	switch c.auth {
	case authNTLMv1:
		lmResp, err = lmResponse(opts.Password, c.serverChallenge)
		if err != nil {
			return fmt.Errorf("SMB1 LM response: %w", err)
		}
		ntResp, err = ntlmv1Response(opts.Password, c.serverChallenge)
		if err != nil {
			return fmt.Errorf("SMB1 NTLMv1 response: %w", err)
		}
	case authNTLMv2:
		lmResp, ntResp, err = ntlmv2Responses(opts, c.serverChallenge)
		if err != nil {
			return fmt.Errorf("SMB1 NTLMv2 response: %w", err)
		}
	default:
		return fmt.Errorf("SMB1 legacy session setup received unsupported auth mode %q", c.auth)
	}
	return c.sessionSetupLegacyWithResponses(opts, lmResp, ntResp)
}

func (c *pipeConn) sessionSetupLegacyWithResponses(opts Options, lmResp, ntResp []byte) error {
	params := make([]byte, 26)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[4:], 0xffff)
	binary.LittleEndian.PutUint16(params[6:], 2)
	binary.LittleEndian.PutUint16(params[8:], 1)
	binary.LittleEndian.PutUint32(params[10:], c.sessionKey)
	binary.LittleEndian.PutUint16(params[14:], uint16(len(lmResp)))
	binary.LittleEndian.PutUint16(params[16:], uint16(len(ntResp)))
	binary.LittleEndian.PutUint32(params[22:], clientCapabilities(c.legacy()))

	data := make([]byte, 0, 96)
	data = append(data, lmResp...)
	data = append(data, ntResp...)
	if legacyStringOffset(len(params), len(data))%2 == 1 {
		data = append(data, 0)
	}
	data = append(data, utf16le(opts.Username)...)
	data = append(data, utf16le(opts.Domain)...)
	data = append(data, utf16le("Unix")...)
	data = append(data, utf16le("Hovel")...)

	req := buildSMB(cmdSessionSetup, c, 13, params, data)
	res, err := c.exchange(req)
	if err != nil {
		return err
	}
	c.debugf("session setup legacy auth=%s status=0x%08x uid=%d lmLen=%d ntLen=%d dataLen=%d", c.auth, res.status, res.uid, len(lmResp), len(ntResp), len(res.data))
	if err := checkStatus(res, statusOK, "SMB1 legacy session setup"); err != nil {
		return err
	}
	c.uid = res.uid
	return nil
}

func sessionSetupBlob(res *smbResponse) []byte {
	if len(res.params) < 8 || len(res.data) == 0 {
		return nil
	}
	blobLen := int(binary.LittleEndian.Uint16(res.params[6:8]))
	if blobLen > len(res.data) {
		blobLen = len(res.data)
	}
	return res.data[:blobLen]
}

func (c *pipeConn) treeConnect() error {
	path := `\\` + c.treeHost + `\IPC$`
	c.debugf("tree connect path=%s", path)
	data := []byte{0}
	data = append(data, []byte(path)...)
	data = append(data, 0)
	data = append(data, []byte("?????\x00")...)
	params := []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	req := buildSMBWithFlags2(cmdTreeConnectAndX, c, 4, params, data, c.flags2()&^flags2Unicode)
	res, err := c.exchange(req)
	if err != nil {
		return err
	}
	if err := checkStatus(res, statusOK, "SMB1 tree connect IPC$"); err != nil {
		return err
	}
	c.debugf("tree connect status=0x%08x tid=%d", res.status, res.tid)
	c.tid = res.tid
	return nil
}

func treeHost(opts Options) string {
	if opts.Domain != "" && !strings.EqualFold(opts.Domain, "WORKGROUP") {
		return opts.Domain
	}
	return opts.Host
}

func (c *pipeConn) openPipe(pipe string) error {
	normalized := NormalizePipePath(pipe)
	names := []string{`\PIPE\` + normalized, `PIPE\` + normalized, `\pipe\` + normalized, `pipe\` + normalized, `\` + normalized, normalized}
	var lastErr error
	for _, name := range names {
		err := c.openPipePath(name)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isStatus(err, statusObjectNameNotFound) {
			return err
		}
		c.debugf("open pipe path %q not found; trying next form", name)
	}
	for _, name := range names {
		err := c.openPipePathASCII(name)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isStatus(err, statusObjectNameNotFound) {
			return err
		}
		c.debugf("open ASCII pipe path %q not found; trying next form", name)
	}
	return lastErr
}

func (c *pipeConn) openPipePath(name string) error {
	encodedName := utf16le(name)
	params := make([]byte, 48)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[5:], uint16(len(encodedName)-2))
	binary.LittleEndian.PutUint32(params[15:], pipeAccess)
	binary.LittleEndian.PutUint32(params[31:], fileShareRead|fileShareWrite)
	binary.LittleEndian.PutUint32(params[35:], fileOpen)
	binary.LittleEndian.PutUint32(params[39:], fileNonDirectory)
	binary.LittleEndian.PutUint32(params[43:], impersonation)
	dataOffset := smbHeaderLen + 1 + len(params) + 2
	payload := bytes.Repeat([]byte{0}, dataOffset%2)
	payload = append(payload, encodedName...)
	c.debugf("open pipe path=%q", name)
	req := buildSMB(cmdNTCreateAndX, c, 24, params, payload)
	res, err := c.exchange(req)
	if err != nil {
		return err
	}
	if err := checkStatus(res, statusOK, "SMB1 open named pipe"); err != nil {
		return err
	}
	if len(res.params) < 7 {
		return fmt.Errorf("SMB1 NT_CREATE response too short")
	}
	c.fid = binary.LittleEndian.Uint16(res.params[5:7])
	c.debugf("open pipe status=0x%08x fid=%d", res.status, c.fid)
	return nil
}

func (c *pipeConn) openPipePathASCII(name string) error {
	encodedName := append([]byte(name), 0)
	params := make([]byte, 48)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[5:], uint16(len(encodedName)-1))
	binary.LittleEndian.PutUint32(params[15:], pipeAccess)
	binary.LittleEndian.PutUint32(params[31:], fileShareRead|fileShareWrite)
	binary.LittleEndian.PutUint32(params[35:], fileOpen)
	binary.LittleEndian.PutUint32(params[39:], fileNonDirectory)
	binary.LittleEndian.PutUint32(params[43:], impersonation)
	c.debugf("open ASCII pipe path=%q", name)
	req := buildSMBWithFlags2(cmdNTCreateAndX, c, 24, params, encodedName, c.flags2()&^flags2Unicode)
	res, err := c.exchange(req)
	if err != nil {
		return err
	}
	if err := checkStatus(res, statusOK, "SMB1 open named pipe"); err != nil {
		return err
	}
	if len(res.params) < 7 {
		return fmt.Errorf("SMB1 NT_CREATE response too short")
	}
	c.fid = binary.LittleEndian.Uint16(res.params[5:7])
	c.debugf("open pipe status=0x%08x fid=%d", res.status, c.fid)
	return nil
}

func (c *pipeConn) readAndX(max int) ([]byte, error) {
	params := make([]byte, 20)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[4:], c.fid)
	binary.LittleEndian.PutUint16(params[10:], uint16(max))
	binary.LittleEndian.PutUint16(params[12:], 1)
	binary.LittleEndian.PutUint32(params[14:], 0xffffffff)
	binary.LittleEndian.PutUint16(params[18:], uint16(max))
	c.debugf("read fid=%d max=%d", c.fid, max)
	req := buildSMB(cmdReadAndX, c, 10, params, nil)
	res, err := c.exchange(req)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(res, statusOK, "SMB1 read named pipe"); err != nil {
		return nil, err
	}
	if len(res.params) < 14 {
		return nil, fmt.Errorf("SMB1 read response too short")
	}
	length := int(binary.LittleEndian.Uint16(res.params[10:12]))
	offset := int(binary.LittleEndian.Uint16(res.params[12:14]))
	if offset < smbHeaderLen || offset+length > len(res.raw) {
		return nil, fmt.Errorf("SMB1 read response has invalid data bounds")
	}
	c.debugf("read status=0x%08x bytes=%d", res.status, length)
	return append([]byte(nil), res.raw[offset:offset+length]...), nil
}

func (c *pipeConn) readClassic(max int) ([]byte, error) {
	params := make([]byte, 10)
	binary.LittleEndian.PutUint16(params[0:], c.fid)
	binary.LittleEndian.PutUint16(params[2:], uint16(max))
	binary.LittleEndian.PutUint16(params[8:], uint16(max))
	c.debugf("read classic fid=%d max=%d", c.fid, max)
	req := buildSMB(cmdRead, c, 5, params, nil)
	res, err := c.exchange(req)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(res, statusOK, "SMB1 read named pipe"); err != nil {
		return nil, err
	}
	if len(res.params) < 2 {
		return nil, fmt.Errorf("SMB1 read response too short")
	}
	count := int(binary.LittleEndian.Uint16(res.params[0:2]))
	if len(res.data) < 3 {
		return nil, fmt.Errorf("SMB1 read response data too short")
	}
	length := int(binary.LittleEndian.Uint16(res.data[1:3]))
	if length > count || 3+length > len(res.data) {
		return nil, fmt.Errorf("SMB1 read response has invalid data bounds")
	}
	c.debugf("read classic status=0x%08x bytes=%d", res.status, length)
	return append([]byte(nil), res.data[3:3+length]...), nil
}

func (c *pipeConn) writeAndX(data []byte) (int, error) {
	params := make([]byte, 28)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[4:], c.fid)
	binary.LittleEndian.PutUint32(params[10:], 0xff)
	binary.LittleEndian.PutUint16(params[14:], 8)
	binary.LittleEndian.PutUint16(params[16:], uint16(len(data)))
	binary.LittleEndian.PutUint16(params[20:], uint16(len(data)))
	dataOffset := smbHeaderLen + 1 + len(params) + 2
	if dataOffset%2 == 1 {
		dataOffset++
	}
	binary.LittleEndian.PutUint16(params[22:], uint16(dataOffset))
	payload := bytes.Repeat([]byte{0}, dataOffset-(smbHeaderLen+1+len(params)+2))
	payload = append(payload, data...)
	c.debugf("write fid=%d bytes=%d dataOffset=%d", c.fid, len(data), dataOffset)
	req := buildSMB(cmdWriteAndX, c, 14, params, payload)
	res, err := c.exchange(req)
	if err != nil {
		return 0, err
	}
	if err := checkStatus(res, statusOK, "SMB1 write named pipe"); err != nil {
		return 0, err
	}
	if len(res.params) < 6 {
		return 0, fmt.Errorf("SMB1 write response too short")
	}
	written := int(binary.LittleEndian.Uint16(res.params[4:6]))
	c.debugf("write status=0x%08x bytes=%d", res.status, written)
	return written, nil
}

func (c *pipeConn) closeFID() error {
	params := make([]byte, 6)
	binary.LittleEndian.PutUint16(params[0:], c.fid)
	req := buildSMB(cmdClose, c, 3, params, nil)
	res, err := c.exchange(req)
	if err != nil {
		return err
	}
	return checkStatus(res, statusOK, "SMB1 close named pipe")
}

func buildSMB(command byte, c *pipeConn, wordCount byte, params, data []byte) []byte {
	return buildSMBWithFlags2(command, c, wordCount, params, data, c.flags2())
}

func buildSMBWithFlags2(command byte, c *pipeConn, wordCount byte, params, data []byte, flags2 uint16) []byte {
	body := make([]byte, smbHeaderLen, smbHeaderLen+1+len(params)+2+len(data))
	copy(body[0:], []byte{0xff, 'S', 'M', 'B'})
	body[4] = command
	body[9] = flagsCaseInsensitive | flagsCanonicalizedPaths
	binary.LittleEndian.PutUint16(body[10:], flags2)
	binary.LittleEndian.PutUint16(body[24:], c.tid)
	binary.LittleEndian.PutUint16(body[26:], c.pid)
	binary.LittleEndian.PutUint16(body[28:], c.uid)
	binary.LittleEndian.PutUint16(body[30:], c.mid)
	c.mid++
	body = append(body, wordCount)
	body = append(body, params...)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(data)))
	body = append(body, data...)
	return withNBT(body)
}

func (c *pipeConn) flags2() uint16 {
	flags := uint16(flags2LongNames | flags2EAS | flags2NTStatus | flags2Unicode)
	if !c.legacy() {
		flags |= flags2ExtSecurity
	}
	return flags
}

func (c *pipeConn) usesExtendedSecurity() bool {
	return !c.legacy() && c.serverCaps&capExtSecurity != 0
}

func (c *pipeConn) legacy() bool {
	return c.auth != authExtended
}

func (c *pipeConn) debugf(format string, args ...any) {
	if c.debug {
		fmt.Fprintf(os.Stderr, "smbpipe: "+format+"\n", args...)
	}
}

func withNBT(body []byte) []byte {
	out := make([]byte, 4, len(body)+4)
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	return append(out, body...)
}

func (c *pipeConn) exchange(req []byte) (*smbResponse, error) {
	if c.timeout > 0 {
		_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
		defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	}
	if _, err := c.conn.Write(req); err != nil {
		return nil, err
	}
	raw, err := readNBT(c.conn)
	if err != nil {
		return nil, err
	}
	return parseResponse(raw)
}

func readNBT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0 {
		return nil, fmt.Errorf("unsupported NetBIOS session packet type 0x%02x", hdr[0])
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

type smbResponse struct {
	raw     []byte
	status  uint32
	command byte
	flags   byte
	flags2  uint16
	tid     uint16
	uid     uint16
	mid     uint16
	params  []byte
	data    []byte
}

func parseResponse(raw []byte) (*smbResponse, error) {
	if len(raw) < smbHeaderLen+3 {
		return nil, fmt.Errorf("SMB1 response too short")
	}
	if !bytes.Equal(raw[:4], []byte{0xff, 'S', 'M', 'B'}) {
		return nil, fmt.Errorf("SMB1 response has invalid protocol header")
	}
	wc := int(raw[smbHeaderLen])
	paramLen := wc * 2
	byteCountOffset := smbHeaderLen + 1 + paramLen
	if len(raw) < byteCountOffset+2 {
		return nil, fmt.Errorf("SMB1 response parameters are truncated")
	}
	byteCount := int(binary.LittleEndian.Uint16(raw[byteCountOffset:]))
	dataOffset := byteCountOffset + 2
	if len(raw) < dataOffset+byteCount {
		return nil, fmt.Errorf("SMB1 response data is truncated")
	}
	return &smbResponse{
		raw:     raw,
		status:  binary.LittleEndian.Uint32(raw[5:9]),
		command: raw[4],
		flags:   raw[9],
		flags2:  binary.LittleEndian.Uint16(raw[10:12]),
		tid:     binary.LittleEndian.Uint16(raw[24:26]),
		uid:     binary.LittleEndian.Uint16(raw[28:30]),
		mid:     binary.LittleEndian.Uint16(raw[30:32]),
		params:  raw[smbHeaderLen+1 : byteCountOffset],
		data:    raw[dataOffset : dataOffset+byteCount],
	}, nil
}

func checkStatus(res *smbResponse, want uint32, op string) error {
	if res.status == want {
		return nil
	}
	return smbStatusError(op, res.status)
}

func smbStatusError(op string, status uint32) error {
	return smbError{op: op, status: status}
}

type smbError struct {
	op     string
	status uint32
}

func (e smbError) Error() string {
	return fmt.Sprintf("%s failed: NTSTATUS 0x%08x", e.op, e.status)
}

func isStatus(err error, status uint32) bool {
	var e smbError
	if errors.As(err, &e) {
		return e.status == status
	}
	return false
}

func desiredPipeAccess() uint32 {
	return fileReadData |
		fileWriteData |
		fileReadEA |
		fileWriteEA |
		fileReadAttributes |
		fileWriteAttributes |
		readControl |
		synchronize
}

func clientCapabilities(legacy bool) uint32 {
	caps := uint32(capRawMode |
		capMpxMode |
		capUnicode |
		capLargeFiles |
		capNT_SMBS |
		capNTStatus |
		capNTFind |
		capLevelIIOplocks |
		capLargeReadX |
		capLargeWriteX)
	if !legacy {
		caps |= capExtSecurity
	}
	return caps
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		if r > 0xffff {
			r = '?'
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return append(out, 0, 0)
}

func legacyStringOffset(paramLen, dataLen int) int {
	return smbHeaderLen + 1 + paramLen + 2 + dataLen
}

func ntlmv1Response(password string, challenge []byte) ([]byte, error) {
	return challengeResponse(ntlmssp.Ntowfv1(password), challenge)
}

func lmResponse(password string, challenge []byte) ([]byte, error) {
	hash, err := lmHash(password)
	if err != nil {
		return nil, err
	}
	return challengeResponse(hash, challenge)
}

func ntlmv2Responses(opts Options, serverChallenge []byte) ([]byte, []byte, error) {
	if len(serverChallenge) != 8 {
		return nil, nil, fmt.Errorf("challenge length %d, want 8", len(serverChallenge))
	}
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, nil, err
	}
	hash := ntlmssp.Ntowfv2(opts.Password, opts.Username, opts.Domain)
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, windowsFiletime(time.Now()))
	ntResp := ntlmssp.ComputeResponseNTLMv2(hash, hash, clientChallenge, serverChallenge, timestamp, nil)

	mac := hmac.New(md5.New, hash)
	mac.Write(serverChallenge)
	mac.Write(clientChallenge)
	lmResp := append(mac.Sum(nil), clientChallenge...)
	return lmResp, ntResp, nil
}

func lmHash(password string) ([]byte, error) {
	const magic = "KGS!@#$%"
	pass := make([]byte, 14)
	copy(pass, []byte(strings.ToUpper(password)))
	left, err := desEncrypt(pass[:7], []byte(magic))
	if err != nil {
		return nil, err
	}
	right, err := desEncrypt(pass[7:], []byte(magic))
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

func challengeResponse(hash, challenge []byte) ([]byte, error) {
	if len(challenge) != 8 {
		return nil, fmt.Errorf("challenge length %d, want 8", len(challenge))
	}
	padded := make([]byte, 21)
	copy(padded, hash)
	out := make([]byte, 0, 24)
	for offset := 0; offset < 21; offset += 7 {
		block, err := desEncrypt(padded[offset:offset+7], challenge)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}
	return out, nil
}

func desEncrypt(key7, data []byte) ([]byte, error) {
	key := expandDESKey(key7)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	block.Encrypt(out, data)
	return out, nil
}

func expandDESKey(key7 []byte) []byte {
	key := []byte{
		key7[0],
		key7[0]<<7 | key7[1]>>1,
		key7[1]<<6 | key7[2]>>2,
		key7[2]<<5 | key7[3]>>3,
		key7[3]<<4 | key7[4]>>4,
		key7[4]<<3 | key7[5]>>5,
		key7[5]<<2 | key7[6]>>6,
		key7[6] << 1,
	}
	for i := range key {
		key[i] = oddParity(key[i] & 0xfe)
	}
	return key
}

func oddParity(b byte) byte {
	ones := 0
	for bit := 1; bit < 8; bit++ {
		if b&(1<<bit) != 0 {
			ones++
		}
	}
	if ones%2 == 0 {
		return b | 1
	}
	return b
}

func windowsFiletime(t time.Time) uint64 {
	const windowsToUnix100ns = 116444736000000000
	return uint64(t.UnixNano()/100) + windowsToUnix100ns
}
