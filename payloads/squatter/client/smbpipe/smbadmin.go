package smbpipe

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	atsvcUUID       = "1ff70682-0a51-30e8-076d-740be8cee98b"
	svcctlUUID      = "367abb81-9844-35f1-ad32-98f038001003"
	ndrUUID         = "8a885d04-1ceb-11c9-9fe8-08002b104860"
	dcerpcDREP      = "\x10\x00\x00\x00"
	dcerpcBind      = 11
	dcerpcBindAck   = 12
	dcerpcRequest   = 0
	dcerpcResponse  = 2
	dcerpcFirstLast = 0x03
	dcerpcFragSize  = 0x16d0
	dcerpcRespHdr   = 24

	svcOpClose   = 0
	svcOpDelete  = 2
	svcOpQuery   = 6
	svcOpCreate  = 12
	svcOpOpenSCM = 15
	svcOpOpenSvc = 16
	svcOpStart   = 19

	atOpJobAdd        = 0
	jobAddCurrentDate = 0x08
	jobNonInteractive = 0x10

	scmAll             = 0x000f003f
	serviceAll         = 0x000f01ff
	serviceInteractive = 0x00000110
	serviceDemandStart = 3
	serviceErrorIgnore = 0
	errorServiceExists = 0x431
	serviceHandleLen   = 20
)

type InstallOptions struct {
	Options
	RemotePath  string
	ServiceName string
	Payload     []byte
	Args        string
}

type InstallResult struct {
	RemotePath    string
	ServiceName   string
	BinaryPath    string
	BytesWritten  int
	ServiceStatus uint32
	ServiceState  uint32
	Win32ExitCode uint32
	QueryError    string
	LaunchMethod  string
	ATStatus      uint32
	ATJobID       uint32
}

func UploadAndStart(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	opts.Options = opts.Options.normalized()
	if err := validateInstallOptions(opts); err != nil {
		return InstallResult{}, err
	}
	c, err := dialInstall(ctx, opts.Options)
	if err != nil {
		return InstallResult{}, err
	}
	defer c.conn.Close()

	written, err := c.uploadAdminFile(opts.RemotePath, opts.Payload)
	if err != nil {
		return InstallResult{}, err
	}
	binaryPath := serviceBinaryPath(opts.RemotePath, opts.ServiceName, opts.Args)
	status, state, win32Exit, queryError, err := c.startService(opts.ServiceName, binaryPath)
	if err != nil {
		return InstallResult{}, err
	}
	method := "svcctl"
	atStatus := uint32(0)
	atJobID := uint32(0)
	if status == 5 {
		var atErr error
		atStatus, atJobID, atErr = c.scheduleAT(scheduledBinaryPath(opts.RemotePath, opts.Args))
		if atErr != nil {
			return InstallResult{}, atErr
		}
		if atStatus == 0 {
			method = "atsvc"
		}
	}
	return InstallResult{
		RemotePath:    opts.RemotePath,
		ServiceName:   opts.ServiceName,
		BinaryPath:    binaryPath,
		BytesWritten:  written,
		ServiceStatus: status,
		ServiceState:  state,
		Win32ExitCode: win32Exit,
		QueryError:    queryError,
		LaunchMethod:  method,
		ATStatus:      atStatus,
		ATJobID:       atJobID,
	}, nil
}

func ScheduleCommand(ctx context.Context, opts Options, command string, delay time.Duration) (uint32, uint32, error) {
	opts = opts.normalized()
	c, err := dialInstall(ctx, opts)
	if err != nil {
		return 0, 0, err
	}
	defer c.conn.Close()
	return c.scheduleATAt(command, c.currentServerTime().Add(delay))
}

func ReadAdminFile(ctx context.Context, opts Options, remotePath string) ([]byte, error) {
	opts = opts.normalized()
	c, err := dialInstall(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer c.conn.Close()
	return c.readAdminFile(remotePath)
}

func validateInstallOptions(opts InstallOptions) error {
	if strings.TrimSpace(opts.Host) == "" {
		return fmt.Errorf("smb host is required")
	}
	if strings.TrimSpace(opts.Username) == "" {
		return fmt.Errorf("smb username is required")
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("smb port is invalid: %d", opts.Port)
	}
	if strings.TrimSpace(opts.RemotePath) == "" {
		return fmt.Errorf("remote path is required")
	}
	if strings.TrimSpace(opts.ServiceName) == "" {
		return fmt.Errorf("service name is required")
	}
	if len(opts.Payload) == 0 {
		return fmt.Errorf("payload is empty")
	}
	return nil
}

func dialInstall(ctx context.Context, opts Options) (*pipeConn, error) {
	conn, err := dialSessionMode(ctx, opts, authExtended)
	if isStatus(err, statusLogonFailure) {
		conn, err = dialSessionMode(ctx, opts, authNTLMv1)
		if isStatus(err, statusLogonFailure) {
			return dialSessionMode(ctx, opts, authNTLMv2)
		}
	}
	return conn, err
}

func (c *pipeConn) uploadAdminFile(remotePath string, data []byte) (int, error) {
	share, path := adminSharePath(remotePath)
	if err := c.treeConnectShare(share); err != nil {
		return 0, err
	}
	fid, err := c.createFile(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.closeFile(fid) }()

	written := 0
	for written < len(data) {
		end := min(len(data), written+4096)
		n, err := c.writeFile(fid, data[written:end], uint32(written))
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, fmt.Errorf("SMB1 write file made no progress")
		}
	}
	return written, nil
}

func adminSharePath(remotePath string) (string, string) {
	path := strings.Trim(strings.ReplaceAll(remotePath, "/", `\`), `"`)
	lower := strings.ToLower(path)
	for _, prefix := range []string{`c:\windows\`, `c:\winnt\`} {
		if strings.HasPrefix(lower, prefix) {
			return "ADMIN$", path[len(prefix):]
		}
	}
	if strings.HasPrefix(lower, `c:\`) {
		return "C$", path[3:]
	}
	return "ADMIN$", strings.TrimLeft(path, `\`)
}

func (c *pipeConn) createFile(path string) (uint16, error) {
	return c.openFile(path, fileOverwriteIf)
}

func (c *pipeConn) openFile(path string, disposition uint32) (uint16, error) {
	nameLength, payload, flags2 := c.fileNamePayload(path)
	params := make([]byte, 48)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[5:], nameLength)
	binary.LittleEndian.PutUint32(params[15:], fileAccess)
	binary.LittleEndian.PutUint32(params[31:], fileShareRead|fileShareWrite)
	binary.LittleEndian.PutUint32(params[35:], disposition)
	binary.LittleEndian.PutUint32(params[39:], fileNonDirectory)
	binary.LittleEndian.PutUint32(params[43:], impersonation)
	c.debugf("open file path=%q unicode=%t", strings.TrimLeft(path, `\`), flags2&flags2Unicode != 0)
	req := buildSMBWithFlags2(cmdNTCreateAndX, c, 24, params, payload, flags2)
	res, err := c.exchange(req)
	if err != nil {
		return 0, err
	}
	if err := checkStatus(res, statusOK, "SMB1 create file"); err != nil {
		return 0, err
	}
	if len(res.params) < 7 {
		return 0, fmt.Errorf("SMB1 NT_CREATE file response too short")
	}
	return binary.LittleEndian.Uint16(res.params[5:7]), nil
}

func (c *pipeConn) fileNamePayload(path string) (uint16, []byte, uint16) {
	trimmed := strings.TrimLeft(path, `\`)
	if c.legacy() {
		name := append([]byte(trimmed), 0)
		return uint16(len(name) - 1), name, c.flags2() &^ flags2Unicode
	}
	name := utf16le(trimmed)
	dataOffset := smbHeaderLen + 1 + 48 + 2
	payload := make([]byte, dataOffset%2)
	payload = append(payload, name...)
	return uint16(len(name) - 2), payload, c.flags2()
}

func (c *pipeConn) readAdminFile(remotePath string) ([]byte, error) {
	share, path := adminSharePath(remotePath)
	if err := c.treeConnectShare(share); err != nil {
		return nil, err
	}
	fid, err := c.openFile(path, fileOpen)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.closeFile(fid) }()

	out := make([]byte, 0, 4096)
	offset := uint32(0)
	for {
		chunk, err := c.readFileAndX(fid, offset, 4096)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			return out, nil
		}
		out = append(out, chunk...)
		offset += uint32(len(chunk))
		if len(chunk) < 4096 {
			return out, nil
		}
	}
}

func (c *pipeConn) readFileAndX(fid uint16, offset uint32, max int) ([]byte, error) {
	params := make([]byte, 20)
	params[0] = 0xff
	binary.LittleEndian.PutUint16(params[4:], fid)
	binary.LittleEndian.PutUint32(params[6:], offset)
	binary.LittleEndian.PutUint16(params[10:], uint16(max))
	binary.LittleEndian.PutUint16(params[12:], 1)
	binary.LittleEndian.PutUint32(params[14:], 0xffffffff)
	binary.LittleEndian.PutUint16(params[18:], uint16(max))
	req := buildSMB(cmdReadAndX, c, 10, params, nil)
	res, err := c.exchange(req)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(res, statusOK, "SMB1 read file"); err != nil {
		return nil, err
	}
	if len(res.params) < 14 {
		return nil, fmt.Errorf("SMB1 read file response too short")
	}
	length := int(binary.LittleEndian.Uint16(res.params[10:12]))
	if length == 0 {
		return nil, nil
	}
	dataOffset := int(binary.LittleEndian.Uint16(res.params[12:14]))
	if dataOffset < smbHeaderLen || dataOffset+length > len(res.raw) {
		return nil, fmt.Errorf("SMB1 read file response has invalid data bounds")
	}
	return append([]byte(nil), res.raw[dataOffset:dataOffset+length]...), nil
}

func (c *pipeConn) readFile(fid uint16, offset uint32, max int) ([]byte, error) {
	params := make([]byte, 10)
	binary.LittleEndian.PutUint16(params[0:], fid)
	binary.LittleEndian.PutUint16(params[2:], uint16(max))
	binary.LittleEndian.PutUint32(params[4:], offset)
	binary.LittleEndian.PutUint16(params[8:], uint16(max))
	req := buildSMB(cmdRead, c, 5, params, nil)
	res, err := c.exchange(req)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(res, statusOK, "SMB1 read file"); err != nil {
		return nil, err
	}
	if len(res.params) < 2 {
		return nil, fmt.Errorf("SMB1 read file response too short")
	}
	if len(res.data) < 3 {
		return nil, fmt.Errorf("SMB1 read file response data too short")
	}
	length := int(binary.LittleEndian.Uint16(res.data[1:3]))
	if 3+length > len(res.data) {
		return nil, fmt.Errorf("SMB1 read file response has invalid data bounds")
	}
	return append([]byte(nil), res.data[3:3+length]...), nil
}

func (c *pipeConn) writeFile(fid uint16, data []byte, offset uint32) (int, error) {
	return c.writeAndXTo(fid, data, offset, 0)
}

func (c *pipeConn) closeFile(fid uint16) error {
	params := make([]byte, 6)
	binary.LittleEndian.PutUint16(params[0:], fid)
	req := buildSMB(cmdClose, c, 3, params, nil)
	res, err := c.exchange(req)
	if err != nil {
		return err
	}
	return checkStatus(res, statusOK, "SMB1 close file")
}

func (c *pipeConn) startService(name, binaryPath string) (uint32, uint32, uint32, string, error) {
	if err := c.treeConnectShare("IPC$"); err != nil {
		return 0, 0, 0, "", err
	}
	if err := c.openPipe("svcctl"); err != nil {
		return 0, 0, 0, "", err
	}
	defer func() { _ = c.closeFID() }()

	svc := serviceControl{client: c}
	if err := svc.bind(); err != nil {
		return 0, 0, 0, "", err
	}
	scm, err := svc.openSCManager()
	if err != nil {
		return 0, 0, 0, "", err
	}
	defer svc.closeHandle(scm)
	service, err := svc.createService(scm, name, binaryPath)
	if err != nil {
		return 0, 0, 0, "", err
	}
	defer svc.closeHandle(service)
	startStatus, err := svc.startService(service)
	if err != nil {
		return 0, 0, 0, "", err
	}
	status, err := svc.queryServiceStatus(service)
	if err != nil {
		return startStatus, 0, 0, err.Error(), nil
	}
	return startStatus, status.CurrentState, status.Win32ExitCode, "", nil
}

func (c *pipeConn) scheduleAT(command string) (uint32, uint32, error) {
	return c.scheduleATAt(command, c.currentServerTime().Add(20*time.Second))
}

func (c *pipeConn) scheduleATAt(command string, when time.Time) (uint32, uint32, error) {
	if err := c.treeConnectShare("IPC$"); err != nil {
		return 0, 0, err
	}
	if err := c.openPipe("atsvc"); err != nil {
		return 0, 0, err
	}
	defer func() { _ = c.closeFID() }()

	at := atService{client: c}
	if err := at.bind(); err != nil {
		return 0, 0, err
	}
	return at.jobAdd(command, when)
}

func (c *pipeConn) currentServerTime() time.Time {
	if c.serverTime.IsZero() || c.serverTimeSeen.IsZero() {
		return time.Now()
	}
	return c.serverTime.Add(time.Since(c.serverTimeSeen))
}

func serviceBinaryPath(remotePath, serviceName, args string) string {
	binaryPath := quoteWindowsArg(remotePath) + " --service " + serviceName
	args = strings.TrimSpace(args)
	if args != "" {
		binaryPath += " " + args
	}
	return binaryPath
}

func scheduledBinaryPath(remotePath, args string) string {
	binaryPath := quoteWindowsArg(remotePath)
	args = strings.TrimSpace(args)
	if args != "" {
		binaryPath += " " + args
	}
	return binaryPath
}

func quoteWindowsArg(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

type serviceControl struct {
	client *pipeConn
	callID uint32
}

func (s *serviceControl) bind() error {
	return bindRPC(s.client, svcctlUUID, 2)
}

func bindRPC(client *pipeConn, uuid string, version uint16) error {
	body := make([]byte, 0, 72)
	body = binary.LittleEndian.AppendUint16(body, dcerpcFragSize)
	body = binary.LittleEndian.AppendUint16(body, dcerpcFragSize)
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = append(body, 1, 0, 0, 0)
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = append(body, 1, 0)
	body = append(body, dcerpcUUID(uuid, version)...)
	body = append(body, dcerpcUUID(ndrUUID, 2)...)
	reply, err := client.transactPipe(dcerpcHeader(dcerpcBind, 1, body))
	if err != nil {
		return err
	}
	if len(reply) < 3 || reply[2] != dcerpcBindAck {
		return fmt.Errorf("DCERPC bind to %s failed", uuid)
	}
	return nil
}

type atService struct {
	client *pipeConn
	callID uint32
}

func (a *atService) bind() error {
	return bindRPC(a.client, atsvcUUID, 1)
}

func (a *atService) request(opnum uint16, stub []byte) ([]byte, error) {
	a.callID++
	body := make([]byte, 0, 8+len(stub))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(stub)))
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint16(body, opnum)
	body = append(body, stub...)
	reply, err := a.client.transactPipe(dcerpcHeader(dcerpcRequest, a.callID, body))
	if err != nil {
		return nil, fmt.Errorf("ATSVC opnum %d failed: %w", opnum, err)
	}
	if len(reply) < dcerpcRespHdr {
		return nil, fmt.Errorf("ATSVC opnum %d response too short", opnum)
	}
	if reply[2] != dcerpcResponse {
		return nil, fmt.Errorf("ATSVC opnum %d returned DCERPC packet type %d: % x", opnum, reply[2], reply)
	}
	return reply[dcerpcRespHdr:], nil
}

func (a *atService) jobAdd(command string, when time.Time) (uint32, uint32, error) {
	stub := make([]byte, 0, 64+len(command)*2)
	stub = binary.LittleEndian.AppendUint32(stub, 0)
	stub = append(stub, atInfo(command, when)...)
	reply, err := a.request(atOpJobAdd, stub)
	if err != nil {
		return 0, 0, err
	}
	if len(reply) < 8 {
		return 0, 0, fmt.Errorf("NetrJobAdd response too short: % x", reply)
	}
	jobID := binary.LittleEndian.Uint32(reply[:4])
	status := binary.LittleEndian.Uint32(reply[len(reply)-4:])
	return status, jobID, nil
}

func atInfo(command string, when time.Time) []byte {
	when = when.Truncate(time.Minute).Add(time.Minute)
	midnight := time.Date(when.Year(), when.Month(), when.Day(), 0, 0, 0, 0, when.Location())
	jobTime := uint32(when.Sub(midnight) / time.Millisecond)
	out := make([]byte, 0, 32+len(command)*2)
	out = binary.LittleEndian.AppendUint32(out, jobTime)
	out = binary.LittleEndian.AppendUint32(out, 0)
	out = append(out, 0, jobAddCurrentDate|jobNonInteractive, 0, 0)
	out = binary.LittleEndian.AppendUint32(out, 0x00020004)
	out = append(out, ndrWString(command)...)
	return out
}

func (s *serviceControl) request(opnum uint16, stub []byte) ([]byte, error) {
	s.callID++
	body := make([]byte, 0, 8+len(stub))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(stub)))
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint16(body, opnum)
	body = append(body, stub...)
	reply, err := s.client.transactPipe(dcerpcHeader(dcerpcRequest, s.callID, body))
	if err != nil {
		return nil, fmt.Errorf("SVCCTL opnum %d failed: %w", opnum, err)
	}
	if len(reply) < dcerpcRespHdr {
		return nil, fmt.Errorf("SVCCTL opnum %d response too short", opnum)
	}
	if reply[2] != dcerpcResponse {
		return nil, fmt.Errorf("SVCCTL opnum %d returned DCERPC packet type %d: % x", opnum, reply[2], reply)
	}
	return reply[dcerpcRespHdr:], nil
}

func (s *serviceControl) openSCManager() ([]byte, error) {
	stub := make([]byte, 0, 12)
	stub = binary.LittleEndian.AppendUint32(stub, 0)
	stub = binary.LittleEndian.AppendUint32(stub, 0)
	stub = binary.LittleEndian.AppendUint32(stub, scmAll)
	reply, err := s.request(svcOpOpenSCM, stub)
	if err != nil {
		return nil, err
	}
	if len(reply) < serviceHandleLen+4 {
		return nil, fmt.Errorf("OpenSCManagerW response too short: % x", reply)
	}
	if status := binary.LittleEndian.Uint32(reply[serviceHandleLen:]); status != 0 {
		return nil, fmt.Errorf("OpenSCManagerW failed: rc=0x%x reply=% x", status, reply)
	}
	return append([]byte(nil), reply[:serviceHandleLen]...), nil
}

func (s *serviceControl) createService(scm []byte, name, binaryPath string) ([]byte, error) {
	handle, status, err := s.tryCreateService(scm, name, binaryPath)
	if err != nil {
		return nil, err
	}
	if status == 0 {
		return handle, nil
	}
	if status != errorServiceExists {
		return nil, fmt.Errorf("CreateServiceW failed: rc=0x%x", status)
	}
	stale, err := s.openService(scm, name)
	if err != nil {
		return nil, err
	}
	_ = s.deleteService(stale)
	_ = s.closeHandle(stale)
	handle, status, err = s.tryCreateService(scm, name, binaryPath)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, fmt.Errorf("CreateServiceW after deleting stale service failed: rc=0x%x", status)
	}
	return handle, nil
}

func (s *serviceControl) tryCreateService(scm []byte, name, binaryPath string) ([]byte, uint32, error) {
	stub := append([]byte{}, scm...)
	stub = append(stub, ndrWString(name)...)
	stub = binary.LittleEndian.AppendUint32(stub, 1)
	stub = append(stub, ndrWString(name)...)
	stub = binary.LittleEndian.AppendUint32(stub, serviceAll)
	stub = binary.LittleEndian.AppendUint32(stub, serviceInteractive)
	stub = binary.LittleEndian.AppendUint32(stub, serviceDemandStart)
	stub = binary.LittleEndian.AppendUint32(stub, serviceErrorIgnore)
	stub = append(stub, ndrWString(binaryPath)...)
	for i := 0; i < 7; i++ {
		stub = binary.LittleEndian.AppendUint32(stub, 0)
	}
	reply, err := s.request(svcOpCreate, stub)
	if err != nil {
		return nil, 0, err
	}
	if len(reply) < 4 {
		return nil, 0, fmt.Errorf("CreateServiceW response too short")
	}
	status := binary.LittleEndian.Uint32(reply[len(reply)-4:])
	if status != 0 {
		return nil, status, nil
	}
	return createServiceHandleFromReply(reply)
}

func createServiceHandleFromReply(reply []byte) ([]byte, uint32, error) {
	if len(reply) < serviceHandleLen+4 {
		return nil, 0, fmt.Errorf("CreateServiceW handle missing")
	}
	status := binary.LittleEndian.Uint32(reply[len(reply)-4:])
	if status != 0 {
		return nil, status, nil
	}
	return append([]byte(nil), reply[4:4+serviceHandleLen]...), 0, nil
}

func (s *serviceControl) openService(scm []byte, name string) ([]byte, error) {
	stub := append([]byte{}, scm...)
	stub = append(stub, ndrWString(name)...)
	stub = binary.LittleEndian.AppendUint32(stub, serviceAll)
	reply, err := s.request(svcOpOpenSvc, stub)
	if err != nil {
		return nil, err
	}
	if len(reply) < serviceHandleLen+4 || binary.LittleEndian.Uint32(reply[serviceHandleLen:]) != 0 {
		return nil, fmt.Errorf("OpenServiceW failed")
	}
	return append([]byte(nil), reply[:serviceHandleLen]...), nil
}

func (s *serviceControl) startService(service []byte) (uint32, error) {
	stub := append([]byte{}, service...)
	stub = binary.LittleEndian.AppendUint32(stub, 0)
	stub = binary.LittleEndian.AppendUint32(stub, 0)
	return s.startServiceWithStub(stub)
}

func (s *serviceControl) startServiceWithStub(stub []byte) (uint32, error) {
	reply, err := s.request(svcOpStart, stub)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			return 0x41d, nil
		}
		return 0, err
	}
	if len(reply) < 4 {
		return 0, fmt.Errorf("StartServiceW response too short")
	}
	return binary.LittleEndian.Uint32(reply[len(reply)-4:]), nil
}

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

func (s *serviceControl) queryServiceStatus(service []byte) (serviceStatus, error) {
	reply, err := s.request(svcOpQuery, service)
	if err != nil {
		return serviceStatus{}, err
	}
	return serviceStatusFromReply(reply)
}

func serviceStatusFromReply(reply []byte) (serviceStatus, error) {
	if len(reply) < 28 {
		return serviceStatus{}, fmt.Errorf("QueryServiceStatus response too short: len=%d reply=% x", len(reply), reply)
	}
	if len(reply) >= 32 {
		if status := binary.LittleEndian.Uint32(reply[28:32]); status != 0 {
			return serviceStatus{}, fmt.Errorf("QueryServiceStatus failed: rc=0x%x", status)
		}
	}
	return serviceStatus{
		ServiceType:             binary.LittleEndian.Uint32(reply[0:4]),
		CurrentState:            binary.LittleEndian.Uint32(reply[4:8]),
		ControlsAccepted:        binary.LittleEndian.Uint32(reply[8:12]),
		Win32ExitCode:           binary.LittleEndian.Uint32(reply[12:16]),
		ServiceSpecificExitCode: binary.LittleEndian.Uint32(reply[16:20]),
		CheckPoint:              binary.LittleEndian.Uint32(reply[20:24]),
		WaitHint:                binary.LittleEndian.Uint32(reply[24:28]),
	}, nil
}

func (s *serviceControl) deleteService(service []byte) error {
	_, err := s.request(svcOpDelete, service)
	return err
}

func (s *serviceControl) closeHandle(handle []byte) error {
	_, err := s.request(svcOpClose, handle)
	return err
}

func dcerpcHeader(packetType byte, callID uint32, body []byte) []byte {
	header := []byte{5, 0, packetType, dcerpcFirstLast}
	header = append(header, []byte(dcerpcDREP)...)
	header = binary.LittleEndian.AppendUint16(header, uint16(16+len(body)))
	header = binary.LittleEndian.AppendUint16(header, 0)
	header = binary.LittleEndian.AppendUint32(header, callID)
	return append(header, body...)
}

func dcerpcUUID(text string, version uint16) []byte {
	parts := strings.Split(text, "-")
	if len(parts) != 5 {
		return nil
	}
	out := make([]byte, 0, 20)
	appendReversedHex := func(hexText string, byteCount int) {
		start := len(out)
		for i := 0; i < byteCount; i++ {
			var b byte
			fmt.Sscanf(hexText[i*2:i*2+2], "%02x", &b)
			out = append(out, b)
		}
		for i, j := start, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	appendHex := func(hexText string) {
		for i := 0; i < len(hexText); i += 2 {
			var b byte
			fmt.Sscanf(hexText[i:i+2], "%02x", &b)
			out = append(out, b)
		}
	}
	appendReversedHex(parts[0], 4)
	appendReversedHex(parts[1], 2)
	appendReversedHex(parts[2], 2)
	appendHex(parts[3])
	appendHex(parts[4])
	out = binary.LittleEndian.AppendUint16(out, version)
	return binary.LittleEndian.AppendUint16(out, 0)
}

func ndrWString(text string) []byte {
	encoded := utf16le(text)
	count := uint32(len(encoded) / 2)
	out := make([]byte, 0, 12+len(encoded)+3)
	out = binary.LittleEndian.AppendUint32(out, count)
	out = binary.LittleEndian.AppendUint32(out, 0)
	out = binary.LittleEndian.AppendUint32(out, count)
	out = append(out, encoded...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}
