package smbpipe

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

const (
	defaultPort    = 445
	defaultTimeout = 10 * time.Second
	ipcShare       = "IPC$"
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
		conn, err := dial(opts)
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

func dial(opts Options) (io.ReadWriteCloser, error) {
	conn, err := smb.NewConnection(smb.Options{
		Host:        opts.Host,
		Port:        opts.Port,
		DialTimeout: opts.Timeout,
		Initiator: &spnego.NTLMInitiator{
			User:      opts.Username,
			Password:  opts.Password,
			Domain:    opts.Domain,
			LocalUser: opts.Domain == "",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("smb connect %s:%s: %w", opts.Host, strconv.Itoa(opts.Port), err)
	}

	createOpts := smb.NewCreateReqOpts()
	createOpts.DesiredAccess = smb.FAccMaskFileReadData |
		smb.FAccMaskFileWriteData |
		smb.FAccMaskFileReadEA |
		smb.FAccMaskFileWriteEA |
		smb.FAccMaskFileReadAttributes |
		smb.FAccMaskFileWriteAttributes |
		smb.FAccMaskReadControl |
		smb.FAccMaskSynchronize
	createOpts.CreateOpts = smb.FileNonDirectoryFile

	file, err := conn.OpenFileExt(ipcShare, opts.Pipe, createOpts)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open smb pipe %s: %w", opts.Pipe, err)
	}
	return &pipeConn{conn: conn, file: file}, nil
}

type pipeConn struct {
	conn *smb.Connection
	file *smb.File
}

func (c *pipeConn) Read(p []byte) (int, error) {
	return c.file.ReadFile(p, 0)
}

func (c *pipeConn) Write(p []byte) (int, error) {
	return c.file.WriteFile(p, 0)
}

func (c *pipeConn) Close() error {
	fileErr := c.file.CloseFile()
	c.conn.Close()
	return fileErr
}
