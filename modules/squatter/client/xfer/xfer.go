// Package xfer implements the getfile/putfile streaming sub-protocol
// (see src/mux/file_xfer.h) on the client side. Files of any size move through
// one fixed-size buffer; nothing larger than a chunk is ever resident.
package xfer

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
)

// Message tags carried in DATA frame payloads.
const (
	tagStat = 'S' // status line: "OK ..." / "ERR ..."
	tagData = 'D' // a file chunk
	tagEOF  = 'E' // end of data
	chunk   = 32768
)

// GetFile opens a getfile stream for remote and writes the file's bytes to dst,
// returning the number of bytes received. The stream id must be unused.
func GetFile(conn io.Writer, r *bufio.Reader, streamID uint64, remote string, dst io.Writer) (int64, error) {
	if err := wire.WriteFrame(conn, wire.KindOpen, streamID, wire.EncodeOpen("getfile", []string{remote})); err != nil {
		return 0, err
	}
	kind, _, payload, err := wire.ReadFrame(r)
	if err != nil {
		return 0, err
	}
	if kind == wire.KindClose || len(payload) == 0 || payload[0] != tagStat {
		return 0, errors.New("getfile: no status from server")
	}
	status := string(payload[1:])
	if !strings.HasPrefix(status, "OK") {
		drain(r)
		return 0, errors.New(status)
	}

	var received int64
	for {
		kind, _, payload, err := wire.ReadFrame(r)
		if err != nil {
			return received, err
		}
		if kind == wire.KindClose {
			return received, nil
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case tagData:
			n, werr := dst.Write(payload[1:])
			received += int64(n)
			if werr != nil {
				return received, werr
			}
		case tagEOF:
			// data complete; the CLOSE frame follows
		}
	}
}

// PutFile opens a putfile stream for remote and streams src to it, returning the
// number of bytes sent and the server's final status line ("OK <bytes>").
func PutFile(conn io.Writer, r *bufio.Reader, streamID uint64, src io.Reader, remote string) (sent int64, ack string, err error) {
	if err = wire.WriteFrame(conn, wire.KindOpen, streamID, wire.EncodeOpen("putfile", []string{remote})); err != nil {
		return
	}
	kind, _, payload, rerr := wire.ReadFrame(r)
	if rerr != nil {
		return 0, "", rerr
	}
	if kind == wire.KindClose || len(payload) == 0 || payload[0] != tagStat {
		return 0, "", errors.New("putfile: no status from server")
	}
	status := string(payload[1:])
	if !strings.HasPrefix(status, "OK") {
		drain(r)
		return 0, "", errors.New(status)
	}

	buf := make([]byte, 1+chunk) // the single fixed buffer
	buf[0] = tagData
	for {
		n, e := src.Read(buf[1:])
		if n > 0 {
			if err = wire.WriteFrame(conn, wire.KindData, streamID, buf[:1+n]); err != nil {
				return
			}
			sent += int64(n)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return sent, "", e
		}
	}
	if err = wire.WriteFrame(conn, wire.KindData, streamID, []byte{tagEOF}); err != nil {
		return
	}

	for {
		kind, _, payload, e := wire.ReadFrame(r)
		if e != nil {
			return sent, ack, e
		}
		if kind == wire.KindClose {
			return sent, ack, nil
		}
		if len(payload) > 0 && payload[0] == tagStat {
			ack = string(payload[1:])
		}
	}
}

func drain(r *bufio.Reader) {
	for {
		kind, _, _, err := wire.ReadFrame(r)
		if err != nil || kind == wire.KindClose {
			return
		}
	}
}
