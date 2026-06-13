// Package wire implements the squatter mux wire protocol: a 16-byte
// little-endian frame header (length, kind, flags, stream_id) followed by the
// payload, plus the hand-encoded OpenStream control message.
//
// It is the shared, first-class definition of the protocol used by the client
// (cmd/squatterctl) and the functional test harness (functest).
package wire

import (
	"encoding/binary"
	"io"
)

// Frame kinds (see src/mux/frame.h).
const (
	KindData  uint16 = 0 // payload is module bytes
	KindOpen  uint16 = 1 // payload is an OpenStream protobuf
	KindClose uint16 = 2 // payload is a CloseStream protobuf (often empty)
)

// HeaderSize is the fixed frame header length in bytes.
const HeaderSize = 16

// WriteFrame writes one framed message to w.
func WriteFrame(w io.Writer, kind uint16, streamID uint64, payload []byte) error {
	var hdr [HeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:], uint32(len(payload)))
	binary.LittleEndian.PutUint16(hdr[4:], kind)
	binary.LittleEndian.PutUint16(hdr[6:], 0) // flags
	binary.LittleEndian.PutUint64(hdr[8:], streamID)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads one complete frame from r, blocking until the whole frame has
// arrived (it reassembles a frame split across reads).
func ReadFrame(r io.Reader) (kind uint16, streamID uint64, payload []byte, err error) {
	var hdr [HeaderSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	length := binary.LittleEndian.Uint32(hdr[0:])
	kind = binary.LittleEndian.Uint16(hdr[4:])
	streamID = binary.LittleEndian.Uint64(hdr[8:])
	if length > 0 {
		payload = make([]byte, length)
		if _, err = io.ReadFull(r, payload); err != nil {
			return
		}
	}
	return
}

// EncodeOpen encodes an OpenStream{module, args} protobuf message
// (proto3: field 1 = module string, field 2 = repeated args string).
func EncodeOpen(module string, args []string) []byte {
	var b []byte
	b = appendLenDelim(b, 1, []byte(module))
	for _, a := range args {
		b = appendLenDelim(b, 2, []byte(a))
	}
	return b
}

func appendLenDelim(b []byte, field int, data []byte) []byte {
	b = append(b, byte(field<<3|2)) // tag: field number, wire type 2 (LEN)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
