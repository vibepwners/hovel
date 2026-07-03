// Package wire implements the squatter mux wire protocol: a 16-byte
// little-endian frame header (length, kind, flags, stream_id) followed by the
// payload, plus the hand-encoded OpenStream control message.
//
// It is the shared, first-class definition of the protocol used by the client
// (cmd/squatterctl) and the functional test harness (functest).
package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame kinds (see src/mux/frame.h).
const (
	KindData    uint16 = 0 // payload is module raw bytes
	KindOpen    uint16 = 1 // payload is an OpenStream protobuf
	KindClose   uint16 = 2 // payload is a CloseStream protobuf (often empty)
	KindControl uint16 = 3 // payload is a StreamEvent protobuf
)

const (
	EventStarted     uint32 = 1
	EventInteractive uint32 = 2
	EventExited      uint32 = 3
	EventError       uint32 = 4
	EventDebug       uint32 = 5
)

// HeaderSize is the fixed frame header length in bytes.
const (
	HeaderSize = 16
	MaxPayload = 1 << 20
)

// WriteFrame writes one framed message to w.
func WriteFrame(w io.Writer, kind uint16, streamID uint64, payload []byte) error {
	var hdr [HeaderSize]byte
	if len(payload) > MaxPayload {
		return fmt.Errorf("squatter frame payload too large: %d", len(payload))
	}
	binary.LittleEndian.PutUint32(hdr[0:], uint32(len(payload)))
	binary.LittleEndian.PutUint16(hdr[4:], kind)
	binary.LittleEndian.PutUint16(hdr[6:], 0) // flags
	binary.LittleEndian.PutUint64(hdr[8:], streamID)
	if err := writeFull(w, hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if err := writeFull(w, payload); err != nil {
			return err
		}
	}
	return nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
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
	if length > MaxPayload {
		err = fmt.Errorf("squatter frame payload too large: %d", length)
		return
	}
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

type StreamEvent struct {
	Kind    uint32
	Code    uint32
	Message string
}

func EncodeClose(code uint32) []byte {
	if code == 0 {
		return nil
	}
	var b []byte
	return appendVarintField(b, 1, uint64(code))
}

func DecodeClose(payload []byte) (uint32, error) {
	var code uint32
	for len(payload) > 0 {
		tag, n, err := consumeVarint(payload)
		if err != nil {
			return 0, err
		}
		payload = payload[n:]
		field, wireType := tag>>3, tag&0x7
		if wireType != 0 {
			return 0, io.ErrUnexpectedEOF
		}
		value, used, err := consumeVarint(payload)
		if err != nil {
			return 0, err
		}
		payload = payload[used:]
		if field == 1 {
			code = uint32(value)
		}
	}
	return code, nil
}

func EncodeStreamEvent(event StreamEvent) []byte {
	var b []byte
	if event.Kind != 0 {
		b = appendVarintField(b, 1, uint64(event.Kind))
	}
	if event.Code != 0 {
		b = appendVarintField(b, 2, uint64(event.Code))
	}
	if event.Message != "" {
		b = appendLenDelim(b, 3, []byte(event.Message))
	}
	return b
}

func DecodeStreamEvent(payload []byte) (StreamEvent, error) {
	var event StreamEvent
	for len(payload) > 0 {
		tag, n, err := consumeVarint(payload)
		if err != nil {
			return event, err
		}
		payload = payload[n:]
		field, wireType := tag>>3, tag&0x7
		switch wireType {
		case 0:
			value, used, err := consumeVarint(payload)
			if err != nil {
				return event, err
			}
			payload = payload[used:]
			switch field {
			case 1:
				event.Kind = uint32(value)
			case 2:
				event.Code = uint32(value)
			}
		case 2:
			length, used, err := consumeVarint(payload)
			if err != nil {
				return event, err
			}
			payload = payload[used:]
			if uint64(len(payload)) < length {
				return event, io.ErrUnexpectedEOF
			}
			n := int(length)
			value := payload[:n]
			payload = payload[n:]
			if field == 3 {
				event.Message = string(value)
			}
		default:
			return event, io.ErrUnexpectedEOF
		}
	}
	return event, nil
}

func appendLenDelim(b []byte, field int, data []byte) []byte {
	b = append(b, byte(field<<3|2)) // tag: field number, wire type 2 (LEN)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func appendVarintField(b []byte, field int, value uint64) []byte {
	b = appendVarint(b, uint64(field<<3))
	return appendVarint(b, value)
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func consumeVarint(b []byte) (uint64, int, error) {
	var value uint64
	for i, c := range b {
		if i >= 10 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		value |= uint64(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			return value, i + 1, nil
		}
	}
	return 0, 0, io.ErrUnexpectedEOF
}
