// Package hovel is the Go SDK for writing Hovel modules.
//
// A module is a separate process that the Hovel daemon launches and drives over
// a small JSON-RPC 2.0 protocol carried on stdin/stdout. Each message is framed
// with an HTTP-style "Content-Length" header so that binary session payloads
// survive the wire intact. Authors implement the [Module] interface and hand it
// to [Serve]; this package takes care of framing, dispatch, logging, and
// sessions.
package hovel

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/Vibe-Pwners/hovel/internal/protocol/framing"
)

const maxFrameBytes = framing.DefaultMaxBytes

// frameError wraps a malformed or truncated frame on the wire.
type frameError struct{ msg string }

func (e frameError) Error() string { return "hovel: " + e.msg }

// frameReader decodes length-prefixed JSON-RPC messages from a stream.
type frameReader struct {
	reader *framing.Reader
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{reader: framing.NewReader(r, maxFrameBytes)}
}

// read returns the next message, or io.EOF when the stream is closed cleanly
// between frames.
func (fr *frameReader) read() (map[string]json.RawMessage, error) {
	var message map[string]json.RawMessage
	if err := fr.reader.ReadJSON(&message); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, frameError{err.Error()}
	}
	return message, nil
}

// frameWriter encodes JSON-RPC messages with a Content-Length header. Writes are
// serialized so that responses and notifications never interleave on stdout.
type frameWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func newFrameWriter(w io.Writer) *frameWriter {
	return &frameWriter{writer: w}
}

func (fw *frameWriter) write(message any) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return framing.WriteJSON(fw.writer, message)
}
