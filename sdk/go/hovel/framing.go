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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

const maxFrameBytes = 64 * 1024 * 1024

// frameError wraps a malformed or truncated frame on the wire.
type frameError struct{ msg string }

func (e frameError) Error() string { return "hovel: " + e.msg }

// frameReader decodes length-prefixed JSON-RPC messages from a stream.
type frameReader struct {
	reader *bufio.Reader
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{reader: bufio.NewReader(r)}
}

// read returns the next message, or io.EOF when the stream is closed cleanly
// between frames.
func (fr *frameReader) read() (map[string]json.RawMessage, error) {
	size, err := fr.readHeader()
	if err != nil {
		return nil, err
	}
	if size > maxFrameBytes {
		return nil, frameError{fmt.Sprintf("frame too large: %d bytes", size)}
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(fr.reader, body); err != nil {
		return nil, err
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(body, &message); err != nil {
		return nil, frameError{err.Error()}
	}
	return message, nil
}

func (fr *frameReader) readHeader() (int, error) {
	size := -1
	for {
		line, err := fr.reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return 0, frameError{"malformed frame header"}
		}
		if !strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			continue
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || parsed < 0 {
			return 0, frameError{"invalid Content-Length header"}
		}
		size = parsed
	}
	if size < 0 {
		return 0, frameError{"missing Content-Length header"}
	}
	return size, nil
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
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(message); err != nil {
		return err
	}
	if body.Len() > maxFrameBytes {
		return errors.New("hovel: frame too large")
	}
	if _, err := fmt.Fprintf(fw.writer, "Content-Length: %d\r\n\r\n", body.Len()); err != nil {
		return err
	}
	_, err := fw.writer.Write(body.Bytes())
	return err
}
