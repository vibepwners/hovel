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
	"encoding/json"
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
	contentLength := -1
	sawHeader := false
	for {
		line, err := fr.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && !sawHeader && line == "" {
				return nil, io.EOF
			}
			return nil, err
		}
		sawHeader = true
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, frameError{fmt.Sprintf("malformed frame header %q", line)}
		}
		if strings.EqualFold(strings.TrimSpace(name), "content-length") {
			length, convErr := strconv.Atoi(strings.TrimSpace(value))
			if convErr != nil || length < 0 {
				return nil, frameError{"invalid Content-Length"}
			}
			if length > maxFrameBytes {
				return nil, frameError{fmt.Sprintf("Content-Length %d exceeds maximum %d", length, maxFrameBytes)}
			}
			contentLength = length
		}
	}
	if contentLength < 0 {
		return nil, frameError{"missing Content-Length"}
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(fr.reader, body); err != nil {
		return nil, frameError{"truncated frame body"}
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(body, &message); err != nil {
		return nil, frameError{"invalid JSON frame body"}
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
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if _, err := fmt.Fprintf(fw.writer, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		return err
	}
	_, err = fw.writer.Write(body)
	return err
}
