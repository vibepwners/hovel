package framing

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const DefaultMaxBytes = 64 * 1024 * 1024

type Reader struct {
	reader   *bufio.Reader
	maxBytes int
}

func NewReader(reader io.Reader, maxBytes int) *Reader {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	return &Reader{reader: bufio.NewReader(reader), maxBytes: maxBytes}
}

func (r *Reader) ReadJSON(value any) error {
	body, err := r.ReadBody()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, value); err != nil {
		return fmt.Errorf("invalid JSON frame body: %w", err)
	}
	return nil
}

func (r *Reader) ReadBody() ([]byte, error) {
	contentLength := -1
	sawHeader := false
	for {
		line, err := r.reader.ReadString('\n')
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
			return nil, fmt.Errorf("malformed frame header %q", line)
		}
		if strings.EqualFold(strings.TrimSpace(name), "content-length") {
			length, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || length < 0 {
				return nil, fmt.Errorf("invalid Content-Length")
			}
			if length > r.maxBytes {
				return nil, fmt.Errorf("Content-Length %d exceeds maximum %d", length, r.maxBytes)
			}
			contentLength = length
		}
	}
	if contentLength < 0 {
		return nil, fmt.Errorf("missing Content-Length")
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(r.reader, body); err != nil {
		return nil, fmt.Errorf("truncated frame body: %w", err)
	}
	return body, nil
}

func WriteJSON(writer io.Writer, message any) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(body)); err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}
