package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

type shortWriter struct {
	buf bytes.Buffer
	max int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}

func TestReadFrameRejectsOversizePayload(t *testing.T) {
	var hdr [HeaderSize]byte

	binary.LittleEndian.PutUint32(hdr[0:], MaxPayload+1)
	binary.LittleEndian.PutUint16(hdr[4:], KindData)

	_, _, _, err := ReadFrame(bytes.NewReader(hdr[:]))
	if err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("ReadFrame error = %v, want payload-too-large error", err)
	}
}

func TestWriteFrameRetriesShortWrites(t *testing.T) {
	w := &shortWriter{max: 3}
	payload := []byte("hello")

	if err := WriteFrame(w, KindData, 42, payload); err != nil {
		t.Fatal(err)
	}
	kind, sid, got, err := ReadFrame(bytes.NewReader(w.buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if kind != KindData || sid != 42 || !bytes.Equal(got, payload) {
		t.Fatalf("frame = kind %d sid %d payload %q", kind, sid, got)
	}
}
