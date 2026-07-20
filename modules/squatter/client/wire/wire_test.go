package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
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

func TestWriteFrameRejectsOversizePayload(t *testing.T) {
	err := WriteFrame(io.Discard, KindData, 1, make([]byte, MaxPayload+1))
	if err == nil || !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("WriteFrame error = %v, want payload-too-large error", err)
	}
}

func TestWriteFramePropagatesHeaderAndPayloadErrors(t *testing.T) {
	want := errors.New("write failed")
	for _, test := range []struct {
		name   string
		writer io.Writer
	}{
		{name: "header", writer: &failWriter{err: want}},
		{name: "payload", writer: &failAfterWriter{remaining: HeaderSize, err: want}},
		{name: "zero write", writer: zeroWriter{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := WriteFrame(test.writer, KindData, 9, []byte("payload"))
			if err == nil {
				t.Fatal("WriteFrame returned nil error")
			}
			if test.name != "zero write" && !errors.Is(err, want) {
				t.Fatalf("WriteFrame error = %v, want %v", err, want)
			}
			if test.name == "zero write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("WriteFrame error = %v, want short write", err)
			}
		})
	}
}

func TestReadFrameHandlesEmptyAndTruncatedFrames(t *testing.T) {
	var empty bytes.Buffer
	if err := WriteFrame(&empty, KindClose, 55, nil); err != nil {
		t.Fatal(err)
	}
	kind, sid, payload, err := ReadFrame(&empty)
	if err != nil || kind != KindClose || sid != 55 || payload != nil {
		t.Fatalf("ReadFrame = (%d, %d, %v, %v)", kind, sid, payload, err)
	}

	var full bytes.Buffer
	if err := WriteFrame(&full, KindData, 1, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{full.Bytes()[:4], full.Bytes()[:HeaderSize+1]} {
		if _, _, _, err := ReadFrame(bytes.NewReader(data)); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ReadFrame truncated error = %v, want unexpected EOF", err)
		}
	}
}

func TestOpenAndControlMessagesRoundTrip(t *testing.T) {
	open := EncodeOpen(strings.Repeat("m", 130), []string{"one", "two"})
	if len(open) < 140 || open[0] != 0x0a || open[1]&0x80 == 0 {
		t.Fatalf("EncodeOpen result = %x", open)
	}

	if got := EncodeClose(0); got != nil {
		t.Fatalf("EncodeClose(0) = %x, want nil", got)
	}
	for _, code := range []uint32{1, 127, 128, 1<<31 + 7} {
		payload := EncodeClose(code)
		got, err := DecodeClose(payload)
		if err != nil || got != code {
			t.Fatalf("DecodeClose(EncodeClose(%d)) = %d, %v", code, got, err)
		}
	}

	event := StreamEvent{Kind: EventExited, Code: 0xdeadbeef, Message: strings.Repeat("done", 40)}
	got, err := DecodeStreamEvent(EncodeStreamEvent(event))
	if err != nil || !reflect.DeepEqual(got, event) {
		t.Fatalf("DecodeStreamEvent round trip = %#v, %v", got, err)
	}
	got, err = DecodeStreamEvent(nil)
	if err != nil || got != (StreamEvent{}) {
		t.Fatalf("DecodeStreamEvent(nil) = %#v, %v", got, err)
	}
}

func TestDecodersSkipUnknownSupportedFields(t *testing.T) {
	closePayload := appendVarintField(nil, 9, 44)
	closePayload = append(closePayload, EncodeClose(7)...)
	code, err := DecodeClose(closePayload)
	if err != nil || code != 7 {
		t.Fatalf("DecodeClose unknown field = %d, %v", code, err)
	}

	payload := appendVarintField(nil, 9, 100)
	payload = appendLenDelim(payload, 8, []byte("ignored"))
	payload = append(payload, EncodeStreamEvent(StreamEvent{Kind: EventDebug, Code: 2, Message: "ok"})...)
	event, err := DecodeStreamEvent(payload)
	if err != nil || event != (StreamEvent{Kind: EventDebug, Code: 2, Message: "ok"}) {
		t.Fatalf("DecodeStreamEvent unknown fields = %#v, %v", event, err)
	}
}

func TestDecodersRejectMalformedMessages(t *testing.T) {
	malformedVarint := bytes.Repeat([]byte{0x80}, 11)
	closeCases := [][]byte{
		{0x0a, 0x00},
		{0x08},
		malformedVarint,
	}
	for _, payload := range closeCases {
		if _, err := DecodeClose(payload); err == nil {
			t.Fatalf("DecodeClose(%x) returned nil error", payload)
		}
	}

	eventCases := [][]byte{
		{0x08},
		{0x1a},
		{0x1a, 0x05, 'x'},
		{0x0d},
		malformedVarint,
	}
	for _, payload := range eventCases {
		if _, err := DecodeStreamEvent(payload); err == nil {
			t.Fatalf("DecodeStreamEvent(%x) returned nil error", payload)
		}
	}
}

type failWriter struct{ err error }

func (w *failWriter) Write([]byte) (int, error) { return 0, w.err }

type failAfterWriter struct {
	remaining int
	err       error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, w.err
	}
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	w.remaining -= len(p)
	return len(p), nil
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
