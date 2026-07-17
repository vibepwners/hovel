package xfer

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vibepwners/hovel/payloads/squatter/client/wire"
)

func TestGetFileStreamsDataUntilClose(t *testing.T) {
	responses := frames(t,
		frame{wire.KindData, []byte("SOK 6")},
		frame{wire.KindData, nil},
		frame{wire.KindData, []byte("Dabc")},
		frame{wire.KindData, []byte("E")},
		frame{wire.KindData, []byte("Ddef")},
		frame{wire.KindClose, nil},
	)
	var request bytes.Buffer
	var dst bytes.Buffer
	n, err := GetFile(&request, bufio.NewReader(bytes.NewReader(responses)), 19, `C:\temp\x`, &dst)
	if err != nil || n != 6 || dst.String() != "abcdef" {
		t.Fatalf("GetFile = %d, %q, %v", n, dst.String(), err)
	}
	assertOpenRequest(t, request.Bytes(), 19)
}

func TestGetFileRejectsProtocolAndStatusFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		responses []byte
	}{
		{name: "read", responses: []byte("short")},
		{name: "close", responses: frames(t, frame{wire.KindClose, nil})},
		{name: "empty", responses: frames(t, frame{wire.KindData, nil})},
		{name: "wrong tag", responses: frames(t, frame{wire.KindData, []byte("Ddata")})},
		{name: "server status", responses: frames(t, frame{wire.KindData, []byte("SERR missing")}, frame{wire.KindClose, nil})},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := GetFile(io.Discard, bufio.NewReader(bytes.NewReader(test.responses)), 1, "remote", io.Discard)
			if err == nil {
				t.Fatal("GetFile returned nil error")
			}
		})
	}

	_, err := GetFile(&alwaysFailWriter{}, bufio.NewReader(bytes.NewReader(nil)), 1, "remote", io.Discard)
	if err == nil {
		t.Fatal("GetFile accepted failed request write")
	}
}

func TestGetFileReturnsPartialCountAndDestinationError(t *testing.T) {
	want := errors.New("destination full")
	responses := frames(t,
		frame{wire.KindData, []byte("SOK")},
		frame{wire.KindData, []byte("Dabc")},
	)
	n, err := GetFile(io.Discard, bufio.NewReader(bytes.NewReader(responses)), 1, "remote", partialErrorWriter{n: 2, err: want})
	if n != 2 || !errors.Is(err, want) {
		t.Fatalf("GetFile = %d, %v, want 2, %v", n, err, want)
	}

	responses = frames(t, frame{wire.KindData, []byte("SOK")}, frame{wire.KindData, []byte("Dx")})
	n, err = GetFile(io.Discard, bufio.NewReader(bytes.NewReader(responses)), 1, "remote", io.Discard)
	if n != 1 || err == nil {
		t.Fatalf("GetFile truncated = %d, %v", n, err)
	}
}

func TestPutFileStreamsChunksAndReturnsAcknowledgement(t *testing.T) {
	responses := frames(t,
		frame{wire.KindData, []byte("SOK ready")},
		frame{wire.KindData, nil},
		frame{wire.KindData, []byte("SOK 40000")},
		frame{wire.KindClose, nil},
	)
	var request bytes.Buffer
	src := bytes.NewReader(bytes.Repeat([]byte{'x'}, 40000))
	sent, ack, err := PutFile(&request, bufio.NewReader(bytes.NewReader(responses)), 23, src, "remote")
	if err != nil || sent != 40000 || ack != "OK 40000" {
		t.Fatalf("PutFile = %d, %q, %v", sent, ack, err)
	}

	r := bufio.NewReader(bytes.NewReader(request.Bytes()))
	kind, sid, _, err := wire.ReadFrame(r)
	if err != nil || kind != wire.KindOpen || sid != 23 {
		t.Fatalf("open frame = %d, %d, %v", kind, sid, err)
	}
	total := 0
	for {
		kind, sid, payload, err := wire.ReadFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		if kind != wire.KindData || sid != 23 || len(payload) == 0 {
			t.Fatalf("data frame = %d, %d, %x", kind, sid, payload)
		}
		if payload[0] == tagEOF {
			break
		}
		if payload[0] != tagData || len(payload)-1 > chunk {
			t.Fatalf("chunk = %x", payload)
		}
		total += len(payload) - 1
	}
	if total != 40000 {
		t.Fatalf("streamed bytes = %d", total)
	}
}

func TestPutFileRejectsProtocolAndStatusFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		responses []byte
	}{
		{name: "read", responses: []byte("short")},
		{name: "close", responses: frames(t, frame{wire.KindClose, nil})},
		{name: "empty", responses: frames(t, frame{wire.KindData, nil})},
		{name: "wrong tag", responses: frames(t, frame{wire.KindData, []byte("Ddata")})},
		{name: "server status", responses: frames(t, frame{wire.KindData, []byte("SERR denied")}, frame{wire.KindData, nil}, frame{wire.KindClose, nil})},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := PutFile(io.Discard, bufio.NewReader(bytes.NewReader(test.responses)), 1, strings.NewReader("x"), "remote")
			if err == nil {
				t.Fatal("PutFile returned nil error")
			}
		})
	}

	_, _, err := PutFile(&alwaysFailWriter{}, bufio.NewReader(bytes.NewReader(nil)), 1, strings.NewReader("x"), "remote")
	if err == nil {
		t.Fatal("PutFile accepted failed request write")
	}
}

func TestPutFilePropagatesSourceWriteAndFinalReadErrors(t *testing.T) {
	ok := frames(t, frame{wire.KindData, []byte("SOK")})
	want := errors.New("source failed")
	sent, _, err := PutFile(io.Discard, bufio.NewReader(bytes.NewReader(ok)), 1, errorReader{data: []byte("abc"), err: want}, "remote")
	if sent != 3 || !errors.Is(err, want) {
		t.Fatalf("PutFile source failure = %d, %v", sent, err)
	}

	writer := &limitedWriter{remaining: wire.HeaderSize + len(wire.EncodeOpen("putfile", []string{"remote"}))}
	_, _, err = PutFile(writer, bufio.NewReader(bytes.NewReader(ok)), 1, strings.NewReader("x"), "remote")
	if err == nil {
		t.Fatal("PutFile accepted data-frame write failure")
	}

	responses := frames(t, frame{wire.KindData, []byte("SOK")})
	sent, _, err = PutFile(io.Discard, bufio.NewReader(bytes.NewReader(responses)), 1, strings.NewReader(""), "remote")
	if sent != 0 || err == nil {
		t.Fatalf("PutFile final read = %d, %v", sent, err)
	}
}

type frame struct {
	kind    uint16
	payload []byte
}

func frames(t *testing.T, values ...frame) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, value := range values {
		if err := wire.WriteFrame(&out, value.kind, 1, value.payload); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func assertOpenRequest(t *testing.T, request []byte, streamID uint64) {
	t.Helper()
	kind, sid, payload, err := wire.ReadFrame(bytes.NewReader(request))
	if err != nil || kind != wire.KindOpen || sid != streamID || len(payload) == 0 {
		t.Fatalf("open request = %d, %d, %x, %v", kind, sid, payload, err)
	}
}

type alwaysFailWriter struct{}

func (*alwaysFailWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type partialErrorWriter struct {
	n   int
	err error
}

func (w partialErrorWriter) Write([]byte) (int, error) { return w.n, w.err }

type errorReader struct {
	data []byte
	err  error
}

func (r errorReader) Read(p []byte) (int, error) {
	return copy(p, r.data), r.err
}

type limitedWriter struct{ remaining int }

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("full")
	}
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	w.remaining -= len(p)
	return len(p), nil
}
