package smbpipe

import (
	"context"
	"testing"
	"time"
)

func TestNormalizePipePathForIPCShare(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "bare", in: "alpha", want: `alpha`},
		{name: "local", in: `\\.\pipe\alpha`, want: `alpha`},
		{name: "remote", in: `\\target\pipe\alpha`, want: `alpha`},
		{name: "nested remote", in: `\\target\pipe\alpha\beta`, want: `alpha\beta`},
		{name: "slash trimmed", in: `\alpha`, want: `alpha`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizePipePath(tc.in); got != tc.want {
				t.Fatalf("NormalizePipePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOptionsDefaultSMBPortAndTimeout(t *testing.T) {
	opts := Options{Host: "target", Username: "u", Password: "p"}
	normalized := opts.normalized()

	if normalized.Port != 445 {
		t.Fatalf("port = %d, want 445", normalized.Port)
	}
	if normalized.Timeout != 10*time.Second {
		t.Fatalf("timeout = %s, want 10s", normalized.Timeout)
	}
}

func TestDialerRejectsMissingHostPipeAndUsername(t *testing.T) {
	d := Dialer{}
	for _, opts := range []Options{
		{Pipe: "pipe", Username: "u", Password: "p"},
		{Host: "target", Username: "u", Password: "p"},
		{Host: "target", Pipe: "pipe", Password: "p"},
	} {
		if _, err := d.Dial(context.Background(), opts); err == nil {
			t.Fatalf("Dial(%#v) succeeded, want validation error", opts)
		}
	}
}
