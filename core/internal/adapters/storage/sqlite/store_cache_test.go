package sqlite

import (
	"context"
	"testing"
)

// A first access whose context is already cancelled must not poison the
// connection cache: a later call with a live context has to succeed.
func TestOpenDoesNotCacheFailedOpen(t *testing.T) {
	store := NewStore(t.TempDir())
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close sqlite store: %v", err)
		}
	})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.open(cancelled); err == nil {
		t.Fatal("expected error opening with a cancelled context")
	}

	if _, err := store.open(context.Background()); err != nil {
		t.Fatalf("open after transient failure should succeed, got: %v", err)
	}
}

// Successful opens are cached: repeated calls reuse the same *sql.DB handle
// rather than opening (and migrating) a fresh pool each time.
func TestOpenReusesCachedHandle(t *testing.T) {
	store := NewStore(t.TempDir())
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close sqlite store: %v", err)
		}
	})
	ctx := context.Background()

	first, err := store.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("expected the cached *sql.DB to be reused across open calls")
	}
}

func TestCloseEvictsCachedHandle(t *testing.T) {
	store := NewStore(t.TempDir())
	first, err := store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.PingContext(t.Context()); err == nil {
		t.Fatal("closed cached database still accepted operations")
	}
	second, err := store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close reopened sqlite store: %v", err)
		}
	})
	if first == second {
		t.Fatal("open after Close() reused the evicted database handle")
	}
}
