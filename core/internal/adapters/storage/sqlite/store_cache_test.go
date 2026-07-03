package sqlite

import (
	"context"
	"testing"
)

// A first access whose context is already cancelled must not poison the
// connection cache: a later call with a live context has to succeed.
func TestOpenDoesNotCacheFailedOpen(t *testing.T) {
	store := NewStore(t.TempDir())

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
