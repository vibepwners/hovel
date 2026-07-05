package commandmode

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestMain(m *testing.M) {
	moduleConfigDir, err := os.MkdirTemp("", "hovel-commandmode-test-*")
	if err != nil {
		panic(err)
	}
	moduleConfigPath := filepath.Join(moduleConfigDir, "hovel-modules.json")
	if err := os.WriteFile(moduleConfigPath, []byte(`{"modules":[]}`+"\n"), 0o600); err != nil {
		panic(err)
	}
	if err := os.Setenv("HOVEL_MODULE_CONFIG", moduleConfigPath); err != nil {
		panic(err)
	}
	code := m.Run()
	if err := os.RemoveAll(moduleConfigDir); err != nil {
		panic(err)
	}
	os.Exit(code)
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
	if s.next >= len(s.values) {
		s.next++
		return fmt.Sprintf("event-%d", s.next)
	}
	value := s.values[s.next]
	s.next++
	return value
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func waitFor(t *testing.T, condition func() bool) {
	testsupport.WaitFor(t, condition)
}

type eventRecorder struct {
	events []event.Event
}

func (r *eventRecorder) Append(_ context.Context, evt event.Event) error {
	r.events = append(r.events, evt)
	return nil
}

func hasEvent(events []event.Event, typ string) bool {
	for _, evt := range events {
		if evt.Type.String() == typ {
			return true
		}
	}
	return false
}
