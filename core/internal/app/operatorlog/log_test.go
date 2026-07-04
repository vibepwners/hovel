package operatorlog

import "testing"

func TestLogPreservesEntriesAndFields(t *testing.T) {
	elapsed := 0.02
	log := New("HOVEL//RUN", "mock-exploit", []Entry{
		Info("run", "module loaded", Field{Name: "module", Value: "mock-exploit"}).
			WithChain("alpha").
			WithModule("mock-exploit").
			WithAttributes(map[string]string{"target": "mock://target"}).
			WithElapsed(elapsed),
		Success("run", "completed", Field{Name: "state", Value: "succeeded"}),
	})

	if log.Title != "HOVEL//RUN" {
		t.Fatalf("title = %q", log.Title)
	}
	if len(log.Entries()) != 2 {
		t.Fatalf("entry count = %d, want 2", len(log.Entries()))
	}
	if log.Entries()[0].Fields[0].Name != "module" {
		t.Fatalf("field name = %q, want module", log.Entries()[0].Fields[0].Name)
	}
	if log.Entries()[0].Kind != KindEvent {
		t.Fatalf("kind = %q, want %q", log.Entries()[0].Kind, KindEvent)
	}
	if got := log.Entries()[0].ChainName; got != "alpha" {
		t.Fatalf("chain name = %q, want alpha", got)
	}
	if got := log.Entries()[0].ModuleID; got != "mock-exploit" {
		t.Fatalf("module id = %q, want mock-exploit", got)
	}
	if got := log.Entries()[0].ElapsedSeconds; got == nil || *got != elapsed {
		t.Fatalf("elapsed = %v, want %v", got, elapsed)
	}

	entries := log.Entries()
	entries[0].Fields[0].Name = "mutated"
	entries[0].Attributes["target"] = "mutated"
	*entries[0].ElapsedSeconds = 99
	if log.Entry(0).Fields[0].Name != "module" {
		t.Fatal("log did not protect field slices from external mutation")
	}
	if log.Entry(0).Attributes["target"] != "mock://target" {
		t.Fatal("log did not protect attribute maps from external mutation")
	}
	if *log.Entry(0).ElapsedSeconds != elapsed {
		t.Fatal("log did not protect elapsed pointer from external mutation")
	}
}

func TestEmptyLog(t *testing.T) {
	if !(Log{}).Empty() {
		t.Fatal("zero log should be empty")
	}
	if (New("title", "", nil)).Empty() {
		t.Fatal("titled log should not be empty")
	}
}
