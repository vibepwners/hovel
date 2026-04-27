package operatorlog

import "testing"

func TestLogPreservesEntriesAndFields(t *testing.T) {
	log := New("HOVEL//RUN", "mock-exploit", []Entry{
		Info("run", "module loaded", Field{Name: "module", Value: "mock-exploit"}),
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

	entries := log.Entries()
	entries[0].Fields[0].Name = "mutated"
	if log.Entry(0).Fields[0].Name != "module" {
		t.Fatal("log did not protect field slices from external mutation")
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
