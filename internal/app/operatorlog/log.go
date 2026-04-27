package operatorlog

type Level string

const (
	LevelInfo     Level = "info"
	LevelSuccess  Level = "success"
	LevelFinding  Level = "finding"
	LevelArtifact Level = "artifact"
)

type Field struct {
	Name  string
	Value string
}

type Entry struct {
	Level   Level
	Source  string
	Message string
	Fields  []Field
}

func Info(source, message string, fields ...Field) Entry {
	return entry(LevelInfo, source, message, fields...)
}

func Success(source, message string, fields ...Field) Entry {
	return entry(LevelSuccess, source, message, fields...)
}

func Finding(source, message string, fields ...Field) Entry {
	return entry(LevelFinding, source, message, fields...)
}

func Artifact(source, message string, fields ...Field) Entry {
	return entry(LevelArtifact, source, message, fields...)
}

func entry(level Level, source, message string, fields ...Field) Entry {
	return Entry{
		Level:   level,
		Source:  source,
		Message: message,
		Fields:  append([]Field(nil), fields...),
	}
}

type Log struct {
	Title    string
	Subtitle string
	entries  []Entry
}

func New(title, subtitle string, entries []Entry) Log {
	return Log{
		Title:    title,
		Subtitle: subtitle,
		entries:  cloneEntries(entries),
	}
}

func (l Log) Empty() bool {
	return l.Title == "" && l.Subtitle == "" && len(l.entries) == 0
}

func (l Log) Entries() []Entry {
	return cloneEntries(l.entries)
}

func (l Log) Entry(index int) Entry {
	return cloneEntry(l.entries[index])
}

func cloneEntries(entries []Entry) []Entry {
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, cloneEntry(entry))
	}
	return out
}

func cloneEntry(entry Entry) Entry {
	entry.Fields = append([]Field(nil), entry.Fields...)
	return entry
}
