package operatorlog

import "time"

type Level string

const (
	LevelInfo     Level = "info"
	LevelWarn     Level = "warn"
	LevelError    Level = "error"
	LevelVerbose  Level = "verbose"
	LevelTrace    Level = "trace"
	LevelStage    Level = "stage"
	LevelSuccess  Level = "success"
	LevelFinding  Level = "finding"
	LevelArtifact Level = "artifact"
)

type Kind string

const (
	KindHeader   Kind = "header"
	KindEvent    Kind = "event"
	KindStage    Kind = "stage"
	KindFinding  Kind = "finding"
	KindArtifact Kind = "artifact"
)

type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Entry struct {
	ID             string            `json:"id,omitempty"`
	Time           time.Time         `json:"time,omitempty"`
	Topic          string            `json:"topic,omitempty"`
	Kind           Kind              `json:"kind"`
	Level          Level             `json:"level"`
	Source         string            `json:"source"`
	Message        string            `json:"message"`
	ChainID        string            `json:"chainId,omitempty"`
	ChainName      string            `json:"chainName,omitempty"`
	RunID          string            `json:"runId,omitempty"`
	Target         string            `json:"target,omitempty"`
	ModuleID       string            `json:"moduleId,omitempty"`
	ElapsedSeconds *float64          `json:"elapsedSeconds,omitempty"`
	Fields         []Field           `json:"fields,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

func Info(source, message string, fields ...Field) Entry {
	return entry(LevelInfo, source, message, fields...)
}

func Warn(source, message string, fields ...Field) Entry {
	return entry(LevelWarn, source, message, fields...)
}

func Error(source, message string, fields ...Field) Entry {
	return entry(LevelError, source, message, fields...)
}

func Verbose(source, message string, fields ...Field) Entry {
	return entry(LevelVerbose, source, message, fields...)
}

func Trace(source, message string, fields ...Field) Entry {
	return entry(LevelTrace, source, message, fields...)
}

func Stage(message string, fields ...Field) Entry {
	return entry(LevelStage, "stage", message, fields...)
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
		Time:    time.Now().UTC(),
		Kind:    kindForLevel(level),
		Level:   level,
		Source:  source,
		Message: message,
		Fields:  append([]Field(nil), fields...),
	}
}

func (e Entry) WithElapsed(seconds float64) Entry {
	if seconds < 0 {
		seconds = 0
	}
	e.ElapsedSeconds = new(float64)
	*e.ElapsedSeconds = seconds
	return e
}

func (e Entry) WithTopic(topic string) Entry {
	e.Topic = topic
	return e
}

func (e Entry) WithChain(name string) Entry {
	e.ChainName = name
	return e
}

func (e Entry) WithRun(id string) Entry {
	e.RunID = id
	return e
}

func (e Entry) WithTarget(target string) Entry {
	e.Target = target
	return e
}

func (e Entry) WithModule(id string) Entry {
	e.ModuleID = id
	return e
}

func (e Entry) WithAttributes(attributes map[string]string) Entry {
	e.Attributes = cloneStringMap(attributes)
	return e
}

func (e Entry) WithLevel(level Level) Entry {
	if level != "" {
		e.Level = level
		e.Kind = kindForLevel(level)
	}
	return e
}

func kindForLevel(level Level) Kind {
	switch level {
	case LevelStage:
		return KindStage
	case LevelFinding:
		return KindFinding
	case LevelArtifact:
		return KindArtifact
	default:
		return KindEvent
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
	entry.Attributes = cloneStringMap(entry.Attributes)
	if entry.ElapsedSeconds != nil {
		elapsed := *entry.ElapsedSeconds
		entry.ElapsedSeconds = &elapsed
	}
	return entry
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
