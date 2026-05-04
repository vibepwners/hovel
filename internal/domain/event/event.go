package event

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
)

type ID string

func NewID(value string) (ID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("event id is required")
	}
	return ID(value), nil
}

func (id ID) String() string {
	return string(id)
}

type Type string

func NewType(value string) (Type, error) {
	if value != strings.TrimSpace(value) || value == "" {
		return "", errors.New("event type is required")
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", errors.New("event type must contain a category and name")
	}
	for _, part := range parts {
		if part == "" {
			return "", errors.New("event type contains an empty segment")
		}
		for i, r := range part {
			if unicode.IsLower(r) || unicode.IsDigit(r) || r == '_' {
				continue
			}
			if i == 0 || !unicode.IsLetter(r) {
				return "", errors.New("event type contains invalid characters")
			}
			return "", errors.New("event type must be lowercase")
		}
	}
	return Type(value), nil
}

func (typ Type) String() string {
	return string(typ)
}

type Refs struct {
	WorkspaceID string
	Operation   string
	Chain       string
	ThrowID     string
	RunID       string
	ModuleID    string
	ServiceID   string
	TargetID    string
	SessionID   string
}

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type Args struct {
	ID            ID
	SchemaVersion string
	Type          Type
	Level         Level
	Message       string
	Timestamp     time.Time
	Topic         string
	Refs          Refs
	Fields        map[string]string
}

type Event struct {
	ID            ID                `json:"id"`
	SchemaVersion string            `json:"schemaVersion"`
	Type          Type              `json:"type"`
	Level         Level             `json:"level"`
	Message       string            `json:"message"`
	Timestamp     time.Time         `json:"timestamp"`
	Topic         string            `json:"topic,omitempty"`
	Refs          Refs              `json:"refs"`
	Fields        map[string]string `json:"fields,omitempty"`
}

func New(args Args) (Event, error) {
	if args.ID == "" {
		return Event{}, errors.New("event id is required")
	}
	if args.Type == "" {
		return Event{}, errors.New("event type is required")
	}
	if args.Timestamp.IsZero() {
		return Event{}, errors.New("event timestamp is required")
	}
	level := args.Level
	if level == "" {
		level = LevelInfo
	}
	switch level {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
	default:
		return Event{}, errors.New("event level is not valid")
	}
	schemaVersion := strings.TrimSpace(args.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = "hovel.event/v1alpha1"
	}
	message := strings.TrimSpace(args.Message)
	if message == "" {
		message = string(args.Type)
	}
	fields := make(map[string]string, len(args.Fields))
	for k, v := range args.Fields {
		fields[k] = v
	}
	return Event{
		ID:            args.ID,
		SchemaVersion: schemaVersion,
		Type:          args.Type,
		Level:         level,
		Message:       message,
		Timestamp:     args.Timestamp,
		Topic:         strings.TrimSpace(args.Topic),
		Refs:          args.Refs,
		Fields:        fields,
	}, nil
}

type Filter struct {
	Workspace string
	Operation string
	Chain     string
	ThrowID   string
	RunID     string
	ModuleID  string
	Target    string
	Level     string
	Type      string
	Topic     string
}

func (f Filter) Match(evt Event) bool {
	if f.Workspace != "" && evt.Refs.WorkspaceID != f.Workspace {
		return false
	}
	if f.Operation != "" && evt.Refs.Operation != f.Operation {
		return false
	}
	if f.Chain != "" && evt.Refs.Chain != f.Chain {
		return false
	}
	if f.ThrowID != "" && evt.Refs.ThrowID != f.ThrowID {
		return false
	}
	if f.RunID != "" && evt.Refs.RunID != f.RunID {
		return false
	}
	if f.ModuleID != "" && evt.Refs.ModuleID != f.ModuleID {
		return false
	}
	if f.Target != "" && evt.Refs.TargetID != f.Target {
		return false
	}
	if f.Level != "" && string(evt.Level) != f.Level {
		return false
	}
	if f.Type != "" && evt.Type.String() != f.Type {
		return false
	}
	if f.Topic != "" && evt.Topic != f.Topic {
		return false
	}
	return true
}

type Handler interface {
	Handle(context.Context, Event) error
}

type HandlerFunc func(context.Context, Event) error

func (fn HandlerFunc) Handle(ctx context.Context, evt Event) error {
	return fn(ctx, evt)
}

type Subscription struct {
	Filter  Filter
	Handler Handler
}

type Bus struct {
	subscriptions []Subscription
}

func NewBus(subscriptions ...Subscription) Bus {
	return Bus{subscriptions: append([]Subscription(nil), subscriptions...)}
}

func (b Bus) Append(ctx context.Context, evt Event) error {
	for _, subscription := range b.subscriptions {
		if subscription.Handler == nil || !subscription.Filter.Match(evt) {
			continue
		}
		if err := subscription.Handler.Handle(ctx, evt); err != nil {
			return err
		}
	}
	return nil
}

type Recorder struct {
	Events []Event
	Filter Filter
}

func (r *Recorder) Append(ctx context.Context, evt Event) error {
	return r.Handle(ctx, evt)
}

func (r *Recorder) Handle(_ context.Context, evt Event) error {
	if !r.Filter.Match(evt) {
		return nil
	}
	r.Events = append(r.Events, evt)
	return nil
}
