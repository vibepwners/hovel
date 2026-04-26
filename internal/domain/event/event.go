package event

import (
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
	RunID       string
	ModuleID    string
	ServiceID   string
	TargetID    string
}

type Args struct {
	ID        ID
	Type      Type
	Timestamp time.Time
	Refs      Refs
	Fields    map[string]string
}

type Event struct {
	ID        ID
	Type      Type
	Timestamp time.Time
	Refs      Refs
	Fields    map[string]string
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
	fields := make(map[string]string, len(args.Fields))
	for k, v := range args.Fields {
		fields[k] = v
	}
	return Event{
		ID:        args.ID,
		Type:      args.Type,
		Timestamp: args.Timestamp,
		Refs:      args.Refs,
		Fields:    fields,
	}, nil
}
