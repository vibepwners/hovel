package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
)

type OptionKind string

const (
	OptionString OptionKind = "string"
	OptionBool   OptionKind = "bool"
)

type Positional struct {
	Name     string
	Help     string
	Required bool
}

type Option struct {
	Name      string
	Short     string
	Help      string
	ValueName string
	Kind      OptionKind
	Required  bool
}

type Handler func(context.Context, Invocation) (Result, error)

type Definition struct {
	Path           []string
	Aliases        [][]string
	Summary        string
	Positionals    []Positional
	Options        []Option
	RequiresDaemon bool
	Handler        Handler
}

func (d Definition) Execute(ctx context.Context, invocation Invocation) (Result, error) {
	if d.Handler == nil {
		return Result{}, fmt.Errorf("command %q has no handler", d.PathString())
	}
	invocation.Definition = d
	return d.Handler(ctx, invocation)
}

func (d Definition) PathString() string {
	return strings.Join(d.Path, " ")
}

type Invocation struct {
	Definition     Definition
	Positionals    map[string]string
	Options        map[string]string
	Flags          map[string]bool
	Input          Input
	Output         io.Writer
	NonInteractive bool
	StreamLog      func(operatorlog.Entry)
}

func (i Invocation) Positional(name string) string {
	if i.Positionals == nil {
		return ""
	}
	return i.Positionals[name]
}

func (i Invocation) Option(name string) string {
	if i.Options == nil {
		return ""
	}
	return i.Options[name]
}

func (i Invocation) Flag(name string) bool {
	if i.Flags == nil {
		return false
	}
	return i.Flags[name]
}

type Result struct {
	Human string
	Raw   []byte
	JSON  any
	Log   operatorlog.Log
}

type Input interface {
	Confirm(context.Context, ConfirmationPrompt) (ConfirmationAnswer, error)
}

type ConfirmationPrompt struct {
	Title           string
	Action          string
	RequiredLiteral string
	Fields          []ConfirmationField
	Plan            ThrowPlanRecord
}

type ConfirmationField struct {
	Label string
	Value string
	Muted bool
}

type ConfirmationAnswer struct {
	Value string
}

func (a ConfirmationAnswer) Confirmed(prompt ConfirmationPrompt) bool {
	required := strings.TrimSpace(prompt.RequiredLiteral)
	if required == "" {
		required = "yes"
	}
	return strings.TrimSpace(a.Value) == required
}

type Registry struct {
	definitions []Definition
	byPath      map[string]Definition
}

func NewRegistry(definitions ...Definition) (Registry, error) {
	if len(definitions) == 0 {
		return Registry{}, errors.New("command registry requires at least one definition")
	}
	registry := Registry{byPath: make(map[string]Definition, len(definitions))}
	for _, definition := range definitions {
		if err := validateDefinition(definition); err != nil {
			return Registry{}, err
		}
		key := definition.PathString()
		if _, exists := registry.byPath[key]; exists {
			return Registry{}, fmt.Errorf("duplicate command path %q", key)
		}
		registry.definitions = append(registry.definitions, definition)
		registry.byPath[key] = definition
		for _, alias := range definition.Aliases {
			aliasDefinition := definition
			aliasDefinition.Path = alias
			aliasKey := aliasDefinition.PathString()
			if _, exists := registry.byPath[aliasKey]; exists {
				return Registry{}, fmt.Errorf("duplicate command path %q", aliasKey)
			}
			registry.byPath[aliasKey] = aliasDefinition
		}
	}
	sort.Slice(registry.definitions, func(i, j int) bool {
		return registry.definitions[i].PathString() < registry.definitions[j].PathString()
	})
	return registry, nil
}

func MustRegistry(definitions ...Definition) Registry {
	registry, err := NewRegistry(definitions...)
	if err != nil {
		panic(err)
	}
	return registry
}

func (r Registry) Definitions() []Definition {
	definitions := make([]Definition, len(r.definitions))
	copy(definitions, r.definitions)
	return definitions
}

func (r Registry) Find(path ...string) (Definition, bool) {
	definition, ok := r.byPath[strings.Join(path, " ")]
	return definition, ok
}

func (r Registry) HasRoot(segment string) bool {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return false
	}
	for _, definition := range r.definitions {
		if len(definition.Path) > 0 && definition.Path[0] == segment {
			return true
		}
		for _, alias := range definition.Aliases {
			if len(alias) > 0 && alias[0] == segment {
				return true
			}
		}
	}
	return false
}

func (r Registry) Children(prefix ...string) []Definition {
	seen := map[string]Definition{}
	for _, definition := range r.definitions {
		for _, path := range definitionPaths(definition) {
			if len(path) <= len(prefix) {
				continue
			}
			if !hasPathPrefix(path, prefix) {
				continue
			}
			childPath := append([]string(nil), prefix...)
			childPath = append(childPath, path[len(prefix)])
			key := strings.Join(childPath, " ")
			child := Definition{
				Path:    childPath,
				Summary: groupSummary(childPath, definition.Summary),
			}
			if len(path) == len(childPath) {
				child = definition
				child.Path = path
			}
			if existing, ok := seen[key]; ok {
				if len(child.Path) < len(existing.Path) || existing.Handler == nil && child.Handler != nil {
					seen[key] = child
				}
				continue
			}
			seen[key] = child
		}
	}
	var children []Definition
	for _, child := range seen {
		children = append(children, child)
	}
	sort.Slice(children, func(i, j int) bool {
		return children[i].PathString() < children[j].PathString()
	})
	return children
}

func definitionPaths(definition Definition) [][]string {
	paths := make([][]string, 0, 1+len(definition.Aliases))
	paths = append(paths, definition.Path)
	paths = append(paths, definition.Aliases...)
	return paths
}

func (r Registry) FirstSegments() []Definition {
	seen := map[string]Definition{}
	for _, definition := range r.definitions {
		if len(definition.Path) == 0 {
			continue
		}
		segment := definition.Path[0]
		if existing, ok := seen[segment]; ok {
			if len(definition.Path) < len(existing.Path) {
				seen[segment] = definition
			}
			continue
		}
		seen[segment] = definition
	}

	var roots []Definition
	for _, definition := range seen {
		roots = append(roots, Definition{
			Path:    []string{definition.Path[0]},
			Summary: groupSummary([]string{definition.Path[0]}, rootSummary(r.definitions, definition.Path[0])),
		})
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].PathString() < roots[j].PathString()
	})
	return roots
}

func validateDefinition(definition Definition) error {
	if len(definition.Path) == 0 {
		return errors.New("command path is required")
	}
	for _, path := range append([][]string{definition.Path}, definition.Aliases...) {
		for _, segment := range path {
			if strings.TrimSpace(segment) == "" || strings.Contains(segment, " ") {
				return fmt.Errorf("invalid command path segment %q", segment)
			}
		}
	}
	if strings.TrimSpace(definition.Summary) == "" {
		return fmt.Errorf("command %q summary is required", definition.PathString())
	}
	seen := map[string]struct{}{}
	for _, positional := range definition.Positionals {
		if strings.TrimSpace(positional.Name) == "" {
			return fmt.Errorf("command %q has unnamed positional", definition.PathString())
		}
		if _, ok := seen[positional.Name]; ok {
			return fmt.Errorf("command %q duplicates argument %q", definition.PathString(), positional.Name)
		}
		seen[positional.Name] = struct{}{}
	}
	for _, option := range definition.Options {
		if strings.TrimSpace(option.Name) == "" {
			return fmt.Errorf("command %q has unnamed option", definition.PathString())
		}
		if option.Kind == "" {
			return fmt.Errorf("command %q option %q has no kind", definition.PathString(), option.Name)
		}
		if _, ok := seen[option.Name]; ok {
			return fmt.Errorf("command %q duplicates argument %q", definition.PathString(), option.Name)
		}
		seen[option.Name] = struct{}{}
	}
	return nil
}

func hasPathPrefix(path, prefix []string) bool {
	if len(prefix) > len(path) {
		return false
	}
	for i, segment := range prefix {
		if path[i] != segment {
			return false
		}
	}
	return true
}

func rootSummary(definitions []Definition, segment string) string {
	var summaries []string
	for _, definition := range definitions {
		if len(definition.Path) == 1 && definition.Path[0] == segment {
			return definition.Summary
		}
		if len(definition.Path) > 0 && definition.Path[0] == segment {
			summaries = append(summaries, definition.Summary)
		}
	}
	if len(summaries) == 0 {
		return ""
	}
	return summaries[0]
}

func groupSummary(path []string, fallback string) string {
	if len(path) == 0 {
		return fallback
	}
	switch path[len(path)-1] {
	case "control":
		return "Initialize workspaces and inspect daemon state."
	case "daemon":
		return "Daemon control and inspection commands."
	case "chain", "chains":
		return "Build and manage operator chains."
	case "op":
		return "Create, select, and inspect operations."
	case "config":
		return "Set, list, and fix configuration."
	case "module", "modules":
		return "Browse, search, and inspect modules."
	case "throws":
		return "List and inspect throws."
	case "session", "sessions":
		return "List and interact with post-exploitation sessions."
	case "target", "targets":
		return "Add and configure chain targets."
	default:
		return fallback
	}
}
