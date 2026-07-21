package commands

import (
	"context"
	"testing"
)

func TestRegistryRejectsDuplicatePaths(t *testing.T) {
	_, err := NewRegistry(
		Definition{Path: []string{"run"}, Summary: "Run a module"},
		Definition{Path: []string{"run"}, Summary: "Run a duplicate"},
	)
	if err == nil {
		t.Fatal("expected duplicate path error")
	}
}

func TestRegistryRejectsRequiredPositionalAfterOptionalPositional(t *testing.T) {
	_, err := NewRegistry(Definition{
		Path:    []string{"inspect"},
		Summary: "Inspect a record.",
		Positionals: []Positional{
			{Name: "scope"},
			{Name: "record", Required: true},
		},
	})
	if err == nil {
		t.Fatal("expected positional ordering error")
	}
}

func TestRegistryRejectsAmbiguousOptionMetadata(t *testing.T) {
	for _, definition := range []Definition{
		{Path: []string{"inspect"}, Summary: "Inspect.", Options: []Option{{Name: "bad option", Kind: OptionString}}},
		{Path: []string{"inspect"}, Summary: "Inspect.", Options: []Option{{Name: "first", Short: "x", Kind: OptionBool}, {Name: "second", Short: "x", Kind: OptionBool}}},
		{Path: []string{"inspect"}, Summary: "Inspect.", Options: []Option{{Name: "value", Short: "xy", Kind: OptionString}}},
		{Path: []string{"inspect"}, Summary: "Inspect.", Options: []Option{{Name: "value", Kind: OptionKind("mystery")}}},
	} {
		if _, err := NewRegistry(definition); err == nil {
			t.Fatalf("NewRegistry(%#v) succeeded, want error", definition.Options)
		}
	}
}

func TestRegistryFindsDefinitionsByPath(t *testing.T) {
	registry := MustRegistry(
		Definition{Path: []string{"init"}, Summary: "Initialize a workspace"},
		Definition{Path: []string{"daemon", "status"}, Summary: "Inspect daemon status"},
	)

	definition, ok := registry.Find("daemon", "status")
	if !ok {
		t.Fatal("daemon status definition was not found")
	}
	if definition.PathString() != "daemon status" {
		t.Fatalf("path = %q, want daemon status", definition.PathString())
	}
}

func TestRegistryListsChildrenForPromptAndHelp(t *testing.T) {
	registry := MustRegistry(
		Definition{Path: []string{"init"}, Summary: "Initialize a workspace"},
		Definition{Path: []string{"daemon", "status"}, Summary: "Inspect daemon status"},
		Definition{Path: []string{"daemon", "stop"}, Summary: "Stop daemon"},
	)

	children := registry.Children("daemon")
	if len(children) != 2 {
		t.Fatalf("child count = %d, want 2", len(children))
	}
	if children[0].PathString() != "daemon status" {
		t.Fatalf("first child = %q, want daemon status", children[0].PathString())
	}
	if children[1].PathString() != "daemon stop" {
		t.Fatalf("second child = %q, want daemon stop", children[1].PathString())
	}
}

func TestRegistryListsIntermediateChildrenForNestedGroups(t *testing.T) {
	registry := MustRegistry(
		Definition{Path: []string{"control", "daemon", "status"}, Summary: "Inspect daemon status"},
		Definition{Path: []string{"control", "init"}, Summary: "Initialize a workspace"},
	)

	children := registry.Children("control")
	if len(children) != 2 {
		t.Fatalf("child count = %d, want 2", len(children))
	}
	if children[0].PathString() != "control daemon" {
		t.Fatalf("first child = %q, want control daemon", children[0].PathString())
	}
	if children[1].PathString() != "control init" {
		t.Fatalf("second child = %q, want control init", children[1].PathString())
	}
}

func TestInvocationAccessorsUseCentralNames(t *testing.T) {
	invocation := Invocation{
		Positionals: map[string]string{"module": "mock-exploit"},
		Options:     map[string]string{"workspace": ".hovel"},
		Flags:       map[string]bool{"json": true},
		Passthrough: []string{"cmd", "--flag"},
	}

	if got := invocation.Positional("module"); got != "mock-exploit" {
		t.Fatalf("module = %q", got)
	}
	if got := invocation.Option("workspace"); got != ".hovel" {
		t.Fatalf("workspace = %q", got)
	}
	if !invocation.Flag("json") {
		t.Fatal("json flag = false, want true")
	}
	if got := invocation.PassthroughArgs(); len(got) != 2 || got[0] != "cmd" || got[1] != "--flag" {
		t.Fatalf("passthrough = %#v", got)
	}
}

func TestDefinitionHandlerRunsValidatedInvocation(t *testing.T) {
	definition := Definition{
		Path:    []string{"hello"},
		Summary: "Say hello",
		Handler: func(ctx context.Context, invocation Invocation) (Result, error) {
			return Result{Human: "hello " + invocation.Option("name")}, nil
		},
	}

	result, err := definition.Execute(context.Background(), Invocation{
		Options: map[string]string{"name": "operator"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Human != "hello operator" {
		t.Fatalf("human result = %q", result.Human)
	}
}
