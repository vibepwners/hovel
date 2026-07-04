package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

var errFakeSessionClosed = errors.New("fake session closed")

func TestRunWithConnectDrivesHovelMCPTools(t *testing.T) {
	session := &fakeSession{
		tools: []string{
			"hovel_workspace_snapshot",
			"hovel_operator_identity",
			"hovel_operator_list_entities",
			"hovel_operation_list",
			"hovel_throw_start",
		},
		results: map[string]any{
			"hovel_operator_identity": operatorIdentityOutput{Entity: operatorEntity{
				ID:          "demo-agent",
				Kind:        "mcp",
				DisplayName: "Mock Codex",
				Agent:       true,
				Operation:   "demo",
				ActiveChain: "alpha",
			}},
			"hovel_operator_list_entities": operatorListEntitiesOutput{
				Operation: "demo",
				Entities: []operatorEntity{{
					ID:          "demo-agent",
					Kind:        "mcp",
					Agent:       true,
					Operation:   "demo",
					ActiveChain: "alpha",
				}},
			},
			"hovel_operation_list": operationListOutput{
				ActiveOperation: "demo",
				ActiveChain:     "alpha",
				Operations: []operationOutput{{
					Name:    "demo",
					Targets: []string{"mock://router-01"},
					Chains:  []chainOutput{{Name: "alpha"}},
				}},
			},
			"hovel_workspace_snapshot": workspaceSnapshotOutput{
				ActiveOperation: "demo",
				ActiveChain:     "alpha",
				Operations: []operationOutput{{
					Name:    "demo",
					Targets: []string{"mock://router-01"},
					Chains: []chainOutput{{
						Name: "alpha",
						Steps: []stepOutput{{
							ID:       "step-1",
							ModuleID: "mock-survey-go@v0.0.0-example",
						}},
						Config: map[string]string{"operator.confirmed_lab": "true"},
					}},
				}},
			},
			"hovel_throw_start": throwStartOutput{
				Operation: "demo",
				ThrowID:   "throw-1",
				Chain:     "alpha",
				Targets:   []string{"mock://router-01"},
				Results: []throwRunOutput{{
					RunID:    "run-1",
					ModuleID: "mock-exploit-session-go@v0.0.0-example",
					Target:   "mock://router-01",
					State:    "succeeded",
					Summary:  "mock exploit opened an interactive shell session",
					Sessions: []throwSessionOutput{{
						ID:        "session-1",
						RunID:     "run-1",
						ModuleID:  "mock-exploit-session-go@v0.0.0-example",
						Target:    "mock://router-01",
						Name:      "mock shell on mock://router-01",
						Kind:      "shell",
						State:     "active",
						Transport: "memory",
					}},
				}},
			},
		},
	}

	var out bytes.Buffer
	err := runWithConnect(context.Background(), Options{
		HovelPath:   "hovel",
		Workspace:   "/tmp/hovel-demo",
		Operation:   "demo",
		Chain:       "alpha",
		EntityID:    "demo-agent",
		DisplayName: "Mock Codex",
		Out:         &out,
		Color:       false,
	}, func(context.Context, Options) (mcpSession, string, error) {
		return session, "", nil
	})
	if err != nil {
		t.Fatalf("runWithConnect returned error: %v", err)
	}

	wantCalls := []string{
		"hovel_operator_identity",
		"hovel_operator_list_entities",
		"hovel_operation_list",
		"hovel_workspace_snapshot",
		"hovel_throw_start",
	}
	if !reflect.DeepEqual(session.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", session.calls, wantCalls)
	}
	if !session.closed {
		t.Fatal("session was not closed")
	}

	text := out.String()
	for _, want := range []string{
		"Mock Codex Agent",
		"tool: hovel_workspace_snapshot",
		"tool: hovel_throw_start",
		"mock://router-01",
		"mock-survey-go@v0.0.0-example",
		"mock exploit opened an interactive shell session",
		"Hovel throw completed",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("transcript missing %q:\n%s", want, text)
		}
	}
}

func TestRunWithConnectRequiresExpectedTools(t *testing.T) {
	session := &fakeSession{tools: []string{"hovel_operator_identity"}}

	err := runWithConnect(context.Background(), Options{
		Out:   &bytes.Buffer{},
		Color: false,
	}, func(context.Context, Options) (mcpSession, string, error) {
		return session, "", nil
	})
	if err == nil {
		t.Fatal("runWithConnect returned nil error")
	}
	if !strings.Contains(err.Error(), "hovel_workspace_snapshot") {
		t.Fatalf("error = %v, want missing tool name", err)
	}
	if !session.closed {
		t.Fatal("session was not closed after tool validation failure")
	}
}

func TestWrapTextPreservesExplicitLines(t *testing.T) {
	got := wrapText("alpha beta gamma\n- step mock-survey-go", 10)
	want := []string{"alpha beta", "gamma", "- step", "mock-survey-go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wrapText = %#v, want %#v", got, want)
	}
}

type fakeSession struct {
	tools   []string
	results map[string]any
	calls   []string
	closed  bool
}

func (f *fakeSession) ListTools(context.Context, *mcpsdk.ListToolsParams) (*mcpsdk.ListToolsResult, error) {
	tools := make([]*mcpsdk.Tool, 0, len(f.tools))
	for _, name := range f.tools {
		tools = append(tools, &mcpsdk.Tool{Name: name})
	}
	return &mcpsdk.ListToolsResult{Tools: tools}, nil
}

func (f *fakeSession) CallTool(_ context.Context, params *mcpsdk.CallToolParams) (*mcpsdk.CallToolResult, error) {
	if f.closed {
		return nil, errFakeSessionClosed
	}
	f.calls = append(f.calls, params.Name)
	result, ok := f.results[params.Name]
	if !ok {
		return &mcpsdk.CallToolResult{IsError: true}, nil
	}
	return &mcpsdk.CallToolResult{StructuredContent: result}, nil
}

func (f *fakeSession) Close() error {
	f.closed = true
	return nil
}
