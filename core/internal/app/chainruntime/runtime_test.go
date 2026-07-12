package chainruntime

import (
	"context"
	"reflect"
	"testing"

	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	"github.com/vibepwners/hovel/internal/domain/run"
)

func TestRuntimeExecutesCapabilityStepsInOrder(t *testing.T) {
	catalog := modulecatalog.New(
		modulecatalog.Module{
			ID:      "ms17-010@v1",
			Enabled: true,
			StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
				ID:   "ms17-010.exploit",
				Kind: "exploit.remote_execution",
				Produces: []modulecatalog.CapabilityRequirement{{
					Type:          modulecatalog.CapabilityRemoteExecution,
					SchemaVersion: "v1",
				}},
			}}},
		},
		modulecatalog.Module{
			ID:      "squatter@v1",
			Enabled: true,
			StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
				ID:   "squatter.connect_smb",
				Kind: "session.connector",
				Requires: []modulecatalog.CapabilityRequirement{{
					Type:   modulecatalog.CapabilityRemoteExecution,
					States: []string{"active"},
				}},
				Produces: []modulecatalog.CapabilityRequirement{{
					Type:          modulecatalog.CapabilitySessionRef,
					SchemaVersion: "v1",
				}},
			}}},
		},
	)
	runner := &fakeStepRunner{
		execute: map[string]StepExecuteResult{
			"ms17-010@v1/ms17-010.exploit": {
				Status: "succeeded",
				Capabilities: []modulecatalog.Capability{{
					ID:            "remote-1",
					Type:          modulecatalog.CapabilityRemoteExecution,
					SchemaVersion: "v1",
					State:         "active",
				}},
			},
			"squatter@v1/squatter.connect_smb": {
				Status: "succeeded",
				Capabilities: []modulecatalog.Capability{{
					ID:            "session-1",
					Type:          modulecatalog.CapabilitySessionRef,
					SchemaVersion: "v1",
					State:         "active",
				}},
			},
		},
	}

	result, err := New(catalog, runner).Execute(context.Background(), Request{
		RunID: "run-1",
		Steps: []StepRef{
			{ModuleID: "ms17-010", StepID: "ms17-010.exploit"},
			{ModuleID: "squatter", StepID: "squatter.connect_smb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", result.Status)
	}
	gotCalls := runner.calls
	wantCalls := []stepCall{
		{phase: "prepare", moduleID: "ms17-010@v1", stepID: "ms17-010.exploit"},
		{phase: "execute", moduleID: "ms17-010@v1", stepID: "ms17-010.exploit"},
		{phase: "prepare", moduleID: "squatter@v1", stepID: "squatter.connect_smb", inputs: []modulecatalog.CapabilityRef{{CapabilityID: "remote-1", Type: modulecatalog.CapabilityRemoteExecution}}},
		{phase: "execute", moduleID: "squatter@v1", stepID: "squatter.connect_smb", inputs: []modulecatalog.CapabilityRef{{CapabilityID: "remote-1", Type: modulecatalog.CapabilityRemoteExecution}}},
	}
	if !reflect.DeepEqual(gotCalls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", gotCalls, wantCalls)
	}
	if got, want := capabilityIDs(result.Capabilities), []string{"remote-1", "session-1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
}

func TestRuntimeStopsWhenStepRequirementsAreMissing(t *testing.T) {
	catalog := modulecatalog.New(modulecatalog.Module{
		ID:      "squatter@v1",
		Enabled: true,
		StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
			ID:   "squatter.connect_smb",
			Kind: "session.connector",
			Requires: []modulecatalog.CapabilityRequirement{{
				Type:       modulecatalog.CapabilityTransport,
				Attributes: map[string]any{"kind": "smb-pipe"},
				States:     []string{"active"},
			}},
		}}},
	})

	result, err := New(catalog, &fakeStepRunner{}).Execute(context.Background(), Request{
		RunID: "run-1",
		Steps: []StepRef{{
			ModuleID: "squatter",
			StepID:   "squatter.connect_smb",
		}},
	})
	if err == nil {
		t.Fatal("expected missing requirement error")
	}
	if result.Status != "blocked" {
		t.Fatalf("status = %q, want blocked", result.Status)
	}
	if len(result.Missing) != 1 || result.Missing[0].StepID != "squatter.connect_smb" {
		t.Fatalf("missing = %#v", result.Missing)
	}
}

func TestRuntimeAppliesCapabilityStateTransitions(t *testing.T) {
	catalog := modulecatalog.New(modulecatalog.Module{
		ID:      "installer@v1",
		Enabled: true,
		StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
			ID:   "install",
			Kind: "payload.install",
		}}},
	})
	runner := &fakeStepRunner{
		prepare: map[string]StepPrepareResult{
			"installer@v1/install": {
				PlannedOutputs: []modulecatalog.Capability{{
					ID:    "payload-1",
					Type:  modulecatalog.CapabilityPayloadInstance,
					State: "planned",
				}},
			},
		},
		execute: map[string]StepExecuteResult{
			"installer@v1/install": {
				Status: "succeeded",
				StateTransitions: []CapabilityTransition{{
					CapabilityID: "payload-1",
					To:           "installed",
				}},
			},
		},
	}

	result, err := New(catalog, runner).Execute(context.Background(), Request{
		RunID: "run-1",
		Steps: []StepRef{{
			ModuleID: "installer",
			StepID:   "install",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0].State != "installed" {
		t.Fatalf("capabilities = %#v, want installed payload", result.Capabilities)
	}
}

func TestRuntimePassesAgentContextAndAggregatesAgentHints(t *testing.T) {
	catalog := modulecatalog.New(modulecatalog.Module{
		ID:      "agent-step@v1",
		Enabled: true,
		StepContracts: modulecatalog.StepContractSet{Steps: []modulecatalog.StepContract{{
			ID:   "agent.execute",
			Kind: "survey.agent",
		}}},
	})
	agent := &run.AgentContext{
		Schema: "hovel.agent_context.v1",
		Entity: run.AgentEntity{
			ID:    "entity-mcp",
			Kind:  "mcp",
			Agent: true,
		},
		Phase: "execute",
	}
	runner := &fakeStepRunner{
		prepare: map[string]StepPrepareResult{
			"agent-step@v1/agent.execute": {
				AgentHints: []run.AgentHint{{
					Schema: "hovel.agent_hint.v1",
					Phase:  "prepare",
					Text:   "Review generated values before approval.",
				}},
			},
		},
		execute: map[string]StepExecuteResult{
			"agent-step@v1/agent.execute": {
				Status: "succeeded",
				AgentHints: []run.AgentHint{{
					Schema: "hovel.agent_hint.v1",
					Phase:  "execute",
					Text:   "Prefer read-only inspection before changing state.",
				}},
			},
		},
	}

	result, err := New(catalog, runner).Execute(context.Background(), Request{
		RunID: "run-1",
		Steps: []StepRef{{
			ModuleID: "agent-step",
			StepID:   "agent.execute",
		}},
		Agent: agent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0].agent != agent || runner.calls[1].agent != agent {
		t.Fatalf("calls = %#v, want agent propagated", runner.calls)
	}
	if got, want := len(result.AgentHints), 2; got != want {
		t.Fatalf("agent hints = %#v, want %d", result.AgentHints, want)
	}
	if result.AgentHints[0].Phase != "prepare" || result.AgentHints[1].Phase != "execute" {
		t.Fatalf("agent hints = %#v", result.AgentHints)
	}
}

type fakeStepRunner struct {
	prepare map[string]StepPrepareResult
	execute map[string]StepExecuteResult
	calls   []stepCall
}

type stepCall struct {
	phase    string
	moduleID string
	stepID   string
	inputs   []modulecatalog.CapabilityRef
	agent    *run.AgentContext
}

func (r *fakeStepRunner) PrepareStep(_ context.Context, req StepPrepareRequest) (StepPrepareResult, error) {
	r.calls = append(r.calls, stepCall{phase: "prepare", moduleID: req.ModuleID, stepID: req.StepID, inputs: req.Inputs, agent: req.Agent})
	return r.prepare[key(req.ModuleID, req.StepID)], nil
}

func (r *fakeStepRunner) ExecuteStep(_ context.Context, req StepExecuteRequest) (StepExecuteResult, error) {
	r.calls = append(r.calls, stepCall{phase: "execute", moduleID: req.ModuleID, stepID: req.StepID, inputs: req.Inputs, agent: req.Agent})
	return r.execute[key(req.ModuleID, req.StepID)], nil
}

func key(moduleID, stepID string) string {
	return moduleID + "/" + stepID
}

func capabilityIDs(capabilities []modulecatalog.Capability) []string {
	ids := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		ids = append(ids, capability.ID)
	}
	return ids
}
