package chainruntime

import (
	"context"
	"fmt"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
)

type StepRunner interface {
	PrepareStep(context.Context, StepPrepareRequest) (StepPrepareResult, error)
	ExecuteStep(context.Context, StepExecuteRequest) (StepExecuteResult, error)
}

type Runtime struct {
	catalog modulecatalog.Catalog
	runner  StepRunner
}

type Request struct {
	RunID        string
	Steps        []StepRef
	Capabilities []modulecatalog.Capability
}

type StepRef struct {
	ModuleID string
	StepID   string
	Config   map[string]any
}

type Result struct {
	Status       string
	Capabilities []modulecatalog.Capability
	Missing      []MissingStepRequirement
	Evidence     []Evidence
}

type MissingStepRequirement struct {
	ModuleID string
	StepID   string
	Missing  modulecatalog.MissingCapability
}

type StepPrepareRequest struct {
	ModuleID               string
	RunID                  string
	StepID                 string
	Config                 map[string]any
	Inputs                 []modulecatalog.CapabilityRef
	ExistingPreparedValues map[string]PreparedValue
}

type StepPrepareResult struct {
	PlannedOutputs  []modulecatalog.Capability
	PreparedValues  map[string]PreparedValue
	OperatorSummary OperatorSummary
	Evidence        []Evidence
}

type StepExecuteRequest struct {
	ModuleID                string
	RunID                   string
	StepID                  string
	ConfirmedPreparedValues map[string]any
	Inputs                  []modulecatalog.CapabilityRef
	RunMetadata             map[string]any
}

type StepExecuteResult struct {
	Status           string
	Capabilities     []modulecatalog.Capability
	StateTransitions []CapabilityTransition
	Evidence         []Evidence
}

type PreparedValue struct {
	Value    any
	Editable bool
}

type OperatorSummary struct {
	Warnings            []string
	TargetSideArtifacts []string
}

type CapabilityTransition struct {
	CapabilityID string
	From         string
	To           string
	Reason       string
}

type Evidence struct {
	ID           string
	Level        string
	Kind         string
	SourceStepID string
	Message      string
	Details      map[string]any
}

func New(catalog modulecatalog.Catalog, runner StepRunner) Runtime {
	return Runtime{catalog: catalog, runner: runner}
}

func (r Runtime) Execute(ctx context.Context, req Request) (Result, error) {
	capabilities := append([]modulecatalog.Capability(nil), req.Capabilities...)
	var evidence []Evidence
	for _, stepRef := range req.Steps {
		module, step, err := r.resolveStep(stepRef)
		if err != nil {
			return Result{Status: "failed", Capabilities: capabilities, Evidence: evidence}, err
		}
		resolution := modulecatalog.ResolveStepInputs(step, capabilities)
		if !resolution.Ready {
			missing := missingStepRequirements(module.ID, step.ID, resolution.Missing)
			return Result{Status: "blocked", Capabilities: capabilities, Missing: missing, Evidence: evidence}, fmt.Errorf("step %s missing %d requirement(s)", step.ID, len(missing))
		}
		inputs := capabilityRefs(resolution.Bindings, capabilities)
		prepared, err := r.runner.PrepareStep(ctx, StepPrepareRequest{
			ModuleID: module.ID,
			RunID:    req.RunID,
			StepID:   step.ID,
			Config:   cloneAnyMap(stepRef.Config),
			Inputs:   inputs,
		})
		if err != nil {
			return Result{Status: "failed", Capabilities: capabilities, Evidence: evidence}, err
		}
		evidence = append(evidence, prepared.Evidence...)
		capabilities = upsertCapabilities(capabilities, prepared.PlannedOutputs)

		executed, err := r.runner.ExecuteStep(ctx, StepExecuteRequest{
			ModuleID:                module.ID,
			RunID:                   req.RunID,
			StepID:                  step.ID,
			ConfirmedPreparedValues: confirmedPreparedValues(prepared.PreparedValues),
			Inputs:                  inputs,
			RunMetadata: map[string]any{
				"config": cloneAnyMap(stepRef.Config),
			},
		})
		if err != nil {
			return Result{Status: "failed", Capabilities: capabilities, Evidence: evidence}, err
		}
		evidence = append(evidence, executed.Evidence...)
		capabilities = upsertCapabilities(capabilities, executed.Capabilities)
		capabilities = applyTransitions(capabilities, executed.StateTransitions)
		if executed.Status != "" && executed.Status != "succeeded" {
			return Result{Status: executed.Status, Capabilities: capabilities, Evidence: evidence}, nil
		}
	}
	return Result{Status: "succeeded", Capabilities: capabilities, Evidence: evidence}, nil
}

func (r Runtime) resolveStep(ref StepRef) (modulecatalog.Module, modulecatalog.StepContract, error) {
	module, ok := r.catalog.Find(ref.ModuleID)
	if !ok {
		return modulecatalog.Module{}, modulecatalog.StepContract{}, fmt.Errorf("module %s does not exist", ref.ModuleID)
	}
	for _, step := range module.StepContracts.Steps {
		if step.ID == ref.StepID {
			return module, step, nil
		}
	}
	return modulecatalog.Module{}, modulecatalog.StepContract{}, fmt.Errorf("module %s step %s does not exist", module.ID, ref.StepID)
}

func missingStepRequirements(moduleID, stepID string, missing []modulecatalog.MissingCapability) []MissingStepRequirement {
	out := make([]MissingStepRequirement, 0, len(missing))
	for _, item := range missing {
		out = append(out, MissingStepRequirement{
			ModuleID: moduleID,
			StepID:   stepID,
			Missing:  item,
		})
	}
	return out
}

func capabilityRefs(bindings []modulecatalog.CapabilityBinding, capabilities []modulecatalog.Capability) []modulecatalog.CapabilityRef {
	if len(bindings) == 0 {
		return nil
	}
	out := make([]modulecatalog.CapabilityRef, 0, len(bindings))
	for _, binding := range bindings {
		for _, capability := range capabilities {
			if capability.ID == binding.CapabilityID {
				out = append(out, modulecatalog.CapabilityRef{
					CapabilityID: capability.ID,
					Type:         capability.Type,
				})
				break
			}
		}
	}
	return out
}

func upsertCapabilities(existing, updates []modulecatalog.Capability) []modulecatalog.Capability {
	out := append([]modulecatalog.Capability(nil), existing...)
	for _, update := range updates {
		replaced := false
		for index, capability := range out {
			if capability.ID == update.ID {
				out[index] = update
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, update)
		}
	}
	return out
}

func applyTransitions(capabilities []modulecatalog.Capability, transitions []CapabilityTransition) []modulecatalog.Capability {
	out := append([]modulecatalog.Capability(nil), capabilities...)
	for _, transition := range transitions {
		for index := range out {
			if out[index].ID == transition.CapabilityID {
				out[index].State = transition.To
				break
			}
		}
	}
	return out
}

func confirmedPreparedValues(values map[string]PreparedValue) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value.Value
	}
	return out
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
