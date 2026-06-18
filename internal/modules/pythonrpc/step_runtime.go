package pythonrpc

import (
	"context"

	"github.com/Vibe-Pwners/hovel/internal/app/chainruntime"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
)

type StepRuntimeRunner struct {
	Runner Runner
}

func (r StepRuntimeRunner) PrepareStep(ctx context.Context, req chainruntime.StepPrepareRequest) (chainruntime.StepPrepareResult, error) {
	result, err := r.Runner.PrepareStep(ctx, StepCallRequest{
		ModuleID: req.ModuleID,
		Params: map[string]any{
			"preparedPlanId":         req.RunID,
			"stepId":                 req.StepID,
			"config":                 req.Config,
			"inputs":                 capabilityRefsToRPC(req.Inputs),
			"existingPreparedValues": preparedValuesToRPC(req.ExistingPreparedValues),
		},
	})
	if err != nil {
		return chainruntime.StepPrepareResult{}, err
	}
	return stepPrepareResultFromRPC(result), nil
}

func (r StepRuntimeRunner) ExecuteStep(ctx context.Context, req chainruntime.StepExecuteRequest) (chainruntime.StepExecuteResult, error) {
	result, err := r.Runner.ExecuteStep(ctx, StepCallRequest{
		ModuleID: req.ModuleID,
		Params: map[string]any{
			"runId":                   req.RunID,
			"stepId":                  req.StepID,
			"confirmedPreparedValues": req.ConfirmedPreparedValues,
			"inputs":                  capabilityRefsToRPC(req.Inputs),
			"runMetadata":             req.RunMetadata,
		},
	})
	if err != nil {
		return chainruntime.StepExecuteResult{}, err
	}
	return stepExecuteResultFromRPC(req, result), nil
}

func (r StepRuntimeRunner) FinishRun(ctx context.Context, runID string) error {
	if r.Runner.StepProcesses == nil {
		return nil
	}
	timeout := r.Runner.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	finishCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.Runner.StepProcesses.FinishRun(finishCtx, runID)
}

func stepPrepareResultFromRPC(result map[string]any) chainruntime.StepPrepareResult {
	return chainruntime.StepPrepareResult{
		PlannedOutputs: capabilitiesFromRPC(result["plannedOutputs"]),
		PreparedValues: preparedValuesFromRPC(result["preparedValues"]),
		Evidence:       evidenceFromRPC(result["evidence"]),
	}
}

func stepExecuteResultFromRPC(req chainruntime.StepExecuteRequest, result map[string]any) chainruntime.StepExecuteResult {
	return chainruntime.StepExecuteResult{
		Status:            stringValue(result["status"]),
		Capabilities:      capabilitiesFromRPC(result["capabilities"]),
		StateTransitions:  transitionsFromRPC(result["stateTransitions"]),
		Evidence:          evidenceFromRPC(result["evidence"]),
		Sessions:          sessionsFromStepRPC(StepCallRequest{ModuleID: req.ModuleID, Params: map[string]any{"runId": req.RunID}}, result["sessions"]),
		InstalledPayloads: stepInstalledPayloadsFromRPC(result["installedPayloads"]),
	}
}

func sessionsFromStepRPC(request StepCallRequest, value any) []run.SessionRef {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var sessions []run.SessionRef
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		session := run.SessionRef{
			ID:                 stringValue(object["id"]),
			RunID:              defaultString(stringValue(object["runId"]), stepCallRunID(request.Params)),
			ModuleID:           defaultString(stringValue(object["moduleId"]), request.ModuleID),
			Target:             stringValue(object["target"]),
			Name:               stringValue(object["name"]),
			Kind:               defaultString(stringValue(object["kind"]), "shell"),
			State:              defaultString(stringValue(object["state"]), "active"),
			Transport:          defaultString(stringValue(object["transport"]), "stdio"),
			InstalledPayloadID: stringValue(object["installedPayloadId"]),
			Capabilities:       stringSlice(object["capabilities"]),
		}
		if session.ID != "" {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

func capabilitiesFromRPC(value any) []modulecatalog.Capability {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	capabilities := make([]modulecatalog.Capability, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		capabilities = append(capabilities, modulecatalog.Capability{
			ID:             stringValue(object["id"]),
			Type:           modulecatalog.CapabilityType(stringValue(object["type"])),
			SchemaVersion:  stringValue(object["schemaVersion"]),
			State:          stringValue(object["state"]),
			ProducerStepID: stringValue(object["producerStepId"]),
			Attributes:     anyMap(object["attributes"]),
			Extensions:     anyMap(object["extensions"]),
		})
	}
	return capabilities
}

func preparedValuesFromRPC(value any) map[string]chainruntime.PreparedValue {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	values := make(map[string]chainruntime.PreparedValue, len(object))
	for key, item := range object {
		valueObject, ok := item.(map[string]any)
		if !ok {
			continue
		}
		values[key] = chainruntime.PreparedValue{
			Value:    valueObject["value"],
			Editable: boolValue(valueObject["editable"]),
		}
	}
	return values
}

func transitionsFromRPC(value any) []chainruntime.CapabilityTransition {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	transitions := make([]chainruntime.CapabilityTransition, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		transitions = append(transitions, chainruntime.CapabilityTransition{
			CapabilityID: stringValue(object["capabilityId"]),
			From:         stringValue(object["from"]),
			To:           stringValue(object["to"]),
			Reason:       stringValue(object["reason"]),
		})
	}
	return transitions
}

func evidenceFromRPC(value any) []chainruntime.Evidence {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	evidence := make([]chainruntime.Evidence, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		evidence = append(evidence, chainruntime.Evidence{
			ID:           stringValue(object["id"]),
			Level:        stringValue(object["level"]),
			Kind:         stringValue(object["kind"]),
			SourceStepID: stringValue(object["sourceStepId"]),
			Message:      stringValue(object["message"]),
			Details:      anyMap(object["details"]),
		})
	}
	return evidence
}

func stepInstalledPayloadsFromRPC(value any) []chainruntime.InstalledPayloadDescriptor {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	payloads := make([]chainruntime.InstalledPayloadDescriptor, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		payload := chainruntime.InstalledPayloadDescriptor{
			Provider:                 stringValue(object["provider"]),
			PayloadID:                stringValue(object["payloadId"]),
			PayloadVersion:           stringValue(object["payloadVersion"]),
			Target:                   stringValue(object["target"]),
			TargetID:                 stringValue(object["targetId"]),
			State:                    stringValue(object["state"]),
			Transport:                stringValue(object["transport"]),
			Endpoint:                 stringValue(object["endpoint"]),
			InstanceKey:              stringValue(object["instanceKey"]),
			StampID:                  stringValue(object["stampId"]),
			ArtifactIDs:              stringSlice(object["artifactIds"]),
			SupportsReconnect:        boolValue(object["supportsReconnect"]),
			SupportsMultipleSessions: boolValue(object["supportsMultipleSessions"]),
			Reconnect:                stepPayloadProviderRecordFromRPC(object["reconnect"]),
			Cleanup:                  stepPayloadProviderRecordFromRPC(object["cleanup"]),
			Metadata:                 stepStringMapFromRPC(object["metadata"]),
		}
		if payload.Provider != "" && payload.PayloadID != "" {
			payloads = append(payloads, payload)
		}
	}
	return payloads
}

func stepPayloadProviderRecordFromRPC(value any) *chainruntime.PayloadProviderRecord {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return &chainruntime.PayloadProviderRecord{
		ProviderID:    stringValue(object["providerId"]),
		Schema:        stringValue(object["schema"]),
		SchemaVersion: stringValue(object["schemaVersion"]),
		Descriptor:    anyMap(object["descriptor"]),
	}
}

func stepStringMapFromRPC(value any) map[string]string {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(object))
	for key, item := range object {
		out[key] = stringValue(item)
	}
	return out
}

func capabilityRefsToRPC(refs []modulecatalog.CapabilityRef) []map[string]any {
	if len(refs) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		out = append(out, map[string]any{
			"capabilityId": ref.CapabilityID,
			"type":         ref.Type,
		})
	}
	return out
}

func preparedValuesToRPC(values map[string]chainruntime.PreparedValue) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = map[string]any{
			"value":    value.Value,
			"editable": value.Editable,
		}
	}
	return out
}
