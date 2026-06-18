package pythonrpc

import (
	"context"
	"fmt"

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
	return stepPrepareResultFromRPC(result)
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
	return stepExecuteResultFromRPC(req, result)
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

func stepPrepareResultFromRPC(result map[string]any) (chainruntime.StepPrepareResult, error) {
	plannedOutputs, err := capabilitiesFromRPC(result["plannedOutputs"], "plannedOutputs")
	if err != nil {
		return chainruntime.StepPrepareResult{}, err
	}
	preparedValues, err := preparedValuesFromRPC(result["preparedValues"])
	if err != nil {
		return chainruntime.StepPrepareResult{}, err
	}
	evidence, err := evidenceFromRPC(result["evidence"])
	if err != nil {
		return chainruntime.StepPrepareResult{}, err
	}
	return chainruntime.StepPrepareResult{
		PlannedOutputs: plannedOutputs,
		PreparedValues: preparedValues,
		Evidence:       evidence,
	}, nil
}

func stepExecuteResultFromRPC(req chainruntime.StepExecuteRequest, result map[string]any) (chainruntime.StepExecuteResult, error) {
	capabilities, err := capabilitiesFromRPC(result["capabilities"], "capabilities")
	if err != nil {
		return chainruntime.StepExecuteResult{}, err
	}
	transitions, err := transitionsFromRPC(result["stateTransitions"])
	if err != nil {
		return chainruntime.StepExecuteResult{}, err
	}
	evidence, err := evidenceFromRPC(result["evidence"])
	if err != nil {
		return chainruntime.StepExecuteResult{}, err
	}
	sessions, err := sessionsFromStepRPC(StepCallRequest{ModuleID: req.ModuleID, Params: map[string]any{"runId": req.RunID}}, result["sessions"])
	if err != nil {
		return chainruntime.StepExecuteResult{}, err
	}
	installedPayloads, err := stepInstalledPayloadsFromRPC(result["installedPayloads"])
	if err != nil {
		return chainruntime.StepExecuteResult{}, err
	}
	return chainruntime.StepExecuteResult{
		Status:            stringValue(result["status"]),
		Capabilities:      capabilities,
		StateTransitions:  transitions,
		Evidence:          evidence,
		Sessions:          sessions,
		InstalledPayloads: installedPayloads,
	}, nil
}

func sessionsFromStepRPC(request StepCallRequest, value any) ([]run.SessionRef, error) {
	items, err := rpcArray(value, "sessions")
	if err != nil {
		return nil, err
	}
	sessions := make([]run.SessionRef, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "sessions", index)
		if err != nil {
			return nil, err
		}
		capabilities, err := strictStringSlice(object["capabilities"], fmt.Sprintf("sessions item %d capabilities", index+1))
		if err != nil {
			return nil, err
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
			Capabilities:       capabilities,
		}
		if session.ID == "" {
			return nil, fmt.Errorf("sessions item %d id is required", index+1)
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func capabilitiesFromRPC(value any, label string) ([]modulecatalog.Capability, error) {
	items, err := rpcArray(value, label)
	if err != nil {
		return nil, err
	}
	capabilities := make([]modulecatalog.Capability, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, label, index)
		if err != nil {
			return nil, err
		}
		attributes, err := optionalAnyMap(object["attributes"], fmt.Sprintf("%s item %d attributes", label, index+1))
		if err != nil {
			return nil, err
		}
		extensions, err := optionalAnyMap(object["extensions"], fmt.Sprintf("%s item %d extensions", label, index+1))
		if err != nil {
			return nil, err
		}
		capability := modulecatalog.Capability{
			ID:             stringValue(object["id"]),
			Type:           modulecatalog.CapabilityType(stringValue(object["type"])),
			SchemaVersion:  stringValue(object["schemaVersion"]),
			State:          stringValue(object["state"]),
			ProducerStepID: stringValue(object["producerStepId"]),
			Attributes:     attributes,
			Extensions:     extensions,
		}
		if capability.ID == "" {
			return nil, fmt.Errorf("%s item %d id is required", label, index+1)
		}
		if capability.Type == "" {
			return nil, fmt.Errorf("%s item %d type is required", label, index+1)
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities, nil
}

func preparedValuesFromRPC(value any) (map[string]chainruntime.PreparedValue, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("preparedValues must be an object")
	}
	values := make(map[string]chainruntime.PreparedValue, len(object))
	for key, item := range object {
		valueObject, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("preparedValues item %q must be an object", key)
		}
		values[key] = chainruntime.PreparedValue{
			Value:    valueObject["value"],
			Editable: boolValue(valueObject["editable"]),
		}
	}
	return values, nil
}

func transitionsFromRPC(value any) ([]chainruntime.CapabilityTransition, error) {
	items, err := rpcArray(value, "stateTransitions")
	if err != nil {
		return nil, err
	}
	transitions := make([]chainruntime.CapabilityTransition, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "stateTransitions", index)
		if err != nil {
			return nil, err
		}
		transition := chainruntime.CapabilityTransition{
			CapabilityID: stringValue(object["capabilityId"]),
			From:         stringValue(object["from"]),
			To:           stringValue(object["to"]),
			Reason:       stringValue(object["reason"]),
		}
		if transition.CapabilityID == "" {
			return nil, fmt.Errorf("stateTransitions item %d capabilityId is required", index+1)
		}
		if transition.To == "" {
			return nil, fmt.Errorf("stateTransitions item %d to is required", index+1)
		}
		transitions = append(transitions, transition)
	}
	return transitions, nil
}

func evidenceFromRPC(value any) ([]chainruntime.Evidence, error) {
	items, err := rpcArray(value, "evidence")
	if err != nil {
		return nil, err
	}
	evidence := make([]chainruntime.Evidence, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "evidence", index)
		if err != nil {
			return nil, err
		}
		details, err := optionalAnyMap(object["details"], fmt.Sprintf("evidence item %d details", index+1))
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, chainruntime.Evidence{
			ID:           stringValue(object["id"]),
			Level:        stringValue(object["level"]),
			Kind:         stringValue(object["kind"]),
			SourceStepID: stringValue(object["sourceStepId"]),
			Message:      stringValue(object["message"]),
			Details:      details,
		})
	}
	return evidence, nil
}

func stepInstalledPayloadsFromRPC(value any) ([]chainruntime.InstalledPayloadDescriptor, error) {
	items, err := rpcArray(value, "installedPayloads")
	if err != nil {
		return nil, err
	}
	payloads := make([]chainruntime.InstalledPayloadDescriptor, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "installedPayloads", index)
		if err != nil {
			return nil, err
		}
		artifactIDs, err := strictStringSlice(object["artifactIds"], fmt.Sprintf("installedPayloads item %d artifactIds", index+1))
		if err != nil {
			return nil, err
		}
		reconnect, err := stepPayloadProviderRecordFromRPC(object["reconnect"], fmt.Sprintf("installedPayloads item %d reconnect", index+1))
		if err != nil {
			return nil, err
		}
		cleanup, err := stepPayloadProviderRecordFromRPC(object["cleanup"], fmt.Sprintf("installedPayloads item %d cleanup", index+1))
		if err != nil {
			return nil, err
		}
		metadata, err := stepStringMapFromRPC(object["metadata"], fmt.Sprintf("installedPayloads item %d metadata", index+1))
		if err != nil {
			return nil, err
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
			ArtifactIDs:              artifactIDs,
			SupportsReconnect:        boolValue(object["supportsReconnect"]),
			SupportsMultipleSessions: boolValue(object["supportsMultipleSessions"]),
			Reconnect:                reconnect,
			Cleanup:                  cleanup,
			Metadata:                 metadata,
		}
		if payload.Provider == "" {
			return nil, fmt.Errorf("installedPayloads item %d provider is required", index+1)
		}
		if payload.PayloadID == "" {
			return nil, fmt.Errorf("installedPayloads item %d payloadId is required", index+1)
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

func stepPayloadProviderRecordFromRPC(value any, label string) (*chainruntime.PayloadProviderRecord, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	descriptor, err := optionalAnyMap(object["descriptor"], label+" descriptor")
	if err != nil {
		return nil, err
	}
	return &chainruntime.PayloadProviderRecord{
		ProviderID:    stringValue(object["providerId"]),
		Schema:        stringValue(object["schema"]),
		SchemaVersion: stringValue(object["schemaVersion"]),
		Descriptor:    descriptor,
	}, nil
}

func stepStringMapFromRPC(value any, label string) (map[string]string, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	out := make(map[string]string, len(object))
	for key, item := range object {
		out[key] = stringValue(item)
	}
	return out, nil
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
