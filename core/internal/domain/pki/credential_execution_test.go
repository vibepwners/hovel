package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCredentialExecutionsStripSecretsAndComplete(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	runtimeRequest := validCredentialRuntimeRequest()
	runtimeRequest.Material.Data = CredentialBytes("runtime-private-secret")
	runtimeRequest.Material.SHA256 = credentialTestSHA256(runtimeRequest.Material.Data)
	runtime, err := NewRuntimeCredentialExecution(runtimeRequest, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	receipt := CredentialDeliveryReceipt{
		RequestID: runtime.ID, ProviderReference: "provider-opaque-secret",
		ReceiptSHA256: strings.Repeat("a", sha256.Size*2),
	}
	completed, err := CompleteCredentialDeliveryExecution(runtime, receipt, createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	filesRequest := validCredentialFilesRequest()
	filesRequest.Files[0].Path = NewCredentialProtectedPath("/protected/private-key-secret.der")
	files, err := NewFilesCredentialExecution(filesRequest, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if got := files.Plan.Materials[0]; got.Encoding != CredentialEncodingRaw ||
		got.MediaType != "application/pkix-cert" {
		t.Fatalf("file execution material = %#v, want distinct raw encoding and media type", got)
	}

	encodingRequest := validCredentialEncodingRequest()
	encoding, err := NewEncodingCredentialExecution(encodingRequest, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	encodedBytes := CredentialBytes("encoded-private-secret")
	encoded, err := CompleteCredentialEncodingExecution(encoding, CredentialEncodingResult{
		RequestID: encoding.ID,
		Form:      encodingRequest.OutputForm,
		Encoding:  "mbedtls-v1",
		SHA256:    credentialTestSHA256(encodedBytes),
		Data:      encodedBytes,
	}, createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	for _, execution := range []CredentialExecution{completed, files, encoded} {
		data, err := json.Marshal(execution)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{
			"runtime-private-secret",
			"provider-opaque-secret",
			"/protected/private-key-secret.der",
			"encoded-private-secret",
		} {
			if strings.Contains(string(data), secret) {
				t.Fatalf("credential execution JSON leaked %q: %s", secret, data)
			}
		}
		var roundTrip CredentialExecution
		if err := json.Unmarshal(data, &roundTrip); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if !reflect.DeepEqual(execution, roundTrip) {
			t.Fatalf("credential execution round trip differs:\n got %#v\nwant %#v", roundTrip, execution)
		}
	}

	providerReferenceDigest := sha256.Sum256([]byte(receipt.ProviderReference))
	if completed.Result == nil ||
		completed.Result.ProviderReferenceSHA256 != hex.EncodeToString(providerReferenceDigest[:]) {
		t.Fatalf("provider reference digest = %#v", completed.Result)
	}
	if encoded.Result == nil || encoded.Result.Output == nil ||
		encoded.Result.Output.SHA256 != credentialTestSHA256(encodedBytes) {
		t.Fatalf("encoded execution result = %#v", encoded.Result)
	}
}

func TestCredentialExecutionAssignmentRequiresUsableState(t *testing.T) {
	t.Parallel()

	execution, err := NewRuntimeCredentialExecution(
		validCredentialRuntimeRequest(),
		time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		state   AssignmentState
		wantErr bool
	}{
		{name: "active", state: AssignmentStateActive},
		{name: "degraded", state: AssignmentStateDegraded},
		{name: "pending", state: AssignmentStatePending, wantErr: true},
		{name: "disabled", state: AssignmentStateDisabled, wantErr: true},
		{name: "retired", state: AssignmentStateRetired, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assignment := credentialExecutionTestAssignment(t, test.state)
			err := ValidateCredentialExecutionAssignment(assignment, execution.Plan)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateCredentialExecutionAssignment() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func credentialExecutionTestAssignment(t *testing.T, state AssignmentState) Assignment {
	t.Helper()
	args := AssignmentArgs{
		ID:           "assignment-1",
		Purpose:      PurposeTLSServer,
		ConsumerType: ConsumerMeshListener,
		ConsumerID:   "mesh-listener-1",
		ProfileID:    ProfileTLSServer,
		State:        state,
		Revision:     1,
		UpdatedAt:    time.Date(2026, time.July, 12, 11, 0, 0, 0, time.UTC),
	}
	switch state {
	case AssignmentStateActive, AssignmentStateDegraded:
		args.ActiveGenerationID = "generation-active"
		args.StagedGenerationID = "generation-staged"
	case AssignmentStateDisabled, AssignmentStateRetired:
		args.ActiveGenerationID = "generation-active"
	case AssignmentStatePending:
	}
	assignment, err := NewAssignment(args)
	if err != nil {
		t.Fatal(err)
	}
	return assignment
}

func TestCredentialExecutionJSONRejectsUnknownNestedFields(t *testing.T) {
	t.Parallel()

	execution, err := NewRuntimeCredentialExecution(
		validCredentialRuntimeRequest(),
		time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
	}{
		{name: "execution"},
		{name: "plan"},
		{name: "material secret bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneJSONMap(t, wire)
			candidatePlan := candidate["plan"].(map[string]any)
			candidateMaterial := candidatePlan["materials"].([]any)[0].(map[string]any)
			switch test.name {
			case "execution":
				candidate["unknown"] = true
			case "plan":
				candidatePlan["unknown"] = true
			case "material secret bytes":
				candidateMaterial["data"] = "c2VjcmV0"
			}
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var decoded CredentialExecution
			if err := json.Unmarshal(encoded, &decoded); err == nil {
				t.Fatal("json.Unmarshal() accepted an unknown credential execution field")
			}
		})
	}
}

func TestCredentialExecutionLifecycleRejectsInvalidTransitions(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	execution, err := NewRuntimeCredentialExecution(validCredentialRuntimeRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := FailCredentialExecution(execution, " provider rejected delivery ", createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if failed.Failure != "provider rejected delivery" || failed.Revision != 2 {
		t.Fatalf("failed credential execution = %#v", failed)
	}
	if err := ValidateCredentialExecutionTransition(execution, failed); err != nil {
		t.Fatalf("ValidateCredentialExecutionTransition() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CredentialExecution)
	}{
		{name: "plan", mutate: func(candidate *CredentialExecution) {
			candidate.Plan.Provider.ModuleID = "other-module"
		}},
		{name: "revision", mutate: func(candidate *CredentialExecution) { candidate.Revision++ }},
		{name: "created at", mutate: func(candidate *CredentialExecution) {
			candidate.CreatedAt = candidate.CreatedAt.Add(time.Second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := failed.Clone()
			test.mutate(&candidate)
			if err := ValidateCredentialExecutionTransition(execution, candidate); err == nil {
				t.Fatal("ValidateCredentialExecutionTransition() accepted an invalid transition")
			}
		})
	}
}

func TestCredentialExecutionMaterialValidation(t *testing.T) {
	t.Parallel()

	execution, err := NewRuntimeCredentialExecution(
		validCredentialRuntimeRequest(),
		time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	valid := execution.Plan.Materials[0]
	reference := valid
	reference.Projection = CredentialProjectionSignerReference
	reference.Form = CredentialMaterialPrivateReference
	reference.Size = 0
	if err := reference.Validate(); err != nil {
		t.Fatalf("valid reference material: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CredentialExecutionMaterial)
	}{
		{name: "projection", mutate: func(material *CredentialExecutionMaterial) { material.Projection = "unknown" }},
		{name: "form", mutate: func(material *CredentialExecutionMaterial) { material.Form = "unknown" }},
		{name: "projection form mismatch", mutate: func(material *CredentialExecutionMaterial) {
			material.Projection = CredentialProjectionCertificateDER
			material.Form = CredentialMaterialPrivateReference
			material.Size = 0
		}},
		{name: "encoding", mutate: func(material *CredentialExecutionMaterial) { material.Encoding = " encoding" }},
		{name: "media type", mutate: func(material *CredentialExecutionMaterial) { material.MediaType = " media/type" }},
		{name: "digest", mutate: func(material *CredentialExecutionMaterial) { material.SHA256 = "invalid" }},
		{name: "empty bytes", mutate: func(material *CredentialExecutionMaterial) { material.Size = 0 }},
		{name: "oversized bytes", mutate: func(material *CredentialExecutionMaterial) { material.Size = MaximumBundleBinaryBytes + 1 }},
		{name: "sized reference", mutate: func(material *CredentialExecutionMaterial) {
			*material = reference
			material.Size = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("CredentialExecutionMaterial.Validate() accepted an invalid contract")
			}
		})
	}

	var destination *CredentialExecutionMaterial
	if err := destination.UnmarshalJSON([]byte(`{}`)); err == nil {
		t.Fatal("CredentialExecutionMaterial.UnmarshalJSON() accepted a nil destination")
	}
}

func TestCredentialExecutionPlanValidation(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	runtimeExecution, err := NewRuntimeCredentialExecution(validCredentialRuntimeRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	filesExecution, err := NewFilesCredentialExecution(validCredentialFilesRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	encodingExecution, err := NewEncodingCredentialExecution(validCredentialEncodingRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		base   CredentialExecutionPlan
		mutate func(*CredentialExecutionPlan)
	}{
		{name: "kind", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Kind = "unknown" }},
		{name: "provider", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Provider.ModuleID = " invalid-module" }},
		{name: "scope", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Scope.OperationID = "bad id" }},
		{name: "empty materials", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Materials = nil }},
		{name: "too many materials", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) {
			plan.Materials = make([]CredentialExecutionMaterial, MaximumCredentialExecutionFiles+1)
		}},
		{name: "invalid material", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Materials[0].SHA256 = "invalid" }},
		{name: "runtime material count", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) {
			plan.Materials = append(plan.Materials, plan.Materials[0])
		}},
		{name: "runtime media type", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Materials[0].MediaType = "application/pem" }},
		{name: "assignment id", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.AssignmentID = "bad id" }},
		{name: "slot name", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.SlotName = "bad slot" }},
		{name: "missing credential metadata", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Credential = nil }},
		{name: "invalid credential metadata", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Credential.Purpose = "unknown" }},
		{name: "delivery encoding fields", base: runtimeExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.ProviderSchema = "schema-v1" }},
		{name: "files media type", base: filesExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Materials[0].MediaType = "" }},
		{name: "files reference", base: filesExecution.Plan, mutate: func(plan *CredentialExecutionPlan) {
			plan.Materials[0].Projection = CredentialProjectionSignerReference
			plan.Materials[0].Form = CredentialMaterialPrivateReference
			plan.Materials[0].Size = 0
		}},
		{name: "encoding material count", base: encodingExecution.Plan, mutate: func(plan *CredentialExecutionPlan) {
			plan.Materials = append(plan.Materials, plan.Materials[0])
		}},
		{name: "encoding media type", base: encodingExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.Materials[0].MediaType = "application/octet-stream" }},
		{name: "encoding delivery fields", base: encodingExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.AssignmentID = "assignment-valid" }},
		{name: "provider schema", base: encodingExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.ProviderSchema = " schema-v1" }},
		{name: "output form", base: encodingExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.OutputForm = "unknown" }},
		{name: "empty encoding bound", base: encodingExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.MaximumEncodedBytes = 0 }},
		{name: "oversized encoding bound", base: encodingExecution.Plan, mutate: func(plan *CredentialExecutionPlan) { plan.MaximumEncodedBytes = MaximumBundleBinaryBytes + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := test.base.Clone()
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("CredentialExecutionPlan.Validate() accepted an invalid contract")
			}
		})
	}

	var destination *CredentialExecutionPlan
	if err := destination.UnmarshalJSON([]byte(`{}`)); err == nil {
		t.Fatal("CredentialExecutionPlan.UnmarshalJSON() accepted a nil destination")
	}
}

func TestCredentialExecutionOutputAndResultValidation(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	encodingRequest := validCredentialEncodingRequest()
	execution, err := NewEncodingCredentialExecution(encodingRequest, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	data := CredentialBytes("encoded-output")
	completed, err := CompleteCredentialEncodingExecution(execution, CredentialEncodingResult{
		RequestID: execution.ID, Form: encodingRequest.OutputForm, Encoding: "provider-v1",
		SHA256: credentialTestSHA256(data), Data: data,
	}, createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if completed.Result == nil || completed.Result.Output == nil {
		t.Fatal("completed encoding execution has no output")
	}
	valid := *completed.Result.Output

	outputTests := []struct {
		name   string
		plan   CredentialExecutionPlan
		mutate func(*CredentialExecutionOutput)
	}{
		{name: "non encoding plan", plan: CredentialExecutionPlan{Kind: CredentialExecutionRuntime}},
		{name: "form", plan: execution.Plan, mutate: func(output *CredentialExecutionOutput) { output.Form = "unknown" }},
		{name: "encoding", plan: execution.Plan, mutate: func(output *CredentialExecutionOutput) { output.Encoding = " output" }},
		{name: "digest", plan: execution.Plan, mutate: func(output *CredentialExecutionOutput) { output.SHA256 = "invalid" }},
		{name: "empty size", plan: execution.Plan, mutate: func(output *CredentialExecutionOutput) { output.Size = 0 }},
		{name: "oversized size", plan: execution.Plan, mutate: func(output *CredentialExecutionOutput) { output.Size = MaximumBundleBinaryBytes + 1 }},
		{name: "form mismatch", plan: execution.Plan, mutate: func(output *CredentialExecutionOutput) { output.Form = CredentialMaterialPublic }},
		{name: "plan bound", plan: execution.Plan, mutate: func(output *CredentialExecutionOutput) { output.Size = execution.Plan.MaximumEncodedBytes + 1 }},
	}
	for _, test := range outputTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			if err := candidate.Validate(test.plan); err == nil {
				t.Fatal("CredentialExecutionOutput.Validate() accepted an invalid contract")
			}
		})
	}

	var outputDestination *CredentialExecutionOutput
	if err := outputDestination.UnmarshalJSON([]byte(`{}`)); err == nil {
		t.Fatal("CredentialExecutionOutput.UnmarshalJSON() accepted a nil destination")
	}
	var resultDestination *CredentialExecutionResult
	if err := resultDestination.UnmarshalJSON([]byte(`{}`)); err == nil {
		t.Fatal("CredentialExecutionResult.UnmarshalJSON() accepted a nil destination")
	}

	runtime, err := NewRuntimeCredentialExecution(validCredentialRuntimeRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	resultTests := []struct {
		name   string
		plan   CredentialExecutionPlan
		result CredentialExecutionResult
	}{
		{name: "encoding without output", plan: execution.Plan, result: CredentialExecutionResult{}},
		{name: "encoding with receipt", plan: execution.Plan, result: CredentialExecutionResult{ReceiptSHA256: strings.Repeat("a", sha256.Size*2), Output: &valid}},
		{name: "delivery with output", plan: runtime.Plan, result: CredentialExecutionResult{Output: &valid}},
		{name: "invalid provider reference digest", plan: runtime.Plan, result: CredentialExecutionResult{ProviderReferenceSHA256: "invalid"}},
		{name: "invalid receipt digest", plan: runtime.Plan, result: CredentialExecutionResult{ReceiptSHA256: "invalid"}},
	}
	for _, test := range resultTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.result.Validate(test.plan); err == nil {
				t.Fatal("CredentialExecutionResult.Validate() accepted an invalid contract")
			}
		})
	}
}

func TestCredentialExecutionLifecycleErrors(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	runtime, err := NewRuntimeCredentialExecution(validCredentialRuntimeRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	encoding, err := NewEncodingCredentialExecution(validCredentialEncodingRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	validReceipt := CredentialDeliveryReceipt{RequestID: runtime.ID, ReceiptSHA256: strings.Repeat("a", sha256.Size*2)}
	validEncoded := CredentialEncodingResult{
		RequestID: encoding.ID, Form: encoding.Plan.OutputForm, Encoding: "provider-v1",
		Data: CredentialBytes("encoded-output"),
	}
	validEncoded.SHA256 = credentialTestSHA256(validEncoded.Data)

	if _, err := CompleteCredentialDeliveryExecution(encoding, validReceipt, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialDeliveryExecution() accepted an encoding execution")
	}
	invalidReceipt := validReceipt
	invalidReceipt.ReceiptSHA256 = "invalid"
	if _, err := CompleteCredentialDeliveryExecution(runtime, invalidReceipt, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialDeliveryExecution() accepted an invalid receipt")
	}
	mismatchedReceipt := validReceipt
	mismatchedReceipt.RequestID = "credential-execution-other"
	if _, err := CompleteCredentialDeliveryExecution(runtime, mismatchedReceipt, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialDeliveryExecution() accepted a mismatched receipt")
	}

	if _, err := CompleteCredentialEncodingExecution(runtime, validEncoded, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialEncodingExecution() accepted a delivery execution")
	}
	invalidEncoded := validEncoded.Clone()
	invalidEncoded.SHA256 = "invalid"
	if _, err := CompleteCredentialEncodingExecution(encoding, invalidEncoded, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialEncodingExecution() accepted an invalid output")
	}
	mismatchedEncoded := validEncoded.Clone()
	mismatchedEncoded.RequestID = "credential-execution-other"
	if _, err := CompleteCredentialEncodingExecution(encoding, mismatchedEncoded, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialEncodingExecution() accepted a mismatched output")
	}

	completed, err := CompleteCredentialDeliveryExecution(runtime, validReceipt, createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteCredentialDeliveryExecution(completed, validReceipt, createdAt.Add(2*time.Minute)); err == nil {
		t.Fatal("CompleteCredentialDeliveryExecution() accepted a terminal execution")
	}
	if _, err := FailCredentialExecution(completed, "late failure", createdAt.Add(2*time.Minute)); err == nil {
		t.Fatal("FailCredentialExecution() accepted a terminal execution")
	}
	if _, err := FailCredentialExecution(runtime, "failure", createdAt.Add(-time.Second)); err == nil {
		t.Fatal("FailCredentialExecution() accepted a timestamp before the current state")
	}
	exhausted := runtime.Clone()
	exhausted.Revision = MaximumSequenceNumber
	if _, err := FailCredentialExecution(exhausted, "failure", createdAt.Add(time.Minute)); err == nil {
		t.Fatal("FailCredentialExecution() accepted an exhausted revision")
	}
	if _, err := FailCredentialExecution(runtime, " ", createdAt.Add(time.Minute)); err == nil {
		t.Fatal("FailCredentialExecution() accepted an empty failure")
	}

	if err := ValidateCredentialExecutionTransition(runtime, runtime); err == nil {
		t.Fatal("ValidateCredentialExecutionTransition() accepted a nonterminal transition")
	}
	invalidPrevious := runtime.Clone()
	invalidPrevious.ID = "bad id"
	if err := ValidateCredentialExecutionTransition(invalidPrevious, completed); err == nil {
		t.Fatal("ValidateCredentialExecutionTransition() accepted an invalid previous state")
	}

	assignment := credentialExecutionTestAssignment(t, AssignmentStateActive)
	invalidAssignment := assignment
	invalidAssignment.ID = "bad id"
	if err := ValidateCredentialExecutionAssignment(invalidAssignment, runtime.Plan); err == nil {
		t.Fatal("ValidateCredentialExecutionAssignment() accepted an invalid assignment")
	}
	invalidPlan := runtime.Plan.Clone()
	invalidPlan.Kind = "unknown"
	if err := ValidateCredentialExecutionAssignment(assignment, invalidPlan); err == nil {
		t.Fatal("ValidateCredentialExecutionAssignment() accepted an invalid plan")
	}
	if err := ValidateCredentialExecutionAssignment(assignment, encoding.Plan); err == nil {
		t.Fatal("ValidateCredentialExecutionAssignment() accepted an encoding plan")
	}
	mismatchedPlan := runtime.Plan.Clone()
	mismatchedPlan.AssignmentID = "assignment-other"
	if err := ValidateCredentialExecutionAssignment(assignment, mismatchedPlan); err == nil {
		t.Fatal("ValidateCredentialExecutionAssignment() accepted a mismatched assignment")
	}
}

func TestCredentialExecutionValidationAndJSONErrorPaths(t *testing.T) {
	t.Parallel()

	if err := CredentialExecutionKind("unknown").Validate(); err == nil {
		t.Fatal("CredentialExecutionKind.Validate() accepted an unknown kind")
	}
	if err := CredentialExecutionStatus("unknown").Validate(); err == nil {
		t.Fatal("CredentialExecutionStatus.Validate() accepted an unknown status")
	}
	for _, destination := range []json.Unmarshaler{
		&CredentialExecutionMaterial{},
		&CredentialExecutionPlan{},
		&CredentialExecutionOutput{},
		&CredentialExecutionResult{},
	} {
		if err := destination.UnmarshalJSON([]byte(`{"unterminated"`)); err == nil {
			t.Fatalf("%T.UnmarshalJSON() accepted malformed JSON", destination)
		}
	}

	invalidResultJSON := []string{
		`{"providerReferenceSha256":"invalid"}`,
		`{"receiptSha256":"invalid"}`,
	}
	for _, data := range invalidResultJSON {
		var result CredentialExecutionResult
		if err := json.Unmarshal([]byte(data), &result); err == nil {
			t.Fatalf("CredentialExecutionResult.UnmarshalJSON() accepted %s", data)
		}
	}

	createdAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	execution, err := NewRuntimeCredentialExecution(validCredentialRuntimeRequest(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := (CredentialExecutionResult{}).Validate(execution.Plan); err != nil {
		t.Fatalf("empty delivery result: %v", err)
	}

	data, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	wireTests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unsupported status", mutate: func(candidate map[string]any) { candidate["status"] = "unknown" }},
		{name: "inactive result", mutate: func(candidate map[string]any) { candidate["result"] = map[string]any{} }},
		{name: "invalid execution", mutate: func(candidate map[string]any) { candidate["revision"] = 0 }},
	}
	for _, test := range wireTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := cloneJSONMap(t, wire)
			test.mutate(candidate)
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var decoded CredentialExecution
			if err := json.Unmarshal(encoded, &decoded); err == nil {
				t.Fatal("CredentialExecution.UnmarshalJSON() accepted an invalid execution")
			}
		})
	}
	var nilExecution *CredentialExecution
	if err := nilExecution.UnmarshalJSON(data); err == nil {
		t.Fatal("CredentialExecution.UnmarshalJSON() accepted a nil destination")
	}

	validResult := &CredentialExecutionResult{ReceiptSHA256: strings.Repeat("a", sha256.Size*2)}
	validationTests := []struct {
		name   string
		mutate func(*CredentialExecution)
	}{
		{name: "schema", mutate: func(candidate *CredentialExecution) { candidate.SchemaVersion = "v2" }},
		{name: "id", mutate: func(candidate *CredentialExecution) { candidate.ID = "bad id" }},
		{name: "plan", mutate: func(candidate *CredentialExecution) { candidate.Plan.Kind = "unknown" }},
		{name: "status", mutate: func(candidate *CredentialExecution) { candidate.Status = "unknown" }},
		{name: "revision", mutate: func(candidate *CredentialExecution) { candidate.Revision = 0 }},
		{name: "created timestamp", mutate: func(candidate *CredentialExecution) { candidate.CreatedAt = time.Time{} }},
		{name: "updated timestamp", mutate: func(candidate *CredentialExecution) { candidate.UpdatedAt = candidate.CreatedAt.Add(-time.Second) }},
		{name: "pending result", mutate: func(candidate *CredentialExecution) { candidate.Result = validResult }},
		{name: "pending failure", mutate: func(candidate *CredentialExecution) { candidate.Failure = "failure" }},
		{name: "succeeded missing result", mutate: func(candidate *CredentialExecution) { candidate.Status = CredentialExecutionSucceeded }},
		{name: "succeeded with failure", mutate: func(candidate *CredentialExecution) {
			candidate.Status = CredentialExecutionSucceeded
			candidate.Result = validResult
			candidate.Failure = "failure"
		}},
		{name: "failed empty", mutate: func(candidate *CredentialExecution) { candidate.Status = CredentialExecutionFailed }},
		{name: "failed noncanonical", mutate: func(candidate *CredentialExecution) {
			candidate.Status = CredentialExecutionFailed
			candidate.Failure = " failure "
		}},
		{name: "failed oversized", mutate: func(candidate *CredentialExecution) {
			candidate.Status = CredentialExecutionFailed
			candidate.Failure = strings.Repeat("x", MaximumCredentialExecutionFailureBytes+1)
		}},
		{name: "failed with result", mutate: func(candidate *CredentialExecution) {
			candidate.Status = CredentialExecutionFailed
			candidate.Failure = "failure"
			candidate.Result = validResult
		}},
	}
	for _, test := range validationTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := execution.Clone()
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("CredentialExecution.Validate() accepted an invalid state")
			}
		})
	}
}

func TestCredentialExecutionConstructorAndTransitionErrorPaths(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	runtimeRequest := validCredentialRuntimeRequest()
	filesRequest := validCredentialFilesRequest()
	encodingRequest := validCredentialEncodingRequest()

	invalidRuntime := runtimeRequest.Clone()
	invalidRuntime.RequestID = "bad id"
	if _, err := NewRuntimeCredentialExecution(invalidRuntime, createdAt); err == nil {
		t.Fatal("NewRuntimeCredentialExecution() accepted an invalid request")
	}
	invalidFiles := filesRequest.Clone()
	invalidFiles.RequestID = "bad id"
	if _, err := NewFilesCredentialExecution(invalidFiles, createdAt); err == nil {
		t.Fatal("NewFilesCredentialExecution() accepted an invalid request")
	}
	invalidEncoding := encodingRequest.Clone()
	invalidEncoding.RequestID = "bad id"
	if _, err := NewEncodingCredentialExecution(invalidEncoding, createdAt); err == nil {
		t.Fatal("NewEncodingCredentialExecution() accepted an invalid request")
	}
	if _, err := NewRuntimeCredentialExecution(runtimeRequest, time.Time{}); err == nil {
		t.Fatal("NewRuntimeCredentialExecution() accepted an invalid creation time")
	}

	runtime, err := NewRuntimeCredentialExecution(runtimeRequest, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	encoding, err := NewEncodingCredentialExecution(encodingRequest, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	receipt := CredentialDeliveryReceipt{RequestID: runtime.ID, ReceiptSHA256: strings.Repeat("a", sha256.Size*2)}
	encodedData := CredentialBytes("encoded-output")
	encoded := CredentialEncodingResult{
		RequestID: encoding.ID, Form: encoding.Plan.OutputForm, Encoding: "provider-v1",
		SHA256: credentialTestSHA256(encodedData), Data: encodedData,
	}

	invalidExecution := runtime.Clone()
	invalidExecution.ID = "bad id"
	if _, err := CompleteCredentialDeliveryExecution(invalidExecution, receipt, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialDeliveryExecution() accepted an invalid execution")
	}
	invalidEncodingExecution := encoding.Clone()
	invalidEncodingExecution.ID = "bad id"
	if _, err := CompleteCredentialEncodingExecution(invalidEncodingExecution, encoded, createdAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialEncodingExecution() accepted an invalid execution")
	}
	if _, err := FailCredentialExecution(invalidExecution, "failure", createdAt.Add(time.Minute)); err == nil {
		t.Fatal("FailCredentialExecution() accepted an invalid execution")
	}
	if _, err := CompleteCredentialDeliveryExecution(runtime, receipt, createdAt.Add(-time.Second)); err == nil {
		t.Fatal("CompleteCredentialDeliveryExecution() accepted an update before the current state")
	}
	const invalidJSONYear = 10000
	invalidBookkeepingTime := time.Date(invalidJSONYear, time.January, 1, 0, 0, 0, 0, time.UTC)
	if _, err := CompleteCredentialEncodingExecution(encoding, encoded, invalidBookkeepingTime); err == nil {
		t.Fatal("CompleteCredentialEncodingExecution() accepted an out-of-range update time")
	}

	failed, err := FailCredentialExecution(runtime, "failure", createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	invalidNext := failed.Clone()
	invalidNext.ID = "bad id"
	if err := ValidateCredentialExecutionTransition(runtime, invalidNext); err == nil {
		t.Fatal("ValidateCredentialExecutionTransition() accepted an invalid next state")
	}
	otherFailed := failed.Clone()
	otherFailed.Revision++
	otherFailed.UpdatedAt = otherFailed.UpdatedAt.Add(time.Minute)
	if err := ValidateCredentialExecutionTransition(failed, otherFailed); err == nil {
		t.Fatal("ValidateCredentialExecutionTransition() accepted a transition from terminal state")
	}
	if err := validateCredentialAssignmentUsable(Assignment{State: "unknown"}, "test"); err == nil {
		t.Fatal("validateCredentialAssignmentUsable() accepted an unsupported state")
	}

	validMaterial := runtime.Plan.Materials[0]
	materialJSON, err := json.Marshal(validMaterial)
	if err != nil {
		t.Fatal(err)
	}
	var materialWire map[string]any
	if err := json.Unmarshal(materialJSON, &materialWire); err != nil {
		t.Fatal(err)
	}
	materialWire["sha256"] = "invalid"
	materialJSON, err = json.Marshal(materialWire)
	if err != nil {
		t.Fatal(err)
	}
	var material CredentialExecutionMaterial
	if err := json.Unmarshal(materialJSON, &material); err == nil {
		t.Fatal("CredentialExecutionMaterial.UnmarshalJSON() accepted invalid material")
	}

	planJSON, err := json.Marshal(runtime.Plan)
	if err != nil {
		t.Fatal(err)
	}
	var planWire map[string]any
	if err := json.Unmarshal(planJSON, &planWire); err != nil {
		t.Fatal(err)
	}
	planWire["kind"] = "unknown"
	planJSON, err = json.Marshal(planWire)
	if err != nil {
		t.Fatal(err)
	}
	var plan CredentialExecutionPlan
	if err := json.Unmarshal(planJSON, &plan); err == nil {
		t.Fatal("CredentialExecutionPlan.UnmarshalJSON() accepted an invalid plan")
	}

	output := CredentialExecutionOutput{
		Form: encoding.Plan.OutputForm, Encoding: "provider-v1",
		SHA256: credentialTestSHA256(encodedData), Size: uint64(len(encodedData)),
	}
	outputJSON, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var outputWire map[string]any
	if err := json.Unmarshal(outputJSON, &outputWire); err != nil {
		t.Fatal(err)
	}
	outputWire["size"] = 0
	outputJSON, err = json.Marshal(outputWire)
	if err != nil {
		t.Fatal(err)
	}
	var decodedOutput CredentialExecutionOutput
	if err := json.Unmarshal(outputJSON, &decodedOutput); err == nil {
		t.Fatal("CredentialExecutionOutput.UnmarshalJSON() accepted invalid output")
	}

	invalidPlan := runtime.Plan.Clone()
	invalidPlan.Kind = "unknown"
	if err := (CredentialExecutionResult{}).Validate(invalidPlan); err == nil {
		t.Fatal("CredentialExecutionResult.Validate() accepted an invalid plan")
	}
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
