package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCredentialProviderExecutionJSONIsStrictAndRoundTrips(t *testing.T) {
	t.Parallel()

	requests := []struct {
		name  string
		value any
		new   func() any
	}{
		{
			name: "runtime request",
			value: CredentialRuntimeRequest{
				SchemaVersion: CredentialProviderExecutionSchemaV1,
				Provider:      validCredentialProviderTarget(),
				RequestID:     "runtime-1",
				AssignmentID:  "assignment-1",
				SlotName:      "tls-server",
				Credential:    validResolvedCredentialMetadata(),
				Material:      validResolvedCredentialMaterial(),
				Scope:         CredentialOperationScope{RunID: "run-1", NodeID: "node-1"},
			},
			new: func() any { return &CredentialRuntimeRequest{} },
		},
		{
			name: "files request",
			value: CredentialFilesRequest{
				SchemaVersion: CredentialProviderExecutionSchemaV1,
				Provider:      validCredentialProviderTarget(),
				RequestID:     "files-1",
				AssignmentID:  "assignment-1",
				SlotName:      "tls-server",
				Credential:    validResolvedCredentialMetadata(),
				Files: []CredentialFile{{
					Projection: CredentialProjectionCertificateDER,
					Form:       CredentialMaterialPublic,
					MediaType:  "application/pkix-cert",
					Path:       "/protected/certificate.der",
					SHA256:     strings.Repeat("a", 64),
					Size:       128,
				}},
			},
			new: func() any { return &CredentialFilesRequest{} },
		},
		{
			name:  "encoding request",
			value: validCredentialEncodingRequest(),
			new:   func() any { return &CredentialEncodingRequest{} },
		},
		{
			name:  "stamp request",
			value: validCredentialStampExecutionRequest(t),
			new:   func() any { return &CredentialStampExecutionRequest{} },
		},
		{
			name: "operation delivery",
			value: CredentialOperationDelivery{
				Capability: DeliveryCapabilityRuntime,
				Runtime:    pointerTo(validCredentialRuntimeRequest()),
			},
			new: func() any { return &CredentialOperationDelivery{} },
		},
	}

	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			destination := test.new()
			if err := json.Unmarshal(data, destination); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			unknown := append(data[:len(data)-1:len(data)-1], []byte(`,"unknown":true}`)...)
			if err := json.Unmarshal(unknown, test.new()); err == nil {
				t.Fatal("json.Unmarshal() accepted an unknown execution field")
			}
		})
	}
}

func TestCredentialMaterialSelectionValidatesProjectionAndForm(t *testing.T) {
	t.Parallel()

	valid := []CredentialMaterialSelection{
		{Projection: CredentialProjectionCertificateDER, Form: CredentialMaterialPublic},
		{Projection: CredentialProjectionPrivateKeyPKCS8, Form: CredentialMaterialPrivateBytes},
		{Projection: CredentialProjectionSignerReference, Form: CredentialMaterialPrivateReference},
		{Projection: CredentialProjectionBundle, Form: CredentialMaterialPrivateBytes},
		{Projection: CredentialProjectionProviderEncoding, Form: CredentialMaterialPrivateReference},
		{Projection: CredentialProjectionLiteralReference, Form: CredentialMaterialPublic},
	}
	for _, selection := range valid {
		if err := selection.Validate(); err != nil {
			t.Fatalf("Validate(%q, %q) error = %v", selection.Projection, selection.Form, err)
		}
	}

	tests := []struct {
		name      string
		selection CredentialMaterialSelection
	}{
		{
			name:      "unknown projection",
			selection: CredentialMaterialSelection{Projection: "unknown", Form: CredentialMaterialPublic},
		},
		{
			name:      "unknown form",
			selection: CredentialMaterialSelection{Projection: CredentialProjectionBundle, Form: "unknown"},
		},
		{
			name: "public projection with private bytes",
			selection: CredentialMaterialSelection{
				Projection: CredentialProjectionCertificateDER,
				Form:       CredentialMaterialPrivateBytes,
			},
		},
		{
			name: "private key with public form",
			selection: CredentialMaterialSelection{
				Projection: CredentialProjectionPrivateKeyPKCS8,
				Form:       CredentialMaterialPublic,
			},
		},
		{
			name: "signer reference with private bytes",
			selection: CredentialMaterialSelection{
				Projection: CredentialProjectionSignerReference,
				Form:       CredentialMaterialPrivateBytes,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.selection.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid material selection")
			}
		})
	}
}

func TestCredentialConsumerBindingConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		new  func() (CredentialConsumerBinding, error)
		want CredentialConsumerBinding
	}{
		{
			name: "provider",
			new:  func() (CredentialConsumerBinding, error) { return NewMeshProviderConsumer("mesh") },
			want: CredentialConsumerBinding{Type: ConsumerMeshProvider, ID: "mesh"},
		},
		{
			name: "listener",
			new: func() (CredentialConsumerBinding, error) {
				return NewMeshListenerConsumer("mesh", "edge")
			},
			want: CredentialConsumerBinding{Type: ConsumerMeshListener, ID: "mesh/edge"},
		},
		{
			name: "node",
			new: func() (CredentialConsumerBinding, error) {
				return NewMeshNodeConsumer("mesh", "pivot")
			},
			want: CredentialConsumerBinding{Type: ConsumerMeshNode, ID: "mesh/pivot"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.new()
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("binding = %#v, want %#v", got, test.want)
			}
			assignment := Assignment{ConsumerType: got.Type, ConsumerID: got.ID}
			if !got.Matches(assignment) {
				t.Fatal("binding did not match its assignment subject")
			}
		})
	}
	if _, err := NewMeshListenerConsumer("mesh", ""); err == nil {
		t.Fatal("NewMeshListenerConsumer() accepted an empty listener id")
	}
}

func TestCredentialDeliveryDescriptorValidatesRuntimeRequest(t *testing.T) {
	t.Parallel()

	descriptor := validCredentialDeliveryDescriptor()
	descriptor.Capabilities = append(descriptor.Capabilities, DeliveryCapabilityRuntime)
	descriptor.Slots[0].AcceptedProjections = []CredentialProjection{
		CredentialProjectionCertificateDER,
	}
	request := validCredentialRuntimeRequest()
	request.Material = ResolvedCredentialMaterial{
		Projection: CredentialProjectionCertificateDER,
		Form:       CredentialMaterialPublic,
		Encoding:   EncodingBase64DER,
		Data:       CredentialBytes("certificate"),
	}
	request.Material.SHA256 = credentialTestSHA256(request.Material.Data)
	if err := descriptor.ValidateRuntimeRequest(request); err != nil {
		t.Fatalf("ValidateRuntimeRequest() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CredentialDeliveryDescriptor, *CredentialRuntimeRequest)
	}{
		{
			name: "runtime capability missing",
			mutate: func(descriptor *CredentialDeliveryDescriptor, _ *CredentialRuntimeRequest) {
				descriptor.Capabilities = []DeliveryCapability{DeliveryCapabilityStampStandard}
			},
		},
		{
			name: "slot missing",
			mutate: func(_ *CredentialDeliveryDescriptor, request *CredentialRuntimeRequest) {
				request.SlotName = "missing"
			},
		},
		{
			name: "projection rejected",
			mutate: func(_ *CredentialDeliveryDescriptor, request *CredentialRuntimeRequest) {
				request.Material = validResolvedCredentialMaterial()
			},
		},
		{
			name: "metadata rejected",
			mutate: func(_ *CredentialDeliveryDescriptor, request *CredentialRuntimeRequest) {
				request.Credential.ProfileID = ProfileTLSClient
			},
		},
		{
			name: "material too large",
			mutate: func(descriptor *CredentialDeliveryDescriptor, request *CredentialRuntimeRequest) {
				descriptor.Slots[0].MaximumEncodedBytes = 1
				request.Material.Data = CredentialBytes("too large")
				request.Material.SHA256 = credentialTestSHA256(request.Material.Data)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateDescriptor := descriptor.Clone()
			candidateRequest := request.Clone()
			test.mutate(&candidateDescriptor, &candidateRequest)
			if err := candidateDescriptor.ValidateRuntimeRequest(candidateRequest); err == nil {
				t.Fatal("ValidateRuntimeRequest() accepted an incompatible request")
			}
		})
	}
}

func TestCredentialOperationDeliveriesClearEphemeralValues(t *testing.T) {
	t.Parallel()

	runtime := validCredentialRuntimeRequest()
	runtimeData := runtime.Material.Data
	files := validCredentialFilesRequest()
	deliveries := CredentialOperationDeliveries{
		{Capability: DeliveryCapabilityRuntime, Runtime: &runtime},
		{Capability: DeliveryCapabilityFiles, Files: &files},
	}
	deliveries.Clear()
	if len(deliveries) != 2 {
		t.Fatalf("delivery length changed to %d", len(deliveries))
	}
	for _, value := range runtimeData {
		if value != 0 {
			t.Fatal("Clear() retained credential bytes")
		}
	}
	for _, delivery := range deliveries {
		if delivery.Runtime != nil || delivery.Files != nil || delivery.Capability != "" {
			t.Fatalf("Clear() retained delivery metadata: %#v", delivery)
		}
	}
}

func TestCredentialSelectionJSONIsStrictNonSecretAndRoundTrips(t *testing.T) {
	t.Parallel()

	want := validCredentialSelection("request-1", "assignment-1", "tls-server")
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"requestId":"request-1","assignmentId":"assignment-1","slotName":"tls-server","capability":"runtime","material":{"projection":"certificate-der","form":"public"}}`
	if string(data) != expected {
		t.Fatalf("json.Marshal() = %s, want exact non-secret contract %s", data, expected)
	}
	var got CredentialSelection
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got != want {
		t.Fatalf("json.Unmarshal() = %#v, want %#v", got, want)
	}

	invalid := []struct {
		name string
		data string
	}{
		{name: "unknown selection field", data: expected[:len(expected)-1] + `,"path":"/secret"}`},
		{name: "unknown material field", data: strings.Replace(expected, `"form":"public"`, `"form":"public","data":"secret"`, 1)},
		{name: "duplicate selection field", data: strings.Replace(expected, `"requestId":"request-1"`, `"requestId":"request-1","requestId":"request-2"`, 1)},
		{name: "duplicate material field", data: strings.Replace(expected, `"form":"public"`, `"form":"public","form":"private-bytes"`, 1)},
		{name: "missing material", data: `{"requestId":"request-1","assignmentId":"assignment-1","slotName":"tls-server","capability":"runtime"}`},
		{name: "null material", data: `{"requestId":"request-1","assignmentId":"assignment-1","slotName":"tls-server","capability":"runtime","material":null}`},
		{name: "two material selections", data: expected[:len(expected)-1] + `,"material":{"projection":"bundle","form":"public"}}`},
		{name: "boolean request id", data: strings.Replace(expected, `"request-1"`, `true`, 1)},
		{name: "numeric capability", data: strings.Replace(expected, `"runtime"`, `1`, 1)},
		{name: "boolean material form", data: strings.Replace(expected, `"public"`, `false`, 1)},
		{name: "secret bytes", data: expected[:len(expected)-1] + `,"data":"secret"}`},
		{name: "provider target", data: expected[:len(expected)-1] + `,"provider":{"moduleId":"module"}}`},
		{name: "descriptor digest", data: expected[:len(expected)-1] + `,"descriptorSha256":"digest"}`},
		{name: "receipt", data: expected[:len(expected)-1] + `,"receipt":"secret"}`},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			var selection CredentialSelection
			if err := json.Unmarshal([]byte(test.data), &selection); err == nil {
				t.Fatal("json.Unmarshal() accepted an invalid credential selection")
			}
		})
	}
}

func TestCredentialSelectionValidatesCanonicalFieldsAndRuntimeCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*CredentialSelection)
	}{
		{name: "empty request id", mutate: func(selection *CredentialSelection) { selection.RequestID = "" }},
		{name: "noncanonical request id", mutate: func(selection *CredentialSelection) { selection.RequestID = " request-1" }},
		{name: "invalid assignment id", mutate: func(selection *CredentialSelection) { selection.AssignmentID = "assignment 1" }},
		{name: "invalid slot name", mutate: func(selection *CredentialSelection) { selection.SlotName = "tls server" }},
		{
			name: "unsupported runtime projection",
			mutate: func(selection *CredentialSelection) {
				selection.Material = CredentialMaterialSelection{
					Projection: CredentialProjectionBundle,
					Form:       CredentialMaterialPublic,
				}
			},
		},
	}
	for _, capability := range []DeliveryCapability{
		DeliveryCapabilityFiles,
		"encode",
		"stamp",
		DeliveryCapabilityStampStandard,
		DeliveryCapabilityStampAdvanced,
		DeliveryCapabilityNone,
	} {
		capability := capability
		tests = append(tests, struct {
			name   string
			mutate func(*CredentialSelection)
		}{
			name: "capability " + string(capability),
			mutate: func(selection *CredentialSelection) {
				selection.Capability = capability
			},
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection := validCredentialSelection("request-1", "assignment-1", "tls-server")
			test.mutate(&selection)
			if err := selection.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid credential selection")
			}
		})
	}
}

func TestCredentialSelectionsValidateBoundsAndUniqueness(t *testing.T) {
	t.Parallel()

	selections := CredentialSelections{
		validCredentialSelection("request-1", "assignment-1", "tls-server"),
		validCredentialSelection("request-2", "assignment-1", "tls-client"),
		validCredentialSelection("request-3", "assignment-2", "tls-server"),
	}
	if err := selections.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	clone := selections.Clone()
	clone[0].RequestID = "changed-request"
	if selections[0].RequestID == clone[0].RequestID {
		t.Fatal("Clone() aliased the credential selections slice")
	}
	if err := (CredentialSelections{}).Validate(); err != nil {
		t.Fatalf("Validate(empty) error = %v", err)
	}
	maximum := make(CredentialSelections, MaximumCredentialSelections)
	for index := range maximum {
		maximum[index] = validCredentialSelection(
			CredentialExecutionRequestID(fmt.Sprintf("maximum-request-%d", index)),
			AssignmentID(fmt.Sprintf("maximum-assignment-%d", index)),
			"tls-server",
		)
	}
	if err := maximum.Validate(); err != nil {
		t.Fatalf("Validate(maximum) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(CredentialSelections) CredentialSelections
	}{
		{
			name: "duplicate request id",
			mutate: func(values CredentialSelections) CredentialSelections {
				values[1].RequestID = values[0].RequestID
				return values
			},
		},
		{
			name: "duplicate assignment and slot",
			mutate: func(values CredentialSelections) CredentialSelections {
				values[1].AssignmentID = values[0].AssignmentID
				values[1].SlotName = values[0].SlotName
				return values
			},
		},
		{
			name: "invalid selection",
			mutate: func(values CredentialSelections) CredentialSelections {
				values[1].Material.Form = CredentialMaterialPrivateBytes
				return values
			},
		},
		{
			name: "over maximum",
			mutate: func(CredentialSelections) CredentialSelections {
				values := make(CredentialSelections, MaximumCredentialSelections+1)
				for index := range values {
					values[index] = validCredentialSelection(
						CredentialExecutionRequestID(fmt.Sprintf("request-%d", index)),
						AssignmentID(fmt.Sprintf("assignment-%d", index)),
						"tls-server",
					)
				}
				return values
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.mutate(selections.Clone())
			if err := candidate.Validate(); err == nil {
				t.Fatal("Validate() accepted invalid credential selections")
			}
		})
	}
}

func TestCredentialSelectionsJSONIsStrict(t *testing.T) {
	t.Parallel()

	want := CredentialSelections{
		validCredentialSelection("request-1", "assignment-1", "tls-server"),
		validCredentialSelection("request-2", "assignment-2", "tls-client"),
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got CredentialSelections
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("json.Unmarshal() = %#v, want %#v", got, want)
	}

	invalid := []string{
		`null`,
		`{}`,
		string(data) + ` true`,
		strings.Replace(string(data), `"requestId":"request-2"`, `"requestId":"request-1"`, 1),
		strings.Replace(string(data), `"form":"public"`, `"form":"public","unknown":true`, 1),
	}
	for _, value := range invalid {
		var selections CredentialSelections
		if err := json.Unmarshal([]byte(value), &selections); err == nil {
			t.Fatalf("json.Unmarshal(%s) accepted invalid credential selections", value)
		}
	}
}

func TestCredentialSecretsAreRedactedAndCloned(t *testing.T) {
	t.Parallel()

	material := validResolvedCredentialMaterial()
	clone := material.Clone()
	clone.Data[0] ^= 0xff
	if material.Data[0] == clone.Data[0] {
		t.Fatal("ResolvedCredentialMaterial.Clone() aliased secret bytes")
	}
	for _, formatted := range []string{
		fmt.Sprint(material.Data),
		fmt.Sprintf("%#v", material.Data),
		fmt.Sprint(CredentialSecretReference("provider-secret")),
		fmt.Sprintf("%#v", CredentialProtectedPath("/secret/path")),
	} {
		if formatted != redactedCredentialSecret {
			t.Fatalf("secret formatting = %q, want redaction", formatted)
		}
	}

	encoded, err := json.Marshal(CredentialSecretReference("provider-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"provider-secret"` {
		t.Fatalf("secret reference JSON = %s", encoded)
	}
}

func TestCredentialEncodingResultValidatesRequestBinding(t *testing.T) {
	t.Parallel()

	request := validCredentialEncodingRequest()
	data := CredentialBytes("provider encoding")
	result := CredentialEncodingResult{
		RequestID: request.RequestID,
		Form:      request.OutputForm,
		Encoding:  "provider-v1",
		SHA256:    credentialTestSHA256(data),
		Data:      data,
	}
	if err := result.ValidateFor(request); err != nil {
		t.Fatalf("ValidateFor() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CredentialEncodingResult, *CredentialEncodingRequest)
	}{
		{name: "request id", mutate: func(result *CredentialEncodingResult, _ *CredentialEncodingRequest) {
			result.RequestID = "other-request"
		}},
		{name: "digest", mutate: func(result *CredentialEncodingResult, _ *CredentialEncodingRequest) {
			result.SHA256 = strings.Repeat("0", 64)
		}},
		{name: "form", mutate: func(result *CredentialEncodingResult, _ *CredentialEncodingRequest) {
			result.Form = CredentialMaterialPublic
		}},
		{name: "bound", mutate: func(_ *CredentialEncodingResult, request *CredentialEncodingRequest) {
			request.MaximumEncodedBytes = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateResult := result.Clone()
			candidateRequest := request.Clone()
			test.mutate(&candidateResult, &candidateRequest)
			if err := candidateResult.ValidateFor(candidateRequest); err == nil {
				t.Fatal("ValidateFor() accepted a mismatched encoding result")
			}
		})
	}
}

func TestCredentialStampExecutionResultValidatesRequestBinding(t *testing.T) {
	t.Parallel()

	request := validCredentialStampExecutionRequest(t)
	result := validCredentialStampExecutionResult(t, request)
	if err := result.ValidateFor(request); err != nil {
		t.Fatalf("ValidateFor() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CredentialStampExecutionResult)
	}{
		{name: "stamp id", mutate: func(result *CredentialStampExecutionResult) { result.StampID = "other-stamp" }},
		{name: "bytes written", mutate: func(result *CredentialStampExecutionResult) { result.BytesWritten = "15" }},
		{name: "target", mutate: func(result *CredentialStampExecutionResult) {
			result.ResolvedTarget.NamedSlot.Name = "other-slot"
		}},
		{name: "digest reference", mutate: func(result *CredentialStampExecutionResult) {
			result.MaterialDigests[0].Reference = "other-bundle"
		}},
		{name: "digest hash", mutate: func(result *CredentialStampExecutionResult) {
			result.MaterialDigests[0].SHA256 = strings.Repeat("f", 64)
		}},
		{name: "output union", mutate: func(result *CredentialStampExecutionResult) {
			result.Output.Deployment = &CredentialDeploymentOutput{Reference: "deployment-1", Receipt: []byte("receipt")}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := result.Clone()
			test.mutate(&candidate)
			if err := candidate.ValidateFor(request); err == nil {
				t.Fatal("ValidateFor() accepted mismatched provider stamp evidence")
			}
		})
	}
}

func TestCredentialStampExecutionRequestRejectsResolvedFormMismatch(t *testing.T) {
	t.Parallel()

	request := validCredentialStampExecutionRequest(t)
	request.Material.Form = CredentialMaterialPublic
	if err := request.Validate(); err == nil {
		t.Fatal("Validate() accepted resolved material whose form differs from the stamp plan")
	}
}

func TestCredentialFilesRequestRejectsDuplicatePath(t *testing.T) {
	t.Parallel()

	file := CredentialFile{
		Projection: CredentialProjectionCertificateDER,
		Form:       CredentialMaterialPublic,
		MediaType:  "application/pkix-cert",
		Path:       "/protected/certificate.der",
		SHA256:     strings.Repeat("a", 64),
		Size:       128,
	}
	request := CredentialFilesRequest{
		SchemaVersion: CredentialProviderExecutionSchemaV1,
		Provider:      validCredentialProviderTarget(),
		RequestID:     "files-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    validResolvedCredentialMetadata(),
		Files:         []CredentialFile{file, file},
	}
	if err := request.Validate(); err == nil {
		t.Fatal("Validate() accepted duplicate credential file paths")
	}
}

func TestCredentialOperationDeliveryRejectsInvalidTaggedVariants(t *testing.T) {
	t.Parallel()

	runtime := validCredentialRuntimeRequest()
	files := validCredentialFilesRequest()
	tests := []struct {
		name     string
		delivery CredentialOperationDelivery
	}{
		{
			name:     "missing runtime",
			delivery: CredentialOperationDelivery{Capability: DeliveryCapabilityRuntime},
		},
		{
			name: "multiple variants",
			delivery: CredentialOperationDelivery{
				Capability: DeliveryCapabilityRuntime,
				Runtime:    &runtime,
				Files:      &files,
			},
		},
		{
			name: "unsupported capability",
			delivery: CredentialOperationDelivery{
				Capability: DeliveryCapabilityStampStandard,
				Runtime:    &runtime,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.delivery.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid operation delivery union")
			}
		})
	}
}

func TestCredentialOperationDeliveriesValidateConsumerBindingAndUniqueness(t *testing.T) {
	t.Parallel()

	runtime := validCredentialRuntimeRequest()
	files := validCredentialFilesRequest()
	files.RequestID = "files-1"
	files.SlotName = "tls-client"
	deliveries := CredentialOperationDeliveries{
		{Capability: DeliveryCapabilityRuntime, Runtime: &runtime},
		{Capability: DeliveryCapabilityFiles, Files: &files},
	}
	if err := deliveries.ValidateForModule(runtime.Provider.ModuleID); err != nil {
		t.Fatalf("ValidateForModule() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(CredentialOperationDeliveries)
	}{
		{
			name: "consumer module",
			mutate: func(values CredentialOperationDeliveries) {
				values[1].Files.Provider.ModuleID = "other-module"
			},
		},
		{
			name: "request id",
			mutate: func(values CredentialOperationDeliveries) {
				values[1].Files.RequestID = values[0].Runtime.RequestID
			},
		},
		{
			name: "slot",
			mutate: func(values CredentialOperationDeliveries) {
				values[1].Files.SlotName = values[0].Runtime.SlotName
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := deliveries.Clone()
			test.mutate(candidate)
			if err := candidate.ValidateForModule(runtime.Provider.ModuleID); err == nil {
				t.Fatal("ValidateForModule() accepted invalid operation deliveries")
			}
		})
	}
}

func validCredentialRuntimeRequest() CredentialRuntimeRequest {
	return CredentialRuntimeRequest{
		SchemaVersion: CredentialProviderExecutionSchemaV1,
		Provider:      validCredentialProviderTarget(),
		RequestID:     "runtime-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    validResolvedCredentialMetadata(),
		Material:      validResolvedCredentialMaterial(),
		Scope:         CredentialOperationScope{RunID: "run-1"},
	}
}

func validCredentialSelection(
	requestID CredentialExecutionRequestID,
	assignmentID AssignmentID,
	slotName CredentialSlotName,
) CredentialSelection {
	return CredentialSelection{
		RequestID:    requestID,
		AssignmentID: assignmentID,
		SlotName:     slotName,
		Capability:   DeliveryCapabilityRuntime,
		Material: CredentialMaterialSelection{
			Projection: CredentialProjectionCertificateDER,
			Form:       CredentialMaterialPublic,
		},
	}
}

func validCredentialFilesRequest() CredentialFilesRequest {
	return CredentialFilesRequest{
		SchemaVersion: CredentialProviderExecutionSchemaV1,
		Provider:      validCredentialProviderTarget(),
		RequestID:     "files-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    validResolvedCredentialMetadata(),
		Files: []CredentialFile{{
			Projection: CredentialProjectionCertificateDER,
			Form:       CredentialMaterialPublic,
			MediaType:  "application/pkix-cert",
			Path:       "/protected/certificate.der",
			SHA256:     strings.Repeat("a", 64),
			Size:       128,
		}},
	}
}

func pointerTo[T any](value T) *T {
	return &value
}

func validResolvedCredentialMetadata() ResolvedCredentialMetadata {
	return ResolvedCredentialMetadata{
		BundleVersion:         BundleSchemaV1,
		Purpose:               PurposeTLSServer,
		ConsumerType:          ConsumerMeshListener,
		ProfileID:             ProfileTLSServer,
		CompatibilityTargetID: CompatibilityPortableX509,
	}
}

func validResolvedCredentialMaterial() ResolvedCredentialMaterial {
	data := CredentialBytes("0123456789abcdef")
	return ResolvedCredentialMaterial{
		Projection: CredentialProjectionBundle,
		Form:       CredentialMaterialPrivateBytes,
		Encoding:   "hovel-bundle-json",
		SHA256:     credentialTestSHA256(data),
		Data:       data,
	}
}

func validCredentialEncodingRequest() CredentialEncodingRequest {
	return CredentialEncodingRequest{
		SchemaVersion:       CredentialProviderExecutionSchemaV1,
		Provider:            validCredentialProviderTarget(),
		RequestID:           "encoding-1",
		ProviderID:          "mesh-provider-1",
		ProviderSchema:      "mbedtls-v1",
		OutputForm:          CredentialMaterialPrivateBytes,
		MaximumEncodedBytes: 1024,
		Source:              validResolvedCredentialMaterial(),
		Scope:               CredentialOperationScope{ListenerID: "listener-1"},
	}
}

func validCredentialStampExecutionRequest(t *testing.T) CredentialStampExecutionRequest {
	t.Helper()
	stamp := validCredentialStamp(t)
	input := CredentialBytes("0123456789abcdef")
	return CredentialStampExecutionRequest{
		SchemaVersion: CredentialProviderExecutionSchemaV1,
		Provider:      validCredentialProviderTarget(),
		StampID:       stamp.ID,
		Request:       stamp.Plan.Request.Clone(),
		Input: CredentialArtifactInput{
			ID:       stamp.Plan.Input.ID,
			SHA256:   credentialTestSHA256(input),
			Encoding: "raw",
			Data:     input,
		},
		Material: validResolvedCredentialMaterial(),
		ExpectedDigests: []StampedMaterialDigest{{
			Projection: CredentialProjectionBundle,
			Reference:  "bundle-1",
			SHA256:     validResolvedCredentialMaterial().SHA256,
		}},
		Scope: CredentialOperationScope{RunID: "run-1", NodeID: "node-1"},
	}
}

func validCredentialProviderTarget() CredentialProviderTarget {
	return CredentialProviderTarget{
		ModuleID:         "mesh-provider-module",
		ProviderID:       "mesh-provider-1",
		ProviderVersion:  "1.2.3",
		DescriptorSHA256: strings.Repeat("a", 64),
	}
}

func validCredentialStampExecutionResult(
	t *testing.T,
	request CredentialStampExecutionRequest,
) CredentialStampExecutionResult {
	t.Helper()
	target := request.Request.Target.Clone()
	return CredentialStampExecutionResult{
		StampID: request.StampID,
		Output: CredentialStampOutput{Artifact: &CredentialArtifactOutput{
			Name: "stamped.bin", Encoding: "raw", Data: CredentialBytes("stamped artifact"),
		}},
		TargetResolution: StampTargetResolutionUnchanged,
		ResolvedTarget:   target,
		BytesWritten:     NewCanonicalUint64(request.Request.EncodedBytes),
		MaterialDigests: []StampedMaterialDigest{{
			Projection: CredentialProjectionBundle,
			Reference:  "bundle-1",
			SHA256:     request.Material.SHA256,
		}},
	}
}

func credentialTestSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
