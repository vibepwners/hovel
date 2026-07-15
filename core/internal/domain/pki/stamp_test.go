package pki

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCredentialStampJSONIsStrictAndRoundTrips(t *testing.T) {
	t.Parallel()

	stamps := []CredentialStamp{validCredentialStamp(t)}
	completed, err := CompleteCredentialStamp(
		stamps[0], validCredentialStampResult(t), stamps[0].UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	stamps = append(stamps, completed)
	for _, stamp := range stamps {
		encoded, err := json.Marshal(stamp)
		if err != nil {
			t.Fatal(err)
		}
		var decoded CredentialStamp
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("json.Unmarshal() round trip error = %v", err)
		}
		if !reflect.DeepEqual(decoded, stamp) {
			t.Fatalf("credential stamp round trip differs:\n got %#v\nwant %#v", decoded, stamp)
		}
	}

	pendingJSON, err := json.Marshal(stamps[0])
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(`{"unknown":true,`), pendingJSON[1:]...)
	inactiveNull := append([]byte(`{"result":null,`), pendingJSON[1:]...)
	invalid := [][]byte{
		unknown,
		inactiveNull,
		append(pendingJSON, []byte(` {}`)...),
		[]byte(`{"schemaVersion":"one","schemaVersion":"two"}`),
		bytes.Replace(
			pendingJSON, []byte(`"request":{`),
			[]byte(`"request":{"unknown":true,`), 1,
		),
		bytes.Replace(
			pendingJSON, []byte(`"input":{`),
			[]byte(`"input":{"unknown":true,`), 1,
		),
		bytes.Replace(
			pendingJSON, []byte(`"expectedDigests":[{`),
			[]byte(`"expectedDigests":[{"unknown":true,`), 1,
		),
	}
	for _, encoded := range invalid {
		var decoded CredentialStamp
		if err := json.Unmarshal(encoded, &decoded); err == nil {
			t.Fatalf("json.Unmarshal(%s) accepted an invalid credential stamp", encoded)
		}
	}

	artifactJSON, err := json.Marshal(stamps[1].Result.Destination.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	var destination StampDestination
	if err := json.Unmarshal([]byte(
		`{"artifact":`+string(artifactJSON)+`,"deployment":null}`,
	), &destination); err == nil {
		t.Fatal("json.Unmarshal() accepted an explicit inactive destination variant")
	}

	planJSON, err := json.Marshal(stamps[0].Plan)
	if err != nil {
		t.Fatal(err)
	}
	var plan CredentialStampPlan
	if err := json.Unmarshal(
		append([]byte(`{"unknown":true,`), planJSON[1:]...), &plan,
	); err == nil {
		t.Fatal("json.Unmarshal() accepted an unknown credential stamp plan field")
	}

	resultJSON, err := json.Marshal(stamps[1].Result)
	if err != nil {
		t.Fatal(err)
	}
	var result CredentialStampResult
	if err := json.Unmarshal(
		append([]byte(`{"unknown":true,`), resultJSON[1:]...), &result,
	); err == nil {
		t.Fatal("json.Unmarshal() accepted an unknown credential stamp result field")
	}
	if err := json.Unmarshal(bytes.Replace(
		resultJSON, []byte(`"artifact":{`),
		[]byte(`"artifact":{"unknown":true,`), 1,
	), &result); err == nil {
		t.Fatal("json.Unmarshal() accepted an unknown artifact reference field")
	}
}

func TestCredentialStampLifecycle(t *testing.T) {
	t.Parallel()

	pending := validCredentialStamp(t)
	if err := pending.Validate(); err != nil {
		t.Fatalf("pending credential stamp: %v", err)
	}

	completedAt := pending.UpdatedAt.Add(time.Minute)
	completed, err := CompleteCredentialStamp(pending, validCredentialStampResult(t), completedAt)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != CredentialStampSucceeded || completed.Revision != 2 ||
		completed.Result == nil || !completed.UpdatedAt.Equal(completedAt) {
		t.Fatalf("completed credential stamp = %#v", completed)
	}

	superseded, err := SupersedeCredentialStamp(
		completed, "credential-stamp-replacement", completedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if superseded.Status != CredentialStampSuperseded || superseded.Revision != 3 ||
		superseded.SupersededBy != "credential-stamp-replacement" {
		t.Fatalf("superseded credential stamp = %#v", superseded)
	}
	if _, err := FailCredentialStamp(superseded, "too late", superseded.UpdatedAt); err == nil {
		t.Fatal("FailCredentialStamp() accepted a terminal stamp")
	}

	failed, err := FailCredentialStamp(
		validCredentialStamp(t), "provider precondition mismatch", completedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != CredentialStampFailed || failed.Failure != "provider precondition mismatch" ||
		failed.Result != nil || failed.Revision != 2 {
		t.Fatalf("failed credential stamp = %#v", failed)
	}
}

func TestCredentialStampRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*CredentialStamp)
	}{
		{name: "schema", mutate: func(stamp *CredentialStamp) { stamp.SchemaVersion = "v2" }},
		{name: "capability", mutate: func(stamp *CredentialStamp) { stamp.Plan.Request.Capability = DeliveryCapabilityRuntime }},
		{name: "standard target mismatch", mutate: func(stamp *CredentialStamp) { stamp.Plan.Request.SlotName = "other-slot" }},
		{name: "input hash", mutate: func(stamp *CredentialStamp) { stamp.Plan.Input.SHA256 = "bad" }},
		{name: "descriptor hash", mutate: func(stamp *CredentialStamp) { stamp.Plan.DescriptorSHA256 = strings.Repeat("0", 64) }},
		{name: "extra expected digest", mutate: func(stamp *CredentialStamp) {
			stamp.Plan.ExpectedDigests = append(stamp.Plan.ExpectedDigests, StampedMaterialDigest{
				Projection: CredentialProjectionBundle, Reference: "bundle-extra", SHA256: strings.Repeat("d", 64),
			})
		}},
		{name: "duplicate link", mutate: func(stamp *CredentialStamp) { stamp.Links = append(stamp.Links, stamp.Links[0]) }},
		{name: "pending result", mutate: func(stamp *CredentialStamp) { result := validCredentialStampResult(t); stamp.Result = &result }},
		{name: "revision", mutate: func(stamp *CredentialStamp) { stamp.Revision = 0 }},
		{name: "noncanonical time", mutate: func(stamp *CredentialStamp) { stamp.UpdatedAt = stamp.UpdatedAt.In(time.FixedZone("test", 3600)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stamp := validCredentialStamp(t)
			test.mutate(&stamp)
			if err := stamp.Validate(); err == nil {
				t.Fatal("CredentialStamp.Validate() accepted an invalid contract")
			}
		})
	}

	stamp := validCredentialStamp(t)
	result := validCredentialStampResult(t)
	result.MaterialDigests = nil
	if _, err := CompleteCredentialStamp(stamp, result, stamp.UpdatedAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialStamp() accepted missing material digests")
	}

	result = validCredentialStampResult(t)
	result.BytesWritten = "15"
	if _, err := CompleteCredentialStamp(stamp, result, stamp.UpdatedAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialStamp() ignored require-exact resolved capacity")
	}

	result = validCredentialStampResult(t)
	result.MaterialDigests = append(result.MaterialDigests, StampedMaterialDigest{
		Projection: CredentialProjectionBundle,
		Reference:  "bundle-extra",
		SHA256:     strings.Repeat("d", 64),
	})
	if _, err := CompleteCredentialStamp(stamp, result, stamp.UpdatedAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialStamp() accepted an unplanned material digest")
	}

	result = validCredentialStampResult(t)
	result.MaterialDigests[0].SHA256 = strings.Repeat("e", 64)
	if _, err := CompleteCredentialStamp(stamp, result, stamp.UpdatedAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialStamp() accepted a material digest that differs from its plan")
	}

	result = validCredentialStampResult(t)
	result.TargetResolution = StampTargetResolutionUnchanged
	if _, err := CompleteCredentialStamp(stamp, result, stamp.UpdatedAt.Add(time.Minute)); err == nil {
		t.Fatal("CompleteCredentialStamp() accepted a mismatched unchanged target")
	}

	if _, err := FailCredentialStamp(stamp, strings.Repeat("x", MaxNameLength+1), stamp.UpdatedAt); err == nil {
		t.Fatal("FailCredentialStamp() accepted an unbounded failure")
	}
}

func TestCredentialStampClonesDefensively(t *testing.T) {
	t.Parallel()

	stamp := validCredentialStamp(t)
	completed, err := CompleteCredentialStamp(
		stamp, validCredentialStampResult(t), stamp.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	clone := completed.Clone()
	clone.Plan.Request.Material.Credential.BundleID = "changed"
	clone.Plan.Request.Target.NamedSlot.Name = "changed"
	clone.Plan.Descriptor.Slots[0].AcceptedProfiles[0] = ProfileTLSClient
	clone.Plan.ExpectedDigests[0].Reference = "changed"
	clone.Links[0].Reference = "changed"
	clone.Result.MaterialDigests[0].Reference = "changed"
	clone.Result.ResolvedTarget.FileOffset.Precondition.Bytes = []byte{9}
	if completed.Plan.Request.Material.Credential.BundleID != "bundle-1" ||
		completed.Plan.Request.Target.NamedSlot.Name != "tls-server" ||
		completed.Plan.Descriptor.Slots[0].AcceptedProfiles[0] != ProfileTLSServer ||
		completed.Plan.ExpectedDigests[0].Reference != "bundle-1" ||
		completed.Links[0].Reference != "payload-stamp-1" ||
		completed.Result.MaterialDigests[0].Reference != "bundle-1" ||
		len(completed.Result.ResolvedTarget.FileOffset.Precondition.Bytes) != 0 {
		t.Fatal("CredentialStamp.Clone() aliased mutable state")
	}
}

func TestCredentialStampReplacementRequiresCompatibleLineage(t *testing.T) {
	t.Parallel()

	previous := validCredentialStamp(t)
	previous, err := CompleteCredentialStamp(
		previous, validCredentialStampResult(t), previous.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement := validCredentialStamp(t)
	replacement.ID = "credential-stamp-2"
	replacement.CreatedAt = previous.UpdatedAt.Add(time.Minute)
	replacement.UpdatedAt = replacement.CreatedAt
	replacement, err = CompleteCredentialStamp(
		replacement, validCredentialStampResult(t), replacement.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := SupersedeCredentialStamp(
		previous, replacement.ID, replacement.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCredentialStampReplacement(previous, replacement, superseded); err != nil {
		t.Fatalf("ValidateCredentialStampReplacement() error = %v", err)
	}

	incompatible := replacement.Clone()
	incompatible.ProviderID = "other-provider"
	if err := ValidateCredentialStampReplacement(previous, incompatible, superseded); err == nil {
		t.Fatal("ValidateCredentialStampReplacement() accepted a different provider")
	}
	impossible := superseded
	impossible.UpdatedAt = replacement.UpdatedAt.Add(-time.Second)
	if err := ValidateCredentialStampReplacement(previous, replacement, impossible); err == nil {
		t.Fatal("ValidateCredentialStampReplacement() accepted impossible chronology")
	}
}

func TestCredentialStampAssignmentRequiresUsableState(t *testing.T) {
	t.Parallel()

	request := credentialStampTestRequest(t, CredentialMaterialReference{
		Projection:   CredentialProjectionCertificateDER,
		Form:         CredentialMaterialPublic,
		GenerationID: "generation-active",
	})
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
			assignment := credentialStampTestAssignment(t, test.state, PurposeTLSServer)
			err := ValidateCredentialStampAssignment(assignment, request)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateCredentialStampAssignment() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestCredentialStampAssignmentBindsMaterialLineage(t *testing.T) {
	t.Parallel()

	tlsAssignment := credentialStampTestAssignment(t, AssignmentStateActive, PurposeTLSServer)
	mtlsAssignment := credentialStampTestAssignment(t, AssignmentStateActive, PurposeMTLSServer)
	tests := []struct {
		name       string
		assignment Assignment
		reference  CredentialMaterialReference
		wantErr    bool
	}{
		{
			name:       "active certificate generation",
			assignment: tlsAssignment,
			reference: CredentialMaterialReference{
				Projection: CredentialProjectionCertificateDER,
				Form:       CredentialMaterialPublic, GenerationID: "generation-active",
			},
		},
		{
			name:       "staged certificate generation",
			assignment: tlsAssignment,
			reference: CredentialMaterialReference{
				Projection: CredentialProjectionPrivateKeyPKCS8,
				Form:       CredentialMaterialPrivateBytes, GenerationID: "generation-staged",
			},
		},
		{
			name:       "unrelated certificate generation",
			assignment: tlsAssignment,
			reference: CredentialMaterialReference{
				Projection: CredentialProjectionSignerReference,
				Form:       CredentialMaterialPrivateReference, GenerationID: "generation-unrelated",
			},
			wantErr: true,
		},
		{
			name:       "active trust generation",
			assignment: mtlsAssignment,
			reference: CredentialMaterialReference{
				Projection: CredentialProjectionTrustDER,
				Form:       CredentialMaterialPublic, TrustSetGenerationID: "trust-generation-active",
			},
		},
		{
			name:       "staged trust generation",
			assignment: mtlsAssignment,
			reference: CredentialMaterialReference{
				Projection: CredentialProjectionTrustDER,
				Form:       CredentialMaterialPublic, TrustSetGenerationID: "trust-generation-staged",
			},
		},
		{
			name:       "unrelated trust generation",
			assignment: mtlsAssignment,
			reference: CredentialMaterialReference{
				Projection: CredentialProjectionTrustDER,
				Form:       CredentialMaterialPublic, TrustSetGenerationID: "trust-generation-unrelated",
			},
			wantErr: true,
		},
		{
			name:       "crl without trust generation lineage",
			assignment: mtlsAssignment,
			reference: CredentialMaterialReference{
				Projection:       CredentialProjectionCRLDER,
				Form:             CredentialMaterialPublic,
				CRLGenerationIDs: []CRLGenerationID{"crl-generation-unrelated"},
			},
			wantErr: true,
		},
		{
			name:       "bundle without certificate generation lineage",
			assignment: tlsAssignment,
			reference: CredentialMaterialReference{
				Projection: CredentialProjectionBundle,
				Form:       CredentialMaterialPrivateBytes, BundleID: "bundle-unbound",
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := credentialStampTestRequest(t, test.reference)
			request.Credential.Purpose = test.assignment.Purpose
			request.Credential.ProfileID = test.assignment.ProfileID
			err := ValidateCredentialStampAssignment(test.assignment, request)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateCredentialStampAssignment() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestCredentialStampAssignmentValidatesProviderEncodingSourceLineage(t *testing.T) {
	t.Parallel()

	assignment := credentialStampTestAssignment(t, AssignmentStateActive, PurposeTLSServer)
	request := validCredentialStamp(t).Plan.Request.Clone()
	material, err := NewProviderEncodingStampMaterial(ProviderEncodingMaterial{
		ProviderID:    "credential-encoder",
		SchemaVersion: "v1",
		Form:          CredentialMaterialPublic,
		Source: CredentialMaterialReference{
			Projection:   CredentialProjectionPublicKeySPKI,
			Form:         CredentialMaterialPublic,
			GenerationID: "generation-staged",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request.Material = material
	if err := ValidateCredentialStampAssignment(assignment, request); err != nil {
		t.Fatalf("ValidateCredentialStampAssignment() error = %v", err)
	}

	request.Material.ProviderEncoding.Source.GenerationID = "generation-unrelated"
	if err := ValidateCredentialStampAssignment(assignment, request); err == nil {
		t.Fatal("ValidateCredentialStampAssignment() accepted unrelated provider-encoding source")
	}
}

func TestCredentialStampAssignmentRejectsMismatchedMetadata(t *testing.T) {
	t.Parallel()

	assignment := credentialStampTestAssignment(t, AssignmentStateActive, PurposeTLSServer)
	request := credentialStampTestRequest(t, CredentialMaterialReference{
		Projection: CredentialProjectionCertificateDER,
		Form:       CredentialMaterialPublic, GenerationID: "generation-active",
	})
	request.Credential.ProfileID = ProfileTLSClient
	if err := ValidateCredentialStampAssignment(assignment, request); err == nil {
		t.Fatal("ValidateCredentialStampAssignment() accepted mismatched metadata")
	}
}

func credentialStampTestRequest(
	t *testing.T,
	reference CredentialMaterialReference,
) CredentialStampRequest {
	t.Helper()
	request := validCredentialStamp(t).Plan.Request.Clone()
	material, err := NewCredentialStampMaterial(reference)
	if err != nil {
		t.Fatal(err)
	}
	request.Material = material
	return request
}

func credentialStampTestAssignment(
	t *testing.T,
	state AssignmentState,
	purpose Purpose,
) Assignment {
	t.Helper()
	profileID := ProfileTLSServer
	if purpose == PurposeMTLSServer {
		profileID = ProfileMTLSServer
	}
	args := AssignmentArgs{
		ID: "assignment-1", Purpose: purpose,
		ConsumerType: ConsumerMeshListener, ConsumerID: "mesh-listener-1",
		ProfileID: profileID, State: state, Revision: 1,
		UpdatedAt: time.Date(2026, time.July, 12, 11, 0, 0, 0, time.UTC),
	}
	switch state {
	case AssignmentStateActive, AssignmentStateDegraded:
		args.ActiveGenerationID = "generation-active"
		args.StagedGenerationID = "generation-staged"
	case AssignmentStateDisabled, AssignmentStateRetired:
		args.ActiveGenerationID = "generation-active"
	case AssignmentStatePending:
	}
	if purpose.RequiresPeerTrust() {
		args.TrustSetID = "trust-set-1"
		if args.ActiveGenerationID != "" {
			args.ActiveTrustGenerationID = "trust-generation-active"
		}
		if args.StagedGenerationID != "" {
			args.StagedTrustGenerationID = "trust-generation-staged"
		}
	}
	assignment, err := NewAssignment(args)
	if err != nil {
		t.Fatal(err)
	}
	return assignment
}

func validCredentialStamp(t *testing.T) CredentialStamp {
	t.Helper()
	target, err := NewNamedSlotStampTarget(NamedSlotTarget{Name: "tls-server"})
	if err != nil {
		t.Fatal(err)
	}
	material, err := NewCredentialStampMaterial(CredentialMaterialReference{
		Projection: CredentialProjectionBundle,
		Form:       CredentialMaterialPrivateBytes,
		BundleID:   "bundle-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := validCredentialDeliveryDescriptor()
	plan, err := NewCredentialStampPlan(
		descriptor,
		CredentialStampRequest{
			AssignmentID: "assignment-1",
			Capability:   DeliveryCapabilityStampStandard,
			SlotName:     "tls-server",
			Target:       target,
			Material:     material,
			EncodedBytes: 16,
			Credential: ResolvedCredentialMetadata{
				BundleVersion: BundleSchemaV1,
				Purpose:       PurposeTLSServer, ConsumerType: ConsumerMeshListener,
				ProfileID:             ProfileTLSServer,
				CompatibilityTargetID: CompatibilityPortableX509,
			},
		},
		StampArtifactReference{
			Kind: StampArtifactWorkspace, ID: "artifact-input-1",
			SHA256: strings.Repeat("a", 64),
		},
		[]StampedMaterialDigest{{
			Projection: CredentialProjectionBundle,
			Reference:  "bundle-1",
			SHA256:     strings.Repeat("b", 64),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := NewCredentialStamp(CredentialStampArgs{
		SchemaVersion:   CredentialStampSchemaV1,
		ID:              "credential-stamp-1",
		ProviderID:      "mesh-provider-1",
		ProviderVersion: "1.2.3",
		Plan:            plan,
		Links:           []CredentialStampLink{{Kind: CredentialStampLinkPayloadStamp, Reference: "payload-stamp-1"}},
		CreatedAt:       time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

func validCredentialStampResult(t *testing.T) CredentialStampResult {
	t.Helper()
	resolved, err := NewFileOffsetStampTarget(FileOffsetTarget{
		Offset: "4096", MaximumLength: "16", Alignment: "16",
		RemainderPolicy: StampRemainderRequireExact,
		Precondition:    StampPrecondition{Kind: StampPreconditionNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	return CredentialStampResult{
		TargetResolution: StampTargetResolutionTranslated,
		ResolvedTarget:   resolved,
		BytesWritten:     "16",
		MaterialDigests: []StampedMaterialDigest{{
			Projection: CredentialProjectionBundle,
			Reference:  "bundle-1",
			SHA256:     strings.Repeat("b", 64),
		}},
		Destination: StampDestination{Artifact: &StampArtifactReference{
			Kind: StampArtifactWorkspace, ID: "artifact-output-1", SHA256: strings.Repeat("c", 64),
		}},
	}
}
