package pki_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pkimemory "github.com/vibepwners/hovel/internal/adapters/pki/memory"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const concurrentCredentialStampWriters = 8

func TestServiceReplaysConcurrentCredentialStampMutations(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestServiceWithRandom(
		t, store, newSwitchableReader(deterministicRandomBytes(0x73)),
	)
	assignment, generationID := bindActiveStampTestAssignment(
		t, service, "concurrent", "assignment-concurrent-stamp",
		"mesh-provider/concurrent-listener",
	)
	pending := testCredentialStamp(
		t, assignment.ID, generationID, "credential-stamp-concurrent",
	)
	planned := runConcurrentCredentialStampMutation(
		t, func() (domainpki.CredentialStamp, error) {
			return service.RecordCredentialStampPlan(
				t.Context(), "test:concurrent-stamp-plan", pending,
			)
		},
	)
	completed, err := domainpki.CompleteCredentialStamp(
		planned, testCredentialStampResult(t, generationID), planned.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	completed = runConcurrentCredentialStampMutation(
		t, func() (domainpki.CredentialStamp, error) {
			return service.RecordCredentialStampTransition(
				t.Context(), "test:concurrent-stamp-success", completed,
			)
		},
	)
	if completed.Status != domainpki.CredentialStampSucceeded {
		t.Fatalf("concurrent credential stamp result = %#v", completed)
	}
	listed, err := service.ListCredentialStamps(t.Context())
	if err != nil || len(listed) != 1 || listed[0].Revision != completed.Revision {
		t.Fatalf("concurrent credential stamp inventory = %#v, %v", listed, err)
	}
}

func runConcurrentCredentialStampMutation(
	t *testing.T,
	mutate func() (domainpki.CredentialStamp, error),
) domainpki.CredentialStamp {
	t.Helper()
	start := make(chan struct{})
	results := make(chan domainpki.CredentialStamp, concurrentCredentialStampWriters)
	errors := make(chan error, concurrentCredentialStampWriters)
	var ready sync.WaitGroup
	ready.Add(concurrentCredentialStampWriters)
	for range concurrentCredentialStampWriters {
		go func() {
			ready.Done()
			<-start
			result, err := mutate()
			results <- result
			errors <- err
		}()
	}
	ready.Wait()
	close(start)
	var canonical domainpki.CredentialStamp
	for range concurrentCredentialStampWriters {
		if err := <-errors; err != nil {
			t.Fatalf("concurrent credential stamp mutation error = %v", err)
		}
		result := <-results
		if canonical.ID == "" {
			canonical = result
			continue
		}
		if result.ID != canonical.ID || result.Revision != canonical.Revision ||
			result.Status != canonical.Status {
			t.Fatalf("concurrent credential stamp replay differs: %#v %#v", canonical, result)
		}
	}
	return canonical
}

func TestServiceRecordsCredentialStampLifecycleIdempotently(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	assignment, generationID := bindActiveStampTestAssignment(
		t, service, "lifecycle", "assignment-stamp-test", "mesh-provider/listener-test",
	)

	pending := testCredentialStamp(
		t, assignment.ID, generationID, "credential-stamp-service-1",
	)
	first, err := service.RecordCredentialStampPlan(
		t.Context(), "test:credential-stamp-plan", pending,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.RecordCredentialStampPlan(
		t.Context(), "test:credential-stamp-plan", pending,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != replayed.ID || first.Revision != replayed.Revision {
		t.Fatalf("credential stamp plan replay differs: %#v %#v", first, replayed)
	}

	completed, err := domainpki.CompleteCredentialStamp(
		first, testCredentialStampResult(t, generationID), first.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err = service.RecordCredentialStampTransition(
		t.Context(), "test:credential-stamp-success", completed,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedCompletion, err := service.RecordCredentialStampTransition(
		t.Context(), "test:credential-stamp-success", completed,
	)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Revision != replayedCompletion.Revision ||
		completed.Status != domainpki.CredentialStampSucceeded {
		t.Fatalf("credential stamp completion replay differs: %#v %#v", completed, replayedCompletion)
	}

	replacement := testCredentialStamp(
		t, assignment.ID, generationID, "credential-stamp-service-2",
	)
	replacement, err = service.RecordCredentialStampPlan(
		t.Context(), "test:credential-stamp-replacement-plan", replacement,
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err = domainpki.CompleteCredentialStamp(
		replacement, testCredentialStampResult(t, generationID), replacement.UpdatedAt.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err = service.RecordCredentialStampTransition(
		t.Context(), "test:credential-stamp-replacement-success", replacement,
	)
	if err != nil {
		t.Fatal(err)
	}
	superseded, err := domainpki.SupersedeCredentialStamp(
		completed, replacement.ID, completed.UpdatedAt.Add(3*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecordCredentialStampTransition(
		t.Context(), "test:credential-stamp-supersede", superseded,
	); err != nil {
		t.Fatal(err)
	}

	orphan := testCredentialStamp(
		t, assignment.ID, generationID, "credential-stamp-service-3",
	)
	orphan, err = service.RecordCredentialStampPlan(
		t.Context(), "test:credential-stamp-orphan-plan", orphan,
	)
	if err != nil {
		t.Fatal(err)
	}
	orphan, err = domainpki.CompleteCredentialStamp(
		orphan, testCredentialStampResult(t, generationID), orphan.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	orphan, err = service.RecordCredentialStampTransition(
		t.Context(), "test:credential-stamp-orphan-success", orphan,
	)
	if err != nil {
		t.Fatal(err)
	}
	missingReplacement, err := domainpki.SupersedeCredentialStamp(
		orphan, "credential-stamp-missing", orphan.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecordCredentialStampTransition(
		t.Context(), "test:credential-stamp-missing-replacement", missingReplacement,
	); !errors.Is(err, apppki.ErrNotFound) {
		t.Fatalf("missing credential stamp replacement error = %v", err)
	}
	orphanAfter, err := service.InspectCredentialStamp(t.Context(), orphan.ID)
	if err != nil || orphanAfter.Status != domainpki.CredentialStampSucceeded {
		t.Fatalf("failed supersession changed original stamp: %#v, %v", orphanAfter, err)
	}

	listed, err := service.ListCredentialStamps(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 3 || listed[0].Status != domainpki.CredentialStampSuperseded {
		t.Fatalf("ListCredentialStamps() = %#v", listed)
	}
	inspected, err := service.InspectCredentialStamp(t.Context(), pending.ID)
	if err != nil || inspected.Status != domainpki.CredentialStampSuperseded {
		t.Fatalf("InspectCredentialStamp() = %#v, %v", inspected, err)
	}

	audits := store.AuditRecords()
	seenPlan := false
	seenSuccess := false
	seenSupersede := false
	for _, audit := range audits {
		if audit.ResourceType != apppki.CredentialStampResourceType {
			continue
		}
		switch audit.Action {
		case apppki.AuditActionCredentialStampPlan:
			seenPlan = audit.Outcome == apppki.AuditOutcomeAttempted
		case apppki.AuditActionCredentialStampSucceed:
			seenSuccess = audit.Outcome == apppki.AuditOutcomeSucceeded
		case apppki.AuditActionCredentialStampSupersede:
			seenSupersede = audit.Outcome == apppki.AuditOutcomeSucceeded
		}
	}
	if !seenPlan || !seenSuccess || !seenSupersede {
		t.Fatalf("credential stamp lifecycle audits are incomplete: %#v", audits)
	}
}

func testCredentialStamp(
	t *testing.T,
	assignmentID domainpki.AssignmentID,
	generationID domainpki.GenerationID,
	id domainpki.StampID,
) domainpki.CredentialStamp {
	t.Helper()
	descriptor, err := domainpki.NewCredentialDeliveryDescriptor(
		domainpki.CredentialDeliveryDescriptorArgs{
			SchemaVersion: domainpki.CredentialDeliverySchemaV1,
			Slots: []domainpki.CredentialSlot{{
				Name: "tls-server", Purpose: domainpki.PurposeTLSServer,
				EndpointRole:           domainpki.CredentialEndpointServer,
				ConsumerType:           domainpki.ConsumerMeshListener,
				AcceptedBundleVersions: []string{domainpki.BundleSchemaV1},
				AcceptedProfiles:       []domainpki.ProfileID{domainpki.ProfileTLSServer},
				AcceptedCompatibilityTargets: []domainpki.CompatibilityTargetID{
					domainpki.CompatibilityPortableX509,
				},
				AcceptedProjections: []domainpki.CredentialProjection{
					domainpki.CredentialProjectionPrivateKeyPKCS8,
				},
				AcceptedMaterialForms: []domainpki.CredentialMaterialForm{
					domainpki.CredentialMaterialPrivateBytes,
				},
				MaximumEncodedBytes: 16,
				RemainderPolicy:     domainpki.StampRemainderRequireExact,
				PrivateMaterial:     domainpki.PrivateMaterialRequired,
			}},
			Capabilities: []domainpki.DeliveryCapability{
				domainpki.DeliveryCapabilityStampStandard,
			},
			StampTargetKinds: []domainpki.StampTargetKind{
				domainpki.StampTargetNamedSlot,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := domainpki.NewNamedSlotStampTarget(
		domainpki.NamedSlotTarget{Name: "tls-server"},
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := domainpki.NewCredentialStampMaterial(
		domainpki.CredentialMaterialReference{
			Projection:   domainpki.CredentialProjectionPrivateKeyPKCS8,
			Form:         domainpki.CredentialMaterialPrivateBytes,
			GenerationID: generationID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := domainpki.NewCredentialStampPlan(
		descriptor,
		domainpki.CredentialStampRequest{
			AssignmentID: assignmentID,
			Capability:   domainpki.DeliveryCapabilityStampStandard,
			SlotName:     "tls-server",
			Target:       target,
			Material:     material,
			EncodedBytes: 16,
			Credential: domainpki.ResolvedCredentialMetadata{
				BundleVersion:         domainpki.BundleSchemaV1,
				Purpose:               domainpki.PurposeTLSServer,
				ConsumerType:          domainpki.ConsumerMeshListener,
				ProfileID:             domainpki.ProfileTLSServer,
				CompatibilityTargetID: domainpki.CompatibilityPortableX509,
			},
		},
		domainpki.StampArtifactReference{
			Kind:   domainpki.StampArtifactWorkspace,
			ID:     "artifact-stamp-input",
			SHA256: strings.Repeat("a", 64),
		},
		[]domainpki.StampedMaterialDigest{{
			Projection: domainpki.CredentialProjectionPrivateKeyPKCS8,
			Reference:  domainpki.StampReferenceID(generationID),
			SHA256:     strings.Repeat("b", 64),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := domainpki.NewCredentialStamp(domainpki.CredentialStampArgs{
		SchemaVersion:   domainpki.CredentialStampSchemaV1,
		ID:              id,
		ProviderID:      "provider-stamp-test",
		ProviderVersion: "1.0.0",
		Plan:            plan,
		CreatedAt:       fixedTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

func bindActiveStampTestAssignment(
	t *testing.T,
	service apppki.Service,
	suffix string,
	assignmentID domainpki.AssignmentID,
	consumerID domainpki.ConsumerID,
) (domainpki.Assignment, domainpki.GenerationID) {
	t.Helper()
	authority, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:stamp-authority-" + suffix,
		Name:           "stamp authority " + suffix,
		Role:           domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, authority.Authority.ID)
	generation, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey:    "test:stamp-certificate-" + suffix,
		IssuerAuthorityID: authority.Authority.ID,
		Name:              "stamp-" + suffix + ".test",
		ProfileID:         domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "test:stamp-assignment-" + suffix,
		ID:             assignmentID,
		Purpose:        domainpki.PurposeTLSServer,
		ConsumerType:   domainpki.ConsumerMeshListener,
		ConsumerID:     consumerID,
		ProfileID:      domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey:   "test:stamp-stage-" + suffix,
		AssignmentID:     assignment.ID,
		GenerationID:     generation.ID,
		ExpectedRevision: assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey:   "test:stamp-activate-" + suffix,
		AssignmentID:     assignment.ID,
		ExpectedRevision: staged.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	return active.Assignment, generation.ID
}

func testCredentialStampResult(
	t *testing.T,
	generationID domainpki.GenerationID,
) domainpki.CredentialStampResult {
	t.Helper()
	target, err := domainpki.NewFileOffsetStampTarget(domainpki.FileOffsetTarget{
		Offset: "4096", MaximumLength: "16", Alignment: "16",
		RemainderPolicy: domainpki.StampRemainderRequireExact,
		Precondition:    domainpki.StampPrecondition{Kind: domainpki.StampPreconditionNone},
	})
	if err != nil {
		t.Fatal(err)
	}
	return domainpki.CredentialStampResult{
		TargetResolution: domainpki.StampTargetResolutionTranslated,
		ResolvedTarget:   target,
		BytesWritten:     "16",
		MaterialDigests: []domainpki.StampedMaterialDigest{{
			Projection: domainpki.CredentialProjectionPrivateKeyPKCS8,
			Reference:  domainpki.StampReferenceID(generationID),
			SHA256:     strings.Repeat("b", 64),
		}},
		Destination: domainpki.StampDestination{
			Artifact: &domainpki.StampArtifactReference{
				Kind:   domainpki.StampArtifactWorkspace,
				ID:     "artifact-stamp-output",
				SHA256: strings.Repeat("c", 64),
			},
		},
	}
}
