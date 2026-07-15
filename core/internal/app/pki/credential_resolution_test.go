package pki_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pkimemory "github.com/vibepwners/hovel/internal/adapters/pki/memory"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

func TestServiceResolvesAndClearsRuntimeCredentialSelections(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	assignment, _ := bindActiveStampTestAssignment(
		t,
		service,
		"runtime-resolution",
		"assignment-runtime-resolution",
		"mesh-provider/listener-edge",
	)
	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}
	selections := domainpki.CredentialSelections{
		{
			RequestID:    "runtime-public",
			AssignmentID: assignment.ID,
			SlotName:     "certificate",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionCertificateDER,
				Form:       domainpki.CredentialMaterialPublic,
			},
		},
		{
			RequestID:    "runtime-private",
			AssignmentID: assignment.ID,
			SlotName:     "private-key",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionPrivateKeyPKCS8,
				Form:       domainpki.CredentialMaterialPrivateBytes,
			},
		},
	}
	deliveries, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		selections,
		domainpki.CredentialOperationScope{OperationID: "mesh-operation-1", ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != len(selections) {
		t.Fatalf("deliveries = %d, want %d", len(deliveries), len(selections))
	}
	publicData := deliveries[0].Runtime.Material.Data
	privateData := deliveries[1].Runtime.Material.Data
	if len(publicData) == 0 || len(privateData) == 0 {
		t.Fatal("resolved runtime delivery omitted credential material")
	}
	cleanup()
	if !bytes.Equal(publicData, make([]byte, len(publicData))) ||
		!bytes.Equal(privateData, make([]byte, len(privateData))) {
		t.Fatal("credential cleanup did not clear ephemeral material")
	}
	provider.DescriptorSHA256 = strings.Repeat("0", 64)
	if _, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		selections,
		domainpki.CredentialOperationScope{OperationID: "mesh-operation-1"},
		[]domainpki.CredentialConsumerBinding{consumer},
	); err == nil {
		cleanup()
		t.Fatal("ResolveCredentialOperation() accepted a mismatched descriptor digest")
	}
}

func TestCredentialOperationLeaseDeduplicatesAssignmentSnapshot(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	setupService := newTestService(t, store)
	assignment, _ := bindActiveStampTestAssignment(
		t,
		setupService,
		"runtime-snapshot",
		"assignment-runtime-snapshot",
		"mesh-provider/listener-edge",
	)
	persistence := &countingCredentialPersistence{Persistence: store}
	authorizer := &countingCredentialAuditContext{}
	service := newCredentialResolutionService(
		t,
		persistence,
		store,
		fixedClock{now: fixedTestTime},
		authorizer,
	)
	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}

	lease, err := service.ResolveCredentialOperationLease(
		t.Context(),
		provider,
		descriptor,
		runtimeCredentialSelections(assignment.ID),
		domainpki.CredentialOperationScope{ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := lease.BorrowedDeliveries()
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("deliveries = %d, want 2", len(deliveries))
	}
	if got := persistence.AssignmentReads(); got != 2 {
		t.Fatalf("assignment snapshot reads = %d, want one resolution and one revalidation", got)
	}
	if got := persistence.GenerationReads(); got != 2 {
		t.Fatalf("generation snapshot reads = %d, want one resolution and one revalidation", got)
	}
	if got := authorizer.Calls(); got != 2 {
		t.Fatalf("authorization calls = %d, want one resolution and one revalidation", got)
	}

	privateData := deliveries[1].Runtime.Material.Data
	if err := lease.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	lease.Close()
	lease.Clear()
	if !errors.Is(lease.Revalidate(t.Context()), apppki.ErrCredentialOperationLeaseClosed) {
		t.Fatal("closed credential lease remained revalidatable")
	}
	if !bytes.Equal(privateData, make([]byte, len(privateData))) {
		t.Fatal("closing credential lease did not clear borrowed private material")
	}
}

func TestCredentialOperationLeaseRejectsRotationDuringResolution(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	setupService := newTestService(t, store)
	assignment, firstGenerationID := bindActiveStampTestAssignment(
		t,
		setupService,
		"runtime-race",
		"assignment-runtime-race",
		"mesh-provider/listener-edge",
	)
	staged := stageCredentialRotation(
		t,
		setupService,
		store,
		assignment,
		firstGenerationID,
		"runtime-race",
	)
	persistence := &countingCredentialPersistence{Persistence: store}
	persistence.afterAssignment = func(read int, _ domainpki.Assignment) error {
		if read != 1 {
			return nil
		}
		_, err := setupService.ActivateAssignment(
			t.Context(),
			apppki.ActivateAssignmentRequest{
				IdempotencyKey:   "test:credential-runtime-race-activate",
				AssignmentID:     staged.Assignment.ID,
				ExpectedRevision: staged.Assignment.Revision,
			},
		)
		return err
	}
	service := newCredentialResolutionService(
		t,
		persistence,
		store,
		fixedClock{now: fixedTestTime},
		&countingCredentialAuditContext{},
	)
	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}

	lease, err := service.ResolveCredentialOperationLease(
		t.Context(),
		provider,
		descriptor,
		runtimeCredentialSelections(assignment.ID),
		domainpki.CredentialOperationScope{ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	if lease != nil {
		lease.Close()
		t.Fatal("ResolveCredentialOperationLease() returned a lease from mixed assignment generations")
	}
	if err == nil || !strings.Contains(err.Error(), "changed after resolution") {
		t.Fatalf("ResolveCredentialOperationLease() rotation error = %v", err)
	}
}

func TestCredentialOperationLeaseRevalidationFailsClosed(t *testing.T) {
	t.Parallel()

	t.Run("assignment rotation", func(t *testing.T) {
		t.Parallel()

		store := pkimemory.NewStore()
		setupService := newTestService(t, store)
		assignment, firstGenerationID := bindActiveStampTestAssignment(
			t,
			setupService,
			"runtime-revalidate-rotation",
			"assignment-runtime-revalidate-rotation",
			"mesh-provider/listener-edge",
		)
		staged := stageCredentialRotation(
			t,
			setupService,
			store,
			assignment,
			firstGenerationID,
			"runtime-revalidate-rotation",
		)
		lease := resolveCredentialTestLease(
			t,
			newCredentialResolutionService(
				t,
				store,
				store,
				fixedClock{now: fixedTestTime},
				&countingCredentialAuditContext{},
			),
			assignment.ID,
		)
		defer lease.Close()
		if _, err := setupService.ActivateAssignment(
			t.Context(),
			apppki.ActivateAssignmentRequest{
				IdempotencyKey:   "test:credential-runtime-revalidate-activate",
				AssignmentID:     staged.Assignment.ID,
				ExpectedRevision: staged.Assignment.Revision,
			},
		); err != nil {
			t.Fatal(err)
		}
		if err := lease.Revalidate(t.Context()); err == nil {
			t.Fatal("Revalidate() accepted a rotated assignment")
		}
	})

	t.Run("assignment retirement", func(t *testing.T) {
		t.Parallel()

		store := pkimemory.NewStore()
		setupService := newTestService(t, store)
		assignment, _ := bindActiveStampTestAssignment(
			t,
			setupService,
			"runtime-revalidate-retired",
			"assignment-runtime-revalidate-retired",
			"mesh-provider/listener-edge",
		)
		lease := resolveCredentialTestLease(
			t,
			newCredentialResolutionService(
				t,
				store,
				store,
				fixedClock{now: fixedTestTime},
				&countingCredentialAuditContext{},
			),
			assignment.ID,
		)
		defer lease.Close()
		if _, err := setupService.UnbindAssignment(
			t.Context(),
			apppki.UnbindAssignmentRequest{
				IdempotencyKey:   "test:credential-runtime-revalidate-unbind",
				AssignmentID:     assignment.ID,
				ExpectedRevision: assignment.Revision,
			},
		); err != nil {
			t.Fatal(err)
		}
		if err := lease.Revalidate(t.Context()); err == nil {
			t.Fatal("Revalidate() accepted a retired assignment")
		}
	})

	t.Run("authorization loss", func(t *testing.T) {
		t.Parallel()

		store := pkimemory.NewStore()
		setupService := newTestService(t, store)
		assignment, _ := bindActiveStampTestAssignment(
			t,
			setupService,
			"runtime-revalidate-authorization",
			"assignment-runtime-revalidate-authorization",
			"mesh-provider/listener-edge",
		)
		authorizer := &countingCredentialAuditContext{}
		lease := resolveCredentialTestLease(
			t,
			newCredentialResolutionService(
				t,
				store,
				store,
				fixedClock{now: fixedTestTime},
				authorizer,
			),
			assignment.ID,
		)
		defer lease.Close()
		authorizer.Deny()
		if err := lease.Revalidate(t.Context()); err == nil ||
			!strings.Contains(err.Error(), "reauthorize credential use") {
			t.Fatalf("Revalidate() authorization error = %v", err)
		}
	})

	t.Run("certificate expiry", func(t *testing.T) {
		t.Parallel()

		store := pkimemory.NewStore()
		setupService := newTestService(t, store)
		assignment, generationID := bindActiveStampTestAssignment(
			t,
			setupService,
			"runtime-revalidate-expiry",
			"assignment-runtime-revalidate-expiry",
			"mesh-provider/listener-edge",
		)
		generation, err := store.Generation(t.Context(), generationID)
		if err != nil {
			t.Fatal(err)
		}
		clock := &mutableClock{now: fixedTestTime}
		lease := resolveCredentialTestLease(
			t,
			newCredentialResolutionService(
				t,
				store,
				store,
				clock,
				&countingCredentialAuditContext{},
			),
			assignment.ID,
		)
		defer lease.Close()
		clock.Add(generation.Template.NotAfter.Sub(clock.Now()))
		if err := lease.Revalidate(t.Context()); err == nil ||
			!strings.Contains(err.Error(), "not currently valid") {
			t.Fatalf("Revalidate() expiry error = %v", err)
		}
	})
}

func TestServiceRejectsCredentialAssignmentOutsideOperation(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	assignment, _ := bindActiveStampTestAssignment(
		t,
		service,
		"runtime-consumer",
		"assignment-runtime-consumer",
		"mesh-provider/listener-other",
	)
	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		domainpki.CredentialSelections{{
			RequestID:    "runtime-wrong-consumer",
			AssignmentID: assignment.ID,
			SlotName:     "certificate",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionCertificateDER,
				Form:       domainpki.CredentialMaterialPublic,
			},
		}},
		domainpki.CredentialOperationScope{ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	cleanup()
	if err == nil {
		t.Fatal("ResolveCredentialOperation() accepted an assignment bound to another consumer")
	}
}

func TestServiceRejectsUnimplementedRuntimeCredentialProjection(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	assignment, _ := bindActiveStampTestAssignment(
		t,
		service,
		"runtime-projection",
		"assignment-runtime-projection",
		"mesh-provider/listener-edge",
	)
	descriptor := runtimeCredentialDescriptor(t)
	descriptor.Slots[0].AcceptedProjections = append(
		descriptor.Slots[0].AcceptedProjections,
		domainpki.CredentialProjectionBundle,
	)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		domainpki.CredentialSelections{{
			RequestID:    "runtime-bundle",
			AssignmentID: assignment.ID,
			SlotName:     "certificate",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionBundle,
				Form:       domainpki.CredentialMaterialPublic,
			},
		}},
		domainpki.CredentialOperationScope{ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	cleanup()
	if err == nil {
		t.Fatal("ResolveCredentialOperation() accepted an unimplemented projection")
	}
}

func TestServiceRejectsTemporallyInvalidAssignmentGeneration(t *testing.T) {
	t.Parallel()

	for _, boundary := range []string{"stage", "activate"} {
		for _, validity := range []string{"not-yet-valid", "expired"} {
			t.Run(boundary+"/"+validity, func(t *testing.T) {
				t.Parallel()

				suffix := boundary + "-" + validity
				store := pkimemory.NewStore()
				setupService := newTestService(t, store)
				assignment, generation := bindPendingTemporalCredentialAssignment(
					t,
					setupService,
					suffix,
				)
				expectedRevision := assignment.Revision
				if boundary == "activate" {
					staged, err := setupService.StageAssignment(
						t.Context(),
						apppki.StageAssignmentRequest{
							IdempotencyKey:   "test:credential-temporal-setup-stage-" + suffix,
							AssignmentID:     assignment.ID,
							GenerationID:     generation.ID,
							ExpectedRevision: assignment.Revision,
						},
					)
					if err != nil {
						t.Fatal(err)
					}
					expectedRevision = staged.Assignment.Revision
				}

				clock := &mutableClock{now: generation.Template.NotBefore.Add(-time.Second)}
				if validity == "expired" {
					clock.Add(generation.Template.NotAfter.Sub(clock.Now()))
				}
				service := newTestServiceWithPersistenceAndBackend(
					t,
					store,
					store,
					infrapki.NewBackend(),
					clock,
				)

				var err error
				switch boundary {
				case "stage":
					_, err = service.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
						IdempotencyKey:   "test:credential-temporal-stage-" + suffix,
						AssignmentID:     assignment.ID,
						GenerationID:     generation.ID,
						ExpectedRevision: expectedRevision,
					})
				case "activate":
					_, err = service.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
						IdempotencyKey:   "test:credential-temporal-activate-" + suffix,
						AssignmentID:     assignment.ID,
						ExpectedRevision: expectedRevision,
					})
				}
				if err == nil || !strings.Contains(err.Error(), "not currently valid") {
					t.Fatalf("%s assignment with %s certificate error = %v", boundary, validity, err)
				}
			})
		}
	}
}

func TestServiceEnforcesRuntimeCredentialCertificateValidityWindow(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	setupService := newTestService(t, store)
	assignment, generation := bindPendingTemporalCredentialAssignment(
		t,
		setupService,
		"runtime-validity",
	)
	staged, err := setupService.StageAssignment(t.Context(), apppki.StageAssignmentRequest{
		IdempotencyKey:   "test:credential-temporal-runtime-stage",
		AssignmentID:     assignment.ID,
		GenerationID:     generation.ID,
		ExpectedRevision: assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := setupService.ActivateAssignment(t.Context(), apppki.ActivateAssignmentRequest{
		IdempotencyKey:   "test:credential-temporal-runtime-activate",
		AssignmentID:     assignment.ID,
		ExpectedRevision: staged.Assignment.Revision,
	})
	if err != nil {
		t.Fatal(err)
	}

	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-runtime-validity")
	if err != nil {
		t.Fatal(err)
	}
	selections := domainpki.CredentialSelections{{
		RequestID:    "runtime-temporal-private",
		AssignmentID: active.Assignment.ID,
		SlotName:     "private-key",
		Capability:   domainpki.DeliveryCapabilityRuntime,
		Material: domainpki.CredentialMaterialSelection{
			Projection: domainpki.CredentialProjectionPrivateKeyPKCS8,
			Form:       domainpki.CredentialMaterialPrivateBytes,
		},
	}}
	resolve := func(service apppki.Service) error {
		deliveries, cleanup, resolveErr := service.ResolveCredentialOperation(
			t.Context(),
			provider,
			descriptor,
			selections,
			domainpki.CredentialOperationScope{ListenerID: "listener-runtime-validity"},
			[]domainpki.CredentialConsumerBinding{consumer},
		)
		cleanup()
		if resolveErr == nil && len(deliveries) != 1 {
			t.Fatalf("runtime credential deliveries = %d, want 1", len(deliveries))
		}
		return resolveErr
	}

	clock := &mutableClock{now: generation.Template.NotBefore.Add(-time.Second)}
	service := newTestServiceWithPersistenceAndBackend(
		t,
		store,
		store,
		infrapki.NewBackend(),
		clock,
	)
	if err := resolve(service); err == nil || !strings.Contains(err.Error(), "not currently valid") {
		t.Fatalf("ResolveCredentialOperation() not-yet-valid error = %v", err)
	}
	clock.Add(time.Second)
	if err := resolve(service); err != nil {
		t.Fatalf("ResolveCredentialOperation() at NotBefore: %v", err)
	}
	clock.Add(generation.Template.NotAfter.Sub(clock.Now()))
	if err := resolve(service); err == nil || !strings.Contains(err.Error(), "not currently valid") {
		t.Fatalf("ResolveCredentialOperation() expired error = %v", err)
	}
}

func bindPendingTemporalCredentialAssignment(
	t *testing.T,
	service apppki.Service,
	suffix string,
) (domainpki.Assignment, domainpki.CertificateGeneration) {
	t.Helper()
	authority, err := service.CreateAuthority(t.Context(), apppki.CreateAuthorityRequest{
		IdempotencyKey: "test:credential-temporal-authority-" + suffix,
		Name:           "credential temporal authority " + suffix,
		Role:           domainpki.AuthorityRoleRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, authority.Authority.ID)
	generation, err := service.IssueCertificate(t.Context(), apppki.IssueCertificateRequest{
		IdempotencyKey:    "test:credential-temporal-certificate-" + suffix,
		IssuerAuthorityID: authority.Authority.ID,
		Name:              "credential-temporal-" + suffix + ".test",
		ProfileID:         domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "test:credential-temporal-assignment-" + suffix,
		ID:             domainpki.AssignmentID("assignment-credential-temporal-" + suffix),
		Purpose:        domainpki.PurposeTLSServer,
		ConsumerType:   domainpki.ConsumerMeshListener,
		ConsumerID:     domainpki.ConsumerID("mesh-provider/listener-" + suffix),
		ProfileID:      domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return assignment, generation
}

func runtimeCredentialDescriptor(t *testing.T) domainpki.CredentialDeliveryDescriptor {
	t.Helper()
	const maximumRuntimeCredentialBytes = 64 * 1024
	common := domainpki.CredentialSlot{
		Purpose:                domainpki.PurposeTLSServer,
		EndpointRole:           domainpki.CredentialEndpointServer,
		ConsumerType:           domainpki.ConsumerMeshListener,
		AcceptedBundleVersions: []string{domainpki.BundleSchemaV1},
		AcceptedProfiles:       []domainpki.ProfileID{domainpki.ProfileTLSServer},
		AcceptedCompatibilityTargets: []domainpki.CompatibilityTargetID{
			domainpki.CompatibilityPortableX509,
		},
		MaximumEncodedBytes: maximumRuntimeCredentialBytes,
		RemainderPolicy:     domainpki.StampRemainderPreserve,
	}
	certificate := common.Clone()
	certificate.Name = "certificate"
	certificate.AcceptedProjections = []domainpki.CredentialProjection{
		domainpki.CredentialProjectionCertificateDER,
	}
	certificate.AcceptedMaterialForms = []domainpki.CredentialMaterialForm{
		domainpki.CredentialMaterialPublic,
	}
	certificate.PrivateMaterial = domainpki.PrivateMaterialForbidden
	privateKey := common.Clone()
	privateKey.Name = "private-key"
	privateKey.AcceptedProjections = []domainpki.CredentialProjection{
		domainpki.CredentialProjectionPrivateKeyPKCS8,
	}
	privateKey.AcceptedMaterialForms = []domainpki.CredentialMaterialForm{
		domainpki.CredentialMaterialPrivateBytes,
	}
	privateKey.PrivateMaterial = domainpki.PrivateMaterialRequired
	descriptor, err := domainpki.NewCredentialDeliveryDescriptor(
		domainpki.CredentialDeliveryDescriptorArgs{
			SchemaVersion: domainpki.CredentialDeliverySchemaV1,
			Slots:         []domainpki.CredentialSlot{certificate, privateKey},
			Capabilities:  []domainpki.DeliveryCapability{domainpki.DeliveryCapabilityRuntime},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func runtimeCredentialProvider(
	t *testing.T,
	descriptor domainpki.CredentialDeliveryDescriptor,
) domainpki.CredentialProviderTarget {
	t.Helper()
	digest, err := descriptor.DigestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return domainpki.CredentialProviderTarget{
		ModuleID:         "mesh-provider",
		ProviderID:       "mesh-provider",
		ProviderVersion:  "1.0.0",
		DescriptorSHA256: digest,
	}
}

func runtimeCredentialSelections(
	assignmentID domainpki.AssignmentID,
) domainpki.CredentialSelections {
	return domainpki.CredentialSelections{
		{
			RequestID:    "runtime-public",
			AssignmentID: assignmentID,
			SlotName:     "certificate",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionCertificateDER,
				Form:       domainpki.CredentialMaterialPublic,
			},
		},
		{
			RequestID:    "runtime-private",
			AssignmentID: assignmentID,
			SlotName:     "private-key",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionPrivateKeyPKCS8,
				Form:       domainpki.CredentialMaterialPrivateBytes,
			},
		},
	}
}

type countingCredentialPersistence struct {
	apppki.Persistence

	mu              sync.Mutex
	assignmentReads int
	generationReads int
	afterAssignment func(int, domainpki.Assignment) error
}

func (p *countingCredentialPersistence) Assignment(
	ctx context.Context,
	id domainpki.AssignmentID,
) (domainpki.Assignment, error) {
	assignment, err := p.Persistence.Assignment(ctx, id)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	p.mu.Lock()
	p.assignmentReads++
	read := p.assignmentReads
	hook := p.afterAssignment
	p.mu.Unlock()
	if hook != nil {
		if err := hook(read, assignment); err != nil {
			return domainpki.Assignment{}, err
		}
	}
	return assignment, nil
}

func (p *countingCredentialPersistence) Generation(
	ctx context.Context,
	id domainpki.GenerationID,
) (domainpki.CertificateGeneration, error) {
	generation, err := p.Persistence.Generation(ctx, id)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	p.mu.Lock()
	p.generationReads++
	p.mu.Unlock()
	return generation, nil
}

func (p *countingCredentialPersistence) AssignmentReads() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.assignmentReads
}

func (p *countingCredentialPersistence) GenerationReads() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generationReads
}

type countingCredentialAuditContext struct {
	fixedAuditContext

	mu       sync.Mutex
	calls    int
	isDenied bool
}

func (a *countingCredentialAuditContext) AuthorizeCredentialUse(
	context.Context,
	domainpki.AssignmentID,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.isDenied {
		return errors.New("credential use denied by test authorizer")
	}
	return nil
}

func (a *countingCredentialAuditContext) Calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func (a *countingCredentialAuditContext) Deny() {
	a.mu.Lock()
	a.isDenied = true
	a.mu.Unlock()
}

func newCredentialResolutionService(
	t *testing.T,
	persistence apppki.Persistence,
	store *pkimemory.Store,
	clock apppki.Clock,
	auditContext apppki.AuditContextProvider,
) apppki.Service {
	t.Helper()
	leases, err := apppki.NewSigningLeaseManager(clock, allowSigningLeaseApprover{})
	if err != nil {
		t.Fatal(err)
	}
	service, err := apppki.NewService(
		t.Context(),
		persistence,
		infrapki.NewBackend(),
		infrapki.NewValidator(),
		leases,
		store,
		store,
		auditContext,
		clock,
		bytes.NewReader(deterministicRandomBytes(173)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func resolveCredentialTestLease(
	t *testing.T,
	service apppki.Service,
	assignmentID domainpki.AssignmentID,
) *apppki.CredentialOperationLease {
	t.Helper()
	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := service.ResolveCredentialOperationLease(
		t.Context(),
		provider,
		descriptor,
		runtimeCredentialSelections(assignmentID),
		domainpki.CredentialOperationScope{ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func stageCredentialRotation(
	t *testing.T,
	service apppki.Service,
	store *pkimemory.Store,
	assignment domainpki.Assignment,
	activeGenerationID domainpki.GenerationID,
	suffix string,
) apppki.AssignmentInspection {
	t.Helper()
	activeGeneration, err := store.Generation(t.Context(), activeGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	unlockTestAuthority(t, service, activeGeneration.IssuerAuthorityID)
	rotatedGeneration, err := service.IssueCertificate(
		t.Context(),
		apppki.IssueCertificateRequest{
			IdempotencyKey:    "test:credential-rotation-certificate-" + suffix,
			IssuerAuthorityID: activeGeneration.IssuerAuthorityID,
			Name:              "credential-rotation-" + suffix + ".test",
			ProfileID:         domainpki.ProfileTLSServer,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := service.StageAssignment(
		t.Context(),
		apppki.StageAssignmentRequest{
			IdempotencyKey:   "test:credential-rotation-stage-" + suffix,
			AssignmentID:     assignment.ID,
			GenerationID:     rotatedGeneration.ID,
			ExpectedRevision: assignment.Revision,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return staged
}

var _ apppki.CredentialUseAuthorizer = fixedAuditContext{}
var _ apppki.CredentialUseAuthorizer = (*countingCredentialAuditContext)(nil)
