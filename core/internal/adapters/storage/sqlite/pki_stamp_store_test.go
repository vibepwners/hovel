package sqlite

import (
	"strings"
	"testing"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

func TestPKIStorePersistsAndChronologicallyOrdersCredentialStamps(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(
		t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x71)},
	)
	clock := pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(),
		pkiTestAuthorization{}, pkiTestAuthorization{}, store,
		pkiTestAuthorization{}, clock, newTestEntropy(0x72),
	)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "sqlite:stamp-assignment",
		ID:             "assignment-sqlite-stamp",
		Purpose:        domainpki.PurposeTLSServer,
		ConsumerType:   domainpki.ConsumerMeshListener,
		ConsumerID:     "mesh-provider/sqlite-listener",
		ProfileID:      domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment = activateCredentialLedgerTestAssignment(t, service, assignment, "stamp-store")

	second := sqliteTestCredentialStamp(
		t, assignment, "credential-stamp-a-later",
		clock.now.Add(900*time.Millisecond),
	)
	first := sqliteTestCredentialStamp(
		t, assignment, "credential-stamp-z-earlier", clock.now,
	)
	if _, err := service.RecordCredentialStampPlan(
		t.Context(), "sqlite:stamp-later", second,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecordCredentialStampPlan(
		t.Context(), "sqlite:stamp-earlier", first,
	); err != nil {
		t.Fatal(err)
	}

	listed, err := store.CredentialStamps(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].ID != first.ID || listed[1].ID != second.ID {
		t.Fatalf("CredentialStamps() chronological order = %#v", listed)
	}
	if listed[0].Plan.DescriptorSHA256 != first.Plan.DescriptorSHA256 ||
		listed[0].Plan.Request.AssignmentID != assignment.ID {
		t.Fatalf("persisted credential stamp plan lost provenance: %#v", listed[0].Plan)
	}

	completed, err := domainpki.CompleteCredentialStamp(
		first, sqliteTestCredentialStampResult(t), first.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecordCredentialStampTransition(
		t.Context(), "sqlite:stamp-complete", completed,
	); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.CredentialStamp(t.Context(), first.ID)
	if err != nil || loaded.Status != domainpki.CredentialStampSucceeded ||
		loaded.Result == nil {
		t.Fatalf("CredentialStamp() = %#v, %v", loaded, err)
	}
}

func sqliteTestCredentialStampResult(t *testing.T) domainpki.CredentialStampResult {
	t.Helper()
	target, err := domainpki.NewFileOffsetStampTarget(domainpki.FileOffsetTarget{
		Offset: "2048", MaximumLength: "16", Alignment: "16",
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
			Projection: domainpki.CredentialProjectionCertificateDER,
			Reference:  "generation-credential-ledger-leaf-stamp-store",
			SHA256:     strings.Repeat("c", 64),
		}},
		Destination: domainpki.StampDestination{
			Artifact: &domainpki.StampArtifactReference{
				Kind:   domainpki.StampArtifactWorkspace,
				ID:     "artifact-sqlite-output",
				SHA256: strings.Repeat("d", 64),
			},
		},
	}
}
