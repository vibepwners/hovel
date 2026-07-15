package sqlite

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

func TestPKIStorePersistsCredentialExecutionWithoutSecrets(t *testing.T) {
	t.Parallel()

	store := newAssignmentTestPKIStore(
		t, testMasterKeyProvider{key: mustTestMasterKey(t, 0x7a)},
	)
	clock := pkiTestClock{now: time.Date(2026, 7, 11, 22, 0, 0, 0, time.UTC)}
	service, err := apppki.NewService(
		t.Context(),
		store, infrapki.NewBackend(), infrapki.NewValidator(),
		pkiTestAuthorization{}, pkiTestAuthorization{}, store,
		pkiTestAuthorization{}, clock, newTestEntropy(0x7b),
	)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := service.BindAssignment(t.Context(), apppki.BindAssignmentRequest{
		IdempotencyKey: "sqlite:credential-execution-assignment",
		ID:             "assignment-sqlite-credential-execution",
		Purpose:        domainpki.PurposeTLSServer,
		ConsumerType:   domainpki.ConsumerMeshListener,
		ConsumerID:     "mesh-provider/sqlite-credential-listener",
		ProfileID:      domainpki.ProfileTLSServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	assignment = activateCredentialLedgerTestAssignment(t, service, assignment, "execution-store")

	const secretMaterial = "sqlite-runtime-private-secret"
	material := domainpki.CredentialBytes(secretMaterial)
	digest := sha256.Sum256(material)
	pending, err := domainpki.NewRuntimeCredentialExecution(
		domainpki.CredentialRuntimeRequest{
			SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
			Provider: domainpki.CredentialProviderTarget{
				ModuleID: "mesh-provider-module", ProviderID: "mesh-provider",
				ProviderVersion: "1.0.0", DescriptorSHA256: strings.Repeat("a", 64),
			},
			RequestID: "credential-runtime-sqlite", AssignmentID: assignment.ID,
			SlotName: "tls-server",
			Credential: domainpki.ResolvedCredentialMetadata{
				BundleVersion: domainpki.BundleSchemaV1, Purpose: domainpki.PurposeTLSServer,
				ConsumerType: domainpki.ConsumerMeshListener, ProfileID: domainpki.ProfileTLSServer,
				CompatibilityTargetID: domainpki.CompatibilityPortableX509,
			},
			Material: domainpki.ResolvedCredentialMaterial{
				Projection: domainpki.CredentialProjectionBundle,
				Form:       domainpki.CredentialMaterialPrivateBytes, Encoding: "hovel-bundle-json",
				SHA256: hex.EncodeToString(digest[:]), Data: material,
			},
			Scope: domainpki.CredentialOperationScope{ListenerID: "listener-sqlite"},
		},
		clock.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	planned, err := service.RecordCredentialExecutionPlan(
		t.Context(), "sqlite:credential-execution-plan", pending,
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := domainpki.CompleteCredentialDeliveryExecution(
		planned,
		domainpki.CredentialDeliveryReceipt{
			RequestID: planned.ID, ProviderReference: "sqlite-opaque-provider-secret",
			ReceiptSHA256: strings.Repeat("c", 64),
		},
		planned.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecordCredentialExecutionTransition(
		t.Context(), "sqlite:credential-execution-complete", completed,
	); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.CredentialExecution(t.Context(), completed.ID)
	if err != nil || loaded.Status != domainpki.CredentialExecutionSucceeded || loaded.Result == nil {
		t.Fatalf("CredentialExecution() = %#v, %v", loaded, err)
	}
	db, err := store.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var encoded []byte
	if err := db.QueryRowContext(
		t.Context(), `SELECT execution_json FROM pki_credential_executions WHERE id = ?`, completed.ID,
	).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secretMaterial, "sqlite-opaque-provider-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("persisted credential execution leaked %q: %s", secret, encoded)
		}
	}
	if _, err := db.ExecContext(
		t.Context(), `UPDATE pki_credential_executions SET provider_id = ? WHERE id = ?`,
		"tampered-provider", completed.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CredentialExecution(t.Context(), completed.ID); err == nil {
		t.Fatal("CredentialExecution() accepted canonical-column tampering")
	}
}
