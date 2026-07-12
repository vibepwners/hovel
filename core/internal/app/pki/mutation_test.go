package pki

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func TestCredentialStampLifecycleContractsAreDistinct(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status  domainpki.CredentialStampStatus
		kind    MutationKind
		action  AuditAction
		outcome AuditOutcome
	}{
		{domainpki.CredentialStampPending, MutationCredentialStampCreate, AuditActionCredentialStampPlan, AuditOutcomeAttempted},
		{domainpki.CredentialStampSucceeded, MutationCredentialStampSucceed, AuditActionCredentialStampSucceed, AuditOutcomeSucceeded},
		{domainpki.CredentialStampFailed, MutationCredentialStampFail, AuditActionCredentialStampFail, AuditOutcomeFailed},
		{domainpki.CredentialStampSuperseded, MutationCredentialStampSupersede, AuditActionCredentialStampSupersede, AuditOutcomeSucceeded},
	}
	seenKinds := make(map[MutationKind]struct{}, len(tests))
	seenActions := make(map[AuditAction]struct{}, len(tests))
	for _, test := range tests {
		kind, action, outcome, err := CredentialStampLifecycleContract(test.status)
		if err != nil {
			t.Fatal(err)
		}
		if kind != test.kind || action != test.action || outcome != test.outcome {
			t.Fatalf(
				"CredentialStampLifecycleContract(%q) = %q, %q, %q",
				test.status, kind, action, outcome,
			)
		}
		if _, exists := seenKinds[kind]; exists {
			t.Fatalf("duplicate credential stamp mutation kind %q", kind)
		}
		if _, exists := seenActions[action]; exists {
			t.Fatalf("duplicate credential stamp audit action %q", action)
		}
		seenKinds[kind] = struct{}{}
		seenActions[action] = struct{}{}
	}
	if _, _, _, err := CredentialStampLifecycleContract("unknown"); err == nil {
		t.Fatal("CredentialStampLifecycleContract() accepted an unknown status")
	}
}

func TestCredentialExecutionLifecycleContractsAreDistinct(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status  domainpki.CredentialExecutionStatus
		kind    MutationKind
		action  AuditAction
		outcome AuditOutcome
	}{
		{domainpki.CredentialExecutionPending, MutationCredentialExecutionCreate, AuditActionCredentialExecutionPlan, AuditOutcomeAttempted},
		{domainpki.CredentialExecutionSucceeded, MutationCredentialExecutionSucceed, AuditActionCredentialExecutionSucceed, AuditOutcomeSucceeded},
		{domainpki.CredentialExecutionFailed, MutationCredentialExecutionFail, AuditActionCredentialExecutionFail, AuditOutcomeFailed},
	}
	seenKinds := make(map[MutationKind]struct{}, len(tests))
	seenActions := make(map[AuditAction]struct{}, len(tests))
	for _, test := range tests {
		kind, action, outcome, err := CredentialExecutionLifecycleContract(test.status)
		if err != nil {
			t.Fatal(err)
		}
		if kind != test.kind || action != test.action || outcome != test.outcome {
			t.Fatalf(
				"CredentialExecutionLifecycleContract(%q) = %q, %q, %q",
				test.status, kind, action, outcome,
			)
		}
		if _, exists := seenKinds[kind]; exists {
			t.Fatalf("duplicate credential execution mutation kind %q", kind)
		}
		if _, exists := seenActions[action]; exists {
			t.Fatalf("duplicate credential execution audit action %q", action)
		}
		seenKinds[kind] = struct{}{}
		seenActions[action] = struct{}{}
	}
	if _, _, _, err := CredentialExecutionLifecycleContract("unknown"); err == nil {
		t.Fatal("CredentialExecutionLifecycleContract() accepted an unknown status")
	}
}

func TestMutationRecordValidationAndClone(t *testing.T) {
	t.Parallel()

	record := validMutationRecord(t)
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := record.Clone()
	clone.ResultJSON[0] = '['
	if record.ResultJSON[0] != '{' {
		t.Fatal("MutationRecord.Clone() retained result json alias")
	}
}

func TestResolveIdempotencyKeyScopesRetries(t *testing.T) {
	t.Parallel()

	requestSHA256 := strings.Repeat("a", sha256.Size*2)
	base := AuditContext{ActorID: "operator-a", OperationID: "operation-a", CorrelationID: "correlation-a"}
	explicit, err := resolveIdempotencyKey("retry-key", MutationAssignmentBind, requestSHA256, base)
	if err != nil {
		t.Fatal(err)
	}
	explicitOtherCall, err := resolveIdempotencyKey("retry-key", MutationAssignmentBind, requestSHA256,
		AuditContext{ActorID: base.ActorID, OperationID: "operation-b", CorrelationID: "correlation-b"})
	if err != nil {
		t.Fatal(err)
	}
	if explicit != explicitOtherCall {
		t.Fatal("explicit retry key changed across calls by the same actor")
	}
	explicitOtherActor, err := resolveIdempotencyKey("retry-key", MutationAssignmentBind, requestSHA256,
		AuditContext{ActorID: "operator-b", OperationID: base.OperationID, CorrelationID: base.CorrelationID})
	if err != nil {
		t.Fatal(err)
	}
	if explicit == explicitOtherActor {
		t.Fatal("explicit retry key was not isolated by actor")
	}

	implicit, err := resolveIdempotencyKey("", MutationAssignmentBind, requestSHA256, base)
	if err != nil {
		t.Fatal(err)
	}
	implicitRetry, err := resolveIdempotencyKey("", MutationAssignmentBind, requestSHA256, base)
	if err != nil {
		t.Fatal(err)
	}
	if implicit != implicitRetry {
		t.Fatal("implicit retry key changed for the same request scope")
	}
	implicitNewCall, err := resolveIdempotencyKey("", MutationAssignmentBind, requestSHA256,
		AuditContext{ActorID: base.ActorID, OperationID: base.OperationID, CorrelationID: "correlation-b"})
	if err != nil {
		t.Fatal(err)
	}
	if implicit == implicitNewCall {
		t.Fatal("implicit retry key replayed across distinct correlations")
	}
	if strings.Contains(explicit, "retry-key") || strings.Contains(explicit, base.ActorID) {
		t.Fatal("resolved retry key exposed caller-controlled scope")
	}
}

func TestResolveIdempotencyKeyRejectsInvalidExplicitKey(t *testing.T) {
	t.Parallel()

	_, err := resolveIdempotencyKey(" retry-key ", MutationAssignmentBind, strings.Repeat("a", sha256.Size*2),
		AuditContext{ActorID: "operator-a", OperationID: "operation-a", CorrelationID: "correlation-a"})
	if err == nil {
		t.Fatal("resolveIdempotencyKey() accepted a noncanonical explicit key")
	}
}

func TestMutationRecordRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*MutationRecord)
	}{
		{name: "id", mutate: func(record *MutationRecord) { record.ID = "bad id" }},
		{name: "idempotency key", mutate: func(record *MutationRecord) { record.IdempotencyKey = "" }},
		{name: "request digest", mutate: func(record *MutationRecord) { record.RequestSHA256 = "bad" }},
		{name: "kind", mutate: func(record *MutationRecord) { record.Kind = "unknown" }},
		{name: "resource type", mutate: func(record *MutationRecord) { record.ResourceType = " " }},
		{name: "resource id", mutate: func(record *MutationRecord) { record.ResourceID = "bad\nvalue" }},
		{name: "result missing", mutate: func(record *MutationRecord) { record.ResultJSON = nil }},
		{name: "result invalid", mutate: func(record *MutationRecord) { record.ResultJSON = json.RawMessage("{") }},
		{name: "result noncanonical", mutate: func(record *MutationRecord) { record.ResultJSON = json.RawMessage(`{ "ok": true }`) }},
		{name: "result oversized", mutate: func(record *MutationRecord) {
			record.ResultJSON = json.RawMessage(`"` + strings.Repeat("a", MaximumMutationResultBytes) + `"`)
		}},
		{name: "creation time", mutate: func(record *MutationRecord) { record.CreatedAt = time.Time{} }},
		{name: "creation timezone", mutate: func(record *MutationRecord) {
			record.CreatedAt = record.CreatedAt.In(time.FixedZone("noncanonical", int(time.Hour/time.Second)))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			record := validMutationRecord(t)
			test.mutate(&record)
			if err := record.Validate(); err == nil {
				t.Fatal("MutationRecord.Validate() accepted invalid contract")
			}
		})
	}
}

func validMutationRecord(t *testing.T) MutationRecord {
	t.Helper()
	digest := sha256.Sum256([]byte("mutation request"))
	return MutationRecord{
		ID: "mutation-test", IdempotencyKey: "test:mutation",
		RequestSHA256: fmt.Sprintf("%x", digest), Kind: MutationTrustSetCreate,
		ResourceType: auditResourceTrustSet, ResourceID: "trust-test",
		ResultJSON: json.RawMessage(`{"id":"trust-test"}`),
		CreatedAt:  time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC),
	}
}
