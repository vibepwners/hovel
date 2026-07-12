package pki_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pkimemory "github.com/vibepwners/hovel/internal/adapters/pki/memory"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func TestServiceRecordsCredentialExecutionLifecycleIdempotently(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	pending := testEncodingCredentialExecution(t, "credential-encoding-service")
	planned, err := service.RecordCredentialExecutionPlan(
		t.Context(), "test:credential-execution-plan", pending,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.RecordCredentialExecutionPlan(
		t.Context(), "test:credential-execution-plan", pending,
	)
	if !errors.Is(err, apppki.ErrCredentialExecutionInProgress) {
		t.Fatalf("credential execution plan replay error = %v, want in progress", err)
	}

	completed, err := domainpki.CompleteCredentialEncodingExecution(
		planned,
		domainpki.CredentialEncodingResult{
			RequestID: planned.ID,
			Form:      domainpki.CredentialMaterialPrivateBytes,
			Encoding:  "provider-encoding-v1",
			SHA256:    credentialExecutionTestSHA256(domainpki.CredentialBytes("encoded-result")),
			Data:      domainpki.CredentialBytes("encoded-result"),
		},
		planned.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err = service.RecordCredentialExecutionTransition(
		t.Context(), "test:credential-execution-complete", completed,
	)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := service.InspectCredentialExecution(t.Context(), completed.ID)
	if err != nil || loaded.Status != domainpki.CredentialExecutionSucceeded || loaded.Result == nil {
		t.Fatalf("InspectCredentialExecution() = %#v, %v", loaded, err)
	}
	listed, err := service.ListCredentialExecutions(t.Context())
	if err != nil || len(listed) != 1 || listed[0].ID != completed.ID {
		t.Fatalf("ListCredentialExecutions() = %#v, %v", listed, err)
	}
	audits := store.AuditRecords()
	if len(audits) < 2 || audits[len(audits)-1].Action != apppki.AuditActionCredentialExecutionSucceed {
		t.Fatalf("credential execution audits = %#v", audits)
	}
}

func TestServiceClaimsCredentialExecutionPlanAtMostOnce(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	template := testEncodingCredentialExecution(t, "credential-encoding-race")

	const contenderCount = 16
	start := make(chan struct{})
	results := make(chan error, contenderCount)
	var contenders sync.WaitGroup
	for index := range contenderCount {
		contenders.Add(1)
		go func() {
			defer contenders.Done()
			<-start
			execution := template.Clone()
			execution.CreatedAt = execution.CreatedAt.Add(time.Duration(index) * time.Second)
			execution.UpdatedAt = execution.CreatedAt
			_, recordErr := service.RecordCredentialExecutionPlan(
				context.Background(), "test:credential-execution-race-plan", execution,
			)
			results <- recordErr
		}()
	}
	close(start)
	contenders.Wait()
	close(results)

	var claimed, inProgress int
	for recordErr := range results {
		switch {
		case recordErr == nil:
			claimed++
		case errors.Is(recordErr, apppki.ErrCredentialExecutionInProgress):
			inProgress++
		default:
			t.Fatalf("RecordCredentialExecutionPlan() race error = %v", recordErr)
		}
	}
	if claimed != 1 || inProgress != contenderCount-1 {
		t.Fatalf("credential execution claims = %d, in progress = %d", claimed, inProgress)
	}
	executions, err := service.ListCredentialExecutions(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(executions) != 1 || executions[0].Status != domainpki.CredentialExecutionPending {
		t.Fatalf("credential executions after race = %#v", executions)
	}
}

func TestServiceResolvesCredentialExecutionBeforeTimestampedMutation(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	pending := testEncodingCredentialExecution(t, "credential-encoding-replay")
	planned, err := service.RecordCredentialExecutionPlan(
		t.Context(), "test:credential-execution-replay-plan", pending,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded := domainpki.CredentialBytes("encoded-replay-result")
	completed, err := domainpki.CompleteCredentialEncodingExecution(
		planned,
		domainpki.CredentialEncodingResult{
			RequestID: planned.ID,
			Form:      domainpki.CredentialMaterialPrivateBytes,
			Encoding:  "provider-encoding-v1",
			SHA256:    credentialExecutionTestSHA256(encoded),
			Data:      encoded,
		},
		planned.UpdatedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err = service.RecordCredentialExecutionTransition(
		t.Context(), "test:credential-execution-replay-complete", completed,
	)
	if err != nil {
		t.Fatal(err)
	}

	retry := pending.Clone()
	retry.CreatedAt = retry.CreatedAt.Add(24 * time.Hour)
	retry.UpdatedAt = retry.CreatedAt
	replayed, err := service.RecordCredentialExecutionPlan(
		t.Context(), "test:credential-execution-replay-plan", retry,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Status != domainpki.CredentialExecutionSucceeded ||
		replayed.Revision != completed.Revision ||
		!replayed.UpdatedAt.Equal(completed.UpdatedAt) {
		t.Fatalf("credential execution replay = %#v, want %#v", replayed, completed)
	}

	changed := retry.Clone()
	changed.Plan.Scope.NodeID = "different-node"
	if _, err := service.RecordCredentialExecutionPlan(
		t.Context(), "test:credential-execution-replay-plan", changed,
	); !errors.Is(err, apppki.ErrIdempotencyConflict) {
		t.Fatalf("changed credential execution replay error = %v, want idempotency conflict", err)
	}
}

func testEncodingCredentialExecution(
	t *testing.T,
	requestID domainpki.CredentialExecutionRequestID,
) domainpki.CredentialExecution {
	t.Helper()
	material := domainpki.CredentialBytes("credential-material-for-provider-encoding")
	execution, err := domainpki.NewEncodingCredentialExecution(
		domainpki.CredentialEncodingRequest{
			SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
			Provider: domainpki.CredentialProviderTarget{
				ModuleID: "mesh-provider-module", ProviderID: "mesh-provider",
				ProviderVersion: "1.0.0", DescriptorSHA256: strings.Repeat("a", sha256.Size*2),
			},
			RequestID: requestID, ProviderID: "mesh-provider",
			ProviderSchema:      "provider-encoding-v1",
			OutputForm:          domainpki.CredentialMaterialPrivateBytes,
			MaximumEncodedBytes: 1024,
			Source: domainpki.ResolvedCredentialMaterial{
				Projection: domainpki.CredentialProjectionBundle,
				Form:       domainpki.CredentialMaterialPrivateBytes,
				Encoding:   "hovel-bundle-json",
				SHA256:     credentialExecutionTestSHA256(material),
				Data:       material,
			},
			Scope: domainpki.CredentialOperationScope{RunID: "run-1"},
		},
		fixedTestTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	return execution
}

func credentialExecutionTestSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
