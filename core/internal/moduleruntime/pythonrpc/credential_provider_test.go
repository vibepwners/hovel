package pythonrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/protocol/framing"
)

const (
	credentialProviderChildEnv          = "HOVEL_TEST_CREDENTIAL_PROVIDER_CHILD"
	credentialProviderMismatchEnv       = "HOVEL_TEST_CREDENTIAL_PROVIDER_MISMATCH"
	credentialProviderBadDigestEnv      = "HOVEL_TEST_CREDENTIAL_PROVIDER_BAD_DIGEST"
	credentialProviderInvocationLogEnv  = "HOVEL_TEST_CREDENTIAL_PROVIDER_INVOCATION_LOG"
	credentialProviderMethodLogEnv      = "HOVEL_TEST_CREDENTIAL_PROVIDER_METHOD_LOG"
	credentialProviderHandshakeModeEnv  = "HOVEL_TEST_CREDENTIAL_PROVIDER_HANDSHAKE_MODE"
	credentialProviderDescriptorModeEnv = "HOVEL_TEST_CREDENTIAL_PROVIDER_DESCRIPTOR_MODE"
	credentialProviderFailureSurfaceEnv = "HOVEL_TEST_CREDENTIAL_PROVIDER_FAILURE_SURFACE"

	credentialProviderName          = "credential-provider"
	credentialProviderVersion       = "v0.0.0-test"
	credentialProviderExactModuleID = credentialProviderName + "@" + credentialProviderVersion
)

var credentialProviderFixtureDeliveryCount int
var credentialProviderFixtureSecret string

func init() {
	if os.Getenv(credentialProviderChildEnv) == "1" {
		if err := serveCredentialProviderFixture(os.Stdin, os.Stdout); err != nil {
			if _, writeErr := fmt.Fprintln(os.Stderr, err); writeErr != nil {
				os.Exit(2)
			}
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func TestRunnerCallsCredentialProviderMethods(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	runner := credentialProviderRecordedRunner(t)
	metadata := credentialProviderTestMetadata()
	material := credentialProviderTestMaterial()

	runtimeRequest := domainpki.CredentialRuntimeRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      credentialProviderExactTestTarget(t),
		RequestID:     "runtime-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    metadata,
		Material:      material,
		Scope:         domainpki.CredentialOperationScope{RunID: "run-1", NodeID: "node-1"},
	}
	receipt, err := runner.LoadRuntimeCredential(
		t.Context(), credentialProviderExactModuleID, runtimeRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RequestID != runtimeRequest.RequestID || receipt.ProviderReference != "provider-receipt-1" {
		t.Fatalf("runtime credential receipt = %#v", receipt)
	}

	filesRequest := domainpki.CredentialFilesRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      credentialProviderExactTestTarget(t),
		RequestID:     "files-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    metadata,
		Files: []domainpki.CredentialFile{{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
			Encoding:   domainpki.CredentialEncodingRaw,
			MediaType:  "application/pkix-cert",
			Path:       domainpki.NewCredentialProtectedPath("/protected/certificate.der"),
			SHA256:     strings.Repeat("b", 64),
			Size:       128,
		}},
	}
	receipt, err = runner.LoadCredentialFiles(
		t.Context(), credentialProviderExactModuleID, filesRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RequestID != filesRequest.RequestID {
		t.Fatalf("files credential receipt = %#v", receipt)
	}

	encodingRequest := domainpki.CredentialEncodingRequest{
		SchemaVersion:       domainpki.CredentialProviderExecutionSchemaV1,
		Provider:            credentialProviderExactTestTarget(t),
		RequestID:           "encoding-1",
		ProviderID:          "credential-provider",
		ProviderSchema:      "mbedtls-v1",
		OutputForm:          domainpki.CredentialMaterialPrivateBytes,
		MaximumEncodedBytes: 1024,
		Source:              material,
	}
	encoded, err := runner.EncodeCredentialMaterial(
		t.Context(), credentialProviderExactModuleID, encodingRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if encoded.RequestID != encodingRequest.RequestID || string(encoded.Data) != "provider encoding" {
		t.Fatalf("credential encoding result = %#v", encoded)
	}

	stampRequest := credentialProviderTestStampRequest(t, metadata, material)
	stampRequest.Provider = credentialProviderExactTestTarget(t)
	stamped, err := runner.StampCredential(
		t.Context(), credentialProviderExactModuleID, stampRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stamped.StampID != stampRequest.StampID || stamped.BytesWritten != "16" ||
		stamped.Output.Artifact == nil || string(stamped.Output.Artifact.Data) != "stamped artifact" {
		t.Fatalf("credential stamp result = %#v", stamped)
	}
}

func TestRunnerRecordsSecretFreeCredentialExecutionLifecycle(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	recorder := &recordingCredentialExecutionRecorder{}
	request := credentialProviderRuntimeRequest()
	request.Provider = credentialProviderExactTestTarget(t)
	request.Material.Data = domainpki.CredentialBytes("runtime-ledger-secret")
	request.Material.SHA256 = credentialProviderTestSHA256(request.Material.Data)
	runner := Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}
	receipt, err := runner.LoadRuntimeCredential(
		t.Context(), credentialProviderExactModuleID, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.executions) != 2 ||
		recorder.executions[0].Status != domainpki.CredentialExecutionPending ||
		recorder.executions[1].Status != domainpki.CredentialExecutionSucceeded {
		t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
	}
	if recorder.keys[0] == recorder.keys[1] ||
		len(recorder.keys[0]) != len(credentialExecutionIdempotencyPrefix)+(sha256.Size*2) {
		t.Fatalf("credential execution idempotency keys = %#v", recorder.keys)
	}
	encoded, err := json.Marshal(recorder.executions)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"runtime-ledger-secret", receipt.ProviderReference} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("credential execution ledger leaked %q: %s", secret, encoded)
		}
	}
}

func TestRunnerRecordsSanitizedCredentialExecutionFailure(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	t.Setenv(credentialProviderMismatchEnv, "1")
	recorder := &recordingCredentialExecutionRecorder{}
	request := credentialProviderRuntimeRequest()
	request.Provider = credentialProviderExactTestTarget(t)
	_, err := (Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}).LoadRuntimeCredential(t.Context(), credentialProviderExactModuleID, request)
	if err == nil || !strings.Contains(err.Error(), "mismatched credential delivery receipt") {
		t.Fatalf("LoadRuntimeCredential() error = %v", err)
	}
	if len(recorder.executions) != 2 ||
		recorder.executions[1].Status != domainpki.CredentialExecutionFailed ||
		recorder.executions[1].Failure != credentialRuntimeFailureReason {
		t.Fatalf("failed credential execution lifecycle = %#v", recorder.executions)
	}
	if strings.Contains(recorder.executions[1].Failure, "mismatched") {
		t.Fatalf("credential execution persisted provider error details: %#v", recorder.executions[1])
	}
}

func TestRunnerRecordsTerminalCredentialStateAfterCallerCancellation(t *testing.T) {
	recorder := &recordingCredentialExecutionRecorder{}
	clock := credentialRecorderClock{
		now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
	}
	runner := Runner{Clock: clock, CredentialExecutions: recorder}
	pending, err := runner.beginCredentialExecution(
		t.Context(),
		func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewRuntimeCredentialExecution(credentialProviderRuntimeRequest(), now)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	receipt := domainpki.CredentialDeliveryReceipt{
		RequestID: pending.ID, ProviderReference: "provider-receipt-1",
		ReceiptSHA256: strings.Repeat("a", sha256.Size*2),
	}
	if err := runner.finishCredentialDeliveryExecution(
		canceled, pending, receipt, nil, credentialRuntimeFailureReason,
	); err != nil {
		t.Fatal(err)
	}
	if len(recorder.contextErrors) != 2 || recorder.contextErrors[1] != nil {
		t.Fatalf("credential execution recorder contexts = %#v", recorder.contextErrors)
	}
}

func TestRunnerDoesNotInvokeProviderWhenCredentialPlanCannotPersist(t *testing.T) {
	recorder := &recordingCredentialExecutionRecorder{
		planErr: errors.New("credential ledger unavailable"),
	}
	_, err := (Runner{
		ConfigPath: filepath.Join(t.TempDir(), "missing-module-config.json"),
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}).LoadRuntimeCredential(t.Context(), "credential-provider", credentialProviderRuntimeRequest())
	if err == nil || !strings.Contains(err.Error(), "record credential execution plan") ||
		!strings.Contains(err.Error(), "credential ledger unavailable") {
		t.Fatalf("LoadRuntimeCredential() error = %v", err)
	}
	if strings.Contains(err.Error(), "module config") || len(recorder.executions) != 0 {
		t.Fatalf("provider was reached after plan failure: error=%v executions=%#v", err, recorder.executions)
	}
}

func TestRunnerReplaysCompletedCredentialDeliveryWithoutProviderInvocation(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	recorder := &recordingCredentialExecutionRecorder{}
	runner := Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}
	request := credentialProviderRuntimeRequest()
	request.Provider = credentialProviderExactTestTarget(t)
	first, err := runner.LoadRuntimeCredential(
		t.Context(), credentialProviderExactModuleID, request,
	)
	if err != nil {
		t.Fatal(err)
	}

	runner.ConfigPath = filepath.Join(t.TempDir(), "missing-module-config.json")
	replayed, err := runner.LoadRuntimeCredential(
		t.Context(), credentialProviderExactModuleID, request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.RequestID != first.RequestID || replayed.ReceiptSHA256 != first.ReceiptSHA256 {
		t.Fatalf("credential delivery replay = %#v, want durable projection of %#v", replayed, first)
	}
	if replayed.ProviderReference != "" {
		t.Fatalf("credential delivery replay exposed unavailable provider reference: %#v", replayed)
	}
	if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 1 {
		t.Fatalf("credential provider invocations = %d, want 1", invocations)
	}
}

func TestRunnerInvokesCredentialProviderAtMostOnceAcrossConcurrentRetries(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	recorder := &recordingCredentialExecutionRecorder{}
	runner := Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}
	request := credentialProviderRuntimeRequest()
	request.Provider = credentialProviderExactTestTarget(t)

	const retryCount = 16
	start := make(chan struct{})
	results := make(chan error, retryCount)
	var retries sync.WaitGroup
	for range retryCount {
		retries.Add(1)
		go func() {
			defer retries.Done()
			<-start
			_, err := runner.LoadRuntimeCredential(
				context.Background(), credentialProviderExactModuleID, request,
			)
			results <- err
		}()
	}
	close(start)
	retries.Wait()
	close(results)

	var completed int
	for err := range results {
		if err == nil {
			completed++
			continue
		}
		if !errors.Is(err, apppki.ErrCredentialExecutionInProgress) {
			t.Fatalf("concurrent credential retry error = %v", err)
		}
	}
	if completed == 0 {
		t.Fatal("no credential retry completed")
	}
	if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 1 {
		t.Fatalf("credential provider invocations = %d, want 1", invocations)
	}
}

func TestRunnerRejectsPendingCredentialRetryWithoutProviderInvocation(t *testing.T) {
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	recorder := &recordingCredentialExecutionRecorder{}
	runner := Runner{
		ConfigPath: filepath.Join(t.TempDir(), "missing-module-config.json"),
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}
	request := credentialProviderRuntimeRequest()
	if _, err := runner.beginCredentialExecution(
		t.Context(),
		func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewRuntimeCredentialExecution(request, now)
		},
	); err != nil {
		t.Fatal(err)
	}

	_, err := runner.LoadRuntimeCredential(t.Context(), "credential-provider", request)
	if !errors.Is(err, apppki.ErrCredentialExecutionInProgress) {
		t.Fatalf("LoadRuntimeCredential() error = %v, want in progress", err)
	}
	if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 0 {
		t.Fatalf("credential provider invocations = %d, want 0", invocations)
	}
}

func TestRunnerConflictsChangedCredentialRetryBeforeProviderInvocation(t *testing.T) {
	recorder := &recordingCredentialExecutionRecorder{}
	runner := Runner{
		ConfigPath: filepath.Join(t.TempDir(), "missing-module-config.json"),
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}
	request := credentialProviderRuntimeRequest()
	if _, err := runner.beginCredentialExecution(
		t.Context(),
		func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewRuntimeCredentialExecution(request, now)
		},
	); err != nil {
		t.Fatal(err)
	}
	request.Scope.NodeID = "different-node"

	_, err := runner.LoadRuntimeCredential(t.Context(), "credential-provider", request)
	if !errors.Is(err, apppki.ErrIdempotencyConflict) {
		t.Fatalf("LoadRuntimeCredential() error = %v, want idempotency conflict", err)
	}
}

func TestRunnerPreflightsCredentialOperationBeforeProviderLaunch(t *testing.T) {
	recorder := &recordingCredentialExecutionRecorder{}
	runner := Runner{
		ConfigPath: filepath.Join(t.TempDir(), "missing-module-config.json"),
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}
	request := credentialProviderRuntimeRequest()
	if _, err := runner.beginCredentialExecution(
		t.Context(),
		func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewRuntimeCredentialExecution(request, now)
		},
	); err != nil {
		t.Fatal(err)
	}
	deliveries := domainpki.CredentialOperationDeliveries{{
		Capability: domainpki.DeliveryCapabilityRuntime,
		Runtime:    &request,
	}}
	resolution := credentialProviderResolution(t, deliveries)

	_, err := runner.RunMeshTaskWithCredentials(
		t.Context(), "credential-provider", resolution,
		mesh.TaskRequest{TaskID: "task-preflight", Kind: mesh.TaskSurvey},
	)
	if !errors.Is(err, apppki.ErrCredentialExecutionInProgress) {
		t.Fatalf("RunMeshTaskWithCredentials() error = %v, want in progress", err)
	}
	if strings.Contains(err.Error(), "module config") {
		t.Fatalf("provider launched before credential preflight: %v", err)
	}
}

func TestRunnerRevalidatesCredentialResolutionAfterLiveProviderDiscovery(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	methodLog := filepath.Join(t.TempDir(), "provider-methods")
	t.Setenv(credentialProviderMethodLogEnv, methodLog)
	deliveries := credentialProviderOperationDeliveries(t)
	lease := &credentialProviderResolutionLease{deliveries: deliveries}
	var methodsAtRevalidation [][]string
	lease.revalidate = func(
		_ context.Context,
		_ domainpki.CredentialOperationDeliveries,
	) error {
		data, err := os.ReadFile(methodLog)
		if err != nil {
			return fmt.Errorf("read provider method log during revalidation: %w", err)
		}
		methodsAtRevalidation = append(
			methodsAtRevalidation,
			strings.Fields(string(data)),
		)
		return nil
	}

	_, err := (Runner{
		ConfigPath:           credentialProviderConfig(t),
		Timeout:              2 * time.Second,
		Clock:                credentialProviderTestClock(),
		CredentialExecutions: &recordingCredentialExecutionRecorder{},
	}).RunMeshTaskWithCredentials(
		t.Context(),
		credentialProviderExactModuleID,
		credentialProviderResolutionForLease(t, lease),
		mesh.TaskRequest{TaskID: "task-revalidate-order", Kind: mesh.TaskSurvey},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantDiscovery := []string{
		"handshake",
		credentialRPCDescribeMethod,
		meshRPCDescribeMethod,
	}
	wantAtRevalidation := [][]string{
		wantDiscovery,
		append(
			append([]string(nil), wantDiscovery...),
			credentialRPCRuntimeMethod,
		),
	}
	if !reflect.DeepEqual(methodsAtRevalidation, wantAtRevalidation) {
		t.Fatalf(
			"provider methods at credential revalidation = %#v, want %#v",
			methodsAtRevalidation,
			wantAtRevalidation,
		)
	}
	wantDeliveryPrefix := append(
		append([]string(nil), wantDiscovery...),
		credentialRPCRuntimeMethod,
		credentialRPCFilesMethod,
	)
	methods := credentialProviderMethodLog(t, methodLog)
	if len(methods) < len(wantDeliveryPrefix) ||
		!reflect.DeepEqual(methods[:len(wantDeliveryPrefix)], wantDeliveryPrefix) {
		t.Fatalf("provider method order = %#v, want prefix %#v", methods, wantDeliveryPrefix)
	}
	lease.mu.Lock()
	borrowCount := lease.borrowCount
	revalidateCalls := lease.revalidateCall
	resolutionCalls := append([]string(nil), lease.calls...)
	lease.mu.Unlock()
	if borrowCount != 3 || revalidateCalls != 2 {
		t.Fatalf(
			"credential resolution lifecycle: borrows=%d revalidations=%d, want 3 and 2",
			borrowCount,
			revalidateCalls,
		)
	}
	wantResolutionCalls := []string{
		"borrow",
		"revalidate",
		"borrow",
		"revalidate",
		"borrow",
	}
	if !reflect.DeepEqual(resolutionCalls, wantResolutionCalls) {
		t.Fatalf(
			"credential resolution call order = %#v, want %#v",
			resolutionCalls,
			wantResolutionCalls,
		)
	}
}

func TestRunnerAbortsCredentialOperationWhenResolutionRevalidationFails(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	methodLog := filepath.Join(t.TempDir(), "provider-methods")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	t.Setenv(credentialProviderMethodLogEnv, methodLog)
	deliveries := credentialProviderOperationDeliveries(t)
	revalidationErr := errors.New("credential assignment changed during provider startup")
	lease := &credentialProviderResolutionLease{
		deliveries: deliveries,
		revalidate: func(
			context.Context,
			domainpki.CredentialOperationDeliveries,
		) error {
			return revalidationErr
		},
	}
	recorder := &recordingCredentialExecutionRecorder{}

	_, err := (Runner{
		ConfigPath:           credentialProviderConfig(t),
		Timeout:              2 * time.Second,
		Clock:                credentialProviderTestClock(),
		CredentialExecutions: recorder,
	}).RunMeshTaskWithCredentials(
		t.Context(),
		credentialProviderExactModuleID,
		credentialProviderResolutionForLease(t, lease),
		mesh.TaskRequest{TaskID: "task-revalidation-failure", Kind: mesh.TaskSurvey},
	)
	if !errors.Is(err, revalidationErr) {
		t.Fatalf("RunMeshTaskWithCredentials() error = %v, want revalidation failure", err)
	}
	assertCredentialOperationAborted(t, recorder, len(deliveries))
	assertNoCredentialProviderDelivery(t, invocationLog, methodLog)
	lease.mu.Lock()
	borrowCount := lease.borrowCount
	revalidateCalls := lease.revalidateCall
	lease.mu.Unlock()
	if borrowCount != 1 || revalidateCalls != 1 {
		t.Fatalf(
			"failed credential resolution lifecycle: borrows=%d revalidations=%d, want 1 and 1",
			borrowCount,
			revalidateCalls,
		)
	}
}

func TestRunnerAbortsBeforeSecondDeliveryWhenResolutionRevalidationFails(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	methodLog := filepath.Join(t.TempDir(), "provider-methods")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	t.Setenv(credentialProviderMethodLogEnv, methodLog)
	deliveries := credentialProviderOperationDeliveries(t)
	revalidationErr := errors.New("credential assignment revoked after first delivery")
	lease := &credentialProviderResolutionLease{
		deliveries:        deliveries,
		revalidateErrorAt: 2,
		revalidateError:   revalidationErr,
	}
	recorder := &recordingCredentialExecutionRecorder{}

	execution, err := (Runner{
		ConfigPath:           credentialProviderConfig(t),
		Timeout:              2 * time.Second,
		Clock:                credentialProviderTestClock(),
		CredentialExecutions: recorder,
	}).RunMeshTaskWithCredentials(
		t.Context(),
		credentialProviderExactModuleID,
		credentialProviderResolutionForLease(t, lease),
		mesh.TaskRequest{TaskID: "task-second-revalidation-failure", Kind: mesh.TaskSurvey},
	)
	if !errors.Is(err, revalidationErr) {
		t.Fatalf("RunMeshTaskWithCredentials() error = %v, want second revalidation failure", err)
	}
	if len(execution.CredentialReceipts) != 1 {
		t.Fatalf("credential receipts = %#v, want first delivery only", execution.CredentialReceipts)
	}
	assertCredentialOperationDeliveredFirstThenAborted(t, recorder)
	assertOnlyFirstCredentialProviderDelivery(t, invocationLog, methodLog)
	lease.mu.Lock()
	borrowCount := lease.borrowCount
	revalidateCalls := lease.revalidateCall
	resolutionCalls := append([]string(nil), lease.calls...)
	lease.mu.Unlock()
	if borrowCount != 2 || revalidateCalls != 2 {
		t.Fatalf(
			"failed credential resolution lifecycle: borrows=%d revalidations=%d, want 2 and 2",
			borrowCount,
			revalidateCalls,
		)
	}
	wantResolutionCalls := []string{
		"borrow",
		"revalidate",
		"borrow",
		"revalidate",
	}
	if !reflect.DeepEqual(resolutionCalls, wantResolutionCalls) {
		t.Fatalf(
			"failed credential resolution call order = %#v, want %#v",
			resolutionCalls,
			wantResolutionCalls,
		)
	}
}

func TestRunnerAbortsCredentialOperationWhenSecondDeliveryBorrowFails(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	methodLog := filepath.Join(t.TempDir(), "provider-methods")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	t.Setenv(credentialProviderMethodLogEnv, methodLog)
	deliveries := credentialProviderOperationDeliveries(t)
	borrowErr := errors.New("credential deliveries changed after revalidation")
	lease := &credentialProviderResolutionLease{
		deliveries:    deliveries,
		borrowErrorAt: 3,
		borrowError:   borrowErr,
	}
	recorder := &recordingCredentialExecutionRecorder{}

	execution, err := (Runner{
		ConfigPath:           credentialProviderConfig(t),
		Timeout:              2 * time.Second,
		Clock:                credentialProviderTestClock(),
		CredentialExecutions: recorder,
	}).RunMeshTaskWithCredentials(
		t.Context(),
		credentialProviderExactModuleID,
		credentialProviderResolutionForLease(t, lease),
		mesh.TaskRequest{TaskID: "task-second-borrow-failure", Kind: mesh.TaskSurvey},
	)
	if !errors.Is(err, borrowErr) {
		t.Fatalf("RunMeshTaskWithCredentials() error = %v, want second borrow failure", err)
	}
	if len(execution.CredentialReceipts) != 1 {
		t.Fatalf("credential receipts = %#v, want first delivery only", execution.CredentialReceipts)
	}
	assertCredentialOperationDeliveredFirstThenAborted(t, recorder)
	assertOnlyFirstCredentialProviderDelivery(t, invocationLog, methodLog)
	lease.mu.Lock()
	borrowCount := lease.borrowCount
	revalidateCalls := lease.revalidateCall
	resolutionCalls := append([]string(nil), lease.calls...)
	lease.mu.Unlock()
	if borrowCount != 3 || revalidateCalls != 2 {
		t.Fatalf(
			"failed credential resolution lifecycle: borrows=%d revalidations=%d, want 3 and 2",
			borrowCount,
			revalidateCalls,
		)
	}
	wantResolutionCalls := []string{
		"borrow",
		"revalidate",
		"borrow",
		"revalidate",
		"borrow",
	}
	if !reflect.DeepEqual(resolutionCalls, wantResolutionCalls) {
		t.Fatalf(
			"failed credential resolution call order = %#v, want %#v",
			resolutionCalls,
			wantResolutionCalls,
		)
	}
}

func TestRunnerRejectsClosedCredentialResolutionBeforeProviderLaunch(t *testing.T) {
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	deliveries := credentialProviderOperationDeliveries(t)
	resolution := credentialProviderResolution(t, deliveries)
	resolution.Close()
	recorder := &recordingCredentialExecutionRecorder{}

	_, err := (Runner{
		ConfigPath:           filepath.Join(t.TempDir(), "missing-module-config.json"),
		CredentialExecutions: recorder,
	}).RunMeshTaskWithCredentials(
		t.Context(),
		credentialProviderExactModuleID,
		resolution,
		mesh.TaskRequest{TaskID: "task-closed-resolution", Kind: mesh.TaskSurvey},
	)
	if !errors.Is(err, services.ErrCredentialOperationResolutionClosed) {
		t.Fatalf("RunMeshTaskWithCredentials() error = %v, want closed resolution", err)
	}
	if len(recorder.executions) != 0 {
		t.Fatalf("closed resolution persisted executions: %#v", recorder.executions)
	}
	if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 0 {
		t.Fatalf("credential provider invocations = %d, want 0", invocations)
	}
}

func TestRunnerCredentialOperationsRequireResolution(t *testing.T) {
	runner := Runner{}
	tests := []struct {
		name   string
		invoke func() error
	}{
		{
			name: "listener",
			invoke: func() error {
				_, err := runner.StartMeshListenerWithCredentials(
					t.Context(),
					credentialProviderExactModuleID,
					nil,
					mesh.ListenerStartRequest{ListenerID: "listener-resolution-required"},
				)
				return err
			},
		},
		{
			name: "task",
			invoke: func() error {
				_, err := runner.RunMeshTaskWithCredentials(
					t.Context(),
					credentialProviderExactModuleID,
					nil,
					mesh.TaskRequest{TaskID: "task-resolution-required", Kind: mesh.TaskSurvey},
				)
				return err
			},
		},
		{
			name: "stream",
			invoke: func() error {
				_, err := runner.OpenMeshStreamWithCredentials(
					t.Context(),
					credentialProviderExactModuleID,
					nil,
					mesh.StreamRequest{RunID: "stream-resolution-required", NodeID: "node-1"},
				)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.invoke(); !errors.Is(err, errCredentialOperationResolutionRequired) {
				t.Fatalf("credential operation error = %v, want resolution required", err)
			}
		})
	}
}

func TestRunnerRejectsCredentialOperationProviderDriftBeforeInvocation(t *testing.T) {
	tests := []struct {
		name           string
		moduleID       string
		handshakeMode  string
		descriptorMode string
		prependExact   bool
		mutateTarget   func(*domainpki.CredentialProviderTarget)
	}{
		{
			name:     "module mismatch",
			moduleID: "credential-provider-alias",
			mutateTarget: func(target *domainpki.CredentialProviderTarget) {
				target.ModuleID = "credential-provider-alias"
			},
		},
		{
			name:     "version mismatch",
			moduleID: credentialProviderExactModuleID,
			mutateTarget: func(target *domainpki.CredentialProviderTarget) {
				target.ProviderVersion = "v9.9.9-drifted"
			},
		},
		{
			name:           "descriptor mismatch",
			moduleID:       credentialProviderExactModuleID,
			descriptorMode: "changed",
		},
		{
			name:           "nested descriptor mismatch",
			moduleID:       credentialProviderExactModuleID,
			descriptorMode: "nested-mismatch",
		},
		{
			name:         "provider mismatch after exact delivery",
			moduleID:     credentialProviderExactModuleID,
			prependExact: true,
			mutateTarget: func(target *domainpki.CredentialProviderTarget) {
				target.ProviderID = "other-provider"
			},
		},
		{
			name:          "missing handshake identity",
			moduleID:      credentialProviderExactModuleID,
			handshakeMode: "missing",
		},
		{
			name:           "missing descriptor",
			moduleID:       credentialProviderExactModuleID,
			descriptorMode: "missing",
		},
		{
			name:           "malformed descriptor",
			moduleID:       credentialProviderExactModuleID,
			descriptorMode: "malformed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(credentialProviderChildEnv, "1")
			t.Setenv(credentialProviderHandshakeModeEnv, test.handshakeMode)
			t.Setenv(credentialProviderDescriptorModeEnv, test.descriptorMode)
			invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
			t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
			target := credentialProviderExactTestTarget(t)
			if test.mutateTarget != nil {
				test.mutateTarget(&target)
			}
			request := credentialProviderRuntimeRequest()
			request.Provider = target
			request.RequestID = "runtime-drift"
			request.SlotName = "tls-client"
			deliveries := domainpki.CredentialOperationDeliveries{}
			if test.prependExact {
				exact := credentialProviderRuntimeRequest()
				exact.Provider = credentialProviderExactTestTarget(t)
				deliveries = append(deliveries, domainpki.CredentialOperationDelivery{
					Capability: domainpki.DeliveryCapabilityRuntime,
					Runtime:    &exact,
				})
			}
			deliveries = append(deliveries, domainpki.CredentialOperationDelivery{
				Capability: domainpki.DeliveryCapabilityRuntime,
				Runtime:    &request,
			})
			recorder := &recordingCredentialExecutionRecorder{}
			_, err := (Runner{
				ConfigPath: credentialProviderConfigForModule(t, test.moduleID),
				Timeout:    2 * time.Second,
				Clock: credentialRecorderClock{
					now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
				},
				CredentialExecutions: recorder,
			}).RunMeshTaskWithCredentials(
				t.Context(),
				test.moduleID,
				credentialProviderResolution(t, deliveries),
				mesh.TaskRequest{TaskID: "task-drift", Kind: mesh.TaskSurvey},
			)
			if err == nil {
				t.Fatal("RunMeshTaskWithCredentials() unexpectedly succeeded")
			}
			if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 0 {
				t.Fatalf("credential provider invocations = %d, want 0", invocations)
			}
			if len(recorder.executions) != 2*len(deliveries) {
				t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
			}
			for index := range deliveries {
				if recorder.executions[index].Status != domainpki.CredentialExecutionPending ||
					recorder.executions[len(deliveries)+index].Status != domainpki.CredentialExecutionFailed ||
					recorder.executions[len(deliveries)+index].Failure != credentialOperationAbortReason {
					t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
				}
			}
		})
	}
}

func TestRunnerSkipsCredentialDiscoveryWithoutOperationDeliveries(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	t.Setenv(credentialProviderHandshakeModeEnv, "missing")
	t.Setenv(credentialProviderDescriptorModeEnv, "malformed")
	execution, err := (Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
	}).RunMeshTask(
		t.Context(), credentialProviderExactModuleID,
		mesh.TaskRequest{TaskID: "task-without-credentials", Kind: mesh.TaskSurvey},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := execution.Outputs["credentialDeliveryCount"]; got != float64(0) {
		t.Fatalf("credential delivery count = %#v, want 0", got)
	}
}

func TestRunnerSequencesCredentialsInMeshOperationProcess(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	deliveries := credentialProviderOperationDeliveries(t)
	recorder := &recordingCredentialExecutionRecorder{}
	execution, err := (Runner{
		ConfigPath: credentialProviderConfig(t),
		Timeout:    2 * time.Second,
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}).RunMeshTaskWithCredentials(
		t.Context(),
		credentialProviderExactModuleID,
		credentialProviderResolution(t, deliveries),
		mesh.TaskRequest{TaskID: "task-1", Kind: mesh.TaskSurvey},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(execution.CredentialReceipts) != len(deliveries) {
		t.Fatalf("credential receipts = %#v", execution.CredentialReceipts)
	}
	if got := execution.Result.Outputs["credentialDeliveryCount"]; got != float64(len(deliveries)) {
		t.Fatalf("same-process credential delivery count = %#v, want %d", got, len(deliveries))
	}
	if len(recorder.executions) != 2*len(deliveries) {
		t.Fatalf("same-process credential execution ledger = %#v", recorder.executions)
	}
	for index := range deliveries {
		planned := recorder.executions[index]
		completed := recorder.executions[len(deliveries)+index]
		if planned.ID != deliveries[index].RequestID() ||
			planned.Status != domainpki.CredentialExecutionPending ||
			completed.ID != planned.ID ||
			completed.Status != domainpki.CredentialExecutionSucceeded {
			t.Fatalf("delivery %d credential execution lifecycle = %#v, %#v", index, planned, completed)
		}
	}
}

func TestRunnerSanitizesCredentialBearingProviderDiagnostics(t *testing.T) {
	const sentinelPKCS8 = "HOVEL_SENTINEL_PKCS8_PRIVATE_KEY_BYTES"

	tests := []struct {
		name           string
		failureSurface string
		wantSummary    string
		wantPrefix     string
	}{
		{
			name:           "standalone delivery",
			failureSurface: "delivery",
			wantSummary:    "module failed during credential provider call",
			wantPrefix:     "module credential provider call failed",
		},
		{
			name:           "operation delivery",
			failureSurface: "delivery",
			wantSummary:    "module failed while loading operation credentials",
			wantPrefix:     "module credential operation delivery failed",
		},
		{
			name:           "task",
			failureSurface: "task",
			wantSummary:    "module failed during mesh task",
			wantPrefix:     "module mesh task failed",
		},
		{
			name:           "stream",
			failureSurface: "stream",
			wantSummary:    "module failed while opening mesh stream",
			wantPrefix:     "module mesh stream failed",
		},
		{
			name:           "shutdown",
			failureSurface: "shutdown",
			wantSummary:    "module exited with error",
			wantPrefix:     "module exited with error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(credentialProviderChildEnv, "1")
			t.Setenv(credentialProviderFailureSurfaceEnv, test.failureSurface)
			deliveries := credentialProviderDiagnosticDeliveries(t, sentinelPKCS8)
			runner := credentialProviderRecordedRunner(t)
			resolution := credentialProviderResolution(t, deliveries)

			var logs strings.Builder
			previousLogOutput := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(previousLogOutput)

			var err error
			switch test.name {
			case "standalone delivery":
				_, err = runner.LoadRuntimeCredential(
					t.Context(), credentialProviderExactModuleID, *deliveries[0].Runtime,
				)
			case "stream":
				_, err = runner.OpenMeshStreamWithCredentials(
					t.Context(), credentialProviderExactModuleID, resolution,
					mesh.StreamRequest{RunID: "diagnostic-stream", NodeID: "node-1"},
				)
			default:
				_, err = runner.RunMeshTaskWithCredentials(
					t.Context(), credentialProviderExactModuleID, resolution,
					mesh.TaskRequest{TaskID: "diagnostic-" + test.failureSurface, Kind: mesh.TaskSurvey},
				)
			}
			if err == nil {
				t.Fatal("credential-bearing provider failure unexpectedly succeeded")
			}
			diagnostics := err.Error() + "\n" + logs.String()
			for _, leaked := range []string{
				sentinelPKCS8,
				"provider-controlled JSON-RPC diagnostic",
				"provider-controlled stderr diagnostic",
			} {
				if strings.Contains(diagnostics, leaked) {
					t.Fatalf("credential-bearing diagnostics leaked %q: %s", leaked, diagnostics)
				}
			}
			for _, safeDiagnostic := range []string{test.wantSummary, test.wantPrefix} {
				if !strings.Contains(err.Error(), safeDiagnostic) {
					t.Fatalf("credential-bearing error omitted safe diagnostic %q: %v", safeDiagnostic, err)
				}
			}
			if !strings.Contains(diagnostics, errCredentialProviderDiagnosticsSuppressed.Error()) {
				t.Fatalf("credential-bearing error omitted diagnostic suppression marker: %s", diagnostics)
			}
		})
	}
}

func TestRunnerSanitizesCredentialBearingMalformedResults(t *testing.T) {
	const sentinelPKCS8 = "HOVEL_SENTINEL_PKCS8_PRIVATE_KEY_BYTES"

	for _, surface := range []string{
		"delivery",
		"encoding",
		"stamp",
		"listener",
		"task",
		"stream",
	} {
		t.Run(surface, func(t *testing.T) {
			t.Setenv(credentialProviderChildEnv, "1")
			t.Setenv(credentialProviderFailureSurfaceEnv, "malformed-"+surface)
			runner := credentialProviderRecordedRunner(t)

			var result any
			var err error
			switch surface {
			case "delivery":
				request := credentialProviderRuntimeRequest()
				request.Provider = credentialProviderExactTestTarget(t)
				request.Material.Data = domainpki.CredentialBytes(sentinelPKCS8)
				request.Material.SHA256 = credentialProviderTestSHA256(request.Material.Data)
				result, err = runner.LoadRuntimeCredential(
					t.Context(), credentialProviderExactModuleID, request,
				)
			case "encoding":
				material := credentialProviderTestMaterial()
				material.Data = domainpki.CredentialBytes(sentinelPKCS8)
				material.SHA256 = credentialProviderTestSHA256(material.Data)
				result, err = runner.EncodeCredentialMaterial(
					t.Context(), credentialProviderExactModuleID,
					domainpki.CredentialEncodingRequest{
						SchemaVersion:       domainpki.CredentialProviderExecutionSchemaV1,
						Provider:            credentialProviderExactTestTarget(t),
						RequestID:           "malformed-encoding",
						ProviderID:          "credential-provider",
						ProviderSchema:      "mbedtls-v1",
						OutputForm:          domainpki.CredentialMaterialPrivateBytes,
						MaximumEncodedBytes: 1024,
						Source:              material,
					},
				)
			case "stamp":
				material := credentialProviderTestMaterial()
				material.Data = domainpki.CredentialBytes(sentinelPKCS8)
				material.SHA256 = credentialProviderTestSHA256(material.Data)
				request := credentialProviderTestStampRequest(
					t, credentialProviderTestMetadata(), material,
				)
				request.Provider = credentialProviderExactTestTarget(t)
				request.Request.EncodedBytes = uint64(len(material.Data))
				result, err = runner.StampCredential(
					t.Context(), credentialProviderExactModuleID, request,
				)
			default:
				deliveries := credentialProviderDiagnosticDeliveries(t, sentinelPKCS8)
				resolution := credentialProviderResolution(t, deliveries)
				switch surface {
				case "listener":
					result, err = runner.StartMeshListenerWithCredentials(
						t.Context(), credentialProviderExactModuleID, resolution,
						mesh.ListenerStartRequest{ListenerID: "malformed-listener"},
					)
				case "task":
					result, err = runner.RunMeshTaskWithCredentials(
						t.Context(), credentialProviderExactModuleID, resolution,
						mesh.TaskRequest{TaskID: "malformed-task", Kind: mesh.TaskSurvey},
					)
				case "stream":
					result, err = runner.OpenMeshStreamWithCredentials(
						t.Context(), credentialProviderExactModuleID, resolution,
						mesh.StreamRequest{RunID: "malformed-stream", NodeID: "node-1"},
					)
				}
			}

			if err == nil {
				t.Fatal("credential-bearing malformed result unexpectedly succeeded")
			}
			encodedResult, marshalErr := json.Marshal(result)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			diagnostics := err.Error() + "\n" + string(encodedResult)
			if strings.Contains(diagnostics, sentinelPKCS8) {
				t.Fatalf("credential-bearing malformed result leaked secret: %s", diagnostics)
			}
			if !strings.Contains(diagnostics, errCredentialProviderDiagnosticsSuppressed.Error()) {
				t.Fatalf("malformed result omitted diagnostic suppression marker: %s", diagnostics)
			}
		})
	}
}

func TestRunnerDiscoversStandaloneCredentialProvider(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	module, err := (Runner{
		ConfigPath: credentialProviderConfig(t),
		Timeout:    2 * time.Second,
	}).Inspect(t.Context(), "credential-provider")
	if err != nil {
		t.Fatal(err)
	}
	if module.CredentialDelivery == nil {
		t.Fatal("standalone credential delivery descriptor was not discovered")
	}
	if module.CredentialDelivery.SchemaVersion != domainpki.CredentialDeliverySchemaV1 {
		t.Fatalf("credential delivery descriptor = %#v", module.CredentialDelivery)
	}
	if module.Mesh.Name != "" || module.Mesh.CredentialDelivery != nil {
		t.Fatalf("provider-only module unexpectedly advertised Mesh: %#v", module.Mesh)
	}
}

func TestReconcileCredentialDeliveryDescriptorsRejectsMismatch(t *testing.T) {
	standalone := credentialProviderFixtureDescriptor()
	nested := standalone.Clone()
	nested.Capabilities = []domainpki.DeliveryCapability{domainpki.DeliveryCapabilityFiles}
	module := modulecatalog.Module{
		CredentialDelivery: &standalone,
		Mesh:               mesh.Descriptor{CredentialDelivery: &nested},
	}
	if err := reconcileCredentialDeliveryDescriptors(&module); err == nil ||
		!strings.Contains(err.Error(), "do not match") {
		t.Fatalf("reconcile credential descriptors error = %v", err)
	}
}

func TestReconcileCredentialDeliveryDescriptorsPromotesMeshOnlyContract(t *testing.T) {
	nested := credentialProviderFixtureDescriptor()
	module := modulecatalog.Module{Mesh: mesh.Descriptor{CredentialDelivery: &nested}}
	if err := reconcileCredentialDeliveryDescriptors(&module); err != nil {
		t.Fatal(err)
	}
	if module.CredentialDelivery == nil {
		t.Fatal("mesh credential delivery descriptor was not promoted")
	}
	module.CredentialDelivery.Capabilities[0] = domainpki.DeliveryCapabilityFiles
	if nested.Capabilities[0] != domainpki.DeliveryCapabilityRuntime {
		t.Fatal("promoted credential delivery aliases the mesh descriptor")
	}
}

func TestReconcileCredentialDeliveryDescriptorsAcceptsExactMatch(t *testing.T) {
	standalone := credentialProviderFixtureDescriptor()
	nested := standalone.Clone()
	module := modulecatalog.Module{
		CredentialDelivery: &standalone,
		Mesh:               mesh.Descriptor{CredentialDelivery: &nested},
	}
	if err := reconcileCredentialDeliveryDescriptors(&module); err != nil {
		t.Fatal(err)
	}
	if module.Mesh.CredentialDelivery == nil || module.CredentialDelivery == nil {
		t.Fatal("matching credential delivery descriptors were lost")
	}
	module.Mesh.CredentialDelivery.Capabilities[0] = domainpki.DeliveryCapabilityFiles
	if module.CredentialDelivery.Capabilities[0] != domainpki.DeliveryCapabilityRuntime {
		t.Fatal("matching credential delivery descriptors alias after reconciliation")
	}
}

func TestCredentialDeliveryDescriptorFromRPCRejectsMalformedContract(t *testing.T) {
	_, err := credentialDeliveryDescriptorFromRPC(map[string]any{
		"schemaVersion":        "unsupported",
		"deliveryCapabilities": []any{"runtime"},
	})
	if err == nil || !strings.Contains(err.Error(), "descriptor is invalid") {
		t.Fatalf("credential descriptor decode error = %v", err)
	}
}

func TestMissingCredentialDescriberErrorsAreRecognized(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{name: "unknown method", message: `unknown method "credential.describe"`},
		{name: "not a provider", message: `module "survey" is not a credential provider`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !isMissingCredentialDescriber(errors.New(test.message)) {
				t.Fatalf("missing credential describer error was not recognized: %q", test.message)
			}
		})
	}
	if isMissingCredentialDescriber(errors.New("credential.describe failed")) {
		t.Fatal("provider failure was mistaken for optional absence")
	}
}

func TestRunnerRejectsMismatchedCredentialProviderReceipt(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	t.Setenv(credentialProviderMismatchEnv, "1")
	request := credentialProviderRuntimeRequest()
	request.Provider = credentialProviderExactTestTarget(t)
	_, err := credentialProviderRecordedRunner(t).LoadRuntimeCredential(
		t.Context(), credentialProviderExactModuleID, request,
	)
	if err == nil || !strings.Contains(err.Error(), "mismatched credential delivery receipt") {
		t.Fatalf("LoadRuntimeCredential() error = %v", err)
	}
}

func TestRunnerRejectsInvalidCredentialProviderDigest(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	t.Setenv(credentialProviderBadDigestEnv, "1")
	request := domainpki.CredentialEncodingRequest{
		SchemaVersion:       domainpki.CredentialProviderExecutionSchemaV1,
		Provider:            credentialProviderExactTestTarget(t),
		RequestID:           "encoding-1",
		ProviderID:          "credential-provider",
		ProviderSchema:      "mbedtls-v1",
		OutputForm:          domainpki.CredentialMaterialPrivateBytes,
		MaximumEncodedBytes: 1024,
		Source:              credentialProviderTestMaterial(),
	}
	_, err := credentialProviderRecordedRunner(t).EncodeCredentialMaterial(
		t.Context(), credentialProviderExactModuleID, request,
	)
	if err == nil || !strings.Contains(err.Error(), "invalid credential encoding result") {
		t.Fatalf("EncodeCredentialMaterial() error = %v", err)
	}
}

func TestRunnerRejectsInvalidCredentialRequestBeforeLaunch(t *testing.T) {
	request := credentialProviderRuntimeRequest()
	request.SchemaVersion = "unsupported"
	_, err := (Runner{ConfigPath: filepath.Join(t.TempDir(), "missing.json")}).LoadRuntimeCredential(
		context.Background(), "credential-provider", request,
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported schema version") {
		t.Fatalf("LoadRuntimeCredential() error = %v", err)
	}
}

func TestRunnerRejectsCredentialProviderModuleMismatchBeforeLaunch(t *testing.T) {
	request := credentialProviderRuntimeRequest()
	_, err := (Runner{ConfigPath: filepath.Join(t.TempDir(), "missing.json")}).LoadRuntimeCredential(
		t.Context(), "other-provider", request,
	)
	if err == nil || !strings.Contains(err.Error(), "does not match descriptor-bound module") {
		t.Fatalf("LoadRuntimeCredential() error = %v", err)
	}
}

func TestRunnerRequiresCredentialExecutionRecorderBeforeProviderLaunch(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
	t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
	target := credentialProviderExactTestTarget(t)
	runner := Runner{
		ConfigPath: filepath.Join(t.TempDir(), "missing-module-config.json"),
		Timeout:    2 * time.Second,
	}

	tests := []struct {
		name   string
		invoke func() error
	}{
		{
			name: "runtime",
			invoke: func() error {
				request := credentialProviderRuntimeRequest()
				request.Provider = target
				_, err := runner.LoadRuntimeCredential(
					t.Context(), credentialProviderExactModuleID, request,
				)
				return err
			},
		},
		{
			name: "files",
			invoke: func() error {
				_, err := runner.LoadCredentialFiles(
					t.Context(),
					credentialProviderExactModuleID,
					credentialProviderFilesRequest(target),
				)
				return err
			},
		},
		{
			name: "encoding",
			invoke: func() error {
				_, err := runner.EncodeCredentialMaterial(
					t.Context(),
					credentialProviderExactModuleID,
					credentialProviderEncodingRequest(target),
				)
				return err
			},
		},
		{
			name: "mesh operation delivery",
			invoke: func() error {
				request := credentialProviderRuntimeRequest()
				request.Provider = target
				_, err := runner.RunMeshTaskWithCredentials(
					t.Context(),
					credentialProviderExactModuleID,
					credentialProviderResolution(t, domainpki.CredentialOperationDeliveries{{
						Capability: domainpki.DeliveryCapabilityRuntime,
						Runtime:    &request,
					}}),
					mesh.TaskRequest{TaskID: "missing-recorder", Kind: mesh.TaskSurvey},
				)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.invoke()
			if !errors.Is(err, errCredentialExecutionRecorderRequired) {
				t.Fatalf("credential provider call error = %v, want recorder required", err)
			}
			if strings.Contains(err.Error(), "module config") {
				t.Fatalf("provider launched before recorder preflight: %v", err)
			}
		})
	}
	if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 0 {
		t.Fatalf("credential provider invocations = %d, want 0", invocations)
	}
}

func TestRunnerReconcilesExactStandaloneCredentialProviderTarget(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	tests := []struct {
		name         string
		moduleID     string
		mutateTarget func(*domainpki.CredentialProviderTarget)
	}{
		{
			name:     "module id",
			moduleID: "credential-provider-alias",
			mutateTarget: func(target *domainpki.CredentialProviderTarget) {
				target.ModuleID = "credential-provider-alias"
			},
		},
		{
			name:     "provider id",
			moduleID: credentialProviderExactModuleID,
			mutateTarget: func(target *domainpki.CredentialProviderTarget) {
				target.ProviderID = "other-provider"
			},
		},
		{
			name:     "provider version",
			moduleID: credentialProviderExactModuleID,
			mutateTarget: func(target *domainpki.CredentialProviderTarget) {
				target.ProviderVersion = "v9.9.9-drifted"
			},
		},
		{
			name:     "descriptor digest",
			moduleID: credentialProviderExactModuleID,
			mutateTarget: func(target *domainpki.CredentialProviderTarget) {
				target.DescriptorSHA256 = strings.Repeat("e", sha256.Size*2)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
			t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
			target := credentialProviderExactTestTarget(t)
			test.mutateTarget(&target)
			request := credentialProviderRuntimeRequest()
			request.Provider = target
			recorder := &recordingCredentialExecutionRecorder{}
			_, err := (Runner{
				ConfigPath:           credentialProviderConfigForModule(t, test.moduleID),
				Timeout:              2 * time.Second,
				Clock:                credentialProviderTestClock(),
				CredentialExecutions: recorder,
			}).LoadRuntimeCredential(t.Context(), test.moduleID, request)
			if err == nil || !strings.Contains(
				err.Error(), "credential provider target does not match the running provider",
			) {
				t.Fatalf("LoadRuntimeCredential() error = %v", err)
			}
			if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 0 {
				t.Fatalf("credential provider invocations = %d, want 0", invocations)
			}
			if len(recorder.executions) != 2 ||
				recorder.executions[0].Status != domainpki.CredentialExecutionPending ||
				recorder.executions[1].Status != domainpki.CredentialExecutionFailed {
				t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
			}
		})
	}
}

func TestRunnerPreflightsEveryStandaloneCredentialProviderMethod(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	target := credentialProviderExactTestTarget(t)
	target.DescriptorSHA256 = strings.Repeat("e", sha256.Size*2)

	tests := []struct {
		name   string
		invoke func(Runner) error
	}{
		{
			name: "runtime",
			invoke: func(runner Runner) error {
				request := credentialProviderRuntimeRequest()
				request.Provider = target
				_, err := runner.LoadRuntimeCredential(
					t.Context(), credentialProviderExactModuleID, request,
				)
				return err
			},
		},
		{
			name: "files",
			invoke: func(runner Runner) error {
				_, err := runner.LoadCredentialFiles(
					t.Context(),
					credentialProviderExactModuleID,
					credentialProviderFilesRequest(target),
				)
				return err
			},
		},
		{
			name: "encoding",
			invoke: func(runner Runner) error {
				_, err := runner.EncodeCredentialMaterial(
					t.Context(),
					credentialProviderExactModuleID,
					credentialProviderEncodingRequest(target),
				)
				return err
			},
		},
		{
			name: "stamp",
			invoke: func(runner Runner) error {
				request := credentialProviderTestStampRequest(
					t,
					credentialProviderTestMetadata(),
					credentialProviderTestMaterial(),
				)
				request.Provider = target
				_, err := runner.StampCredential(
					t.Context(), credentialProviderExactModuleID, request,
				)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocationLog := filepath.Join(t.TempDir(), "provider-invocations")
			t.Setenv(credentialProviderInvocationLogEnv, invocationLog)
			err := test.invoke(credentialProviderRecordedRunner(t))
			if err == nil || !strings.Contains(
				err.Error(), "credential provider target does not match the running provider",
			) {
				t.Fatalf("credential provider call error = %v", err)
			}
			if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 0 {
				t.Fatalf("credential provider invocations = %d, want 0", invocations)
			}
		})
	}
}

func TestCredentialBearingProcessClearsAndDiscardsDiagnostics(t *testing.T) {
	const secret = "credential-bearing-diagnostic-secret"
	stderr := newCapturedStderr()
	if _, err := stderr.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	callbackCount := 0
	client := &rpcClient{
		logs: []rpcLog{{Message: secret, Fields: map[string]any{"secret": secret}}},
		onLog: func(rpcLog) error {
			callbackCount++
			return nil
		},
		onEvent: func(rpcSessionEvent) error {
			callbackCount++
			return nil
		},
	}
	process := &moduleProcess{client: client, stderr: stderr}

	process.markCredentialBearing()
	if got := stderr.String(); got != "" {
		t.Fatalf("credential-bearing stderr retained %q", got)
	}
	if logs := client.logsSnapshot(); len(logs) != 0 {
		t.Fatalf("credential-bearing logs retained %#v", logs)
	}
	if client.onLog != nil || client.onEvent != nil {
		t.Fatal("credential-bearing notification callbacks were retained")
	}

	if _, err := stderr.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := client.handleNotification(rpcMessage{
		Method: "module/log",
		Log:    rpcLog{Message: secret},
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.handleNotification(rpcMessage{
		Method:  "module/session",
		Session: rpcSessionEvent{Event: secret},
	}); err != nil {
		t.Fatal(err)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("credential-bearing stderr accepted new diagnostics %q", got)
	}
	if logs := client.logsSnapshot(); len(logs) != 0 {
		t.Fatalf("credential-bearing logs accepted new diagnostics %#v", logs)
	}
	if callbackCount != 0 {
		t.Fatalf("credential-bearing notification callbacks = %d, want 0", callbackCount)
	}
}

func TestCredentialResultCleanupClearsOwnedBytes(t *testing.T) {
	encodingData := domainpki.CredentialBytes("encoded-secret")
	encodingAlias := encodingData
	encoding := domainpki.CredentialEncodingResult{Data: encodingData}
	clearCredentialEncodingResult(&encoding)
	if encoding.Data != nil || !allBytesZero(encodingAlias) {
		t.Fatalf("credential encoding result was not cleared: %#v", encoding)
	}

	artifactData := domainpki.CredentialBytes("artifact-secret")
	artifactAlias := artifactData
	stamp := domainpki.CredentialStampExecutionResult{
		Output: domainpki.CredentialStampOutput{
			Artifact: &domainpki.CredentialArtifactOutput{Data: artifactData},
		},
	}
	clearCredentialStampExecutionResult(&stamp)
	if stamp.Output.Artifact != nil || !allBytesZero(artifactAlias) {
		t.Fatalf("credential stamp result was not cleared: %#v", stamp)
	}

	deploymentReceipt := domainpki.CredentialBytes("deployment-secret")
	deploymentAlias := deploymentReceipt
	stamp = domainpki.CredentialStampExecutionResult{
		Output: domainpki.CredentialStampOutput{
			Deployment: &domainpki.CredentialDeploymentOutput{Receipt: deploymentReceipt},
		},
	}
	clearCredentialStampExecutionResult(&stamp)
	if stamp.Output.Deployment != nil || !allBytesZero(deploymentAlias) {
		t.Fatalf("credential deployment result was not cleared: %#v", stamp)
	}
}

func allBytesZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func credentialProviderRuntimeRequest() domainpki.CredentialRuntimeRequest {
	return domainpki.CredentialRuntimeRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      credentialProviderTestTarget(),
		RequestID:     "runtime-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    credentialProviderTestMetadata(),
		Material:      credentialProviderTestMaterial(),
	}
}

func credentialProviderFilesRequest(
	provider domainpki.CredentialProviderTarget,
) domainpki.CredentialFilesRequest {
	return domainpki.CredentialFilesRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      provider,
		RequestID:     "files-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    credentialProviderTestMetadata(),
		Files: []domainpki.CredentialFile{{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
			Encoding:   domainpki.CredentialEncodingRaw,
			MediaType:  "application/pkix-cert",
			Path:       domainpki.NewCredentialProtectedPath("/protected/certificate.der"),
			SHA256:     strings.Repeat("b", sha256.Size*2),
			Size:       128,
		}},
	}
}

func credentialProviderOperationDeliveries(
	t *testing.T,
) domainpki.CredentialOperationDeliveries {
	t.Helper()
	runtimeRequest := credentialProviderRuntimeRequest()
	runtimeRequest.Provider = credentialProviderExactTestTarget(t)
	filesRequest := credentialProviderFilesRequest(credentialProviderExactTestTarget(t))
	filesRequest.SlotName = "tls-client"
	return domainpki.CredentialOperationDeliveries{
		{Capability: domainpki.DeliveryCapabilityRuntime, Runtime: &runtimeRequest},
		{Capability: domainpki.DeliveryCapabilityFiles, Files: &filesRequest},
	}
}

func credentialProviderEncodingRequest(
	provider domainpki.CredentialProviderTarget,
) domainpki.CredentialEncodingRequest {
	return domainpki.CredentialEncodingRequest{
		SchemaVersion:       domainpki.CredentialProviderExecutionSchemaV1,
		Provider:            provider,
		RequestID:           "encoding-1",
		ProviderID:          credentialProviderName,
		ProviderSchema:      "mbedtls-v1",
		OutputForm:          domainpki.CredentialMaterialPrivateBytes,
		MaximumEncodedBytes: 1024,
		Source:              credentialProviderTestMaterial(),
	}
}

func credentialProviderDiagnosticDeliveries(
	t *testing.T,
	secret string,
) domainpki.CredentialOperationDeliveries {
	t.Helper()
	request := credentialProviderRuntimeRequest()
	request.Provider = credentialProviderExactTestTarget(t)
	request.RequestID = "diagnostic-runtime"
	request.Material = domainpki.ResolvedCredentialMaterial{
		Projection: domainpki.CredentialProjectionPrivateKeyPKCS8,
		Form:       domainpki.CredentialMaterialPrivateBytes,
		Encoding:   "der",
		Data:       domainpki.CredentialBytes(secret),
	}
	request.Material.SHA256 = credentialProviderTestSHA256(request.Material.Data)
	return domainpki.CredentialOperationDeliveries{{
		Capability: domainpki.DeliveryCapabilityRuntime,
		Runtime:    &request,
	}}
}

func credentialProviderResolution(
	t *testing.T,
	deliveries domainpki.CredentialOperationDeliveries,
) *services.CredentialOperationResolution {
	t.Helper()
	return credentialProviderResolutionForLease(t, &credentialProviderResolutionLease{
		deliveries: deliveries,
	})
}

func credentialProviderResolutionForLease(
	t *testing.T,
	lease *credentialProviderResolutionLease,
) *services.CredentialOperationResolution {
	t.Helper()
	resolution, err := services.NewCredentialOperationResolution(lease)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolution.Close)
	return resolution
}

type credentialProviderResolutionLease struct {
	mu                sync.Mutex
	deliveries        domainpki.CredentialOperationDeliveries
	revalidate        func(context.Context, domainpki.CredentialOperationDeliveries) error
	borrowErrorAt     int
	borrowError       error
	revalidateErrorAt int
	revalidateError   error
	borrowCount       int
	revalidateCall    int
	calls             []string
	closed            bool
}

func (l *credentialProviderResolutionLease) BorrowedDeliveries() (
	domainpki.CredentialOperationDeliveries,
	error,
) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, services.ErrCredentialOperationResolutionClosed
	}
	l.borrowCount++
	l.calls = append(l.calls, "borrow")
	if l.borrowErrorAt != 0 && l.borrowCount == l.borrowErrorAt {
		if l.borrowError != nil {
			return nil, l.borrowError
		}
		return nil, errors.New("test credential deliveries became unavailable")
	}
	return l.deliveries, nil
}

func (l *credentialProviderResolutionLease) Revalidate(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return services.ErrCredentialOperationResolutionClosed
	}
	l.revalidateCall++
	l.calls = append(l.calls, "revalidate")
	if l.revalidateErrorAt != 0 && l.revalidateCall == l.revalidateErrorAt {
		if l.revalidateError != nil {
			return l.revalidateError
		}
		return errors.New("test credential resolution became invalid")
	}
	if l.revalidate == nil {
		return nil
	}
	return l.revalidate(ctx, l.deliveries)
}

func (l *credentialProviderResolutionLease) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.deliveries.Clear()
	l.deliveries = nil
	l.closed = true
}

func credentialProviderTestTarget() domainpki.CredentialProviderTarget {
	return domainpki.CredentialProviderTarget{
		ModuleID:         "credential-provider",
		ProviderID:       "credential-provider",
		ProviderVersion:  "v0.0.0-test",
		DescriptorSHA256: strings.Repeat("d", 64),
	}
}

func credentialProviderExactTestTarget(t *testing.T) domainpki.CredentialProviderTarget {
	t.Helper()
	digest, err := credentialProviderFixtureDescriptor().DigestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return domainpki.CredentialProviderTarget{
		ModuleID:         credentialProviderExactModuleID,
		ProviderID:       credentialProviderName,
		ProviderVersion:  credentialProviderVersion,
		DescriptorSHA256: digest,
	}
}

func credentialProviderConfig(t *testing.T) string {
	return credentialProviderConfigForModule(t, credentialProviderName)
}

func credentialProviderRecordedRunner(t *testing.T) Runner {
	t.Helper()
	return Runner{
		ConfigPath:           credentialProviderConfig(t),
		Timeout:              2 * time.Second,
		Clock:                credentialProviderTestClock(),
		CredentialExecutions: &recordingCredentialExecutionRecorder{},
	}
}

func credentialProviderTestClock() credentialRecorderClock {
	return credentialRecorderClock{
		now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
	}
}

func credentialProviderConfigForModule(t *testing.T, moduleID string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config := ModuleConfig{Modules: []ModuleEntry{{
		ID:      moduleID,
		Runtime: "jsonrpc-stdio",
		Command: []string{executable},
	}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "modules.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type credentialProviderRPCRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type credentialProviderFixtureRPCError struct {
	message string
}

func (e credentialProviderFixtureRPCError) Error() string {
	return e.message
}

func serveCredentialProviderFixture(input io.Reader, output io.Writer) error {
	reader := framing.NewReader(input, framing.DefaultMaxBytes)
	for {
		var request credentialProviderRPCRequest
		if err := reader.ReadJSON(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := recordCredentialProviderMethod(request.Method); err != nil {
			return err
		}
		result, shouldStop, err := credentialProviderFixtureResult(request)
		response := map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}
		var rpcErr credentialProviderFixtureRPCError
		if errors.As(err, &rpcErr) {
			delete(response, "result")
			response["error"] = map[string]any{"message": rpcErr.message}
		} else if err != nil {
			return err
		}
		if err := framing.WriteJSON(output, response); err != nil {
			return err
		}
		if shouldStop {
			if os.Getenv(credentialProviderFailureSurfaceEnv) == "shutdown" {
				return fmt.Errorf(
					"provider shutdown failed after receiving %s",
					credentialProviderFixtureSecret,
				)
			}
			return nil
		}
	}
}

func credentialProviderFixtureResult(
	request credentialProviderRPCRequest,
) (result any, shouldStop bool, err error) {
	switch request.Method {
	case "handshake":
		if os.Getenv(credentialProviderHandshakeModeEnv) == "missing" {
			return map[string]any{
				"version": credentialProviderVersion, "moduleType": "payload_provider",
			}, false, nil
		}
		return map[string]any{
			"name": credentialProviderName, "version": credentialProviderVersion, "moduleType": "payload_provider",
		}, false, nil
	case "schema":
		return map[string]any{"chainConfig": []any{}, "targetConfig": []any{}}, false, nil
	case "step.describe":
		return map[string]any{"steps": []any{}}, false, nil
	case meshRPCDescribeMethod:
		if os.Getenv(credentialProviderDescriptorModeEnv) == "nested-mismatch" {
			descriptor := credentialProviderFixtureDescriptor()
			descriptor.Capabilities = []domainpki.DeliveryCapability{domainpki.DeliveryCapabilityFiles}
			return map[string]any{"credentialDelivery": descriptor}, false, nil
		}
		return map[string]any{}, false, nil
	case credentialRPCDescribeMethod:
		switch os.Getenv(credentialProviderDescriptorModeEnv) {
		case "missing":
			return nil, false, nil
		case "malformed":
			return map[string]any{
				"schemaVersion":        domainpki.CredentialDeliverySchemaV1,
				"deliveryCapabilities": []any{"runtime"},
				"unexpected":           true,
			}, false, nil
		case "changed":
			descriptor := credentialProviderFixtureDescriptor()
			descriptor.Capabilities = []domainpki.DeliveryCapability{domainpki.DeliveryCapabilityFiles}
			return descriptor, false, nil
		}
		return credentialProviderFixtureDescriptor(), false, nil
	case credentialRPCRuntimeMethod:
		var params domainpki.CredentialRuntimeRequest
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return nil, false, err
		}
		requestID := params.RequestID
		if os.Getenv(credentialProviderMismatchEnv) == "1" {
			requestID = "other-request"
		}
		if err := recordCredentialProviderInvocation(); err != nil {
			return nil, false, err
		}
		credentialProviderFixtureSecret = string(params.Material.Data)
		if os.Getenv(credentialProviderFailureSurfaceEnv) == "malformed-delivery" {
			return credentialProviderMalformedResult(map[string]any{
				"requestId":         params.RequestID,
				"providerReference": "provider-receipt-1",
				"receiptSha256":     strings.Repeat("a", 64),
			}), false, nil
		}
		if err := credentialProviderFixtureDiagnosticFailure("delivery"); err != nil {
			return nil, false, err
		}
		credentialProviderFixtureDeliveryCount++
		return domainpki.CredentialDeliveryReceipt{
			RequestID: requestID, ProviderReference: "provider-receipt-1", ReceiptSHA256: strings.Repeat("a", 64),
		}, false, nil
	case credentialRPCFilesMethod:
		var params domainpki.CredentialFilesRequest
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return nil, false, err
		}
		if err := recordCredentialProviderInvocation(); err != nil {
			return nil, false, err
		}
		credentialProviderFixtureDeliveryCount++
		return domainpki.CredentialDeliveryReceipt{
			RequestID: params.RequestID, ProviderReference: "provider-receipt-1", ReceiptSHA256: strings.Repeat("a", 64),
		}, false, nil
	case credentialRPCEncodeMethod:
		var params domainpki.CredentialEncodingRequest
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return nil, false, err
		}
		if err := recordCredentialProviderInvocation(); err != nil {
			return nil, false, err
		}
		credentialProviderFixtureSecret = string(params.Source.Data)
		if os.Getenv(credentialProviderFailureSurfaceEnv) == "malformed-encoding" {
			return credentialProviderMalformedResult(map[string]any{
				"requestId": params.RequestID,
				"form":      params.OutputForm,
				"encoding":  "mbedtls-v1",
				"sha256":    strings.Repeat("0", 64),
				"data":      "provider encoding",
			}), false, nil
		}
		data := domainpki.CredentialBytes("provider encoding")
		digest := credentialProviderTestSHA256(data)
		if os.Getenv(credentialProviderBadDigestEnv) == "1" {
			digest = strings.Repeat("0", 64)
		}
		return domainpki.CredentialEncodingResult{
			RequestID: params.RequestID,
			Form:      params.OutputForm,
			Encoding:  "mbedtls-v1",
			SHA256:    digest,
			Data:      data,
		}, false, nil
	case credentialRPCStampMethod:
		var params domainpki.CredentialStampExecutionRequest
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return nil, false, err
		}
		if err := recordCredentialProviderInvocation(); err != nil {
			return nil, false, err
		}
		credentialProviderFixtureSecret = string(params.Material.Data)
		if os.Getenv(credentialProviderFailureSurfaceEnv) == "malformed-stamp" {
			return credentialProviderMalformedResult(map[string]any{
				"stampId": params.StampID,
			}), false, nil
		}
		return domainpki.CredentialStampExecutionResult{
			StampID: params.StampID,
			Output: domainpki.CredentialStampOutput{Artifact: &domainpki.CredentialArtifactOutput{
				Name: "stamped.bin", Encoding: "raw", Data: domainpki.CredentialBytes("stamped artifact"),
			}},
			TargetResolution: domainpki.StampTargetResolutionUnchanged,
			ResolvedTarget:   params.Request.Target.Clone(),
			BytesWritten:     domainpki.NewCanonicalUint64(params.Request.EncodedBytes),
			MaterialDigests:  append([]domainpki.StampedMaterialDigest(nil), params.ExpectedDigests...),
		}, false, nil
	case meshRPCListenerStartMethod:
		if os.Getenv(credentialProviderFailureSurfaceEnv) == "malformed-listener" {
			return map[string]any{
				"id":        credentialProviderFixtureSecret,
				"addresses": []any{true},
			}, false, nil
		}
		return mesh.Listener{ID: "listener-1", State: mesh.ListenerStateActive}, false, nil
	case meshRPCTaskMethod:
		var params mesh.TaskRequest
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return nil, false, err
		}
		if err := credentialProviderFixtureDiagnosticFailure("task"); err != nil {
			return nil, false, err
		}
		if os.Getenv(credentialProviderFailureSurfaceEnv) == "malformed-task" {
			return mesh.TaskResult{
				TaskID: params.TaskID,
				Status: mesh.TaskStatusSucceeded,
				Sessions: []run.SessionRef{
					{ID: credentialProviderFixtureSecret},
					{ID: credentialProviderFixtureSecret},
				},
			}, false, nil
		}
		return mesh.TaskResult{
			TaskID: params.TaskID,
			Status: mesh.TaskStatusSucceeded,
			Outputs: map[string]any{
				"credentialDeliveryCount": credentialProviderFixtureDeliveryCount,
			},
		}, false, nil
	case meshRPCOpenStreamMethod:
		if err := credentialProviderFixtureDiagnosticFailure("stream"); err != nil {
			return nil, false, err
		}
		if os.Getenv(credentialProviderFailureSurfaceEnv) == "malformed-stream" {
			return map[string]any{
				"id":           credentialProviderFixtureSecret,
				"capabilities": []any{true},
			}, false, nil
		}
		return map[string]any{"id": "diagnostic-session"}, false, nil
	case rpcShutdownMethod:
		if err := credentialProviderFixtureDiagnosticFailure("shutdown"); err != nil {
			return nil, true, err
		}
		return map[string]string{"status": "ok"}, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported fixture method %q", request.Method)
	}
}

func credentialProviderMalformedResult(result map[string]any) map[string]any {
	result[credentialProviderFixtureSecret] = true
	return result
}

func credentialProviderFixtureDiagnosticFailure(surface string) error {
	if os.Getenv(credentialProviderFailureSurfaceEnv) != surface {
		return nil
	}
	if _, err := fmt.Fprintf(
		os.Stderr,
		"provider-controlled stderr diagnostic: %s\n",
		credentialProviderFixtureSecret,
	); err != nil {
		return err
	}
	return credentialProviderFixtureRPCError{
		message: "provider-controlled JSON-RPC diagnostic: " + credentialProviderFixtureSecret,
	}
}

func recordCredentialProviderInvocation() error {
	path := os.Getenv(credentialProviderInvocationLogEnv)
	if path == "" {
		return nil
	}
	return appendCredentialProviderLog(path, "invoked\n")
}

func recordCredentialProviderMethod(method string) error {
	path := os.Getenv(credentialProviderMethodLogEnv)
	if path == "" {
		return nil
	}
	return appendCredentialProviderLog(path, method+"\n")
}

func appendCredentialProviderLog(path string, line string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(line); err != nil {
		return errors.Join(err, file.Close())
	}
	return file.Close()
}

func credentialProviderInvocationCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "invoked\n")
}

func credentialProviderMethodLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

func assertNoCredentialProviderDelivery(
	t *testing.T,
	invocationLog string,
	methodLog string,
) {
	t.Helper()
	if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 0 {
		t.Fatalf("credential provider invocations = %d, want 0", invocations)
	}
	for _, method := range credentialProviderMethodLog(t, methodLog) {
		if method == credentialRPCRuntimeMethod || method == credentialRPCFilesMethod {
			t.Fatalf("credential delivery method %q reached provider", method)
		}
	}
}

func assertOnlyFirstCredentialProviderDelivery(
	t *testing.T,
	invocationLog string,
	methodLog string,
) {
	t.Helper()
	if invocations := credentialProviderInvocationCount(t, invocationLog); invocations != 1 {
		t.Fatalf("credential provider invocations = %d, want 1", invocations)
	}
	var runtimeCalls int
	var filesCalls int
	var taskCalls int
	for _, method := range credentialProviderMethodLog(t, methodLog) {
		switch method {
		case credentialRPCRuntimeMethod:
			runtimeCalls++
		case credentialRPCFilesMethod:
			filesCalls++
		case meshRPCTaskMethod:
			taskCalls++
		}
	}
	if runtimeCalls != 1 || filesCalls != 0 || taskCalls != 0 {
		t.Fatalf(
			"provider calls after first delivery: runtime=%d files=%d task=%d, want 1, 0, 0",
			runtimeCalls,
			filesCalls,
			taskCalls,
		)
	}
}

func assertCredentialOperationDeliveredFirstThenAborted(
	t *testing.T,
	recorder *recordingCredentialExecutionRecorder,
) {
	t.Helper()
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.executions) != 4 {
		t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
	}
	firstPlan := recorder.executions[0]
	secondPlan := recorder.executions[1]
	firstCompleted := recorder.executions[2]
	secondFailed := recorder.executions[3]
	if firstPlan.Status != domainpki.CredentialExecutionPending ||
		secondPlan.Status != domainpki.CredentialExecutionPending ||
		firstCompleted.ID != firstPlan.ID ||
		firstCompleted.Status != domainpki.CredentialExecutionSucceeded ||
		secondFailed.ID != secondPlan.ID ||
		secondFailed.Status != domainpki.CredentialExecutionFailed ||
		secondFailed.Failure != credentialOperationAbortReason {
		t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
	}
}

func assertCredentialOperationAborted(
	t *testing.T,
	recorder *recordingCredentialExecutionRecorder,
	deliveryCount int,
) {
	t.Helper()
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.executions) != 2*deliveryCount {
		t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
	}
	for index := range deliveryCount {
		planned := recorder.executions[index]
		failed := recorder.executions[deliveryCount+index]
		if planned.Status != domainpki.CredentialExecutionPending ||
			failed.ID != planned.ID ||
			failed.Status != domainpki.CredentialExecutionFailed ||
			failed.Failure != credentialOperationAbortReason {
			t.Fatalf("credential execution lifecycle = %#v", recorder.executions)
		}
	}
}

func credentialProviderFixtureDescriptor() domainpki.CredentialDeliveryDescriptor {
	return domainpki.CredentialDeliveryDescriptor{
		SchemaVersion: domainpki.CredentialDeliverySchemaV1,
		Capabilities:  []domainpki.DeliveryCapability{domainpki.DeliveryCapabilityRuntime},
		Slots: []domainpki.CredentialSlot{{
			Name:                         "tls-server",
			Purpose:                      domainpki.PurposeTLSServer,
			EndpointRole:                 domainpki.CredentialEndpointServer,
			ConsumerType:                 domainpki.ConsumerMeshListener,
			AcceptedBundleVersions:       []string{domainpki.BundleSchemaV1},
			AcceptedProfiles:             []domainpki.ProfileID{domainpki.ProfileTLSServer},
			AcceptedCompatibilityTargets: []domainpki.CompatibilityTargetID{domainpki.CompatibilityPortableX509},
			AcceptedProjections:          []domainpki.CredentialProjection{domainpki.CredentialProjectionCertificateDER},
			AcceptedMaterialForms:        []domainpki.CredentialMaterialForm{domainpki.CredentialMaterialPublic},
			MaximumEncodedBytes:          4096,
			RemainderPolicy:              domainpki.StampRemainderPreserve,
			PrivateMaterial:              domainpki.PrivateMaterialForbidden,
		}},
	}
}

func credentialProviderTestMetadata() domainpki.ResolvedCredentialMetadata {
	return domainpki.ResolvedCredentialMetadata{
		BundleVersion:         domainpki.BundleSchemaV1,
		Purpose:               domainpki.PurposeTLSServer,
		ConsumerType:          domainpki.ConsumerMeshListener,
		ProfileID:             domainpki.ProfileTLSServer,
		CompatibilityTargetID: domainpki.CompatibilityPortableX509,
	}
}

func credentialProviderTestMaterial() domainpki.ResolvedCredentialMaterial {
	data := domainpki.CredentialBytes("0123456789abcdef")
	return domainpki.ResolvedCredentialMaterial{
		Projection: domainpki.CredentialProjectionBundle,
		Form:       domainpki.CredentialMaterialPrivateBytes,
		Encoding:   "hovel-bundle-json",
		SHA256:     credentialProviderTestSHA256(data),
		Data:       data,
	}
}

func credentialProviderTestStampRequest(
	t *testing.T,
	metadata domainpki.ResolvedCredentialMetadata,
	material domainpki.ResolvedCredentialMaterial,
) domainpki.CredentialStampExecutionRequest {
	t.Helper()
	target, err := domainpki.NewNamedSlotStampTarget(domainpki.NamedSlotTarget{Name: "tls-server"})
	if err != nil {
		t.Fatal(err)
	}
	stampMaterial, err := domainpki.NewCredentialStampMaterial(domainpki.CredentialMaterialReference{
		Projection: domainpki.CredentialProjectionBundle,
		Form:       domainpki.CredentialMaterialPrivateBytes,
		BundleID:   "bundle-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := domainpki.CredentialBytes("0123456789abcdef")
	return domainpki.CredentialStampExecutionRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      credentialProviderTestTarget(),
		StampID:       "credential-stamp-1",
		Request: domainpki.CredentialStampRequest{
			AssignmentID: "assignment-1",
			Capability:   domainpki.DeliveryCapabilityStampStandard,
			SlotName:     "tls-server",
			Target:       target,
			Material:     stampMaterial,
			EncodedBytes: 16,
			Credential:   metadata,
		},
		Input: domainpki.CredentialArtifactInput{
			ID: "artifact-input-1", SHA256: credentialProviderTestSHA256(input), Encoding: "raw", Data: input,
		},
		Material: material,
		ExpectedDigests: []domainpki.StampedMaterialDigest{{
			Projection: domainpki.CredentialProjectionBundle,
			Reference:  "bundle-1",
			SHA256:     material.SHA256,
		}},
		Scope: domainpki.CredentialOperationScope{RunID: "run-1", NodeID: "node-1"},
	}
}

func credentialProviderTestSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

type recordingCredentialExecutionRecorder struct {
	mu            sync.Mutex
	keys          []string
	executions    []domainpki.CredentialExecution
	contextErrors []error
	byID          map[domainpki.CredentialExecutionRequestID]domainpki.CredentialExecution
	planErr       error
	transitionErr error
}

type credentialRecorderClock struct {
	now time.Time
}

func (c credentialRecorderClock) Now() time.Time {
	return c.now
}

func (r *recordingCredentialExecutionRecorder) RecordCredentialExecutionPlan(
	ctx context.Context,
	key string,
	execution domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.planErr != nil {
		return domainpki.CredentialExecution{}, r.planErr
	}
	if execution.Status != domainpki.CredentialExecutionPending {
		return domainpki.CredentialExecution{}, errors.New("test recorder received terminal plan")
	}
	if existing, exists := r.byID[execution.ID]; exists {
		if !reflect.DeepEqual(existing.Plan, execution.Plan) {
			return domainpki.CredentialExecution{}, apppki.ErrIdempotencyConflict
		}
		if existing.Status == domainpki.CredentialExecutionPending {
			return domainpki.CredentialExecution{}, apppki.ErrCredentialExecutionInProgress
		}
		return existing.Clone(), nil
	}
	return r.recordLocked(ctx, key, execution)
}

func (r *recordingCredentialExecutionRecorder) RecordCredentialExecutionTransition(
	ctx context.Context,
	key string,
	execution domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.transitionErr != nil {
		return domainpki.CredentialExecution{}, r.transitionErr
	}
	if execution.Status == domainpki.CredentialExecutionPending {
		return domainpki.CredentialExecution{}, errors.New("test recorder received pending transition")
	}
	if existing, exists := r.byID[execution.ID]; !exists {
		return domainpki.CredentialExecution{}, errors.New("test recorder transition is missing its plan")
	} else if existing.Status != domainpki.CredentialExecutionPending {
		if reflect.DeepEqual(existing, execution) {
			return existing.Clone(), nil
		}
		return domainpki.CredentialExecution{}, apppki.ErrIdempotencyConflict
	}
	return r.recordLocked(ctx, key, execution)
}

func (r *recordingCredentialExecutionRecorder) recordLocked(
	ctx context.Context,
	key string,
	execution domainpki.CredentialExecution,
) (domainpki.CredentialExecution, error) {
	if err := execution.Validate(); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	r.keys = append(r.keys, key)
	r.executions = append(r.executions, execution.Clone())
	r.contextErrors = append(r.contextErrors, ctx.Err())
	if r.byID == nil {
		r.byID = make(map[domainpki.CredentialExecutionRequestID]domainpki.CredentialExecution)
	}
	r.byID[execution.ID] = execution.Clone()
	return execution.Clone(), nil
}
