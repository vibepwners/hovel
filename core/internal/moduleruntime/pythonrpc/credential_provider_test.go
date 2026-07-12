package pythonrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/protocol/framing"
)

const (
	credentialProviderChildEnv          = "HOVEL_TEST_CREDENTIAL_PROVIDER_CHILD"
	credentialProviderMismatchEnv       = "HOVEL_TEST_CREDENTIAL_PROVIDER_MISMATCH"
	credentialProviderBadDigestEnv      = "HOVEL_TEST_CREDENTIAL_PROVIDER_BAD_DIGEST"
	credentialProviderInvocationLogEnv  = "HOVEL_TEST_CREDENTIAL_PROVIDER_INVOCATION_LOG"
	credentialProviderHandshakeModeEnv  = "HOVEL_TEST_CREDENTIAL_PROVIDER_HANDSHAKE_MODE"
	credentialProviderDescriptorModeEnv = "HOVEL_TEST_CREDENTIAL_PROVIDER_DESCRIPTOR_MODE"

	credentialProviderName          = "credential-provider"
	credentialProviderVersion       = "v0.0.0-test"
	credentialProviderExactModuleID = credentialProviderName + "@" + credentialProviderVersion
)

var credentialProviderFixtureDeliveryCount int

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
	runner := Runner{ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second}
	metadata := credentialProviderTestMetadata()
	material := credentialProviderTestMaterial()

	runtimeRequest := domainpki.CredentialRuntimeRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      credentialProviderTestTarget(),
		RequestID:     "runtime-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    metadata,
		Material:      material,
		Scope:         domainpki.CredentialOperationScope{RunID: "run-1", NodeID: "node-1"},
	}
	receipt, err := runner.LoadRuntimeCredential(t.Context(), "credential-provider", runtimeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RequestID != runtimeRequest.RequestID || receipt.ProviderReference != "provider-receipt-1" {
		t.Fatalf("runtime credential receipt = %#v", receipt)
	}

	filesRequest := domainpki.CredentialFilesRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      credentialProviderTestTarget(),
		RequestID:     "files-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-server",
		Credential:    metadata,
		Files: []domainpki.CredentialFile{{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
			MediaType:  "application/pkix-cert",
			Path:       "/protected/certificate.der",
			SHA256:     strings.Repeat("b", 64),
			Size:       128,
		}},
	}
	receipt, err = runner.LoadCredentialFiles(t.Context(), "credential-provider", filesRequest)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RequestID != filesRequest.RequestID {
		t.Fatalf("files credential receipt = %#v", receipt)
	}

	encodingRequest := domainpki.CredentialEncodingRequest{
		SchemaVersion:       domainpki.CredentialProviderExecutionSchemaV1,
		Provider:            credentialProviderTestTarget(),
		RequestID:           "encoding-1",
		ProviderID:          "credential-provider",
		ProviderSchema:      "mbedtls-v1",
		OutputForm:          domainpki.CredentialMaterialPrivateBytes,
		MaximumEncodedBytes: 1024,
		Source:              material,
	}
	encoded, err := runner.EncodeCredentialMaterial(t.Context(), "credential-provider", encodingRequest)
	if err != nil {
		t.Fatal(err)
	}
	if encoded.RequestID != encodingRequest.RequestID || string(encoded.Data) != "provider encoding" {
		t.Fatalf("credential encoding result = %#v", encoded)
	}

	stampRequest := credentialProviderTestStampRequest(t, metadata, material)
	stamped, err := runner.StampCredential(t.Context(), "credential-provider", stampRequest)
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
	request.Material.Data = domainpki.CredentialBytes("runtime-ledger-secret")
	request.Material.SHA256 = credentialProviderTestSHA256(request.Material.Data)
	runner := Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}
	receipt, err := runner.LoadRuntimeCredential(t.Context(), "credential-provider", request)
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
	_, err := (Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
		Clock: credentialRecorderClock{
			now: time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC),
		},
		CredentialExecutions: recorder,
	}).LoadRuntimeCredential(t.Context(), "credential-provider", request)
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
	first, err := runner.LoadRuntimeCredential(t.Context(), "credential-provider", request)
	if err != nil {
		t.Fatal(err)
	}

	runner.ConfigPath = filepath.Join(t.TempDir(), "missing-module-config.json")
	replayed, err := runner.LoadRuntimeCredential(t.Context(), "credential-provider", request)
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
				context.Background(), "credential-provider", request,
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

	_, err := runner.RunMeshTaskWithCredentials(
		t.Context(), "credential-provider", deliveries,
		mesh.TaskRequest{TaskID: "task-preflight", Kind: mesh.TaskSurvey},
	)
	if !errors.Is(err, apppki.ErrCredentialExecutionInProgress) {
		t.Fatalf("RunMeshTaskWithCredentials() error = %v, want in progress", err)
	}
	if strings.Contains(err.Error(), "module config") {
		t.Fatalf("provider launched before credential preflight: %v", err)
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
				deliveries,
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
	}).RunMeshTaskWithCredentials(
		t.Context(), credentialProviderExactModuleID, nil,
		mesh.TaskRequest{TaskID: "task-without-credentials", Kind: mesh.TaskSurvey},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := execution.Result.Outputs["credentialDeliveryCount"]; got != float64(0) {
		t.Fatalf("credential delivery count = %#v, want 0", got)
	}
}

func TestRunnerSequencesCredentialsInMeshOperationProcess(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	runtimeRequest := credentialProviderRuntimeRequest()
	runtimeRequest.Provider = credentialProviderExactTestTarget(t)
	filesRequest := domainpki.CredentialFilesRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      credentialProviderExactTestTarget(t),
		RequestID:     "files-1",
		AssignmentID:  "assignment-1",
		SlotName:      "tls-client",
		Credential:    credentialProviderTestMetadata(),
		Files: []domainpki.CredentialFile{{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
			MediaType:  "application/pkix-cert",
			Path:       "/protected/certificate.der",
			SHA256:     strings.Repeat("b", 64),
			Size:       128,
		}},
	}
	deliveries := domainpki.CredentialOperationDeliveries{
		{Capability: domainpki.DeliveryCapabilityRuntime, Runtime: &runtimeRequest},
		{Capability: domainpki.DeliveryCapabilityFiles, Files: &filesRequest},
	}
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
		deliveries,
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
	_, err := (Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
	}).LoadRuntimeCredential(t.Context(), "credential-provider", request)
	if err == nil || !strings.Contains(err.Error(), "mismatched credential delivery receipt") {
		t.Fatalf("LoadRuntimeCredential() error = %v", err)
	}
}

func TestRunnerRejectsInvalidCredentialProviderDigest(t *testing.T) {
	t.Setenv(credentialProviderChildEnv, "1")
	t.Setenv(credentialProviderBadDigestEnv, "1")
	request := domainpki.CredentialEncodingRequest{
		SchemaVersion:       domainpki.CredentialProviderExecutionSchemaV1,
		Provider:            credentialProviderTestTarget(),
		RequestID:           "encoding-1",
		ProviderID:          "credential-provider",
		ProviderSchema:      "mbedtls-v1",
		OutputForm:          domainpki.CredentialMaterialPrivateBytes,
		MaximumEncodedBytes: 1024,
		Source:              credentialProviderTestMaterial(),
	}
	_, err := (Runner{
		ConfigPath: credentialProviderConfig(t), Timeout: 2 * time.Second,
	}).EncodeCredentialMaterial(t.Context(), "credential-provider", request)
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
		result, shouldStop, err := credentialProviderFixtureResult(request)
		if err != nil {
			return err
		}
		response := map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}
		if err := framing.WriteJSON(output, response); err != nil {
			return err
		}
		if shouldStop {
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
	case meshRPCTaskMethod:
		var params mesh.TaskRequest
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return nil, false, err
		}
		return mesh.TaskResult{
			TaskID: params.TaskID,
			Status: mesh.TaskStatusSucceeded,
			Outputs: map[string]any{
				"credentialDeliveryCount": credentialProviderFixtureDeliveryCount,
			},
		}, false, nil
	case rpcShutdownMethod:
		return map[string]string{"status": "ok"}, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported fixture method %q", request.Method)
	}
}

func recordCredentialProviderInvocation() error {
	path := os.Getenv(credentialProviderInvocationLogEnv)
	if path == "" {
		return nil
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString("invoked\n"); err != nil {
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
