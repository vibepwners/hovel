package daemonrpc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vibepwners/hovel/internal/app/operatorlog"
	"github.com/vibepwners/hovel/internal/app/operatorsession"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/domain/event"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	operatordomain "github.com/vibepwners/hovel/internal/domain/operator"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
	"github.com/vibepwners/hovel/internal/testmodules/mockexploit"
)

func TestBindMeshCredentialContextRequiresExplicitApprovedScope(t *testing.T) {
	t.Parallel()

	credentials := domainpki.CredentialSelections{{
		RequestID:    "credential-request-1",
		AssignmentID: "assignment-1",
		SlotName:     "tls-server",
		Capability:   domainpki.DeliveryCapabilityRuntime,
		Material: domainpki.CredentialMaterialSelection{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
		},
	}}
	if _, err := bindMeshCredentialContext(t.Context(), credentials, nil); err == nil {
		t.Fatal("bindMeshCredentialContext() accepted selections without authenticated context")
	}
	unused := &PKIRequestContext{
		ActorID: "operator-1", OperationID: "operation-1", CorrelationID: "request-1",
	}
	if _, err := bindMeshCredentialContext(t.Context(), nil, unused); err == nil {
		t.Fatal("bindMeshCredentialContext() accepted an unused credential context")
	}

	denied, err := bindMeshCredentialContext(t.Context(), credentials, unused)
	if err != nil {
		t.Fatal(err)
	}
	if err := (apppki.ContextCredentialUseAuthorizer{}).AuthorizeCredentialUse(
		denied,
		"assignment-1",
	); err == nil {
		t.Fatal("credential use was approved without the narrow approval bit")
	}

	approvedRequest := *unused
	approvedRequest.ApproveCredentialUse = true
	approved, err := bindMeshCredentialContext(t.Context(), credentials, &approvedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := (apppki.ContextCredentialUseAuthorizer{}).AuthorizeCredentialUse(
		approved,
		"assignment-1",
	); err != nil {
		t.Fatalf("approved credential use: %v", err)
	}
}

func TestClientRunsMockExploitThroughDaemonRPC(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	result, err := client.RunMockExploit(context.Background(), RunMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.RunID != "run-1" {
		t.Fatalf("run id = %q, want run-1", result.RunID)
	}
	if result.State != "succeeded" {
		t.Fatalf("state = %q, want succeeded", result.State)
	}
	if result.Summary != "mock exploit completed without target interaction" {
		t.Fatalf("summary = %q", result.Summary)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(result.Findings))
	}
	if len(result.Artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(result.Artifacts))
	}
	if result.Artifacts[0].Data == "" {
		t.Fatalf("artifact = %#v, want inline data", result.Artifacts[0])
	}
}

func TestTCPDaemonRPCIsLoopbackReadOnly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, "tcp://"+address, runs)

	client, err := Dial("tcp://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	_, err = client.RunMockExploit(context.Background(), RunMockExploitRequest{
		ModuleID: "mock-exploit",
		Target:   "mock://target",
	})
	if err == nil || !strings.Contains(err.Error(), "privileged daemon control") {
		t.Fatalf("RunMockExploit error = %v, want privileged transport rejection", err)
	}
	_, err = client.ListMeshOperations(context.Background(), MeshOperationListRequest{})
	if err == nil || !strings.Contains(err.Error(), "privileged daemon control") {
		t.Fatalf("ListMeshOperations error = %v, want confidential read rejection", err)
	}
}

func TestDaemonRPCTCPRejectsNonLoopbackBind(t *testing.T) {
	for _, endpoint := range []string{
		"tcp://0.0.0.0:8080",
		"http://192.0.2.10:8080",
		"[::]:8080",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := ParseEndpoint(endpoint); err == nil || !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("ParseEndpoint(%q) error = %v, want loopback rejection", endpoint, err)
			}
		})
	}

	for _, endpoint := range []string{
		"tcp://127.0.0.1:8080",
		"http://localhost:8080",
		"[::1]:8080",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := ParseEndpoint(endpoint); err != nil {
				t.Fatalf("ParseEndpoint(%q) error = %v", endpoint, err)
			}
		})
	}
}

func TestClientControlsWorkspacePKIThroughDaemonRPC(t *testing.T) {
	t.Parallel()

	socketPath := shortTempDir(t) + "/hoveld.sock"
	control := &recordingPKIControl{}
	serveTestDaemon(t, socketPath, services.RunService{}, WithPKIControl(control))
	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	status, err := client.PKIStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.Initialized {
		t.Fatalf("initial status = %#v", status)
	}
	requestContext := PKIRequestContext{
		ActorID: "operator-1", OperationID: "operation-1", CorrelationID: "correlation-1",
	}
	if _, err := client.InitializePKI(t.Context(), PKIInitializeRequest{Context: requestContext}); err == nil {
		t.Fatal("InitializePKI() accepted missing confirmation")
	}
	status, err = client.InitializePKI(t.Context(), PKIInitializeRequest{Context: requestContext, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Initialized || control.initializedBy != "operator-1" {
		t.Fatalf("initialized status = %#v, actor = %q", status, control.initializedBy)
	}
	profiles, err := client.ListPKIProfiles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles.Profiles) == 0 {
		t.Fatal("ListPKIProfiles() returned no built-in profiles")
	}
	renewed, err := client.RenewPKICertificate(t.Context(), PKIMutationRequest[apppki.RenewCertificateRequest]{
		Context: requestContext, Request: apppki.RenewCertificateRequest{
			IdempotencyKey: "rpc:certificate-renew", SourceGenerationID: "generation-rpc-source",
			GenerationID: "generation-rpc-renewed",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Kind != apppki.IssuanceKindCertificateRenewal || renewed.Generation.ID != "generation-rpc-renewed" {
		t.Fatalf("RenewPKICertificate() = %#v", renewed)
	}
	rotated, err := client.RotatePKICertificate(t.Context(), PKIMutationRequest[apppki.RotateCertificateRequest]{
		Context: requestContext, Request: apppki.RotateCertificateRequest{
			IdempotencyKey: "rpc:certificate-rotate", SourceGenerationID: renewed.Generation.ID,
			GenerationID: "generation-rpc-rotated", KeyID: "key-rpc-rotated",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Kind != apppki.IssuanceKindCertificateRotation || rotated.Generation.ID != "generation-rpc-rotated" {
		t.Fatalf("RotatePKICertificate() = %#v", rotated)
	}
	revoked, err := client.RevokePKICertificate(t.Context(), PKIMutationRequest[apppki.RevokeCertificateRequest]{
		Context: requestContext, Request: apppki.RevokeCertificateRequest{
			IdempotencyKey: "rpc:certificate-revoke", GenerationID: rotated.Generation.ID,
			Reason: domainpki.RevocationReasonKeyCompromise,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Revocation.GenerationID != rotated.Generation.ID ||
		revoked.Revocation.Reason != domainpki.RevocationReasonKeyCompromise {
		t.Fatalf("RevokePKICertificate() = %#v", revoked)
	}
	if inspected, err := client.InspectPKIRevocation(
		t.Context(), PKIRevocationRequest{ID: revoked.Revocation.ID},
	); err != nil || inspected.ID != revoked.Revocation.ID {
		t.Fatalf("InspectPKIRevocation() = %#v, %v", inspected, err)
	}
	if inspected, err := client.InspectPKIGenerationRevocation(
		t.Context(), PKICertificateRequest{ID: rotated.Generation.ID},
	); err != nil || inspected.GenerationID != rotated.Generation.ID {
		t.Fatalf("InspectPKIGenerationRevocation() = %#v, %v", inspected, err)
	}
	listedRevocations, err := client.ListPKIRevocations(
		t.Context(), PKIRevocationListRequest{AuthorityID: "authority-rpc"},
	)
	if err != nil || len(listedRevocations.Revocations) != 1 {
		t.Fatalf("ListPKIRevocations() = %#v, %v", listedRevocations, err)
	}
	publishedCRL, err := client.PublishPKICRL(t.Context(), PKIMutationRequest[apppki.PublishCRLRequest]{
		Context: requestContext, Request: apppki.PublishCRLRequest{
			IdempotencyKey: "rpc:crl-publish", AuthorityID: "authority-rpc",
		},
	})
	if err != nil || publishedCRL.Generation.ID != "crl-generation-rpc" {
		t.Fatalf("PublishPKICRL() = %#v, %v", publishedCRL, err)
	}
	if publication, err := client.InspectPKICRLPublication(
		t.Context(), PKICRLPublicationRequest{ID: "crl-publication-rpc"},
	); err != nil || publication.ID != "crl-publication-rpc" {
		t.Fatalf("InspectPKICRLPublication() = %#v, %v", publication, err)
	}
	if publications, err := client.ListPKICRLPublications(
		t.Context(), PKICRLListRequest{AuthorityID: "authority-rpc"},
	); err != nil || len(publications.Publications) != 1 {
		t.Fatalf("ListPKICRLPublications() = %#v, %v", publications, err)
	}
	if inspected, err := client.InspectPKICRL(
		t.Context(), PKICRLRequest{ID: publishedCRL.Generation.ID},
	); err != nil || inspected.ID != publishedCRL.Generation.ID {
		t.Fatalf("InspectPKICRL() = %#v, %v", inspected, err)
	}
	listedCRLs, err := client.ListPKICRLs(t.Context(), PKICRLListRequest{AuthorityID: "authority-rpc"})
	if err != nil || len(listedCRLs.CRLs) != 1 || listedCRLs.CRLs[0].ID != publishedCRL.Generation.ID {
		t.Fatalf("ListPKICRLs() = %#v, %v", listedCRLs, err)
	}
	reconciliationContext := requestContext
	reconciliationContext.ApproveCRLReconciliation = true
	reconciledCRL, err := client.ReconcilePKICRL(t.Context(), PKIMutationRequest[apppki.ReconcileCRLPublicationRequest]{
		Context: reconciliationContext,
		Request: apppki.ReconcileCRLPublicationRequest{PublicationID: "crl-publication-rpc", StaleAfterSeconds: 60},
	})
	if err != nil || reconciledCRL.ID != "crl-publication-rpc" {
		t.Fatalf("ReconcilePKICRL() = %#v, %v", reconciledCRL, err)
	}
	reconciledCRLs, err := client.ReconcilePKICRLs(t.Context(), PKIMutationRequest[apppki.ReconcileCRLPublicationsRequest]{
		Context: reconciliationContext,
		Request: apppki.ReconcileCRLPublicationsRequest{StaleAfterSeconds: 60, Limit: 10},
	})
	if err != nil || len(reconciledCRLs.Publications) != 1 {
		t.Fatalf("ReconcilePKICRLs() = %#v, %v", reconciledCRLs, err)
	}
	trustSet, err := client.CreatePKITrustSet(t.Context(), PKIMutationRequest[apppki.CreateTrustSetRequest]{
		Context: requestContext, Request: apppki.CreateTrustSetRequest{
			IdempotencyKey: "rpc:trust-create", ID: "trust-rpc", Name: "RPC trust",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.StagePKITrustSet(t.Context(), PKIMutationRequest[apppki.StageTrustSetRequest]{
		Context: requestContext, Request: apppki.StageTrustSetRequest{
			IdempotencyKey: "rpc:trust-stage", TrustSetID: trustSet.ID, ExpectedRevision: 1,
			GenerationID: "trust-rpc-generation-1", AnchorGenerationIDs: []domainpki.GenerationID{"generation-rpc-root"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ActivatePKITrustSet(t.Context(), PKIMutationRequest[apppki.ActivateTrustSetRequest]{
		Context: requestContext, Request: apppki.ActivateTrustSetRequest{
			IdempotencyKey: "rpc:trust-activate", TrustSetID: trustSet.ID, ExpectedRevision: 2,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListPKITrustSets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.InspectPKITrustSet(t.Context(), PKITrustSetRequest{ID: trustSet.ID}); err != nil {
		t.Fatal(err)
	}
	assignment, err := client.BindPKIAssignment(t.Context(), PKIMutationRequest[apppki.BindAssignmentRequest]{
		Context: requestContext, Request: apppki.BindAssignmentRequest{
			IdempotencyKey: "rpc:assignment-bind", ID: "assignment-rpc",
			Purpose: domainpki.PurposeMTLSServer, ConsumerType: domainpki.ConsumerMeshListener,
			ConsumerID: "mesh-provider/listener-rpc", ProfileID: domainpki.ProfileMTLSServer,
			TrustSetID: trustSet.ID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.StagePKIAssignment(t.Context(), PKIMutationRequest[apppki.StageAssignmentRequest]{
		Context: requestContext, Request: apppki.StageAssignmentRequest{
			IdempotencyKey: "rpc:assignment-stage", AssignmentID: assignment.ID,
			GenerationID: "generation-rpc-listener", ExpectedRevision: 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ActivatePKIAssignment(t.Context(), PKIMutationRequest[apppki.ActivateAssignmentRequest]{
		Context: requestContext, Request: apppki.ActivateAssignmentRequest{
			IdempotencyKey: "rpc:assignment-activate", AssignmentID: assignment.ID, ExpectedRevision: 2,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UnbindPKIAssignment(t.Context(), PKIMutationRequest[apppki.UnbindAssignmentRequest]{
		Context: requestContext, Request: apppki.UnbindAssignmentRequest{
			IdempotencyKey: "rpc:assignment-unbind", AssignmentID: assignment.ID, ExpectedRevision: 3,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListPKIAssignments(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.InspectPKIAssignment(t.Context(), PKIAssignmentRequest{ID: assignment.ID}); err != nil {
		t.Fatal(err)
	}
	operations, err := client.ListPKIOperations(t.Context())
	if err != nil || len(operations.Operations) != 1 || operations.Operations[0].ID != "operation-rpc" {
		t.Fatalf("ListPKIOperations() = %#v, %v", operations, err)
	}
	if inspected, err := client.InspectPKIOperation(
		t.Context(), PKIOperationRequest{ID: "operation-rpc"},
	); err != nil || inspected.Operation.ID != "operation-rpc" {
		t.Fatalf("InspectPKIOperation() = %#v, %v", inspected, err)
	}
	credentialExecutions, err := client.ListPKICredentialExecutions(t.Context())
	if err != nil || len(credentialExecutions.Executions) != 1 ||
		credentialExecutions.Executions[0].ID != "credential-execution-rpc" {
		t.Fatalf("ListPKICredentialExecutions() = %#v, %v", credentialExecutions, err)
	}
	inspectedExecution, err := client.InspectPKICredentialExecution(
		t.Context(),
		PKICredentialExecutionRequest{ID: "credential-execution-rpc"},
	)
	if err != nil || inspectedExecution.ID != "credential-execution-rpc" {
		t.Fatalf("InspectPKICredentialExecution() = %#v, %v", inspectedExecution, err)
	}
	rolloverID := domainpki.OperationID("operation-rpc-rollover")
	if _, err := client.StartPKIAuthorityRollover(
		t.Context(), PKIMutationRequest[apppki.StartAuthorityRolloverRequest]{
			Context: requestContext, Request: apppki.StartAuthorityRolloverRequest{
				IdempotencyKey: "rpc:rollover-start", OperationID: rolloverID,
				PreviousAuthorityID: "authority-rpc-old", ReplacementAuthorityID: "authority-rpc-new",
				TrustSetID: "trust-rpc", OverlapTrustGenerationID: "trustgen-rpc-overlap",
				ConsumerTracking: domainpki.RolloverConsumerTrackingNone,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AcknowledgePKIAuthorityRollover(
		t.Context(), PKIMutationRequest[apppki.AcknowledgeAuthorityRolloverRequest]{
			Context: requestContext, Request: apppki.AcknowledgeAuthorityRolloverRequest{
				IdempotencyKey: "rpc:rollover-ack", OperationID: rolloverID,
				AcknowledgementID: "ack-rpc-rollover", AssignmentID: "assignment-rpc",
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ActivatePKIAuthorityRollover(
		t.Context(), PKIMutationRequest[apppki.ActivateAuthorityRolloverRequest]{
			Context: requestContext, Request: apppki.ActivateAuthorityRolloverRequest{
				IdempotencyKey: "rpc:rollover-activate", OperationID: rolloverID,
				ExpectedRevision: 1, ExpectedTrustSetRevision: 3,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := client.BeginPKIAuthorityRolloverFinalTrust(
		t.Context(), PKIMutationRequest[apppki.BeginAuthorityRolloverFinalTrustRequest]{
			Context: requestContext, Request: apppki.BeginAuthorityRolloverFinalTrustRequest{
				IdempotencyKey: "rpc:rollover-final", OperationID: rolloverID,
				ExpectedRevision: 2, ExpectedTrustSetRevision: 4,
				FinalTrustGenerationID: "trustgen-rpc-final",
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CompletePKIAuthorityRollover(
		t.Context(), PKIMutationRequest[apppki.CompleteAuthorityRolloverRequest]{
			Context: requestContext, Request: apppki.CompleteAuthorityRolloverRequest{
				IdempotencyKey: "rpc:rollover-complete", OperationID: rolloverID,
				ExpectedRevision: 3, ExpectedTrustSetRevision: 5,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CancelPKIAuthorityRollover(
		t.Context(), PKIMutationRequest[apppki.CancelAuthorityRolloverRequest]{
			Context: requestContext, Request: apppki.CancelAuthorityRolloverRequest{
				IdempotencyKey: "rpc:rollover-cancel", OperationID: rolloverID, ExpectedRevision: 4,
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	if control.mutationActor != requestContext.ActorID {
		t.Fatalf("PKI mutation actor = %q, want %q", control.mutationActor, requestContext.ActorID)
	}
	expectedMutationKeys := []string{
		"rpc:certificate-renew",
		"rpc:certificate-rotate",
		"rpc:certificate-revoke",
		"rpc:crl-publish",
		"crl-publication-rpc",
		"crl-reconcile-batch",
		"rpc:trust-create",
		"rpc:trust-stage",
		"rpc:trust-activate",
		"rpc:assignment-bind",
		"rpc:assignment-stage",
		"rpc:assignment-activate",
		"rpc:assignment-unbind",
		"rpc:rollover-start",
		"rpc:rollover-ack",
		"rpc:rollover-activate",
		"rpc:rollover-final",
		"rpc:rollover-complete",
		"rpc:rollover-cancel",
	}
	if !reflect.DeepEqual(control.mutationKeys, expectedMutationKeys) {
		t.Fatalf("PKI mutation keys = %v, want %v", control.mutationKeys, expectedMutationKeys)
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		client.baseURL+serviceURLPrefix+rpcMethodExportBundle,
		strings.NewReader(`{"context":{"actorId":"operator-1","operationId":"operation-1","correlationId":"correlation-1"},"generationId":"certgen-test","purpose":"tls-server","includePrivate":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close private export response: %v", err)
		}
	}()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("private export status = %d", response.StatusCode)
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("private export Cache-Control = %q", got)
	}
}

func TestDaemonRPCRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	t.Parallel()

	socketPath := shortTempDir(t) + "/hoveld.sock"
	serveTestDaemon(t, socketPath, services.RunService{}, WithPKIControl(&recordingPKIControl{}))
	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	for _, payload := range []string{`{"unknown":true}`, `{} {}`} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			client.baseURL+serviceURLPrefix+rpcMethodPKIStatus, strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.httpClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("payload %q status = %d, want %d", payload, response.StatusCode, http.StatusBadRequest)
		}
		if err := response.Body.Close(); err != nil {
			t.Errorf("close invalid JSON response: %v", err)
		}
	}
}

func TestDaemonRPCRoundTripsTypedPKIErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "not found", err: apppki.ErrNotFound, want: apppki.ErrNotFound},
		{
			name: "revision conflict",
			err:  apppki.ErrRevisionConflict,
			want: apppki.ErrRevisionConflict,
		},
		{name: "acknowledgement exists", err: apppki.ErrAcknowledgementExists, want: apppki.ErrAcknowledgementExists},
		{name: "idempotency conflict", err: apppki.ErrIdempotencyConflict, want: apppki.ErrIdempotencyConflict},
		{name: "mutation exists", err: apppki.ErrMutationExists, want: apppki.ErrMutationExists},
		{name: "issuance in progress", err: apppki.ErrIssuanceInProgress, want: apppki.ErrIssuanceInProgress},
		{
			name: "crl publication in progress",
			err:  apppki.ErrCRLPublicationInProgress,
			want: apppki.ErrCRLPublicationInProgress,
		},
		{
			name: "private key export denied",
			err:  apppki.ErrPrivateKeyExportDenied,
			want: apppki.ErrPrivateKeyExportDenied,
		},
		{
			name: "authority signing locked",
			err:  apppki.ErrAuthoritySigningLocked,
			want: apppki.ErrAuthoritySigningLocked,
		},
		{
			name: "authority signing lease owned",
			err:  apppki.ErrAuthoritySigningLeaseOwned,
			want: apppki.ErrAuthoritySigningLeaseOwned,
		},
		{
			name: "rollover precondition",
			err: apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionAssignmentsNotRotated, "assignment drifted after acknowledgement",
			),
			want: apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionAssignmentsNotRotated, "",
			),
		},
		{
			name: "rollover precondition without detail",
			err: apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionResourceReserved, "",
			),
			want: apppki.NewRolloverPreconditionError(
				apppki.RolloverPreconditionResourceReserved, "",
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			control := &recordingPKIControl{rolloverErr: test.err}
			socketPath := shortTempDir(t) + "/hoveld.sock"
			serveTestDaemon(t, socketPath, services.RunService{}, WithPKIControl(control))
			client, err := Dial(socketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer closeTestClient(t, client)

			_, err = client.ActivatePKIAuthorityRollover(
				t.Context(),
				PKIMutationRequest[apppki.ActivateAuthorityRolloverRequest]{
					Context: PKIRequestContext{
						ActorID: "operator-typed-error", OperationID: "operation-typed-error",
						CorrelationID: "correlation-typed-error",
					},
					Request: apppki.ActivateAuthorityRolloverRequest{
						OperationID: "operation-rollover", ExpectedRevision: 1, ExpectedTrustSetRevision: 1,
					},
				},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("ActivatePKIAuthorityRollover() error = %v, want %v", err, test.want)
			}
			if strings.HasPrefix(test.name, "rollover precondition") {
				var typed *apppki.RolloverPreconditionError
				if !errors.As(err, &typed) {
					t.Fatalf("typed rollover error = %#v", typed)
				}
				wantDetail := ""
				if test.name == "rollover precondition" {
					wantDetail = "assignment drifted after acknowledgement"
				}
				if typed.Detail != wantDetail {
					t.Fatalf("typed rollover detail = %q, want %q", typed.Detail, wantDetail)
				}
			}
		})
	}
}

func TestDaemonRPCRejectsUnplannedExecutionCapableMeshTask(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 11, 30, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	_, err = client.RunMeshTask(context.Background(), MeshTaskRunRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.TaskRequest{
			TaskID: "unplanned-command",
			Kind:   mesh.TaskCommand,
			NodeID: "relay-1",
		},
	})
	if !errors.Is(err, errPrivilegedControlUnavailable) ||
		!strings.Contains(err.Error(), "persisted throw plan") {
		t.Fatalf("unplanned RunMeshTask error = %v, want permission denial", err)
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind: MeshOperationKindTask,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 1 ||
		operations.Operations[0].State != MeshOperationStateFailed ||
		!strings.Contains(operations.Operations[0].Error, "persisted throw plan") {
		t.Fatalf("rejected task bookkeeping = %#v", operations.Operations)
	}
}

func TestDaemonRPCTracksMeshTaskAndStreamOperations(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(recordingSessionBroker{}))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	task, err := client.RunMeshTask(context.Background(), MeshTaskRunRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.TaskRequest{
			RunID:           "run-mesh-1",
			TaskID:          "survey-destination",
			Kind:            mesh.TaskSurvey,
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
			Route:           &mesh.Route{ID: "route-relay-1", Nodes: []string{"controller", "relay-1"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "succeeded" || task.DestinationHost != "10.10.10.10" {
		t.Fatalf("mesh task = %#v", task)
	}

	session, err := client.OpenMeshStream(context.Background(), MeshStreamOpenRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-2",
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
			Config:          map[string]any{"bridge.localAddress": "127.0.0.1:1445"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "mesh-session-1" {
		t.Fatalf("mesh stream session = %#v", session)
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		ModuleID: "mesh-provider@v0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 2 {
		t.Fatalf("mesh operations = %#v, want task and stream", operations.Operations)
	}
	taskOperation := operations.Operations[0]
	if taskOperation.Kind != "task" ||
		taskOperation.State != "succeeded" ||
		taskOperation.TaskKind != "survey" ||
		taskOperation.SessionID != "mesh-task-session-1" ||
		taskOperation.DestinationHost != "10.10.10.10" ||
		taskOperation.DestinationPort != 445 ||
		taskOperation.RouteID != "route-relay-1" {
		t.Fatalf("task operation = %#v", taskOperation)
	}
	if !reflect.DeepEqual(taskOperation.SessionIDs, []string{"mesh-task-session-1", "mesh-task-session-2"}) {
		t.Fatalf("task operation sessions = %#v", taskOperation.SessionIDs)
	}
	streamOperation := operations.Operations[1]
	if streamOperation.Kind != "stream" ||
		streamOperation.State != "active" ||
		streamOperation.SessionID != "mesh-session-1" ||
		streamOperation.LocalAddress != "" {
		t.Fatalf("stream operation = %#v", streamOperation)
	}

	byTaskSession, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-task-session-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(byTaskSession.Operations) != 1 || byTaskSession.Operations[0].Kind != "task" {
		t.Fatalf("task session operations = %#v, want task operation", byTaskSession.Operations)
	}
	bySecondaryTaskSession, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-task-session-2",
		State:     "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bySecondaryTaskSession.Operations) != 0 {
		t.Fatalf("closed secondary task session operations = %#v, want none", bySecondaryTaskSession.Operations)
	}

	if err := client.CloseSession(context.Background(), "mesh-session-1"); err != nil {
		t.Fatal(err)
	}
	closed, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-session-1",
		State:     "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(closed.Operations) != 1 || closed.Operations[0].ClosedAt == "" {
		t.Fatalf("closed operations = %#v, want closed stream with timestamp", closed.Operations)
	}
	stillSucceeded, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		SessionID: "mesh-task-session-1",
		State:     "succeeded",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stillSucceeded.Operations) != 1 || stillSucceeded.Operations[0].Kind != "task" {
		t.Fatalf("task operations after stream close = %#v, want succeeded task", stillSucceeded.Operations)
	}
}

func TestDaemonRPCExposesMeshListenerLifecycleForExternalControl(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 11, 15, 30, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	started, err := client.StartMeshListener(context.Background(), MeshListenerStartRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.ListenerStartRequest{
			ListenerID: "listener-web",
			Name:       "web-controlled listener",
			Kind:       "https",
			Deployment: mesh.ListenerDeploymentSeparate,
			Management: mesh.ListenerManagementProvider,
			Config:     map[string]any{"token": "write-only-secret"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.OperationID == "" || started.Listener.ID != "listener-web" ||
		started.Listener.State != mesh.ListenerStateActive {
		t.Fatalf("started listener = %#v", started)
	}

	listed, err := client.ListMeshListeners(context.Background(), MeshListenerListRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request:  mesh.ListenerListRequest{ListenerID: "listener-web"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Listeners) != 1 || listed.Listeners[0].ID != "listener-web" {
		t.Fatalf("listed listeners = %#v", listed.Listeners)
	}

	stopped, err := client.StopMeshListener(context.Background(), MeshListenerStopRequest{
		ModuleID: "mesh-provider@v0.1.0",
		Request:  mesh.ListenerStopRequest{ListenerID: "listener-web"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.OperationID == "" || stopped.Listener.State != mesh.ListenerStateStopped {
		t.Fatalf("stopped listener = %#v", stopped)
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind:       MeshOperationKindListener,
		ListenerID: "listener-web",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 2 {
		t.Fatalf("listener operations = %#v, want start and stop", operations.Operations)
	}
	if strings.Contains(fmt.Sprintf("%#v", operations.Operations), "write-only-secret") {
		t.Fatalf("listener operations exposed write-only configuration: %#v", operations.Operations)
	}
	if operations.Operations[0].Action != MeshListenerActionStart ||
		operations.Operations[0].State != MeshOperationStateSucceeded ||
		operations.Operations[1].Action != MeshListenerActionStop ||
		operations.Operations[1].ListenerState != mesh.ListenerStateStopped {
		t.Fatalf("listener operations = %#v", operations.Operations)
	}
	startOperations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind:       MeshOperationKindListener,
		ListenerID: "listener-web",
		Action:     MeshListenerActionStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(startOperations.Operations) != 1 || startOperations.Operations[0].ID != started.OperationID {
		t.Fatalf("listener start operations = %#v, want %q", startOperations.Operations, started.OperationID)
	}
}

func TestClientOpensTCPMeshBridgeAsLocalEndpoint(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 0, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalHost:    "127.0.0.1",
		LocalNetwork: MeshBridgeNetworkTCP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bridge.OperationID == "" || bridge.SessionID != "mesh-session-1" {
		t.Fatalf("mesh bridge = %#v, want operation and mesh session", bridge)
	}
	if bridge.LocalHost != "127.0.0.1" || bridge.LocalPort == 0 || bridge.LocalAddress == "" {
		t.Fatalf("mesh bridge endpoint = %#v, want local loopback address", bridge)
	}
	if bridge.LocalNetwork != MeshBridgeNetworkTCP {
		t.Fatalf("mesh bridge local network = %q, want tcp", bridge.LocalNetwork)
	}
	if bridge.Capability.reveal() == "" {
		t.Fatal("mesh bridge capability is empty")
	}

	conn, err := net.DialTimeout("tcp", bridge.LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close bridge connection: %v", err)
		}
	}()
	framedPayload := append(meshBridgeCapabilityFrame(bridge.Capability), []byte("ping")...)
	if n, err := conn.Write(framedPayload); err != nil {
		t.Fatal(err)
	} else if n != len(framedPayload) {
		t.Fatalf("framed TCP bridge write = %d bytes, want %d", n, len(framedPayload))
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "ping" {
			t.Fatalf("session write = %q, want ping", string(got))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mesh bridge to write to session")
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("pong")}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("local bridge read = %q, want pong", string(buf[:n]))
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.closes:
		if got != bridge.SessionID {
			t.Fatalf("closed session = %q, want %q", got, bridge.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for natural mesh bridge session close")
	}
	if _, err := client.CloseMeshBridge(context.Background(), MeshBridgeCloseRequest{
		OperationID: bridge.OperationID,
	}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("CloseMeshBridge after natural close error = %v, want missing bridge", err)
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind:  "bridge",
		State: "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 1 ||
		operations.Operations[0].ID != bridge.OperationID ||
		operations.Operations[0].LocalNetwork != MeshBridgeNetworkTCP ||
		operations.Operations[0].LocalAddress != bridge.LocalAddress {
		t.Fatalf("closed bridge operations = %#v", operations.Operations)
	}
	if strings.Contains(
		fmt.Sprintf("%#v", operations.Operations),
		bridge.Capability.reveal(),
	) {
		t.Fatal("ephemeral Mesh bridge capability leaked into operation bookkeeping")
	}
}

func TestMeshBridgeOpenResponseDisablesCaching(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 10, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(newBridgeSessionBroker()))
	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		client.baseURL+serviceURLPrefix+rpcMethodOpenMeshBridge,
		strings.NewReader(`{"moduleId":"mesh-provider@v0.1.0","localNetwork":"tcp","request":{"runId":"run-no-store","destinationHost":"10.10.10.10","destinationPort":445,"protocol":"tcp"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close Mesh bridge response: %v", err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Mesh bridge open status = %d", response.StatusCode)
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Mesh bridge open Cache-Control = %q", got)
	}
	var bridge MeshBridgeOpenResponse
	if err := json.NewDecoder(response.Body).Decode(&bridge); err != nil {
		t.Fatal(err)
	}
	if bridge.Capability.reveal() == "" {
		t.Fatal("Mesh bridge response capability is empty")
	}
	if _, err := client.CloseMeshBridge(t.Context(), MeshBridgeCloseRequest{
		OperationID: bridge.OperationID,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClientOpensUDPMeshBridgeAsLocalEndpoint(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 15, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalHost:    "127.0.0.1",
		LocalNetwork: MeshBridgeNetworkUDP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-bridge",
			NodeID:          "relay-1",
			Target:          "dc-1",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bridge.OperationID == "" || bridge.SessionID != "mesh-session-1" {
		t.Fatalf("mesh bridge = %#v, want operation and mesh session", bridge)
	}
	if bridge.LocalHost != "127.0.0.1" || bridge.LocalPort == 0 || bridge.LocalAddress == "" {
		t.Fatalf("mesh bridge endpoint = %#v, want local loopback address", bridge)
	}
	if bridge.Capability.reveal() == "" {
		t.Fatal("mesh bridge capability is empty")
	}
	if bridge.LocalNetwork != MeshBridgeNetworkUDP {
		t.Fatalf("mesh bridge local network = %q, want udp", bridge.LocalNetwork)
	}

	remote, err := net.ResolveUDPAddr("udp", bridge.LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close udp bridge connection: %v", err)
		}
	}()
	authenticateUDPMeshBridge(t, conn, bridge.Capability)

	if _, err := conn.Write([]byte("dns?")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "dns?" {
			t.Fatalf("session datagram = %q, want dns?", string(got))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mesh bridge to write UDP datagram to session")
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("dns!")}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "dns!" {
		t.Fatalf("local bridge datagram = %q, want dns!", string(buf[:n]))
	}

	closed, err := client.CloseMeshBridge(context.Background(), MeshBridgeCloseRequest{
		SessionID: bridge.SessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if closed.State != "closed" || closed.OperationID != bridge.OperationID {
		t.Fatalf("closed bridge = %#v, want closed operation", closed)
	}
	select {
	case got := <-sessions.closes:
		if got != bridge.SessionID {
			t.Fatalf("closed session = %q, want %q", got, bridge.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mesh bridge session close")
	}

	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind: "bridge",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 1 ||
		operations.Operations[0].Protocol != "udp" ||
		operations.Operations[0].LocalNetwork != MeshBridgeNetworkUDP ||
		operations.Operations[0].LocalAddress != bridge.LocalAddress {
		t.Fatalf("udp bridge operations = %#v", operations.Operations)
	}
}

func TestUDPMeshBridgePreservesProviderDatagramUntilLocalPeerArrives(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 18, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalNetwork: MeshBridgeNetworkUDP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-early-reply",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, closeErr := client.CloseMeshBridge(
			context.Background(),
			MeshBridgeCloseRequest{OperationID: bridge.OperationID},
		)
		if closeErr != nil && !strings.Contains(closeErr.Error(), "does not exist") {
			t.Errorf("close UDP bridge: %v", closeErr)
		}
	}()

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("early")}
	select {
	case <-sessions.readDelivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for provider datagram read")
	}
	// Give the bridge pump time to process the provider read before a local peer
	// exists. The datagram must remain pending rather than being discarded.
	time.Sleep(25 * time.Millisecond)

	remote, err := net.ResolveUDPAddr("udp", bridge.LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close UDP peer: %v", err)
		}
	}()
	authenticateUDPMeshBridge(t, conn, bridge.Capability)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "early" {
		t.Fatalf("pending provider datagram = %q, want early", got)
	}
	if _, err := conn.Write([]byte("claim")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "claim" {
			t.Fatalf("session datagram = %q, want claim", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for authenticated local peer datagram")
	}
}

func TestUDPMeshBridgeClosesWhenProviderSessionEnds(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 20, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalNetwork: MeshBridgeNetworkUDP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-close",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Closed: true}
	select {
	case got := <-sessions.closes:
		if got != bridge.SessionID {
			t.Fatalf("closed session = %q, want %q", got, bridge.SessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for provider-closed UDP bridge cleanup")
	}
	if _, err := client.CloseMeshBridge(context.Background(), MeshBridgeCloseRequest{
		OperationID: bridge.OperationID,
	}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("CloseMeshBridge after provider close error = %v, want missing bridge", err)
	}
	operations, err := client.ListMeshOperations(context.Background(), MeshOperationListRequest{
		Kind:  "bridge",
		State: "closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations.Operations) != 1 || operations.Operations[0].ID != bridge.OperationID {
		t.Fatalf("closed UDP bridge operations = %#v", operations.Operations)
	}
}

func TestUDPMeshBridgeRequiresDatagramSessionCapability(t *testing.T) {
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	sessions := newBridgeSessionBroker()
	_, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalNetwork: MeshBridgeNetworkUDP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-capability",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{omitDatagramCapability: true},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 13, 25, 0, 0, time.UTC)},
		),
		Sessions: sessions,
		Book:     book,
		Bridges:  manager,
	})
	if err == nil || !strings.Contains(err.Error(), "datagram capability") {
		t.Fatalf("OpenMeshBridge error = %v, want datagram capability rejection", err)
	}
	select {
	case got := <-sessions.closes:
		if got != "mesh-session-1" {
			t.Fatalf("closed session = %q, want mesh-session-1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rejected UDP session cleanup")
	}
	if _, ok := manager.Find("mesh-op-1", ""); ok {
		t.Fatal("rejected UDP bridge remains tracked")
	}
	operations := book.List(MeshOperationListRequest{Kind: "bridge", State: "failed"})
	if len(operations) != 1 || !strings.Contains(operations[0].Error, "datagram capability") {
		t.Fatalf("failed UDP bridge operations = %#v", operations)
	}
}

func TestUDPMeshBridgeKeepsFirstLocalPeer(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 27, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalNetwork: MeshBridgeNetworkUDP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-peer",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "udp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, closeErr := client.CloseMeshBridge(
			context.Background(),
			MeshBridgeCloseRequest{OperationID: bridge.OperationID},
		)
		if closeErr != nil && !strings.Contains(closeErr.Error(), "does not exist") {
			t.Errorf("close UDP bridge: %v", closeErr)
		}
	}()
	remote, err := net.ResolveUDPAddr("udp", bridge.LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	first, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := first.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close first UDP peer: %v", err)
		}
	}()
	second, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := second.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close second UDP peer: %v", err)
		}
	}()

	authenticateUDPMeshBridge(t, first, bridge.Capability)
	if _, err := first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "first" {
			t.Fatalf("first session datagram = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first UDP peer")
	}
	if _, err := second.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		t.Fatalf("second UDP peer reached session: %q", got)
	case <-time.After(100 * time.Millisecond):
	}

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("reply")}
	if err := first.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	n, err := first.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "reply" {
		t.Fatalf("first UDP peer reply = %q", buf[:n])
	}
	if err := second.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(buf); err == nil {
		t.Fatal("second UDP peer received bridge reply")
	}
}

func TestTCPMeshBridgeRejectsMissingAndWrongCapabilities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 28, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalNetwork: MeshBridgeNetworkTCP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-tcp-auth",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "provider-stream",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	stalling, err := net.DialTimeout(string(MeshBridgeNetworkTCP), bridge.LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stalling.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close stalling TCP bridge peer: %v", err)
		}
	}()

	wrong, err := net.DialTimeout(string(MeshBridgeNetworkTCP), bridge.LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	authenticateMeshBridge(t, wrong, meshBridgeCapabilityValue("wrong-capability"))
	if err := wrong.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Read(make([]byte, 1)); err == nil {
		t.Fatal("TCP peer with wrong capability remained connected")
	}
	if err := wrong.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	assertNoMeshBridgeWrite(t, sessions)

	authorized, err := net.DialTimeout(string(MeshBridgeNetworkTCP), bridge.LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := authorized.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close authorized TCP bridge peer: %v", err)
		}
	}()
	authenticateMeshBridge(t, authorized, bridge.Capability)
	if _, err := authorized.Write([]byte("authorized")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "authorized" {
			t.Fatalf("authorized TCP session write = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for authorized TCP bridge write")
	}
}

func TestUDPMeshBridgeRejectsMissingAndWrongCapabilities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 29, 0, 0, time.UTC)},
	)
	sessions := newBridgeSessionBroker()
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(sessions))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalNetwork: MeshBridgeNetworkUDP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-udp-auth",
			DestinationHost: "10.10.10.53",
			DestinationPort: 53,
			Protocol:        "provider-datagram",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, closeErr := client.CloseMeshBridge(
			context.Background(),
			MeshBridgeCloseRequest{OperationID: bridge.OperationID},
		)
		if closeErr != nil && !strings.Contains(closeErr.Error(), "does not exist") {
			t.Errorf("close UDP bridge: %v", closeErr)
		}
	}()
	remote, err := net.ResolveUDPAddr(string(MeshBridgeNetworkUDP), bridge.LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := net.DialUDP(string(MeshBridgeNetworkUDP), nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := attacker.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close unauthorized UDP peer: %v", err)
		}
	}()
	if _, err := attacker.Write([]byte("missing-capability")); err != nil {
		t.Fatal(err)
	}
	authenticateUDPMeshBridge(t, attacker, meshBridgeCapabilityValue("wrong-capability"))
	assertNoMeshBridgeWrite(t, sessions)

	authorized, err := net.DialUDP(string(MeshBridgeNetworkUDP), nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := authorized.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close authorized UDP peer: %v", err)
		}
	}()
	authenticateUDPMeshBridge(t, authorized, bridge.Capability)
	if _, err := authorized.Write([]byte("authorized")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sessions.writes:
		if string(got) != "authorized" {
			t.Fatalf("authorized UDP session write = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for authorized UDP bridge write")
	}
	if _, err := attacker.Write([]byte("hijack")); err != nil {
		t.Fatal(err)
	}
	assertNoMeshBridgeWrite(t, sessions)

	sessions.reads <- run.SessionChunk{SessionID: bridge.SessionID, Data: []byte("reply")}
	if err := authorized.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("reply"))
	n, err := authorized.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "reply" {
		t.Fatalf("authorized UDP reply = %q", got)
	}
}

func TestMeshBridgeRejectsNonLoopbackLocalHost(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		fakeMeshRunner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 30, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(newBridgeSessionBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	_, err = client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:  "mesh-provider@v0.1.0",
		LocalHost: "0.0.0.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Fatalf("OpenMeshBridge error = %v, want loopback rejection", err)
	}
}

func TestMeshBridgePreservesProviderDefinedProtocol(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	streamRequests := make(chan mesh.StreamRequest, 1)
	runs := services.NewRunService(
		fakeMeshRunner{streamRequests: streamRequests},
		discardEvents{},
		&sequenceIDs{values: []string{"run-unused"}},
		fixedClock{now: time.Date(2026, 7, 9, 13, 45, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithModuleSessions(newBridgeSessionBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	bridge, err := client.OpenMeshBridge(context.Background(), MeshBridgeOpenRequest{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalHost:    "127.0.0.1",
		LocalNetwork: MeshBridgeNetworkTCP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			DestinationHost: "10.10.10.10",
			Protocol:        "icmp",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bridge.LocalNetwork != MeshBridgeNetworkTCP {
		t.Fatalf("mesh bridge local network = %q, want tcp", bridge.LocalNetwork)
	}
	select {
	case request := <-streamRequests:
		if request.Protocol != "icmp" {
			t.Fatalf("provider protocol = %q, want icmp", request.Protocol)
		}
		if request.Config[meshBridgeConfigLocalNetwork] != MeshBridgeNetworkTCP {
			t.Fatalf("provider bridge config = %#v, want local tcp network", request.Config)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for provider stream request")
	}
	if _, err := client.CloseMeshBridge(t.Context(), MeshBridgeCloseRequest{
		OperationID: bridge.OperationID,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestMeshBridgeRejectsUnsupportedLocalNetwork(t *testing.T) {
	t.Parallel()

	for _, network := range []MeshBridgeNetwork{"raw", "TCP", " tcp"} {
		t.Run(string(network), func(t *testing.T) {
			t.Parallel()

			_, err := OpenMeshBridge(t.Context(), MeshBridgeOpenArgs{
				ModuleID:     "mesh-provider@v0.1.0",
				LocalNetwork: network,
				Runs:         fakeMeshRunner{},
				Sessions:     newBridgeSessionBroker(),
				Book:         NewMeshBook(),
				Bridges:      NewMeshBridgeManager(),
			})
			if err == nil || !strings.Contains(err.Error(), "local network") {
				t.Fatalf("OpenMeshBridge error = %v, want local network rejection", err)
			}
		})
	}
}

func TestOpenMeshBridgeRejectsMissingStreamOpener(t *testing.T) {
	_, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Sessions: newBridgeSessionBroker(),
		Book:     NewMeshBook(),
		Bridges:  NewMeshBridgeManager(),
	})
	if err == nil || !strings.Contains(err.Error(), "mesh stream opener is not configured") {
		t.Fatalf("OpenMeshBridge error = %v, want missing stream opener", err)
	}
}

func TestOpenMeshBridgePassesCredentialSelectionsWithOperationScope(t *testing.T) {
	t.Parallel()

	opener := &credentialBridgeOpener{}
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	credentials := domainpki.CredentialSelections{{
		RequestID: "credential-bridge-1", AssignmentID: "assignment-bridge",
		SlotName: "tls-client", Capability: domainpki.DeliveryCapabilityRuntime,
		Material: domainpki.CredentialMaterialSelection{
			Projection: domainpki.CredentialProjectionCertificateDER,
			Form:       domainpki.CredentialMaterialPublic,
		},
	}}
	response, err := OpenMeshBridge(t.Context(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			Protocol: "tcp", NodeID: "node-edge", DestinationHost: "10.0.0.1",
		},
		Credentials:     credentials,
		CredentialScope: domainpki.CredentialOperationScope{OperationID: "credential-operation-1"},
		Runs:            opener,
		Sessions:        newBridgeSessionBroker(),
		Book:            book,
		Bridges:         manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.LocalNetwork != MeshBridgeNetworkTCP {
		t.Fatalf(
			"default local Mesh bridge network = %q, want tcp",
			response.LocalNetwork,
		)
	}
	bridge, ok := manager.Find(response.OperationID, "")
	if !ok {
		t.Fatal("credential-aware bridge was not tracked")
	}
	defer func() {
		if err := bridge.Close(t.Context()); err != nil {
			t.Errorf("close credential-aware bridge: %v", err)
		}
	}()
	if !opener.called || len(opener.credentials) != 1 {
		t.Fatalf("credential opener call = %v, credentials = %#v", opener.called, opener.credentials)
	}
	if opener.scope.OperationID != "credential-operation-1" {
		t.Fatalf("credential scope operation = %q, want stable caller id", opener.scope.OperationID)
	}
}

func TestMeshBridgeManagerIndexesAndRemovesBothSelectors(t *testing.T) {
	manager := NewMeshBridgeManager()
	bridge := &MeshBridge{operationID: "mesh-op-1", sessionID: "mesh-session-1"}
	if err := manager.Add(bridge); err != nil {
		t.Fatal(err)
	}

	for operationID, sessionID := range map[string]string{
		"mesh-op-1": "",
		"":          "mesh-session-1",
	} {
		got, ok := manager.Find(operationID, sessionID)
		if !ok || got != bridge {
			t.Fatalf("Find(%q, %q) = %#v, %v; want bridge", operationID, sessionID, got, ok)
		}
	}

	manager.Remove("mesh-op-1")
	if _, ok := manager.Find("mesh-op-1", ""); ok {
		t.Fatal("removed bridge remains indexed by operation")
	}
	if _, ok := manager.Find("", "mesh-session-1"); ok {
		t.Fatal("removed bridge remains indexed by session")
	}
}

func TestMeshBridgeManagerRejectsDuplicateSelectors(t *testing.T) {
	manager := NewMeshBridgeManager()
	if err := manager.Add(&MeshBridge{operationID: "mesh-op-1", sessionID: "mesh-session-1"}); err != nil {
		t.Fatal(err)
	}
	for _, bridge := range []*MeshBridge{
		{operationID: "mesh-op-1", sessionID: "mesh-session-2"},
		{operationID: "mesh-op-2", sessionID: "mesh-session-1"},
	} {
		if err := manager.Add(bridge); err == nil {
			t.Fatalf("Add(%#v) error = nil, want duplicate rejection", bridge)
		}
	}
}

func TestOpenMeshBridgeDoesNotAssociateRejectedDuplicateSession(t *testing.T) {
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	sessions := newBridgeSessionBroker()
	args := MeshBridgeOpenArgs{
		ModuleID:     "mesh-provider@v0.1.0",
		LocalNetwork: MeshBridgeNetworkTCP,
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-duplicate",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "provider-stream",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 13, 50, 0, 0, time.UTC)},
		),
		Sessions: sessions,
		Book:     book,
		Bridges:  manager,
	}
	first, err := OpenMeshBridge(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	bridge, ok := manager.Find(first.OperationID, "")
	if !ok {
		t.Fatal("first bridge is not tracked")
	}
	defer func() {
		if err := bridge.Close(context.Background()); err != nil {
			t.Errorf("close first bridge: %v", err)
		}
	}()

	if _, err := OpenMeshBridge(context.Background(), args); err == nil ||
		!strings.Contains(err.Error(), "already tracked") {
		t.Fatalf("second OpenMeshBridge error = %v, want duplicate session rejection", err)
	}
	failed := book.List(MeshOperationListRequest{
		Kind:  MeshOperationKindBridge,
		State: MeshOperationStateFailed,
	})
	if len(failed) != 1 || failed[0].SessionID != "" || len(failed[0].SessionIDs) != 0 {
		t.Fatalf("failed duplicate bridge operation = %#v, want no associated session", failed)
	}
}

func TestMeshBridgeRequestOwnsReservedConfig(t *testing.T) {
	tests := []struct {
		name             string
		providerProtocol string
		localNetwork     MeshBridgeNetwork
		forgedDatagram   bool
		expectedDatagram bool
	}{
		{
			name:             "udp owns datagram mode",
			providerProtocol: "dns",
			localNetwork:     MeshBridgeNetworkUDP,
			forgedDatagram:   false,
			expectedDatagram: true,
		},
		{
			name:             "tcp clears forged datagram mode",
			providerProtocol: "icmp",
			localNetwork:     MeshBridgeNetworkTCP,
			forgedDatagram:   true,
			expectedDatagram: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := meshBridgeRequest(mesh.StreamRequest{
				Protocol: test.providerProtocol,
				Config: map[string]any{
					"provider.option":            "preserved",
					meshBridgeConfigLocalAddress: "forged",
					meshBridgeConfigOwner:        "caller",
					meshBridgeConfigLocalNetwork: "forged",
					meshBridgeConfigDatagram:     test.forgedDatagram,
				}}, "127.0.0.1:1445", test.localNetwork)

			if request.Config["provider.option"] != "preserved" ||
				request.Config[meshBridgeConfigLocalAddress] != "127.0.0.1:1445" ||
				request.Config[meshBridgeConfigOwner] != meshBridgeOwnerDaemon ||
				request.Config[meshBridgeConfigLocalNetwork] != test.localNetwork ||
				request.Config[meshBridgeConfigDatagram] != test.expectedDatagram ||
				request.Protocol != test.providerProtocol {
				t.Fatalf("mesh bridge config = %#v", request.Config)
			}
		})
	}
}

func TestOpenMeshBridgeDefaultsClock(t *testing.T) {
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	response, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-bridge",
			NodeID:          "relay-1",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 14, 0, 0, 0, time.UTC)},
		),
		Sessions: newBridgeSessionBroker(),
		Book:     book,
		Bridges:  manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, ok := manager.Find(response.OperationID, "")
	if !ok {
		t.Fatal("opened bridge is not tracked")
	}
	defer func() {
		if err := bridge.Close(context.Background()); err != nil {
			t.Fatalf("close bridge: %v", err)
		}
	}()

	operations := book.List(MeshOperationListRequest{Kind: "bridge"})
	if len(operations) != 1 {
		t.Fatalf("bridge operations = %#v, want one operation", operations)
	}
	if operations[0].StartedAt == "" || operations[0].UpdatedAt == "" {
		t.Fatalf("bridge operation timestamps = %#v, want defaulted clock timestamps", operations[0])
	}
}

func TestMeshBridgeDoesNotStoreConnectionAfterClose(t *testing.T) {
	bridge := &MeshBridge{}
	bridge.setClosed()
	client, server := net.Pipe()
	defer func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close client pipe: %v", err)
		}
	}()

	if bridge.setConn(server) {
		t.Fatal("setConn after close = true, want false")
	}
	if bridge.currentConn() != nil {
		t.Fatal("currentConn after close is set, want nil")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMeshBridgeWritesEntireSessionChunkToLocalStream(t *testing.T) {
	sessions := newBridgeSessionBroker()
	sessions.reads <- run.SessionChunk{SessionID: "mesh-session-1", Data: []byte("complete"), Closed: true}
	conn := &shortWriteConn{}
	bridge := &MeshBridge{sessions: sessions, sessionID: "mesh-session-1"}

	if err := bridge.copySessionToLocal(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	if got := string(conn.data); got != "complete" {
		t.Fatalf("local stream write = %q, want complete", got)
	}
}

func TestMeshBridgeCloseRetainsProviderSessionForRetry(t *testing.T) {
	closeFailure := errors.New("provider close failed")
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	sessions := newBridgeSessionBroker()
	sessions.closeErr = closeFailure
	response, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-close-error",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 14, 5, 0, 0, time.UTC)},
		),
		Sessions: sessions,
		Book:     book,
		Bridges:  manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, ok := manager.Find(response.OperationID, "")
	if !ok {
		t.Fatal("opened bridge is not tracked")
	}
	if err := bridge.Close(context.Background()); !errors.Is(err, closeFailure) {
		t.Fatalf("first Close error = %v, want provider failure", err)
	}
	if _, ok := manager.Find(response.OperationID, ""); !ok {
		t.Fatal("failed-close bridge was removed before provider cleanup could be retried")
	}
	failed := book.List(MeshOperationListRequest{Kind: "bridge", State: "failed"})
	if len(failed) != 1 || !strings.Contains(failed[0].Error, closeFailure.Error()) {
		t.Fatalf("failed-close bridge operations = %#v", failed)
	}

	sessions.closeErr = nil
	if err := bridge.Close(context.Background()); err != nil {
		t.Fatalf("retry Close error = %v, want success", err)
	}
	if _, ok := manager.Find(response.OperationID, ""); ok {
		t.Fatal("successfully closed bridge remains tracked")
	}
	closed := book.List(MeshOperationListRequest{Kind: "bridge", State: "closed"})
	if len(closed) != 1 || closed[0].ID != response.OperationID {
		t.Fatalf("closed bridge operations = %#v", closed)
	}
}

func TestMeshBridgeFinishRetainsTransferAndCleanupErrors(t *testing.T) {
	transferFailure := errors.New("bridge transfer failed")
	closeFailure := errors.New("provider close failed")
	book := NewMeshBook()
	manager := NewMeshBridgeManager()
	sessions := newBridgeSessionBroker()
	sessions.closeErr = closeFailure
	response, err := OpenMeshBridge(context.Background(), MeshBridgeOpenArgs{
		ModuleID: "mesh-provider@v0.1.0",
		Request: mesh.StreamRequest{
			RunID:           "run-mesh-transfer-error",
			DestinationHost: "10.10.10.10",
			DestinationPort: 445,
			Protocol:        "tcp",
		},
		Runs: services.NewRunService(
			fakeMeshRunner{},
			discardEvents{},
			&sequenceIDs{values: []string{"run-unused"}},
			fixedClock{now: time.Date(2026, 7, 9, 14, 7, 0, 0, time.UTC)},
		),
		Sessions: sessions,
		Book:     book,
		Bridges:  manager,
	})
	if err != nil {
		t.Fatal(err)
	}
	bridge, ok := manager.Find(response.OperationID, "")
	if !ok {
		t.Fatal("opened bridge is not tracked")
	}
	bridge.finish(transferFailure)

	operations := book.List(MeshOperationListRequest{Kind: "bridge", State: "failed"})
	if len(operations) != 1 ||
		!strings.Contains(operations[0].Error, transferFailure.Error()) ||
		!strings.Contains(operations[0].Error, closeFailure.Error()) {
		t.Fatalf("failed bridge operations = %#v, want transfer and cleanup errors", operations)
	}
	if _, ok := manager.Find(response.OperationID, ""); !ok {
		t.Fatal("bridge with failed provider cleanup is not available for retry")
	}
	sessions.closeErr = nil
	if err := bridge.Close(context.Background()); !errors.Is(err, transferFailure) {
		t.Fatalf("retry Close error = %v, want retained transfer failure", err)
	}
	if _, ok := manager.Find(response.OperationID, ""); ok {
		t.Fatal("bridge remains tracked after provider cleanup succeeds")
	}
}

func TestCloseMeshBridgeRequiresExactlyOneSelector(t *testing.T) {
	server := &Server{}
	for _, req := range []MeshBridgeCloseRequest{
		{},
		{OperationID: "mesh-op-1", SessionID: "mesh-session-1"},
	} {
		_, err := server.closeMeshBridgeRPC(context.Background(), req)
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("closeMeshBridgeRPC(%#v) error = %v, want selector rejection", req, err)
		}
	}
}

func TestMeshBookListDefensivelyCopiesSessionIDs(t *testing.T) {
	book := NewMeshBook()
	operation := book.StartStream("mesh-provider@v0.1.0", mesh.StreamRequest{}, time.Now())
	book.ActivateStream(operation.ID, run.SessionRef{ID: "mesh-session-1"}, time.Now())

	listed := book.List(MeshOperationListRequest{})
	listed[0].SessionIDs[0] = "mutated"
	listed = book.List(MeshOperationListRequest{})
	if got := listed[0].SessionIDs[0]; got != "mesh-session-1" {
		t.Fatalf("stored session id = %q, want defensive copy", got)
	}
}

func TestMeshBookBoundsRecentOperationsAndKeepsRingIndexesCurrent(t *testing.T) {
	book := newMeshBook(2)
	now := time.Date(2026, 7, 9, 15, 0, 0, 0, time.UTC)
	first := book.StartTask("provider", mesh.TaskRequest{TaskID: "first"}, now)
	second := book.StartTask("provider", mesh.TaskRequest{TaskID: "second"}, now.Add(time.Second))
	third := book.StartTask("provider", mesh.TaskRequest{TaskID: "third"}, now.Add(2*time.Second))

	listed := book.List(MeshOperationListRequest{})
	if len(listed) != 2 || listed[0].ID != second.ID || listed[1].ID != third.ID {
		t.Fatalf("bounded Mesh operations = %#v, want second and third in order", listed)
	}
	if book.count != 2 || len(book.operations) != 2 || len(book.byID) != 2 {
		t.Fatalf(
			"Mesh book bounds = count %d, slots %d, indexes %d; want 2 each",
			book.count,
			len(book.operations),
			len(book.byID),
		)
	}
	book.CompleteTask(first.ID, mesh.TaskResult{Status: "evicted"}, now.Add(3*time.Second))
	book.CompleteTask(second.ID, mesh.TaskResult{Status: "partial"}, now.Add(4*time.Second))
	listed = book.List(MeshOperationListRequest{})
	if listed[0].ProviderStatus != "partial" || listed[0].State != MeshOperationStateFailed {
		t.Fatalf("retained ring operation = %#v, want provider status and fail-closed daemon state", listed[0])
	}
}

func TestMeshBookSeparatesProviderTaskStatusFromDaemonLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 9, 15, 5, 0, 0, time.UTC)
	tests := []struct {
		name          string
		providerState mesh.TaskStatus
		daemonState   MeshOperationState
	}{
		{name: "unknown provider status fails closed", providerState: "partial", daemonState: MeshOperationStateFailed},
		{name: "provider failure", providerState: mesh.TaskStatusFailed, daemonState: MeshOperationStateFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			book := NewMeshBook()
			operation := book.StartTask("provider", mesh.TaskRequest{TaskID: "task"}, now)
			book.CompleteTask(
				operation.ID,
				mesh.TaskResult{Status: test.providerState},
				now.Add(time.Second),
			)

			listed := book.List(MeshOperationListRequest{State: test.daemonState})
			if len(listed) != 1 || listed[0].ProviderStatus != test.providerState {
				t.Fatalf("provider task status operation = %#v", listed)
			}
			filtered := book.List(MeshOperationListRequest{ProviderStatus: test.providerState})
			if len(filtered) != 1 || filtered[0].State != test.daemonState {
				t.Fatalf("provider task status filter = %#v", filtered)
			}
			if invalid := book.List(MeshOperationListRequest{
				State: MeshOperationState(test.providerState),
			}); test.providerState == "partial" && len(invalid) != 0 {
				t.Fatalf("provider status leaked into daemon lifecycle: %#v", invalid)
			}
		})
	}
}

func authenticateMeshBridge(t *testing.T, writer io.Writer, capability MeshBridgeCapability) {
	t.Helper()
	frame := meshBridgeCapabilityFrame(capability)
	n, err := writer.Write(frame)
	if err != nil {
		t.Fatalf("write Mesh bridge capability: %v", err)
	}
	if n != len(frame) {
		t.Fatalf("write Mesh bridge capability = %d bytes, want %d", n, len(frame))
	}
}

func authenticateUDPMeshBridge(t *testing.T, writer io.Writer, capability MeshBridgeCapability) {
	t.Helper()
	frame := []byte(capability.reveal())
	n, err := writer.Write(frame)
	if err != nil {
		t.Fatalf("write UDP Mesh bridge capability: %v", err)
	}
	if n != len(frame) {
		t.Fatalf("write UDP Mesh bridge capability = %d bytes, want %d", n, len(frame))
	}
}

func assertNoMeshBridgeWrite(t *testing.T, sessions *bridgeSessionBroker) {
	t.Helper()
	select {
	case got := <-sessions.writes:
		t.Fatalf("unauthorized Mesh bridge write reached session: %q", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestMeshBookFormatsZeroTimeDeterministically(t *testing.T) {
	zero := time.Time{}
	if got, want := formatMeshTime(zero), zero.UTC().Format(time.RFC3339Nano); got != want {
		t.Fatalf("formatMeshTime(zero) = %q, want %q", got, want)
	}
}

func TestMeshBridgeCapabilityUsesFullRandomEntropy(t *testing.T) {
	first, err := newMeshBridgeCapability()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newMeshBridgeCapability()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first.reveal())
	if err != nil {
		t.Fatalf("decode capability: %v", err)
	}
	if len(decoded) != meshBridgeCapabilityBytes {
		t.Fatalf("capability entropy = %d bytes, want %d", len(decoded), meshBridgeCapabilityBytes)
	}
	if first.reveal() == second.reveal() {
		t.Fatal("independent Mesh bridges received the same capability")
	}
}

func TestMeshBridgeCapabilityIsRedactedInDiagnostics(t *testing.T) {
	t.Parallel()

	const secret = "mesh-bridge-secret"
	capability := meshBridgeCapabilityValue(secret)
	for _, format := range []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%p",
	} {
		formatted := fmt.Sprintf(format, capability)
		if strings.Contains(formatted, secret) {
			t.Fatalf("format %q exposed Mesh bridge capability: %s", format, formatted)
		}
		if format != "%p" && !strings.Contains(formatted, redactedMeshBridgeCapability) {
			t.Fatalf("format %q omitted redaction marker: %s", format, formatted)
		}
	}

	response := MeshBridgeOpenResponse{Capability: capability}
	formatted := fmt.Sprintf("%#v", response)
	if strings.Contains(formatted, secret) ||
		!strings.Contains(formatted, redactedMeshBridgeCapability) {
		t.Fatalf("response diagnostics did not redact Mesh bridge capability: %s", formatted)
	}
}

func TestSessionClientPublishesModuleAddedLog(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}

	logs, err := client.PollLogs(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Logs) != 2 {
		t.Fatalf("log count = %d, want 2: %#v", len(logs.Logs), logs.Logs)
	}
	got := logs.Logs[1]
	if got.Chain != "c1" || got.Entry.Message != "module added" || got.Entry.Fields["module"] != "mock-survey" {
		t.Fatalf("published log = %#v", got)
	}
}

func TestPollChainLogsOnlyReturnsRequestedChain(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	alphaLogs, err := client.PollChainLogs(context.Background(), "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alphaLogs.Logs) != 2 {
		t.Fatalf("alpha log count = %d, want 2: %#v", len(alphaLogs.Logs), alphaLogs.Logs)
	}
	for _, log := range alphaLogs.Logs {
		if log.Chain != "alpha" {
			t.Fatalf("alpha poll returned chain %q log: %#v", log.Chain, log)
		}
	}

	allLogs, err := client.PollLogs(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(allLogs.Logs) != 4 {
		t.Fatalf("all log count = %d, want 4: %#v", len(allLogs.Logs), allLogs.Logs)
	}
}

func TestLogBrokerRetainsBoundedHistory(t *testing.T) {
	broker := NewLogBrokerWithLimit(3)
	for i := 1; i <= 10; i++ {
		chain := "alpha"
		if i%2 == 0 {
			chain = "beta"
		}
		broker.Publish("op", chain, operatorlog.Entry{Message: "log"})
	}

	last, logs := broker.Since(0)
	if last != 10 {
		t.Fatalf("last = %d, want 10", last)
	}
	if len(logs) != 3 {
		t.Fatalf("retained logs = %d, want 3", len(logs))
	}
	if logs[0].Seq != 8 || logs[2].Seq != 10 {
		t.Fatalf("retained seqs = %#v, want 8..10", logs)
	}

	last, alpha := broker.SinceChain("op", "alpha", 0)
	if last != 10 {
		t.Fatalf("chain last = %d, want 10", last)
	}
	if len(alpha) != 1 || alpha[0].Seq != 9 {
		t.Fatalf("alpha logs = %#v, want only retained alpha seq 9", alpha)
	}
}

func TestLogBrokerPublishDoesNotScanHistory(t *testing.T) {
	broker := NewLogBrokerWithLimit(32)
	started := time.Now()
	for i := 0; i < 10000; i++ {
		broker.Publish("op", "chain", operatorlog.Entry{Message: "log"})
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("publishing 10000 bounded logs took %s, want under 500ms", elapsed)
	}
	if len(broker.logs) != 32 {
		t.Fatalf("retained logs = %d, want 32", len(broker.logs))
	}
}

func TestSessionLogFloodIsBoundedThroughRPC(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBrokerWithLimit(64)))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseOperation("flood-op"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("flood"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250; i++ {
		if err := session.AppendLog(operatorlog.Info("flood", "log")); err != nil {
			t.Fatal(err)
		}
	}

	logs, err := client.PollOperationChainLogs(context.Background(), "flood-op", "flood", 0)
	if err != nil {
		t.Fatal(err)
	}
	if logs.Last < 250 {
		t.Fatalf("last = %d, want at least 250 flood logs", logs.Last)
	}
	if len(logs.Logs) != 64 {
		t.Fatalf("retained logs = %d, want broker limit 64", len(logs.Logs))
	}
	wantFirst := logs.Last - uint64(len(logs.Logs)) + 1
	if logs.Logs[0].Seq != wantFirst || logs.Logs[len(logs.Logs)-1].Seq != logs.Last {
		t.Fatalf("retained seq range = %d..%d, want contiguous tail %d..%d", logs.Logs[0].Seq, logs.Logs[len(logs.Logs)-1].Seq, wantFirst, logs.Last)
	}

	next, err := client.PollOperationChainLogs(context.Background(), "flood-op", "flood", logs.Last)
	if err != nil {
		t.Fatal(err)
	}
	if next.Last != logs.Last || len(next.Logs) != 0 {
		t.Fatalf("poll after cursor = %#v, want no new logs", next)
	}
}

func TestConcurrentSessionClientsAppendLogsWithoutCrossChainContamination(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBrokerWithLimit(512)))

	clientA, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientA)
	clientB, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientB)

	alpha := NewSessionClient(context.Background(), clientA)
	beta := NewSessionClient(context.Background(), clientB)
	for _, setup := range []struct {
		name    string
		session *SessionClient
		chain   string
	}{
		{name: "alpha", session: alpha, chain: "alpha"},
		{name: "beta", session: beta, chain: "beta"},
	} {
		if err := setup.session.UseOperation("concurrent-op"); err != nil {
			t.Fatalf("%s operation: %v", setup.name, err)
		}
		if err := setup.session.UseChain(setup.chain); err != nil {
			t.Fatalf("%s chain: %v", setup.name, err)
		}
	}
	alphaCursor, err := clientA.PollOperationChainLogs(context.Background(), "concurrent-op", "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	betaCursor, err := clientB.PollOperationChainLogs(context.Background(), "concurrent-op", "beta", 0)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	appendLogs := func(session *SessionClient, chain string) {
		<-start
		for i := 0; i < 50; i++ {
			if err := session.AppendLog(operatorlog.Info("concurrent", fmt.Sprintf("%s-%02d", chain, i))); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}
	go appendLogs(alpha, "alpha")
	go appendLogs(beta, "beta")
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	alphaLogs, err := clientA.PollOperationChainLogs(context.Background(), "concurrent-op", "alpha", alphaCursor.Last)
	if err != nil {
		t.Fatal(err)
	}
	betaLogs, err := clientB.PollOperationChainLogs(context.Background(), "concurrent-op", "beta", betaCursor.Last)
	if err != nil {
		t.Fatal(err)
	}
	assertConcurrentChainLogs(t, "alpha", alphaLogs.Logs)
	assertConcurrentChainLogs(t, "beta", betaLogs.Logs)
}

func assertConcurrentChainLogs(t *testing.T, chain string, logs []PublishedLog) {
	t.Helper()
	if len(logs) != 50 {
		t.Fatalf("%s log count = %d, want 50: %#v", chain, len(logs), logs)
	}
	for i, log := range logs {
		if log.Operation != "concurrent-op" || log.Chain != chain {
			t.Fatalf("%s log %d topic = %s/%s, want concurrent-op/%s: %#v", chain, i, log.Operation, log.Chain, chain, log)
		}
		wantMessage := fmt.Sprintf("%s-%02d", chain, i)
		if log.Entry.Message != wantMessage {
			t.Fatalf("%s log %d message = %q, want %q", chain, i, log.Entry.Message, wantMessage)
		}
	}
}

func TestSessionClientsKeepIndependentOperationChainAttachments(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	clientA, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientA)
	clientB, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, clientB)

	alpha := NewSessionClient(context.Background(), clientA)
	beta := NewSessionClient(context.Background(), clientB)
	if err := alpha.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := beta.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := alpha.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.UseChain("beta"); err != nil {
		t.Fatal(err)
	}
	if err := alpha.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := beta.AddTarget("mock://beta"); err != nil {
		t.Fatal(err)
	}
	if _, err := alpha.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}
	if _, err := beta.AddModule("mock-exploit"); err != nil {
		t.Fatal(err)
	}

	alphaState := alpha.Snapshot()
	if alphaState.ActiveOperation != "redteam-lab" || alphaState.ActiveChain != "alpha" {
		t.Fatalf("alpha attachment = %s/%s, want redteam-lab/alpha", alphaState.ActiveOperation, alphaState.ActiveChain)
	}
	if got, want := alphaState.OperationTargets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alpha operation targets = %#v, want %#v", got, want)
	}
	if got, want := alphaState.Targets, []string{"mock://alpha"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("alpha chain targets = %#v, want %#v", got, want)
	}
	betaState := beta.Snapshot()
	if betaState.ActiveOperation != "redteam-lab" || betaState.ActiveChain != "beta" {
		t.Fatalf("beta attachment = %s/%s, want redteam-lab/beta", betaState.ActiveOperation, betaState.ActiveChain)
	}
	if got, want := betaState.OperationTargets, []string{"mock://alpha", "mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("beta operation targets = %#v, want %#v", got, want)
	}
	if got, want := betaState.Targets, []string{"mock://beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("beta chain targets = %#v, want %#v", got, want)
	}

	alphaLogs, err := clientA.PollOperationChainLogs(context.Background(), "redteam-lab", "alpha", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, log := range alphaLogs.Logs {
		if log.Operation != "redteam-lab" || log.Chain != "alpha" {
			t.Fatalf("alpha poll returned wrong topic: %#v", log)
		}
	}
}

func TestSessionClientBindsAndUnbindsOperationTarget(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs, WithSession(operatorsession.New()), WithLogBroker(NewLogBroker()))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	session := NewSessionClient(context.Background(), client)
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://ops"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.BindTarget("mock://ops"); err != nil {
		t.Fatal(err)
	}
	if got, want := session.Snapshot().Targets, []string{"mock://ops"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bound chain targets = %#v, want %#v", got, want)
	}

	if err := session.UnbindTarget("mock://ops"); err != nil {
		t.Fatal(err)
	}
	state := session.Snapshot()
	if len(state.Targets) != 0 {
		t.Fatalf("chain targets after unbind = %#v, want none", state.Targets)
	}
	if got, want := state.OperationTargets, []string{"mock://ops"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("operation targets after unbind = %#v, want %#v", got, want)
	}
}

func TestSessionMutationsPersistSnapshots(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithLogBroker(NewLogBroker()),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseOperation("redteam-lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTarget("mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.CreateTargetSet("lab"); err != nil {
		t.Fatal(err)
	}
	if err := session.AddTargetToSet("lab", "mock://alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.AddModule("mock-survey"); err != nil {
		t.Fatal(err)
	}

	if len(persisted) == 0 {
		t.Fatal("no persisted snapshots")
	}
	last := persisted[len(persisted)-1]
	var gotOperation operatorsession.PersistedOperation
	var got operatorsession.PersistedChain
	for _, operation := range last.Operations {
		if operation.Name != "redteam-lab" {
			continue
		}
		gotOperation = operation
		for _, chain := range operation.Chains {
			if chain.Name == "alpha" {
				got = chain
			}
		}
	}
	if got.Name != "alpha" {
		t.Fatalf("persisted operations = %#v, want redteam-lab/alpha", last.Operations)
	}
	if !reflect.DeepEqual(gotOperation.Targets, []string{"mock://alpha"}) {
		t.Fatalf("persisted operation targets = %#v", gotOperation.Targets)
	}
	if !reflect.DeepEqual(gotOperation.TargetSets, []operatorsession.TargetSet{{Name: "lab", Targets: []string{"mock://alpha"}}}) {
		t.Fatalf("persisted operation target sets = %#v", gotOperation.TargetSets)
	}
	if !reflect.DeepEqual(got.Targets, []string{"mock://alpha"}) {
		t.Fatalf("persisted chain targets = %#v, want alpha", got.Targets)
	}
	if !reflect.DeepEqual(got.Steps, []operatorsession.Step{{ID: "step-1", ModuleID: "mock-survey"}}) {
		t.Fatalf("persisted steps = %#v", got.Steps)
	}
}

func TestActiveLogsDoesNotPersistSnapshot(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithLogBroker(NewLogBroker()),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	session := NewSessionClient(context.Background(), client)
	if err := session.UseChain("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := session.AppendLogToChain("alpha", operatorlogEntryFromTest("existing log")); err != nil {
		t.Fatal(err)
	}
	persistCount := len(persisted)
	if persistCount == 0 {
		t.Fatal("setup did not persist")
	}

	logs := session.ActiveLogs()
	if len(logs) != 1 || logs[0].Message != "existing log" {
		t.Fatalf("active logs = %#v", logs)
	}
	if len(persisted) != persistCount {
		t.Fatalf("persist count = %d, want %d after read-only ActiveLogs", len(persisted), persistCount)
	}
}

func TestClientCanAttachHeartbeatAndDetachOperatorEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	clock := &mutableClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
	serveTestDaemon(t, socketPath, runs, WithOperatorClock(clock))

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	attached, err := client.AttachEntity(context.Background(), AttachEntityRequest{
		ID:           "entity-mcp",
		Kind:         "mcp",
		DisplayName:  "codex",
		Agent:        true,
		Operation:    "redteam-lab",
		ActiveChain:  "alpha",
		Capabilities: []string{"tools", "resources"},
		PolicyTags:   []string{"allow-plan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attached.Entity.ID != "entity-mcp" || attached.Entity.Kind != "mcp" || !attached.Entity.Agent {
		t.Fatalf("attached entity = %#v", attached.Entity)
	}
	if attached.Entity.ConnectedAt != "2026-06-20T12:00:00Z" || attached.Entity.LastSeenAt != "2026-06-20T12:00:00Z" {
		t.Fatalf("attached times = %s/%s", attached.Entity.ConnectedAt, attached.Entity.LastSeenAt)
	}

	clock.now = clock.now.Add(30 * time.Second)
	heartbeat, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{
		ID:          "entity-mcp",
		Operation:   stringPtr("redteam-lab"),
		ActiveChain: stringPtr("bravo"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.Entity.ConnectedAt != "2026-06-20T12:00:00Z" || heartbeat.Entity.LastSeenAt != "2026-06-20T12:00:30Z" {
		t.Fatalf("heartbeat times = %s/%s", heartbeat.Entity.ConnectedAt, heartbeat.Entity.LastSeenAt)
	}
	if heartbeat.Entity.ActiveChain != "bravo" {
		t.Fatalf("heartbeat active chain = %q, want bravo", heartbeat.Entity.ActiveChain)
	}

	entities, err := client.ListEntities(context.Background(), ListEntitiesRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entityIDs(entities.Entities), []string{"entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("entities = %#v, want %#v", got, want)
	}

	cleared, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{
		ID:          "entity-mcp",
		Operation:   stringPtr(""),
		ActiveChain: stringPtr(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Entity.Operation != "" || cleared.Entity.ActiveChain != "" {
		t.Fatalf("cleared entity operation/chain = %q/%q, want empty", cleared.Entity.Operation, cleared.Entity.ActiveChain)
	}

	entities, err = client.ListEntities(context.Background(), ListEntitiesRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entities.Entities) != 0 {
		t.Fatalf("entities after clearing operation = %#v, want none for redteam-lab", entities.Entities)
	}

	if err := client.DetachEntity(context.Background(), DetachEntityRequest{ID: "entity-mcp"}); err != nil {
		t.Fatal(err)
	}
	entities, err = client.ListEntities(context.Background(), ListEntitiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entities.Entities) != 0 {
		t.Fatalf("entities after detach = %#v, want none", entities.Entities)
	}
}

func TestOperatorEntityAttachmentsDoNotPersistSessionSnapshots(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	var persisted []operatorsession.PersistedState
	serveTestDaemon(t, socketPath, runs,
		WithSession(operatorsession.New()),
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithSessionPersistence(func(state operatorsession.PersistedState) error {
			persisted = append(persisted, state)
			return nil
		}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.HeartbeatEntity(context.Background(), HeartbeatEntityRequest{ID: "entity-cli", Operation: stringPtr("redteam-lab")}); err != nil {
		t.Fatal(err)
	}
	if err := client.DetachEntity(context.Background(), DetachEntityRequest{ID: "entity-cli"}); err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 0 {
		t.Fatalf("persisted snapshots = %#v, want none for live operator entity lifecycle", persisted)
	}
}

func TestClientCoordinatesLaunchKeyApprovalsFromLiveEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAllConnected, HeartbeatTimeout: time.Minute}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-mcp", Kind: "mcp", Agent: true, Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}

	pending, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{
		ID:             "pending-1",
		Operation:      "redteam-lab",
		Chain:          "alpha",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready {
		t.Fatalf("pending throw unexpectedly ready: %#v", pending)
	}
	if got, want := pending.MissingApproverIDs, []string{"entity-cli", "entity-mcp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("missing approvers = %#v, want %#v", got, want)
	}

	if _, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err == nil {
		t.Fatal("RequirePendingThrowReady returned nil error before approvals")
	}

	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:             "pending-1",
		EntityID:       "entity-mcp",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Ready || !reflect.DeepEqual(pending.MissingApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("pending after mcp approval = %#v, want entity-cli missing", pending)
	}

	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:             "pending-1",
		EntityID:       "entity-cli",
		PlanHash:       "hash-1",
		AllowDangerous: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || len(pending.MissingApproverIDs) != 0 {
		t.Fatalf("pending after all approvals = %#v, want ready", pending)
	}
	if ready, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err != nil || !ready.Ready {
		t.Fatalf("RequirePendingThrowReady = %#v, %v; want ready", ready, err)
	}
}

func TestLaunchKeyPendingThrowSnapshotsRequiredEntities(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithOperatorClock(fixedClock{now: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}),
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAllConnected, HeartbeatTimeout: time.Minute}),
	)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-cli", Kind: "cli", Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	pending, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{
		ID:        "pending-1",
		Operation: "redteam-lab",
		Chain:     "alpha",
		PlanHash:  "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pending.RequiredApproverIDs, []string{"entity-cli"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("required approvers = %#v, want snapshot %#v", got, want)
	}

	if _, err := client.AttachEntity(context.Background(), AttachEntityRequest{ID: "entity-mcp", Kind: "mcp", Agent: true, Operation: "redteam-lab", ActiveChain: "alpha"}); err != nil {
		t.Fatal(err)
	}
	pending, err = client.ConfirmPendingThrow(context.Background(), ConfirmPendingThrowRequest{
		ID:       "pending-1",
		EntityID: "entity-cli",
		PlanHash: "hash-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Ready || !reflect.DeepEqual(pending.RequiredApproverIDs, []string{"entity-cli"}) {
		t.Fatalf("pending after late attachment = %#v, want original snapshot ready", pending)
	}
}

func TestClientCancelsPendingLaunchKeyThrow(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1", "event-1", "event-2"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs)

	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)
	if _, err := client.CreatePendingThrow(context.Background(), CreatePendingThrowRequest{ID: "pending-1", Operation: "redteam-lab", Chain: "alpha", PlanHash: "hash-1"}); err != nil {
		t.Fatal(err)
	}
	if err := client.CancelPendingThrow(context.Background(), PendingThrowRequest{ID: "pending-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RequirePendingThrowReady(context.Background(), PendingThrowRequest{ID: "pending-1"}); err == nil {
		t.Fatal("RequirePendingThrowReady returned nil after cancel")
	}
}

func TestClientQueriesAndOverridesLaunchKeyPolicy(t *testing.T) {
	socketPath := shortTempDir(t) + "/hoveld.sock"
	runs := services.NewRunService(
		mockexploit.Runner{},
		discardEvents{},
		&sequenceIDs{values: []string{"run-1"}},
		fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)},
	)
	serveTestDaemon(t, socketPath, runs,
		WithLaunchKeyPolicy(operatordomain.LaunchKeyPolicy{Mode: operatordomain.LaunchKeyAnyone}),
	)
	client, err := Dial(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestClient(t, client)

	policy, err := client.GetLaunchKeyPolicy(context.Background(), LaunchKeyPolicyRequest{Operation: "redteam-lab"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Policy.Mode != "anyone" {
		t.Fatalf("default policy = %#v, want anyone", policy)
	}
	policy, err = client.SetLaunchKeyPolicy(context.Background(), SetLaunchKeyPolicyRequest{Operation: "redteam-lab", Mode: "quorum", Quorum: 2, HeartbeatTimeout: "30s"})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Operation != "redteam-lab" || policy.Policy.Mode != "quorum" || policy.Policy.Quorum != 2 || policy.Policy.HeartbeatTimeout != "30s" {
		t.Fatalf("set policy = %#v, want quorum override", policy)
	}
	if _, err := client.SetLaunchKeyPolicy(context.Background(), SetLaunchKeyPolicyRequest{Operation: "redteam-lab", Mode: "quorum"}); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("invalid quorum error = %v, want quorum error", err)
	}
}

func entityIDs(entities []OperatorEntity) []string {
	ids := make([]string, 0, len(entities))
	for _, entity := range entities {
		ids = append(ids, entity.ID)
	}
	return ids
}

func stringPtr(value string) *string {
	return &value
}

func TestSessionRPCPropagatesRequestContext(t *testing.T) {
	server := &Server{moduleSessions: contextCheckingSessionBroker{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.listSessionsRPC(ctx, EmptyRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list sessions error = %v, want context canceled", err)
	}
	if _, err := server.readSessionRPC(ctx, SessionReadRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("read session error = %v, want context canceled", err)
	}
	if _, err := server.tailSessionRPC(ctx, SessionTailRequest{SessionID: "s1", MaxLines: 20}); !errors.Is(err, context.Canceled) {
		t.Fatalf("tail session error = %v, want context canceled", err)
	}
	if _, err := server.writeSessionRPC(ctx, SessionWriteRequest{SessionID: "s1", Data: []byte("x")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("write session error = %v, want context canceled", err)
	}
	if _, err := server.closeSessionRPC(ctx, SessionCloseRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("close session error = %v, want context canceled", err)
	}
	if _, err := server.listSessionCommandsRPC(ctx, SessionCommandListRequest{SessionID: "s1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("list session commands error = %v, want context canceled", err)
	}
	if _, err := server.runSessionCommandRPC(ctx, SessionCommandRunRequest{SessionID: "s1", Request: run.PayloadCommandRequest{Command: "process.list"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("run session command error = %v, want context canceled", err)
	}
}

func operatorlogEntryFromTest(message string) operatorlog.Entry {
	return operatorlog.Entry{Message: message}
}

type contextCheckingSessionBroker struct{}

func (contextCheckingSessionBroker) ListSessions(ctx context.Context) ([]run.SessionRef, error) {
	return nil, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) WriteSession(ctx context.Context, _ string, _ []byte) error {
	return contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) ReadSession(ctx context.Context, _ string, _ time.Duration) (run.SessionChunk, error) {
	return run.SessionChunk{}, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) TailSession(ctx context.Context, _ string, _ run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) CloseSession(ctx context.Context, _ string) error {
	return contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) ListSessionCommands(ctx context.Context, _ string, _ run.PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	return nil, contextOrMissing(ctx)
}

func (contextCheckingSessionBroker) RunSessionCommand(ctx context.Context, _ string, _ run.PayloadCommandRequest) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, contextOrMissing(ctx)
}

func contextOrMissing(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("request context was not propagated")
}

type fakeMeshRunner struct {
	omitDatagramCapability bool
	streamRequests         chan<- mesh.StreamRequest
}

type credentialBridgeOpener struct {
	called      bool
	credentials domainpki.CredentialSelections
	scope       domainpki.CredentialOperationScope
}

func (*credentialBridgeOpener) OpenMeshStream(
	context.Context,
	string,
	mesh.StreamRequest,
) (run.SessionRef, error) {
	return run.SessionRef{}, errors.New("credential bridge used the credential-free opener")
}

func (o *credentialBridgeOpener) OpenMeshStreamWithCredentialSelections(
	_ context.Context,
	moduleID string,
	_ mesh.StreamRequest,
	credentials domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
) (run.SessionRef, error) {
	o.called = true
	o.credentials = credentials.Clone()
	o.scope = scope
	return run.SessionRef{
		ID: "mesh-credential-session-1", ModuleID: moduleID, State: "active",
	}, nil
}

func (fakeMeshRunner) Run(_ context.Context, req run.Request) (run.Result, error) {
	return run.Succeeded(req, run.ResultArgs{Summary: "unused fake mesh run"})
}

func (fakeMeshRunner) DescribeMesh(
	_ context.Context,
	_ string,
	_ mesh.DescribeRequest,
) (mesh.Descriptor, error) {
	return mesh.Descriptor{Name: "mesh-provider"}, nil
}

func (fakeMeshRunner) MeshTopology(
	_ context.Context,
	_ string,
	_ mesh.TopologyRequest,
) (mesh.Topology, error) {
	return mesh.Topology{}, nil
}

func (fakeMeshRunner) ListMeshBeacons(
	_ context.Context,
	_ string,
	_ mesh.BeaconRequest,
) ([]mesh.Beacon, error) {
	return []mesh.Beacon{}, nil
}

func (fakeMeshRunner) ListMeshListeners(
	_ context.Context,
	_ string,
	req mesh.ListenerListRequest,
) ([]mesh.Listener, error) {
	listenerID := req.ListenerID
	if listenerID == "" {
		listenerID = "listener-primary"
	}
	return []mesh.Listener{{
		ID:         listenerID,
		Name:       "primary HTTPS listener",
		Kind:       "https",
		State:      mesh.ListenerStateActive,
		Deployment: mesh.ListenerDeploymentSeparate,
		Management: mesh.ListenerManagementProvider,
		Addresses:  []string{"https://127.0.0.1:8443"},
		Protocols:  []string{"https"},
	}}, nil
}

func (fakeMeshRunner) StartMeshListener(
	_ context.Context,
	_ string,
	req mesh.ListenerStartRequest,
) (mesh.Listener, error) {
	return mesh.Listener{
		ID:         req.ListenerID,
		Name:       req.Name,
		Kind:       req.Kind,
		State:      mesh.ListenerStateActive,
		Deployment: req.Deployment,
		Management: req.Management,
		Addresses:  []string{"https://127.0.0.1:8443"},
		Protocols:  []string{"https"},
	}, nil
}

func (fakeMeshRunner) StopMeshListener(
	_ context.Context,
	_ string,
	req mesh.ListenerStopRequest,
) (mesh.Listener, error) {
	return mesh.Listener{
		ID:         req.ListenerID,
		State:      mesh.ListenerStateStopped,
		Deployment: mesh.ListenerDeploymentSeparate,
		Management: mesh.ListenerManagementProvider,
	}, nil
}

func (fakeMeshRunner) RunMeshTask(
	_ context.Context,
	moduleID string,
	req mesh.TaskRequest,
) (mesh.TaskResult, error) {
	return mesh.TaskResult{
		TaskID:          req.TaskID,
		Status:          "succeeded",
		Summary:         "mesh task routed",
		NodeID:          req.NodeID,
		Route:           req.Route,
		DestinationHost: req.DestinationHost,
		DestinationPort: req.DestinationPort,
		Protocol:        req.Protocol,
		Sessions: []run.SessionRef{
			{
				ID:       "mesh-task-session-1",
				RunID:    req.RunID,
				ModuleID: moduleID,
				Target:   req.Target,
				Name:     "task-opened session",
				Kind:     "agent",
				State:    "active",
			},
			{
				ID:       "mesh-task-session-2",
				RunID:    req.RunID,
				ModuleID: moduleID,
				Target:   req.Target,
				Name:     "task-secondary session",
				Kind:     "stream",
				State:    "active",
			},
		},
	}, nil
}

func (r fakeMeshRunner) OpenMeshStream(
	_ context.Context,
	moduleID string,
	req mesh.StreamRequest,
) (run.SessionRef, error) {
	if r.streamRequests != nil {
		r.streamRequests <- req
	}
	session := run.SessionRef{
		ID:        "mesh-session-1",
		RunID:     req.RunID,
		ModuleID:  moduleID,
		Target:    req.Target,
		Name:      "Mesh routed session",
		Kind:      "stream",
		State:     "active",
		Transport: "mesh-route",
	}
	datagramBridge, _ := req.Config[meshBridgeConfigDatagram].(bool)
	if (datagramBridge || req.Protocol == "udp") && !r.omitDatagramCapability {
		session.Capabilities = []string{run.SessionCapabilityDatagram}
	}
	return session, nil
}

type recordingPKIControl struct {
	initialized   bool
	initializedBy string
	mutationActor string
	mutationKeys  []string
	rolloverErr   error
}

func (*recordingPKIControl) Close() error { return nil }

func (c *recordingPKIControl) Status(context.Context) apppki.WorkspaceStatus {
	return apppki.WorkspaceStatus{Initialized: c.initialized}
}

func (c *recordingPKIControl) Initialize(ctx context.Context) (apppki.WorkspaceStatus, error) {
	audit, err := (apppki.ContextAuditContextProvider{}).AuditContext(ctx)
	if err != nil {
		return apppki.WorkspaceStatus{}, err
	}
	c.initialized = true
	c.initializedBy = audit.ActorID
	return apppki.WorkspaceStatus{Initialized: true, ActiveKeyVersion: "master-key-v1", MasterKeyVersions: 1}, nil
}

func (*recordingPKIControl) BackendDescriptors(context.Context) ([]domainpki.BackendDescriptor, error) {
	return nil, nil
}

func (*recordingPKIControl) ListAuthorities(context.Context) ([]domainpki.Authority, error) {
	return nil, nil
}

func (*recordingPKIControl) InspectAuthority(context.Context, domainpki.AuthorityID) (apppki.AuthorityInspection, error) {
	return apppki.AuthorityInspection{}, nil
}

func (*recordingPKIControl) ListCertificateGenerations(context.Context) ([]domainpki.CertificateGeneration, error) {
	return nil, nil
}

func (*recordingPKIControl) InspectCertificateGeneration(context.Context, domainpki.GenerationID) (domainpki.CertificateGeneration, error) {
	return domainpki.CertificateGeneration{}, nil
}

func (*recordingPKIControl) ListAssignments(context.Context) ([]domainpki.Assignment, error) {
	return nil, nil
}

func (*recordingPKIControl) ListCredentialStamps(context.Context) ([]domainpki.CredentialStamp, error) {
	return nil, nil
}

func (*recordingPKIControl) InspectCredentialStamp(
	context.Context,
	domainpki.StampID,
) (domainpki.CredentialStamp, error) {
	return domainpki.CredentialStamp{}, nil
}

func (*recordingPKIControl) ListCredentialExecutions(
	context.Context,
) ([]domainpki.CredentialExecution, error) {
	execution, err := newRecordingCredentialExecution("credential-execution-rpc")
	if err != nil {
		return nil, err
	}
	return []domainpki.CredentialExecution{execution}, nil
}

func (*recordingPKIControl) InspectCredentialExecution(
	_ context.Context,
	id domainpki.CredentialExecutionRequestID,
) (domainpki.CredentialExecution, error) {
	return newRecordingCredentialExecution(id)
}

func newRecordingCredentialExecution(
	id domainpki.CredentialExecutionRequestID,
) (domainpki.CredentialExecution, error) {
	data := domainpki.CredentialBytes("credential-execution-rpc-material")
	digest := sha256.Sum256(data)
	provider := domainpki.CredentialProviderTarget{
		ModuleID: "credential-provider-rpc", ProviderID: "credential-provider-rpc",
		ProviderVersion: "1.0.0", DescriptorSHA256: strings.Repeat("a", sha256.Size*2),
	}
	return domainpki.NewEncodingCredentialExecution(domainpki.CredentialEncodingRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      provider, RequestID: id, ProviderID: provider.ProviderID,
		ProviderSchema:      "credential-provider-rpc-v1",
		OutputForm:          domainpki.CredentialMaterialPrivateBytes,
		MaximumEncodedBytes: 1024,
		Source: domainpki.ResolvedCredentialMaterial{
			Projection: domainpki.CredentialProjectionBundle,
			Form:       domainpki.CredentialMaterialPrivateBytes,
			Encoding:   "hovel-bundle-json", SHA256: hex.EncodeToString(digest[:]), Data: data,
		},
		Scope: domainpki.CredentialOperationScope{RunID: "run-rpc"},
	}, time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC))
}

func (*recordingPKIControl) InspectAssignment(context.Context, domainpki.AssignmentID) (apppki.AssignmentInspection, error) {
	return apppki.AssignmentInspection{}, nil
}

func (c *recordingPKIControl) BindAssignment(ctx context.Context, request apppki.BindAssignmentRequest) (domainpki.Assignment, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return domainpki.Assignment{}, err
	}
	return domainpki.Assignment{ID: request.ID}, nil
}

func (c *recordingPKIControl) StageAssignment(ctx context.Context, request apppki.StageAssignmentRequest) (apppki.AssignmentInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.AssignmentInspection{}, err
	}
	return apppki.AssignmentInspection{Assignment: domainpki.Assignment{ID: request.AssignmentID}}, nil
}

func (c *recordingPKIControl) ActivateAssignment(ctx context.Context, request apppki.ActivateAssignmentRequest) (apppki.AssignmentInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.AssignmentInspection{}, err
	}
	return apppki.AssignmentInspection{Assignment: domainpki.Assignment{ID: request.AssignmentID}}, nil
}

func (c *recordingPKIControl) UnbindAssignment(ctx context.Context, request apppki.UnbindAssignmentRequest) (domainpki.Assignment, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return domainpki.Assignment{}, err
	}
	return domainpki.Assignment{ID: request.AssignmentID}, nil
}

func (*recordingPKIControl) ListTrustSets(context.Context) ([]domainpki.TrustSet, error) {
	return nil, nil
}

func (*recordingPKIControl) InspectTrustSet(context.Context, domainpki.TrustSetID) (apppki.TrustSetInspection, error) {
	return apppki.TrustSetInspection{}, nil
}

func (c *recordingPKIControl) CreateTrustSet(ctx context.Context, request apppki.CreateTrustSetRequest) (domainpki.TrustSet, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return domainpki.TrustSet{}, err
	}
	return domainpki.TrustSet{ID: request.ID}, nil
}

func (c *recordingPKIControl) StageTrustSet(ctx context.Context, request apppki.StageTrustSetRequest) (apppki.TrustSetInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.TrustSetInspection{}, err
	}
	return apppki.TrustSetInspection{TrustSet: domainpki.TrustSet{ID: request.TrustSetID}}, nil
}

func (c *recordingPKIControl) ActivateTrustSet(ctx context.Context, request apppki.ActivateTrustSetRequest) (apppki.TrustSetInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.TrustSetInspection{}, err
	}
	return apppki.TrustSetInspection{TrustSet: domainpki.TrustSet{ID: request.TrustSetID}}, nil
}

func (c *recordingPKIControl) recordMutation(ctx context.Context, idempotencyKey string) error {
	audit, err := (apppki.ContextAuditContextProvider{}).AuditContext(ctx)
	if err != nil {
		return err
	}
	c.mutationActor = audit.ActorID
	if idempotencyKey == "" {
		return errors.New("recording pki control: idempotency key is required")
	}
	c.mutationKeys = append(c.mutationKeys, idempotencyKey)
	return nil
}

func (*recordingPKIControl) CreateAuthority(context.Context, apppki.CreateAuthorityRequest) (apppki.CreateAuthorityResult, error) {
	return apppki.CreateAuthorityResult{}, nil
}

func (*recordingPKIControl) IssueCertificate(context.Context, apppki.IssueCertificateRequest) (domainpki.CertificateGeneration, error) {
	return domainpki.CertificateGeneration{}, nil
}

func (c *recordingPKIControl) RenewCertificate(ctx context.Context, request apppki.RenewCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	return apppki.CertificateLifecycleResult{
		Kind: apppki.IssuanceKindCertificateRenewal, SourceGenerationID: request.SourceGenerationID,
		Generation: domainpki.CertificateGeneration{ID: request.GenerationID}, KeyReused: true,
	}, nil
}

func (c *recordingPKIControl) RotateCertificate(ctx context.Context, request apppki.RotateCertificateRequest) (apppki.CertificateLifecycleResult, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	return apppki.CertificateLifecycleResult{
		Kind: apppki.IssuanceKindCertificateRotation, SourceGenerationID: request.SourceGenerationID,
		Generation: domainpki.CertificateGeneration{ID: request.GenerationID},
	}, nil
}

func (c *recordingPKIControl) RevokeCertificate(ctx context.Context, request apppki.RevokeCertificateRequest) (apppki.CertificateRevocationResult, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.CertificateRevocationResult{}, err
	}
	revocation := domainpki.Revocation{
		ID: "revocation-rpc", CertificateID: "certificate-rpc", GenerationID: request.GenerationID,
		IssuerAuthorityID: "authority-rpc", IssuerGenerationID: "generation-rpc-root",
		SerialNumber: "01", Reason: request.Reason, PreviousState: domainpki.CertificateStateActive,
		EffectiveAt: time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC),
	}
	return apppki.CertificateRevocationResult{
		Revocation: revocation,
		Generation: domainpki.CertificateGeneration{ID: request.GenerationID, State: domainpki.CertificateStateRevoked},
	}, nil
}

func (*recordingPKIControl) InspectRevocation(_ context.Context, id domainpki.RevocationID) (domainpki.Revocation, error) {
	return domainpki.Revocation{ID: id, GenerationID: "generation-rpc-rotated"}, nil
}

func (*recordingPKIControl) InspectGenerationRevocation(_ context.Context, id domainpki.GenerationID) (domainpki.Revocation, error) {
	return domainpki.Revocation{ID: "revocation-rpc", GenerationID: id}, nil
}

func (*recordingPKIControl) ListAuthorityRevocations(_ context.Context, id domainpki.AuthorityID) ([]domainpki.Revocation, error) {
	return []domainpki.Revocation{{ID: "revocation-rpc", IssuerAuthorityID: id}}, nil
}

func (c *recordingPKIControl) PublishCRL(ctx context.Context, request apppki.PublishCRLRequest) (apppki.CRLPublicationResult, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.CRLPublicationResult{}, err
	}
	return apppki.CRLPublicationResult{
		Publication: apppki.CRLPublicationIntent{AuthorityID: request.AuthorityID},
		Generation:  domainpki.CRLGeneration{ID: "crl-generation-rpc", AuthorityID: request.AuthorityID},
	}, nil
}

func (*recordingPKIControl) InspectCRLPublication(_ context.Context, id domainpki.CRLPublicationID) (apppki.CRLPublicationIntent, error) {
	return apppki.CRLPublicationIntent{ID: id, AuthorityID: "authority-rpc"}, nil
}

func (*recordingPKIControl) ListCRLPublications(_ context.Context, id domainpki.AuthorityID) ([]apppki.CRLPublicationIntent, error) {
	return []apppki.CRLPublicationIntent{{ID: "crl-publication-rpc", AuthorityID: id}}, nil
}

func (*recordingPKIControl) InspectCRLGeneration(_ context.Context, id domainpki.CRLGenerationID) (domainpki.CRLGeneration, error) {
	return domainpki.CRLGeneration{ID: id, AuthorityID: "authority-rpc"}, nil
}

func (*recordingPKIControl) ListCRLGenerations(_ context.Context, id domainpki.AuthorityID) ([]domainpki.CRLGeneration, error) {
	return []domainpki.CRLGeneration{{ID: "crl-generation-rpc", AuthorityID: id}}, nil
}

func (c *recordingPKIControl) ReconcileCRLPublication(ctx context.Context, request apppki.ReconcileCRLPublicationRequest) (apppki.CRLPublicationIntent, error) {
	if err := c.recordMutation(ctx, string(request.PublicationID)); err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	return apppki.CRLPublicationIntent{ID: request.PublicationID, Status: apppki.CRLPublicationStatusFailed}, nil
}

func (c *recordingPKIControl) ReconcileCRLPublications(ctx context.Context, _ apppki.ReconcileCRLPublicationsRequest) ([]apppki.CRLPublicationIntent, error) {
	if err := c.recordMutation(ctx, "crl-reconcile-batch"); err != nil {
		return nil, err
	}
	return []apppki.CRLPublicationIntent{{ID: "crl-publication-rpc", Status: apppki.CRLPublicationStatusFailed}}, nil
}

func (*recordingPKIControl) ListOperations(context.Context) ([]domainpki.Operation, error) {
	return []domainpki.Operation{{ID: "operation-rpc"}}, nil
}

func (*recordingPKIControl) InspectOperation(
	_ context.Context,
	id domainpki.OperationID,
) (apppki.OperationInspection, error) {
	return apppki.OperationInspection{Operation: domainpki.Operation{ID: id}}, nil
}

func (c *recordingPKIControl) StartAuthorityRollover(
	ctx context.Context,
	request apppki.StartAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.OperationInspection{}, err
	}
	return apppki.OperationInspection{Operation: domainpki.Operation{ID: request.OperationID}}, nil
}

func (c *recordingPKIControl) AcknowledgeAuthorityRollover(
	ctx context.Context,
	request apppki.AcknowledgeAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.OperationInspection{}, err
	}
	return apppki.OperationInspection{Operation: domainpki.Operation{ID: request.OperationID}}, nil
}

func (c *recordingPKIControl) ActivateAuthorityRollover(
	ctx context.Context,
	request apppki.ActivateAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	if c.rolloverErr != nil {
		return apppki.OperationInspection{}, c.rolloverErr
	}
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.OperationInspection{}, err
	}
	return apppki.OperationInspection{Operation: domainpki.Operation{ID: request.OperationID}}, nil
}

func (c *recordingPKIControl) BeginAuthorityRolloverFinalTrust(
	ctx context.Context,
	request apppki.BeginAuthorityRolloverFinalTrustRequest,
) (apppki.OperationInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.OperationInspection{}, err
	}
	return apppki.OperationInspection{Operation: domainpki.Operation{ID: request.OperationID}}, nil
}

func (c *recordingPKIControl) CompleteAuthorityRollover(
	ctx context.Context,
	request apppki.CompleteAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.OperationInspection{}, err
	}
	return apppki.OperationInspection{Operation: domainpki.Operation{ID: request.OperationID}}, nil
}

func (c *recordingPKIControl) CancelAuthorityRollover(
	ctx context.Context,
	request apppki.CancelAuthorityRolloverRequest,
) (apppki.OperationInspection, error) {
	if err := c.recordMutation(ctx, request.IdempotencyKey); err != nil {
		return apppki.OperationInspection{}, err
	}
	return apppki.OperationInspection{Operation: domainpki.Operation{ID: request.OperationID}}, nil
}

func (*recordingPKIControl) UnlockAuthoritySigning(context.Context, domainpki.AuthorityID, time.Duration) (apppki.SigningLease, error) {
	return apppki.SigningLease{}, nil
}

func (*recordingPKIControl) LockAuthoritySigning(context.Context, domainpki.AuthorityID) error {
	return nil
}

func (*recordingPKIControl) AuthoritySigningLease(context.Context, domainpki.AuthorityID) (apppki.SigningLease, bool, error) {
	return apppki.SigningLease{}, false, nil
}

func (*recordingPKIControl) ExportBundle(context.Context, domainpki.GenerationID, domainpki.Purpose, bool) (domainpki.Bundle, error) {
	return domainpki.Bundle{}, nil
}

var _ apppki.WorkspaceControl = (*recordingPKIControl)(nil)
var _ apppki.OperationControl = (*recordingPKIControl)(nil)

type recordingSessionBroker struct{}

func (recordingSessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	return []run.SessionRef{}, nil
}

func (recordingSessionBroker) WriteSession(context.Context, string, []byte) error {
	return nil
}

func (recordingSessionBroker) ReadSession(context.Context, string, time.Duration) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (recordingSessionBroker) TailSession(context.Context, string, run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (recordingSessionBroker) CloseSession(context.Context, string) error {
	return nil
}

func (recordingSessionBroker) ListSessionCommands(
	context.Context,
	string,
	run.PayloadCommandListRequest,
) ([]run.PayloadCommand, error) {
	return []run.PayloadCommand{}, nil
}

func (recordingSessionBroker) RunSessionCommand(
	context.Context,
	string,
	run.PayloadCommandRequest,
) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, nil
}

type bridgeSessionBroker struct {
	writes        chan []byte
	reads         chan run.SessionChunk
	readDelivered chan struct{}
	closes        chan string
	closeErr      error
}

func newBridgeSessionBroker() *bridgeSessionBroker {
	return &bridgeSessionBroker{
		writes:        make(chan []byte, 8),
		reads:         make(chan run.SessionChunk, 8),
		readDelivered: make(chan struct{}, 8),
		closes:        make(chan string, 8),
	}
}

func (b *bridgeSessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	return []run.SessionRef{}, nil
}

func (b *bridgeSessionBroker) WriteSession(ctx context.Context, _ string, data []byte) error {
	copied := append([]byte(nil), data...)
	select {
	case b.writes <- copied:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *bridgeSessionBroker) ReadSession(
	ctx context.Context,
	sessionID string,
	timeout time.Duration,
) (run.SessionChunk, error) {
	if timeout <= 0 {
		return run.SessionChunk{SessionID: sessionID}, nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case chunk := <-b.reads:
		select {
		case b.readDelivered <- struct{}{}:
		default:
		}
		if chunk.SessionID == "" {
			chunk.SessionID = sessionID
		}
		return chunk, nil
	case <-ctx.Done():
		return run.SessionChunk{}, ctx.Err()
	case <-timer.C:
		return run.SessionChunk{SessionID: sessionID}, nil
	}
}

func (b *bridgeSessionBroker) TailSession(context.Context, string, run.SessionTailOptions) (run.SessionChunk, error) {
	return run.SessionChunk{}, nil
}

func (b *bridgeSessionBroker) CloseSession(ctx context.Context, sessionID string) error {
	select {
	case b.closes <- sessionID:
		return b.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

type shortWriteConn struct {
	data []byte
}

func (*shortWriteConn) Read([]byte) (int, error) { return 0, errors.New("unexpected read") }

func (c *shortWriteConn) Write(data []byte) (int, error) {
	n := (len(data) + 1) / 2
	c.data = append(c.data, data[:n]...)
	return n, nil
}

func (*shortWriteConn) Close() error                     { return nil }
func (*shortWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*shortWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (*shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*shortWriteConn) SetWriteDeadline(time.Time) error { return nil }

func (b *bridgeSessionBroker) ListSessionCommands(
	context.Context,
	string,
	run.PayloadCommandListRequest,
) ([]run.PayloadCommand, error) {
	return []run.PayloadCommand{}, nil
}

func (b *bridgeSessionBroker) RunSessionCommand(
	context.Context,
	string,
	run.PayloadCommandRequest,
) (run.PayloadCommandResult, error) {
	return run.PayloadCommandResult{}, nil
}

func serveTestDaemon(t *testing.T, endpoint string, runs services.RunService, options ...ServerOption) {
	t.Helper()
	// Test daemons use an owner-only Unix socket and therefore model the
	// authenticated local transport used by production composition.
	options = append([]ServerOption{WithPrivilegedControl(true)}, options...)
	parsed, err := ParseEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen(parsed.Network, parsed.Address)
	if err != nil {
		t.Fatal(err)
	}
	options = append(options, WithPrivilegedControl(parsed.Network == "unix"))
	handler, err := NewHandler(runs, options...)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("serve test daemon: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Logf("close test daemon server: %v", err)
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("close test daemon listener: %v", err)
		}
	})
}

func closeTestClient(t *testing.T, client *Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Logf("close daemon rpc client: %v", err)
	}
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if _, err := os.Stat(base); err != nil {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "hovel-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("remove temp dir: %v", err)
		}
	})
	return dir
}

type discardEvents struct{}

func (discardEvents) Append(context.Context, event.Event) error {
	return nil
}

type sequenceIDs struct {
	values []string
	next   int
}

func (s *sequenceIDs) NewID() string {
	value := s.values[s.next]
	s.next++
	return value
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	return c.now
}
