package daemonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vibepwners/hovel/internal/app/launchkey"
	"github.com/vibepwners/hovel/internal/app/operatorlog"
	"github.com/vibepwners/hovel/internal/app/operatorsession"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	operatordomain "github.com/vibepwners/hovel/internal/domain/operator"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
)

const (
	serviceURLPrefix       = "/hovel.daemon.v1.DaemonService/"
	maximumRPCRequestBytes = 64 * 1024 * 1024
	maximumRPCErrorBytes   = 64 * 1024
	rpcErrorVersionV1      = "v1"

	rpcMethodDescribeMesh               = "DescribeMesh"
	rpcMethodMeshTopology               = "MeshTopology"
	rpcMethodListMeshBeacons            = "ListMeshBeacons"
	rpcMethodListMeshListeners          = "ListMeshListeners"
	rpcMethodStartMeshListener          = "StartMeshListener"
	rpcMethodStopMeshListener           = "StopMeshListener"
	rpcMethodRunMeshTask                = "RunMeshTask"
	rpcMethodOpenMeshStream             = "OpenMeshStream"
	rpcMethodOpenMeshBridge             = "OpenMeshBridge"
	rpcMethodCloseMeshBridge            = "CloseMeshBridge"
	rpcMethodListMeshOperations         = "ListMeshOperations"
	rpcMethodPKIStatus                  = "PKIStatus"
	rpcMethodInitializePKI              = "InitializePKI"
	rpcMethodListPKIBackends            = "ListPKIBackends"
	rpcMethodListPKIProfiles            = "ListPKIProfiles"
	rpcMethodListAuthorities            = "ListPKIAuthorities"
	rpcMethodInspectAuthority           = "InspectPKIAuthority"
	rpcMethodCreateAuthority            = "CreatePKIAuthority"
	rpcMethodUnlockAuthority            = "UnlockPKIAuthority"
	rpcMethodLockAuthority              = "LockPKIAuthority"
	rpcMethodListCertificates           = "ListPKICertificates"
	rpcMethodInspectCertificate         = "InspectPKICertificate"
	rpcMethodIssueCertificate           = "IssuePKICertificate"
	rpcMethodRenewCertificate           = "RenewPKICertificate"
	rpcMethodRotateCertificate          = "RotatePKICertificate"
	rpcMethodRevokeCertificate          = "RevokePKICertificate"
	rpcMethodInspectRevocation          = "InspectPKIRevocation"
	rpcMethodGenerationRevocation       = "InspectPKIGenerationRevocation"
	rpcMethodListRevocations            = "ListPKIRevocations"
	rpcMethodPublishCRL                 = "PublishPKICRL"
	rpcMethodInspectCRLPublication      = "InspectPKICRLPublication"
	rpcMethodListCRLPublications        = "ListPKICRLPublications"
	rpcMethodInspectCRL                 = "InspectPKICRL"
	rpcMethodListCRLs                   = "ListPKICRLs"
	rpcMethodReconcileCRL               = "ReconcilePKICRL"
	rpcMethodReconcileCRLs              = "ReconcilePKICRLs"
	rpcMethodListPKIOperations          = "ListPKIOperations"
	rpcMethodInspectPKIOperation        = "InspectPKIOperation"
	rpcMethodListCredentialStamps       = "ListPKICredentialStamps"
	rpcMethodInspectCredentialStamp     = "InspectPKICredentialStamp"
	rpcMethodListCredentialExecutions   = "ListPKICredentialExecutions"
	rpcMethodInspectCredentialExecution = "InspectPKICredentialExecution"
	rpcMethodStartRollover              = "StartPKIAuthorityRollover"
	rpcMethodAcknowledgeRollover        = "AcknowledgePKIAuthorityRollover"
	rpcMethodActivateRollover           = "ActivatePKIAuthorityRollover"
	rpcMethodBeginRolloverFinal         = "BeginPKIAuthorityRolloverFinalTrust"
	rpcMethodCompleteRollover           = "CompletePKIAuthorityRollover"
	rpcMethodCancelRollover             = "CancelPKIAuthorityRollover"
	rpcMethodExportBundle               = "ExportPKIBundle"
	rpcMethodListAssignments            = "ListPKIAssignments"
	rpcMethodInspectAssignment          = "InspectPKIAssignment"
	rpcMethodBindAssignment             = "BindPKIAssignment"
	rpcMethodStageAssignment            = "StagePKIAssignment"
	rpcMethodActivateAssignment         = "ActivatePKIAssignment"
	rpcMethodUnbindAssignment           = "UnbindPKIAssignment"
	rpcMethodListTrustSets              = "ListPKITrustSets"
	rpcMethodInspectTrustSet            = "InspectPKITrustSet"
	rpcMethodCreateTrustSet             = "CreatePKITrustSet"
	rpcMethodStageTrustSet              = "StagePKITrustSet"
	rpcMethodActivateTrustSet           = "ActivatePKITrustSet"
)

// RPCErrorCode is the stable machine-readable category for a daemon failure.
type RPCErrorCode string

const (
	RPCErrorCodeInternal                   RPCErrorCode = "internal"
	RPCErrorCodeNotFound                   RPCErrorCode = "not-found"
	RPCErrorCodeRevisionConflict           RPCErrorCode = "revision-conflict"
	RPCErrorCodeAcknowledgementExists      RPCErrorCode = "acknowledgement-exists"
	RPCErrorCodeRolloverPrecondition       RPCErrorCode = "rollover-precondition"
	RPCErrorCodeIdempotencyConflict        RPCErrorCode = "idempotency-conflict"
	RPCErrorCodeMutationExists             RPCErrorCode = "mutation-exists"
	RPCErrorCodeIssuanceInProgress         RPCErrorCode = "issuance-in-progress"
	RPCErrorCodeCRLPublicationInProgress   RPCErrorCode = "crl-publication-in-progress"
	RPCErrorCodePrivateKeyExportDenied     RPCErrorCode = "private-key-export-denied"
	RPCErrorCodeAuthoritySigningLocked     RPCErrorCode = "authority-signing-locked"
	RPCErrorCodeAuthoritySigningLeaseOwned RPCErrorCode = "authority-signing-lease-owned"
	RPCErrorCodePermissionDenied           RPCErrorCode = "permission-denied"
)

var (
	errPrivilegedControlUnavailable = errors.New("privileged daemon control is unavailable on this transport")
	errMeshTaskPlanRequired         = errors.New(
		"mesh task requires a persisted throw plan and recorded confirmation",
	)
)

func (c RPCErrorCode) Validate() error {
	switch c {
	case RPCErrorCodeInternal, RPCErrorCodeNotFound, RPCErrorCodeRevisionConflict,
		RPCErrorCodeAcknowledgementExists, RPCErrorCodeRolloverPrecondition,
		RPCErrorCodeIdempotencyConflict, RPCErrorCodeMutationExists,
		RPCErrorCodeIssuanceInProgress, RPCErrorCodeCRLPublicationInProgress,
		RPCErrorCodePrivateKeyExportDenied, RPCErrorCodeAuthoritySigningLocked,
		RPCErrorCodeAuthoritySigningLeaseOwned,
		RPCErrorCodePermissionDenied:
		return nil
	default:
		return fmt.Errorf("daemon rpc: unsupported error code %q", c)
	}
}

// RPCErrorEnvelope is the versioned error contract returned by daemon handlers.
type RPCErrorEnvelope struct {
	Version        string                            `json:"version"`
	Code           RPCErrorCode                      `json:"code"`
	Message        string                            `json:"message"`
	RolloverReason apppki.RolloverPreconditionReason `json:"rolloverReason,omitempty"`
	RolloverDetail string                            `json:"rolloverDetail,omitempty"`
}

func (e RPCErrorEnvelope) Validate() error {
	if e.Version != rpcErrorVersionV1 {
		return fmt.Errorf("daemon rpc: unsupported error envelope version %q", e.Version)
	}
	if err := e.Code.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(e.Message) == "" {
		return errors.New("daemon rpc: error envelope message is required")
	}
	if e.Code == RPCErrorCodeRolloverPrecondition {
		if err := e.RolloverReason.Validate(); err != nil {
			return err
		}
		if e.RolloverDetail != strings.TrimSpace(e.RolloverDetail) {
			return errors.New("daemon rpc: rollover detail must be canonical")
		}
		return nil
	}
	if e.RolloverReason != "" || e.RolloverDetail != "" {
		return errors.New("daemon rpc: rollover fields require a rollover precondition error")
	}
	return nil
}

// RemoteError preserves an unclassified daemon failure without requiring callers to parse text.
type RemoteError struct {
	Method     string
	StatusCode int
	Envelope   RPCErrorEnvelope
}

func (e *RemoteError) Error() string {
	if e == nil {
		return "daemon rpc: remote error"
	}
	return fmt.Sprintf("%s: %s", e.Method, e.Envelope.Message)
}

type RunMockExploitRequest struct {
	Operation    string
	Chain        string
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	ThrowStarted string
}

type ExecuteModuleRequest = RunMockExploitRequest

type Finding struct {
	Title    string
	Severity string
	Detail   string
}

type Artifact struct {
	Name string
	Kind string
	Data string
	Path string
}

type SessionRef struct {
	ID                 string
	RunID              string
	ModuleID           string
	Target             string
	Name               string
	Kind               string
	State              string
	Transport          string
	InstalledPayloadID string
	Capabilities       []string
}

type SessionChunk struct {
	SessionID string
	Data      []byte
	Closed    bool
}

type LogEntry struct {
	ID             string
	Time           string
	Topic          string
	Kind           string
	Level          string
	Source         string
	Message        string
	Logger         string
	ChainID        string
	ChainName      string
	RunID          string
	Target         string
	ModuleID       string
	ElapsedSeconds *float64
	Fields         map[string]string
	Attributes     map[string]string
}

type OperatorLogEntry struct {
	ID             string
	Time           string
	Topic          string
	Kind           string
	Level          string
	Source         string
	Message        string
	ChainID        string
	ChainName      string
	RunID          string
	Target         string
	ModuleID       string
	ElapsedSeconds *float64
	Fields         map[string]string
	Attributes     map[string]string
}

type PublishedLog struct {
	Seq       uint64
	Operation string
	Chain     string
	Entry     OperatorLogEntry
}

type PollLogsRequest struct {
	Since     uint64
	Operation string
	Chain     string
}

type PollLogsResponse struct {
	Last uint64
	Logs []PublishedLog
}

type RunMockExploitResponse struct {
	RunID             string
	ModuleID          string
	Target            string
	State             string
	Summary           string
	Findings          []Finding
	Artifacts         []Artifact
	Logs              []LogEntry
	Sessions          []SessionRef
	InstalledPayloads []InstalledPayloadDescriptor
}

type ExecuteModuleResponse = RunMockExploitResponse

type PayloadProviderRecord = run.PayloadProviderRecord
type InstalledPayloadDescriptor = run.InstalledPayloadDescriptor

type OperatorEntity struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	DisplayName  string   `json:"displayName"`
	Agent        bool     `json:"agent"`
	Operation    string   `json:"operation,omitempty"`
	ActiveChain  string   `json:"activeChain,omitempty"`
	ConnectedAt  string   `json:"connectedAt"`
	LastSeenAt   string   `json:"lastSeenAt"`
	Capabilities []string `json:"capabilities,omitempty"`
	PolicyTags   []string `json:"policyTags,omitempty"`
}

type AttachEntityRequest struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	DisplayName  string   `json:"displayName,omitempty"`
	Agent        bool     `json:"agent,omitempty"`
	Operation    string   `json:"operation,omitempty"`
	ActiveChain  string   `json:"activeChain,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	PolicyTags   []string `json:"policyTags,omitempty"`
}

type HeartbeatEntityRequest struct {
	ID          string  `json:"id"`
	Operation   *string `json:"operation,omitempty"`
	ActiveChain *string `json:"activeChain,omitempty"`
}

type DetachEntityRequest struct {
	ID string `json:"id"`
}

type ListEntitiesRequest struct {
	Operation string `json:"operation,omitempty"`
}

type EntityResponse struct {
	Entity OperatorEntity `json:"entity"`
}

type ListEntitiesResponse struct {
	Entities []OperatorEntity `json:"entities"`
}

type CreatePendingThrowRequest struct {
	ID             string `json:"id"`
	Operation      string `json:"operation"`
	Chain          string `json:"chain"`
	PlanHash       string `json:"planHash"`
	AllowDangerous bool   `json:"allowDangerous,omitempty"`
	NowBypass      bool   `json:"nowBypass,omitempty"`
}

type ConfirmPendingThrowRequest struct {
	ID             string `json:"id"`
	EntityID       string `json:"entityId"`
	PlanHash       string `json:"planHash"`
	AllowDangerous bool   `json:"allowDangerous,omitempty"`
	NowBypass      bool   `json:"nowBypass,omitempty"`
}

type PendingThrowRequest struct {
	ID string `json:"id"`
}

type PendingThrowResponse struct {
	ID                  string   `json:"id"`
	Operation           string   `json:"operation"`
	Chain               string   `json:"chain"`
	PlanHash            string   `json:"planHash"`
	AllowDangerous      bool     `json:"allowDangerous,omitempty"`
	NowBypass           bool     `json:"nowBypass,omitempty"`
	CreatedAt           string   `json:"createdAt"`
	Ready               bool     `json:"ready"`
	RequiredApproverIDs []string `json:"requiredApproverIds"`
	MissingApproverIDs  []string `json:"missingApproverIds"`
}

type LaunchKeyPolicyRequest struct {
	Operation string `json:"operation,omitempty"`
}

type SetLaunchKeyPolicyRequest struct {
	Operation        string `json:"operation,omitempty"`
	Mode             string `json:"mode"`
	Quorum           int    `json:"quorum,omitempty"`
	HeartbeatTimeout string `json:"heartbeatTimeout,omitempty"`
}

type LaunchKeyPolicyResponse struct {
	Operation string                `json:"operation"`
	Policy    LaunchKeyPolicyOutput `json:"policy"`
}

type LaunchKeyPolicyOutput struct {
	Mode             string `json:"mode"`
	Quorum           int    `json:"quorum,omitempty"`
	HeartbeatTimeout string `json:"heartbeatTimeout,omitempty"`
}

type PayloadCommand = run.PayloadCommand
type PayloadGenerateRequest struct {
	ModuleID string                     `json:"moduleId"`
	Request  run.GeneratePayloadRequest `json:"request"`
}

type PayloadGenerateResponse = run.PayloadArtifactSet

type PayloadCommandListRequest struct {
	ModuleID string                        `json:"moduleId"`
	Request  run.PayloadCommandListRequest `json:"request"`
}

type PayloadCommandListResponse struct {
	Commands []run.PayloadCommand `json:"commands"`
}

type PayloadCommandRunRequest struct {
	Operation string                    `json:"operation,omitempty"`
	Chain     string                    `json:"chain,omitempty"`
	ModuleID  string                    `json:"moduleId"`
	Request   run.PayloadCommandRequest `json:"request"`
}

type PayloadCommandRunResponse = run.PayloadCommandResult

type MeshDescribeRequest struct {
	ModuleID string               `json:"moduleId"`
	Request  mesh.DescribeRequest `json:"request"`
}

type MeshDescribeResponse = mesh.Descriptor

type MeshTopologyRequest struct {
	ModuleID string               `json:"moduleId"`
	Request  mesh.TopologyRequest `json:"request"`
}

type MeshTopologyResponse = mesh.Topology

type MeshBeaconListRequest struct {
	ModuleID string             `json:"moduleId"`
	Request  mesh.BeaconRequest `json:"request"`
}

type MeshBeaconListResponse struct {
	Beacons []mesh.Beacon `json:"beacons"`
}

type MeshListenerListRequest struct {
	ModuleID string                   `json:"moduleId"`
	Request  mesh.ListenerListRequest `json:"request"`
}

type MeshListenerListResponse struct {
	Listeners []mesh.Listener `json:"listeners"`
}

type MeshListenerStartRequest struct {
	ModuleID          string                         `json:"moduleId"`
	Request           mesh.ListenerStartRequest      `json:"request"`
	Credentials       domainpki.CredentialSelections `json:"credentials,omitempty"`
	CredentialContext *PKIRequestContext             `json:"credentialContext,omitempty"`
}

type MeshListenerStartResponse struct {
	OperationID string        `json:"operationId"`
	Listener    mesh.Listener `json:"listener"`
}

type MeshListenerStopRequest struct {
	ModuleID string                   `json:"moduleId"`
	Request  mesh.ListenerStopRequest `json:"request"`
}

type MeshListenerStopResponse struct {
	OperationID string        `json:"operationId"`
	Listener    mesh.Listener `json:"listener"`
}

type MeshTaskRunRequest struct {
	ModuleID          string                         `json:"moduleId"`
	Request           mesh.TaskRequest               `json:"request"`
	Credentials       domainpki.CredentialSelections `json:"credentials,omitempty"`
	CredentialContext *PKIRequestContext             `json:"credentialContext,omitempty"`
}

type MeshTaskRunResponse = mesh.TaskResult

type MeshStreamOpenRequest struct {
	ModuleID          string                         `json:"moduleId"`
	Request           mesh.StreamRequest             `json:"request"`
	Credentials       domainpki.CredentialSelections `json:"credentials,omitempty"`
	CredentialContext *PKIRequestContext             `json:"credentialContext,omitempty"`
}

type MeshStreamOpenResponse = run.SessionRef

type MeshBridgeOpenRequest struct {
	ModuleID          string                         `json:"moduleId"`
	Request           mesh.StreamRequest             `json:"request"`
	LocalHost         string                         `json:"localHost,omitempty"`
	LocalPort         int                            `json:"localPort,omitempty"`
	LocalNetwork      MeshBridgeNetwork              `json:"localNetwork,omitempty"`
	Credentials       domainpki.CredentialSelections `json:"credentials,omitempty"`
	CredentialContext *PKIRequestContext             `json:"credentialContext,omitempty"`
}

type MeshBridgeOpenResponse struct {
	OperationID  string            `json:"operationId"`
	SessionID    string            `json:"sessionId"`
	LocalHost    string            `json:"localHost"`
	LocalPort    int               `json:"localPort"`
	LocalNetwork MeshBridgeNetwork `json:"localNetwork"`
	// Capability is an ephemeral bearer secret for the local endpoint. Send
	// capability + "\n" as the first TCP bytes or the first complete UDP
	// datagram. The handshake frame is consumed and is never sent to the Mesh
	// provider. Hovel retains the capability only in memory for the bridge's
	// lifetime; callers must not log or persist it.
	Capability   MeshBridgeCapability `json:"capability"`
	LocalAddress string               `json:"localAddress"`
}

type MeshBridgeCloseRequest struct {
	OperationID string `json:"operationId,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
}

type MeshBridgeCloseResponse struct {
	OperationID string             `json:"operationId,omitempty"`
	SessionID   string             `json:"sessionId,omitempty"`
	State       MeshOperationState `json:"state"`
}

type PKIRequestContext struct {
	ActorID                  string `json:"actorId"`
	OperationID              string `json:"operationId"`
	CorrelationID            string `json:"correlationId"`
	ApproveSigningLease      bool   `json:"approveSigningLease,omitempty"`
	ApprovePrivateKeyExport  bool   `json:"approvePrivateKeyExport,omitempty"`
	ApproveCredentialUse     bool   `json:"approveCredentialUse,omitempty"`
	ApproveReconciliation    bool   `json:"approveIssuanceReconciliation,omitempty"`
	ApproveCRLReconciliation bool   `json:"approveCrlPublicationReconciliation,omitempty"`
}

func (c PKIRequestContext) bind(ctx context.Context) (context.Context, error) {
	return apppki.WithRequestContext(ctx, apppki.RequestContext{
		Audit: apppki.AuditContext{
			ActorID:       c.ActorID,
			OperationID:   c.OperationID,
			CorrelationID: c.CorrelationID,
		},
		ApproveSigningLease:      c.ApproveSigningLease,
		ApprovePrivateKeyExport:  c.ApprovePrivateKeyExport,
		ApproveCredentialUse:     c.ApproveCredentialUse,
		ApproveReconciliation:    c.ApproveReconciliation,
		ApproveCRLReconciliation: c.ApproveCRLReconciliation,
	})
}

type PKIInitializeRequest struct {
	Context   PKIRequestContext `json:"context"`
	Confirmed bool              `json:"confirmed"`
}

type PKIBackendListResponse struct {
	Backends []domainpki.BackendDescriptor `json:"backends"`
}

type PKIProfileListResponse struct {
	Profiles []domainpki.Profile `json:"profiles"`
}

type PKIAuthorityListResponse struct {
	Authorities []domainpki.Authority `json:"authorities"`
}

type PKIAuthorityRequest struct {
	ID domainpki.AuthorityID `json:"id"`
}

type PKIAuthorityInspectResponse struct {
	Authority        domainpki.Authority             `json:"authority"`
	ActiveGeneration domainpki.CertificateGeneration `json:"activeGeneration"`
}

type PKIAuthorityCreateRequest struct {
	Context PKIRequestContext             `json:"context"`
	Request apppki.CreateAuthorityRequest `json:"request"`
}

type PKIAuthorityLeaseRequest struct {
	Context  PKIRequestContext     `json:"context"`
	ID       domainpki.AuthorityID `json:"id"`
	Duration string                `json:"duration,omitempty"`
}

type PKIAuthorityLockRequest struct {
	Context PKIRequestContext     `json:"context"`
	ID      domainpki.AuthorityID `json:"id"`
}

type PKICertificateListResponse struct {
	Certificates []domainpki.CertificateGeneration `json:"certificates"`
}

type PKICertificateRequest struct {
	ID domainpki.GenerationID `json:"id"`
}

type PKICertificateIssueRequest struct {
	Context PKIRequestContext              `json:"context"`
	Request apppki.IssueCertificateRequest `json:"request"`
}

type PKIRevocationRequest struct {
	ID domainpki.RevocationID `json:"id"`
}

type PKIRevocationListRequest struct {
	AuthorityID domainpki.AuthorityID `json:"authorityId"`
}

type PKIRevocationListResponse struct {
	Revocations []domainpki.Revocation `json:"revocations"`
}

type PKICRLRequest struct {
	ID domainpki.CRLGenerationID `json:"id"`
}

type PKICRLPublicationRequest struct {
	ID domainpki.CRLPublicationID `json:"id"`
}

type PKICRLListRequest struct {
	AuthorityID domainpki.AuthorityID `json:"authorityId"`
}

type PKICRLListResponse struct {
	CRLs []domainpki.CRLGeneration `json:"crls"`
}

type PKICRLPublicationListResponse struct {
	Publications []apppki.CRLPublicationIntent `json:"publications"`
}

type PKIOperationListResponse struct {
	Operations []domainpki.Operation `json:"operations"`
}

type PKIOperationRequest struct {
	ID domainpki.OperationID `json:"id"`
}

type PKICredentialStampListResponse struct {
	Stamps []domainpki.CredentialStamp `json:"stamps"`
}

type PKICredentialStampRequest struct {
	ID domainpki.StampID `json:"id"`
}

type PKICredentialExecutionListResponse struct {
	Executions []domainpki.CredentialExecution `json:"executions"`
}

type PKICredentialExecutionRequest struct {
	ID domainpki.CredentialExecutionRequestID `json:"id"`
}

type PKIBundleExportRequest struct {
	Context        PKIRequestContext      `json:"context"`
	GenerationID   domainpki.GenerationID `json:"generationId"`
	Purpose        domainpki.Purpose      `json:"purpose"`
	IncludePrivate bool                   `json:"includePrivate,omitempty"`
}

type PKIAssignmentListResponse struct {
	Assignments []domainpki.Assignment `json:"assignments"`
}

type PKIAssignmentRequest struct {
	ID domainpki.AssignmentID `json:"id"`
}

type PKIMutationRequest[T any] struct {
	Context PKIRequestContext `json:"context"`
	Request T                 `json:"request"`
}

type PKITrustSetListResponse struct {
	TrustSets []domainpki.TrustSet `json:"trustSets"`
}

type PKITrustSetRequest struct {
	ID domainpki.TrustSetID `json:"id"`
}

type operatorClock interface {
	Now() time.Time
}

type systemOperatorClock struct{}

func (systemOperatorClock) Now() time.Time {
	return time.Now().UTC()
}

type Server struct {
	runs            services.RunService
	moduleSessions  services.SessionBroker
	meshOps         *MeshBook
	meshBridges     *MeshBridgeManager
	session         *operatorsession.Session
	logs            *LogBroker
	entities        map[string]operatordomain.Entity
	launchKeys      *launchkey.Coordinator
	launchKeyPolicy operatordomain.LaunchKeyPolicy
	launchKeyByOp   map[string]operatordomain.LaunchKeyPolicy
	clock           operatorClock
	pki             apppki.WorkspaceControl
	pkiSecrets      bool
	privileged      bool
	persistSession  func(operatorsession.PersistedState) error
	mu              sync.Mutex
}

func Register(mux *http.ServeMux, runs services.RunService, options ...ServerOption) error {
	if mux == nil {
		return errors.New("daemon rpc mux is required")
	}
	rpcServer := &Server{
		runs:        runs,
		meshOps:     NewMeshBook(),
		meshBridges: NewMeshBridgeManager(),
		session:     operatorsession.New(),
		logs:        NewLogBroker(),
		entities:    map[string]operatordomain.Entity{},
		launchKeys:  launchkey.NewCoordinator(),
		clock:       systemOperatorClock{},
	}
	for _, option := range options {
		option(rpcServer)
	}
	registerPrivilegedUnary[ExecuteModuleRequest, ExecuteModuleResponse](mux, "ExecuteModule", rpcServer.privileged, rpcServer.executeModuleRPC)
	registerUnary[EmptyRequest, ListSessionsResponse](mux, "ListSessions", rpcServer.listSessionsRPC)
	registerUnary[SessionReadRequest, SessionChunk](mux, "ReadSession", rpcServer.readSessionRPC)
	registerUnary[SessionTailRequest, SessionChunk](mux, "TailSession", rpcServer.tailSessionRPC)
	registerPrivilegedUnary[SessionWriteRequest, EmptyResponse](mux, "WriteSession", rpcServer.privileged, rpcServer.writeSessionRPC)
	registerPrivilegedUnary[SessionCloseRequest, EmptyResponse](mux, "CloseSession", rpcServer.privileged, rpcServer.closeSessionRPC)
	registerUnary[SessionCommandListRequest, SessionCommandListResponse](mux, "ListSessionCommands", rpcServer.listSessionCommandsRPC)
	registerPrivilegedUnary[SessionCommandRunRequest, SessionCommandRunResponse](mux, "RunSessionCommand", rpcServer.privileged, rpcServer.runSessionCommandRPC)
	registerPrivilegedUnary[OperationRequest, EmptyResponse](mux, "CreateOperation", rpcServer.privileged, rpcServer.createOperationRPC)
	registerPrivilegedUnary[OperationRequest, EmptyResponse](mux, "UseOperation", rpcServer.privileged, rpcServer.useOperationRPC)
	registerPrivilegedUnary[ChainRequest, EmptyResponse](mux, "CreateChain", rpcServer.privileged, rpcServer.createChainRPC)
	registerPrivilegedUnary[ChainRequest, EmptyResponse](mux, "UseChain", rpcServer.privileged, rpcServer.useChainRPC)
	registerPrivilegedUnary[RenameChainRequest, EmptyResponse](mux, "RenameChain", rpcServer.privileged, rpcServer.renameChainRPC)
	registerPrivilegedUnary[ChainRequest, EmptyResponse](mux, "DeleteChain", rpcServer.privileged, rpcServer.deleteChainRPC)
	registerPrivilegedUnary[TargetRequest, EmptyResponse](mux, "AddTarget", rpcServer.privileged, rpcServer.addTargetRPC)
	registerPrivilegedUnary[TargetRequest, EmptyResponse](mux, "BindTarget", rpcServer.privileged, rpcServer.bindTargetRPC)
	registerPrivilegedUnary[TargetRequest, EmptyResponse](mux, "UnbindTarget", rpcServer.privileged, rpcServer.unbindTargetRPC)
	registerPrivilegedUnary[ChainRequest, EmptyResponse](mux, "ClearTargets", rpcServer.privileged, rpcServer.clearTargetsRPC)
	registerPrivilegedUnary[TargetSetRequest, EmptyResponse](mux, "CreateTargetSet", rpcServer.privileged, rpcServer.createTargetSetRPC)
	registerPrivilegedUnary[TargetSetRequest, EmptyResponse](mux, "AddTargetToSet", rpcServer.privileged, rpcServer.addTargetToSetRPC)
	registerPrivilegedUnary[TargetSetRequest, EmptyResponse](mux, "RemoveTargetFromSet", rpcServer.privileged, rpcServer.removeTargetFromSetRPC)
	registerPrivilegedUnary[ModuleRequest, StepResponse](mux, "AddModule", rpcServer.privileged, rpcServer.addModuleRPC)
	registerPrivilegedUnary[ConfigRequest, EmptyResponse](mux, "SetChainConfig", rpcServer.privileged, rpcServer.setChainConfigRPC)
	registerPrivilegedUnary[ConfigRequest, EmptyResponse](mux, "UnsetChainConfig", rpcServer.privileged, rpcServer.unsetChainConfigRPC)
	registerPrivilegedUnary[TargetConfigRequest, EmptyResponse](mux, "SetTargetConfig", rpcServer.privileged, rpcServer.setTargetConfigRPC)
	registerPrivilegedUnary[TargetConfigRequest, EmptyResponse](mux, "UnsetTargetConfig", rpcServer.privileged, rpcServer.unsetTargetConfigRPC)
	registerUnary[SnapshotRequest, SnapshotResponse](mux, "Snapshot", rpcServer.snapshotRPC)
	registerUnary[ActiveLogsRequest, []OperatorLogEntry](mux, "ActiveLogs", rpcServer.activeLogsRPC)
	registerPrivilegedUnary[AppendLogRequest, EmptyResponse](mux, "AppendLog", rpcServer.privileged, rpcServer.appendLogRPC)
	registerUnary[PollLogsRequest, PollLogsResponse](mux, "PollLogs", rpcServer.pollLogsRPC)
	registerPrivilegedUnary[AttachEntityRequest, EntityResponse](mux, "AttachEntity", rpcServer.privileged, rpcServer.attachEntityRPC)
	registerPrivilegedUnary[HeartbeatEntityRequest, EntityResponse](mux, "HeartbeatEntity", rpcServer.privileged, rpcServer.heartbeatEntityRPC)
	registerPrivilegedUnary[DetachEntityRequest, EmptyResponse](mux, "DetachEntity", rpcServer.privileged, rpcServer.detachEntityRPC)
	registerUnary[ListEntitiesRequest, ListEntitiesResponse](mux, "ListEntities", rpcServer.listEntitiesRPC)
	registerPrivilegedUnary[CreatePendingThrowRequest, PendingThrowResponse](mux, "CreatePendingThrow", rpcServer.privileged, rpcServer.createPendingThrowRPC)
	registerPrivilegedUnary[ConfirmPendingThrowRequest, PendingThrowResponse](mux, "ConfirmPendingThrow", rpcServer.privileged, rpcServer.confirmPendingThrowRPC)
	registerPrivilegedUnary[PendingThrowRequest, PendingThrowResponse](mux, "RequirePendingThrowReady", rpcServer.privileged, rpcServer.requirePendingThrowReadyRPC)
	registerPrivilegedUnary[PendingThrowRequest, EmptyResponse](mux, "CancelPendingThrow", rpcServer.privileged, rpcServer.cancelPendingThrowRPC)
	registerUnary[LaunchKeyPolicyRequest, LaunchKeyPolicyResponse](mux, "GetLaunchKeyPolicy", rpcServer.getLaunchKeyPolicyRPC)
	registerPrivilegedUnary[SetLaunchKeyPolicyRequest, LaunchKeyPolicyResponse](mux, "SetLaunchKeyPolicy", rpcServer.privileged, rpcServer.setLaunchKeyPolicyRPC)
	registerPrivilegedUnary[PayloadGenerateRequest, PayloadGenerateResponse](mux, "GeneratePayload", rpcServer.privileged, rpcServer.generatePayloadRPC)
	registerUnary[PayloadCommandListRequest, PayloadCommandListResponse](mux, "ListPayloadCommands", rpcServer.listPayloadCommandsRPC)
	registerPrivilegedUnary[PayloadCommandRunRequest, PayloadCommandRunResponse](mux, "RunPayloadCommand", rpcServer.privileged, rpcServer.runPayloadCommandRPC)
	registerUnary[MeshDescribeRequest, MeshDescribeResponse](mux, rpcMethodDescribeMesh, rpcServer.describeMeshRPC)
	registerPrivilegedUnary[MeshTopologyRequest, MeshTopologyResponse](mux, rpcMethodMeshTopology, rpcServer.privileged, rpcServer.meshTopologyRPC)
	registerPrivilegedUnary[MeshBeaconListRequest, MeshBeaconListResponse](mux, rpcMethodListMeshBeacons, rpcServer.privileged, rpcServer.listMeshBeaconsRPC)
	registerPrivilegedUnary[MeshListenerListRequest, MeshListenerListResponse](mux, rpcMethodListMeshListeners, rpcServer.privileged, rpcServer.listMeshListenersRPC)
	registerPrivilegedUnary[MeshListenerStartRequest, MeshListenerStartResponse](mux, rpcMethodStartMeshListener, rpcServer.privileged, rpcServer.startMeshListenerRPC)
	registerPrivilegedUnary[MeshListenerStopRequest, MeshListenerStopResponse](mux, rpcMethodStopMeshListener, rpcServer.privileged, rpcServer.stopMeshListenerRPC)
	registerPrivilegedUnary[MeshTaskRunRequest, MeshTaskRunResponse](mux, rpcMethodRunMeshTask, rpcServer.privileged, rpcServer.runMeshTaskRPC)
	registerPrivilegedUnary[MeshStreamOpenRequest, MeshStreamOpenResponse](mux, rpcMethodOpenMeshStream, rpcServer.privileged, rpcServer.openMeshStreamRPC)
	registerPrivilegedNoStoreUnary[MeshBridgeOpenRequest, MeshBridgeOpenResponse](mux, rpcMethodOpenMeshBridge, rpcServer.privileged, rpcServer.openMeshBridgeRPC)
	registerPrivilegedUnary[MeshBridgeCloseRequest, MeshBridgeCloseResponse](mux, rpcMethodCloseMeshBridge, rpcServer.privileged, rpcServer.closeMeshBridgeRPC)
	registerPrivilegedUnary[MeshOperationListRequest, MeshOperationListResponse](mux, rpcMethodListMeshOperations, rpcServer.privileged, rpcServer.listMeshOperationsRPC)
	registerUnary[EmptyRequest, apppki.WorkspaceStatus](mux, rpcMethodPKIStatus, rpcServer.pkiStatusRPC)
	registerPrivilegedUnary[PKIInitializeRequest, apppki.WorkspaceStatus](mux, rpcMethodInitializePKI, rpcServer.privileged, rpcServer.initializePKIRPC)
	registerUnary[EmptyRequest, PKIBackendListResponse](mux, rpcMethodListPKIBackends, rpcServer.listPKIBackendsRPC)
	registerUnary[EmptyRequest, PKIProfileListResponse](mux, rpcMethodListPKIProfiles, rpcServer.listPKIProfilesRPC)
	registerPrivilegedUnary[EmptyRequest, PKIAuthorityListResponse](mux, rpcMethodListAuthorities, rpcServer.privileged, rpcServer.listPKIAuthoritiesRPC)
	registerPrivilegedUnary[PKIAuthorityRequest, PKIAuthorityInspectResponse](mux, rpcMethodInspectAuthority, rpcServer.privileged, rpcServer.inspectPKIAuthorityRPC)
	registerPrivilegedUnary[PKIAuthorityCreateRequest, apppki.CreateAuthorityResult](mux, rpcMethodCreateAuthority, rpcServer.privileged, rpcServer.createPKIAuthorityRPC)
	registerPrivilegedUnary[PKIAuthorityLeaseRequest, apppki.SigningLease](mux, rpcMethodUnlockAuthority, rpcServer.privileged, rpcServer.unlockPKIAuthorityRPC)
	registerPrivilegedUnary[PKIAuthorityLockRequest, EmptyResponse](mux, rpcMethodLockAuthority, rpcServer.privileged, rpcServer.lockPKIAuthorityRPC)
	registerPrivilegedUnary[EmptyRequest, PKICertificateListResponse](mux, rpcMethodListCertificates, rpcServer.privileged, rpcServer.listPKICertificatesRPC)
	registerPrivilegedUnary[PKICertificateRequest, domainpki.CertificateGeneration](mux, rpcMethodInspectCertificate, rpcServer.privileged, rpcServer.inspectPKICertificateRPC)
	registerPrivilegedUnary[PKICertificateIssueRequest, domainpki.CertificateGeneration](mux, rpcMethodIssueCertificate, rpcServer.privileged, rpcServer.issuePKICertificateRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.RenewCertificateRequest], apppki.CertificateLifecycleResult](mux, rpcMethodRenewCertificate, rpcServer.privileged, rpcServer.renewPKICertificateRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.RotateCertificateRequest], apppki.CertificateLifecycleResult](mux, rpcMethodRotateCertificate, rpcServer.privileged, rpcServer.rotatePKICertificateRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.RevokeCertificateRequest], apppki.CertificateRevocationResult](mux, rpcMethodRevokeCertificate, rpcServer.privileged, rpcServer.revokePKICertificateRPC)
	registerPrivilegedUnary[PKIRevocationRequest, domainpki.Revocation](mux, rpcMethodInspectRevocation, rpcServer.privileged, rpcServer.inspectPKIRevocationRPC)
	registerPrivilegedUnary[PKICertificateRequest, domainpki.Revocation](mux, rpcMethodGenerationRevocation, rpcServer.privileged, rpcServer.inspectPKIGenerationRevocationRPC)
	registerPrivilegedUnary[PKIRevocationListRequest, PKIRevocationListResponse](mux, rpcMethodListRevocations, rpcServer.privileged, rpcServer.listPKIRevocationsRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.PublishCRLRequest], apppki.CRLPublicationResult](mux, rpcMethodPublishCRL, rpcServer.privileged, rpcServer.publishPKICRLRPC)
	registerPrivilegedUnary[PKICRLPublicationRequest, apppki.CRLPublicationIntent](mux, rpcMethodInspectCRLPublication, rpcServer.privileged, rpcServer.inspectPKICRLPublicationRPC)
	registerPrivilegedUnary[PKICRLListRequest, PKICRLPublicationListResponse](mux, rpcMethodListCRLPublications, rpcServer.privileged, rpcServer.listPKICRLPublicationsRPC)
	registerPrivilegedUnary[PKICRLRequest, domainpki.CRLGeneration](mux, rpcMethodInspectCRL, rpcServer.privileged, rpcServer.inspectPKICRLRPC)
	registerPrivilegedUnary[PKICRLListRequest, PKICRLListResponse](mux, rpcMethodListCRLs, rpcServer.privileged, rpcServer.listPKICRLsRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.ReconcileCRLPublicationRequest], apppki.CRLPublicationIntent](mux, rpcMethodReconcileCRL, rpcServer.privileged, rpcServer.reconcilePKICRLRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.ReconcileCRLPublicationsRequest], PKICRLPublicationListResponse](mux, rpcMethodReconcileCRLs, rpcServer.privileged, rpcServer.reconcilePKICRLsRPC)
	registerPrivilegedUnary[EmptyRequest, PKIOperationListResponse](mux, rpcMethodListPKIOperations, rpcServer.privileged, rpcServer.listPKIOperationsRPC)
	registerPrivilegedUnary[PKIOperationRequest, apppki.OperationInspection](mux, rpcMethodInspectPKIOperation, rpcServer.privileged, rpcServer.inspectPKIOperationRPC)
	registerPrivilegedUnary[EmptyRequest, PKICredentialStampListResponse](mux, rpcMethodListCredentialStamps, rpcServer.privileged, rpcServer.listPKICredentialStampsRPC)
	registerPrivilegedUnary[PKICredentialStampRequest, domainpki.CredentialStamp](mux, rpcMethodInspectCredentialStamp, rpcServer.privileged, rpcServer.inspectPKICredentialStampRPC)
	registerPrivilegedUnary[EmptyRequest, PKICredentialExecutionListResponse](mux, rpcMethodListCredentialExecutions, rpcServer.privileged, rpcServer.listPKICredentialExecutionsRPC)
	registerPrivilegedUnary[PKICredentialExecutionRequest, domainpki.CredentialExecution](mux, rpcMethodInspectCredentialExecution, rpcServer.privileged, rpcServer.inspectPKICredentialExecutionRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.StartAuthorityRolloverRequest], apppki.OperationInspection](mux, rpcMethodStartRollover, rpcServer.privileged, rpcServer.startPKIAuthorityRolloverRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.AcknowledgeAuthorityRolloverRequest], apppki.OperationInspection](mux, rpcMethodAcknowledgeRollover, rpcServer.privileged, rpcServer.acknowledgePKIAuthorityRolloverRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.ActivateAuthorityRolloverRequest], apppki.OperationInspection](mux, rpcMethodActivateRollover, rpcServer.privileged, rpcServer.activatePKIAuthorityRolloverRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.BeginAuthorityRolloverFinalTrustRequest], apppki.OperationInspection](mux, rpcMethodBeginRolloverFinal, rpcServer.privileged, rpcServer.beginPKIAuthorityRolloverFinalTrustRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.CompleteAuthorityRolloverRequest], apppki.OperationInspection](mux, rpcMethodCompleteRollover, rpcServer.privileged, rpcServer.completePKIAuthorityRolloverRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.CancelAuthorityRolloverRequest], apppki.OperationInspection](mux, rpcMethodCancelRollover, rpcServer.privileged, rpcServer.cancelPKIAuthorityRolloverRPC)
	registerPrivilegedNoStoreUnary[PKIBundleExportRequest, domainpki.Bundle](mux, rpcMethodExportBundle, rpcServer.privileged, rpcServer.exportPKIBundleRPC)
	registerPrivilegedUnary[EmptyRequest, PKIAssignmentListResponse](mux, rpcMethodListAssignments, rpcServer.privileged, rpcServer.listPKIAssignmentsRPC)
	registerPrivilegedUnary[PKIAssignmentRequest, apppki.AssignmentInspection](mux, rpcMethodInspectAssignment, rpcServer.privileged, rpcServer.inspectPKIAssignmentRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.BindAssignmentRequest], domainpki.Assignment](mux, rpcMethodBindAssignment, rpcServer.privileged, rpcServer.bindPKIAssignmentRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.StageAssignmentRequest], apppki.AssignmentInspection](mux, rpcMethodStageAssignment, rpcServer.privileged, rpcServer.stagePKIAssignmentRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.ActivateAssignmentRequest], apppki.AssignmentInspection](mux, rpcMethodActivateAssignment, rpcServer.privileged, rpcServer.activatePKIAssignmentRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.UnbindAssignmentRequest], domainpki.Assignment](mux, rpcMethodUnbindAssignment, rpcServer.privileged, rpcServer.unbindPKIAssignmentRPC)
	registerPrivilegedUnary[EmptyRequest, PKITrustSetListResponse](mux, rpcMethodListTrustSets, rpcServer.privileged, rpcServer.listPKITrustSetsRPC)
	registerPrivilegedUnary[PKITrustSetRequest, apppki.TrustSetInspection](mux, rpcMethodInspectTrustSet, rpcServer.privileged, rpcServer.inspectPKITrustSetRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.CreateTrustSetRequest], domainpki.TrustSet](mux, rpcMethodCreateTrustSet, rpcServer.privileged, rpcServer.createPKITrustSetRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.StageTrustSetRequest], apppki.TrustSetInspection](mux, rpcMethodStageTrustSet, rpcServer.privileged, rpcServer.stagePKITrustSetRPC)
	registerPrivilegedUnary[PKIMutationRequest[apppki.ActivateTrustSetRequest], apppki.TrustSetInspection](mux, rpcMethodActivateTrustSet, rpcServer.privileged, rpcServer.activatePKITrustSetRPC)
	return nil
}

func NewHandler(runs services.RunService, options ...ServerOption) (http.Handler, error) {
	mux := http.NewServeMux()
	if err := Register(mux, runs, options...); err != nil {
		return nil, err
	}
	return mux, nil
}

func registerUnary[Req, Res any](mux *http.ServeMux, method string, fn func(context.Context, Req) (Res, error)) {
	registerUnaryWithHeaders(mux, method, nil, fn)
}

func registerPrivilegedUnary[Req, Res any](
	mux *http.ServeMux,
	method string,
	allowed bool,
	fn func(context.Context, Req) (Res, error),
) {
	registerUnaryWithHeaders(mux, method, nil, privilegedRPCHandler(allowed, fn))
}

func registerPrivilegedNoStoreUnary[Req, Res any](
	mux *http.ServeMux,
	method string,
	allowed bool,
	fn func(context.Context, Req) (Res, error),
) {
	registerUnaryWithHeaders(
		mux,
		method,
		http.Header{"Cache-Control": []string{"no-store"}},
		privilegedRPCHandler(allowed, fn),
	)
}

func privilegedRPCHandler[Req, Res any](
	allowed bool,
	fn func(context.Context, Req) (Res, error),
) func(context.Context, Req) (Res, error) {
	return func(ctx context.Context, req Req) (Res, error) {
		if !allowed {
			var zero Res
			return zero, errPrivilegedControlUnavailable
		}
		return fn(ctx, req)
	}
}

func registerUnaryWithHeaders[Req, Res any](mux *http.ServeMux, method string, headers http.Header, fn func(context.Context, Req) (Res, error)) {
	path := serviceURLPrefix + method
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		for key, values := range headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer func() { logDaemonRPCError("close request body", r.Body.Close()) }()
		var req Req
		r.Body = http.MaxBytesReader(w, r.Body, maximumRPCRequestBytes)
		if err := decodeRPCRequest(r.Body, &req); err != nil {
			status := http.StatusBadRequest
			var sizeError *http.MaxBytesError
			if errors.As(err, &sizeError) {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, "invalid JSON request: "+err.Error(), status)
			return
		}
		resp, err := fn(r.Context(), req)
		if err != nil {
			writeRPCError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func writeRPCError(w http.ResponseWriter, err error) {
	status, envelope := classifyRPCError(err)
	if envelope.Code == RPCErrorCodeInternal {
		http.Error(w, envelope.Message, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if encodeErr := json.NewEncoder(w).Encode(envelope); encodeErr != nil {
		logDaemonRPCError("encode rpc error response", encodeErr)
	}
}

func classifyRPCError(err error) (int, RPCErrorEnvelope) {
	envelope := RPCErrorEnvelope{
		Version: rpcErrorVersionV1,
		Code:    RPCErrorCodeInternal,
		Message: err.Error(),
	}
	var rollover *apppki.RolloverPreconditionError
	switch {
	case errors.As(err, &rollover):
		envelope.Code = RPCErrorCodeRolloverPrecondition
		envelope.RolloverReason = rollover.Reason
		envelope.RolloverDetail = rollover.Detail
		return http.StatusConflict, envelope
	case errors.Is(err, apppki.ErrRevisionConflict):
		envelope.Code = RPCErrorCodeRevisionConflict
		return http.StatusConflict, envelope
	case errors.Is(err, apppki.ErrAcknowledgementExists):
		envelope.Code = RPCErrorCodeAcknowledgementExists
		return http.StatusConflict, envelope
	case errors.Is(err, apppki.ErrIdempotencyConflict):
		envelope.Code = RPCErrorCodeIdempotencyConflict
		return http.StatusConflict, envelope
	case errors.Is(err, apppki.ErrMutationExists):
		envelope.Code = RPCErrorCodeMutationExists
		return http.StatusConflict, envelope
	case errors.Is(err, apppki.ErrIssuanceInProgress):
		envelope.Code = RPCErrorCodeIssuanceInProgress
		return http.StatusConflict, envelope
	case errors.Is(err, apppki.ErrCRLPublicationInProgress):
		envelope.Code = RPCErrorCodeCRLPublicationInProgress
		return http.StatusConflict, envelope
	case errors.Is(err, apppki.ErrPrivateKeyExportDenied):
		envelope.Code = RPCErrorCodePrivateKeyExportDenied
		return http.StatusForbidden, envelope
	case errors.Is(err, apppki.ErrAuthoritySigningLeaseOwned):
		envelope.Code = RPCErrorCodeAuthoritySigningLeaseOwned
		return http.StatusForbidden, envelope
	case errors.Is(err, apppki.ErrAuthoritySigningLocked):
		envelope.Code = RPCErrorCodeAuthoritySigningLocked
		return http.StatusLocked, envelope
	case errors.Is(err, errPrivilegedControlUnavailable):
		envelope.Code = RPCErrorCodePermissionDenied
		return http.StatusForbidden, envelope
	case errors.Is(err, errMeshTaskPlanRequired):
		envelope.Code = RPCErrorCodePermissionDenied
		return http.StatusForbidden, envelope
	case errors.Is(err, apppki.ErrNotFound):
		envelope.Code = RPCErrorCodeNotFound
		return http.StatusNotFound, envelope
	default:
		return http.StatusInternalServerError, envelope
	}
}

func decodeRPCRequest[T any](reader io.Reader, target *T) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

type ServerOption func(*Server)

func WithSession(session *operatorsession.Session) ServerOption {
	return func(server *Server) {
		if session != nil {
			server.session = session
		}
	}
}

func WithLogBroker(logs *LogBroker) ServerOption {
	return func(server *Server) {
		if logs != nil {
			server.logs = logs
		}
	}
}

func WithSessionPersistence(persist func(operatorsession.PersistedState) error) ServerOption {
	return func(server *Server) {
		server.persistSession = persist
	}
}

func WithModuleSessions(sessions services.SessionBroker) ServerOption {
	return func(server *Server) {
		server.moduleSessions = sessions
	}
}

func WithMeshBook(book *MeshBook) ServerOption {
	return func(server *Server) {
		if book != nil {
			server.meshOps = book
		}
	}
}

func WithMeshBridgeManager(manager *MeshBridgeManager) ServerOption {
	return func(server *Server) {
		if manager != nil {
			server.meshBridges = manager
		}
	}
}

func WithOperatorClock(clock operatorClock) ServerOption {
	return func(server *Server) {
		if clock != nil {
			server.clock = clock
		}
	}
}

func WithPKIControl(control apppki.WorkspaceControl) ServerOption {
	return func(server *Server) {
		server.pki = control
	}
}

func WithPKISecretResponses(allowed bool) ServerOption {
	return func(server *Server) {
		server.pkiSecrets = allowed
	}
}

// WithPrivilegedControl enables mutation and execution-capable RPC methods.
// Production composition must enable it only for an authenticated transport;
// the built-in daemon currently treats its owner-only Unix socket as that
// boundary and leaves plain TCP read-only.
func WithPrivilegedControl(allowed bool) ServerOption {
	return func(server *Server) {
		server.privileged = allowed
	}
}

func WithLaunchKeyPolicy(policy operatordomain.LaunchKeyPolicy) ServerOption {
	return func(server *Server) {
		server.launchKeyPolicy = operatordomain.NormalizeLaunchKeyPolicy(policy)
	}
}

func (s *Server) meshBook() *MeshBook {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meshOps == nil {
		s.meshOps = NewMeshBook()
	}
	return s.meshOps
}

func (s *Server) meshBridgeManager() *MeshBridgeManager {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meshBridges == nil {
		s.meshBridges = NewMeshBridgeManager()
	}
	return s.meshBridges
}

func (s *Server) now() time.Time {
	if s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock.Now().UTC()
}

func (s *Server) RunMockExploit(req RunMockExploitRequest, resp *RunMockExploitResponse) error {
	return s.ExecuteModule(ExecuteModuleRequest(req), (*ExecuteModuleResponse)(resp))
}

func (s *Server) executeModuleRPC(ctx context.Context, req ExecuteModuleRequest) (ExecuteModuleResponse, error) {
	var resp ExecuteModuleResponse
	err := s.executeModule(ctx, req, &resp)
	return resp, err
}

func (s *Server) ExecuteModule(req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	return s.executeModule(context.Background(), req, resp)
}

func (s *Server) executeModule(ctx context.Context, req ExecuteModuleRequest, resp *ExecuteModuleResponse) error {
	var throwStarted time.Time
	if req.ThrowStarted != "" {
		var err error
		throwStarted, err = time.Parse(time.RFC3339Nano, req.ThrowStarted)
		if err != nil {
			return fmt.Errorf("parse throw started timestamp: %w", err)
		}
	}
	result, err := s.runs.ExecuteModule(ctx, services.ExecuteModuleRequest{
		Operation:    req.Operation,
		Chain:        req.Chain,
		ModuleID:     req.ModuleID,
		Target:       req.Target,
		Inputs:       req.Inputs,
		ChainConfig:  req.ChainConfig,
		TargetConfig: req.TargetConfig,
		ThrowStarted: throwStarted,
	})
	if err != nil {
		return err
	}
	*resp = responseFromResult(result)
	return nil
}

func (s *Server) generatePayloadRPC(ctx context.Context, req PayloadGenerateRequest) (PayloadGenerateResponse, error) {
	return s.runs.GeneratePayload(ctx, services.GeneratePayloadRequest{
		ModuleID: req.ModuleID,
		Request:  req.Request,
	})
}

func (s *Server) listPayloadCommandsRPC(ctx context.Context, req PayloadCommandListRequest) (PayloadCommandListResponse, error) {
	commands, err := s.runs.ListPayloadCommands(ctx, services.PayloadCommandListRequest{
		ModuleID: req.ModuleID,
		Request:  req.Request,
	})
	if err != nil {
		return PayloadCommandListResponse{}, err
	}
	return PayloadCommandListResponse{Commands: commands}, nil
}

func (s *Server) runPayloadCommandRPC(ctx context.Context, req PayloadCommandRunRequest) (PayloadCommandRunResponse, error) {
	return s.runs.RunPayloadCommand(ctx, services.PayloadCommandRunRequest{
		Operation: req.Operation,
		Chain:     req.Chain,
		ModuleID:  req.ModuleID,
		Request:   req.Request,
	})
}

func (s *Server) describeMeshRPC(ctx context.Context, req MeshDescribeRequest) (MeshDescribeResponse, error) {
	return s.runs.DescribeMesh(ctx, req.ModuleID, req.Request)
}

func (s *Server) meshTopologyRPC(ctx context.Context, req MeshTopologyRequest) (MeshTopologyResponse, error) {
	return s.runs.MeshTopology(ctx, req.ModuleID, req.Request)
}

func (s *Server) listMeshBeaconsRPC(
	ctx context.Context,
	req MeshBeaconListRequest,
) (MeshBeaconListResponse, error) {
	beacons, err := s.runs.ListMeshBeacons(ctx, req.ModuleID, req.Request)
	if err != nil {
		return MeshBeaconListResponse{}, err
	}
	return MeshBeaconListResponse{Beacons: beacons}, nil
}

func (s *Server) listMeshListenersRPC(
	ctx context.Context,
	req MeshListenerListRequest,
) (MeshListenerListResponse, error) {
	listeners, err := s.runs.ListMeshListeners(ctx, req.ModuleID, req.Request)
	if err != nil {
		return MeshListenerListResponse{}, err
	}
	return MeshListenerListResponse{Listeners: listeners}, nil
}

func (s *Server) startMeshListenerRPC(
	ctx context.Context,
	req MeshListenerStartRequest,
) (MeshListenerStartResponse, error) {
	operation := s.meshBook().StartListener(
		req.ModuleID,
		MeshListenerActionStart,
		req.Request.ListenerID,
		s.now(),
	)
	ctx, err := bindMeshCredentialContext(ctx, req.Credentials, req.CredentialContext)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return MeshListenerStartResponse{}, err
	}
	listener, err := s.runs.StartMeshListenerWithCredentialSelections(
		ctx,
		req.ModuleID,
		req.Request,
		req.Credentials,
		meshCredentialOperationScope(req.CredentialContext),
	)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return MeshListenerStartResponse{}, err
	}
	s.meshBook().CompleteListener(operation.ID, listener, s.now())
	return MeshListenerStartResponse{OperationID: operation.ID, Listener: listener}, nil
}

func (s *Server) stopMeshListenerRPC(
	ctx context.Context,
	req MeshListenerStopRequest,
) (MeshListenerStopResponse, error) {
	operation := s.meshBook().StartListener(
		req.ModuleID,
		MeshListenerActionStop,
		req.Request.ListenerID,
		s.now(),
	)
	listener, err := s.runs.StopMeshListener(ctx, req.ModuleID, req.Request)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return MeshListenerStopResponse{}, err
	}
	s.meshBook().CompleteListener(operation.ID, listener, s.now())
	return MeshListenerStopResponse{OperationID: operation.ID, Listener: listener}, nil
}

func (s *Server) runMeshTaskRPC(ctx context.Context, req MeshTaskRunRequest) (MeshTaskRunResponse, error) {
	operation := s.meshBook().StartTask(req.ModuleID, req.Request, s.now())
	if err := authorizeDirectMeshTask(req.Request.Kind); err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return MeshTaskRunResponse{}, err
	}
	ctx, err := bindMeshCredentialContext(ctx, req.Credentials, req.CredentialContext)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return MeshTaskRunResponse{}, err
	}
	result, err := s.runs.RunMeshTaskWithCredentialSelections(
		ctx,
		req.ModuleID,
		req.Request,
		req.Credentials,
		meshCredentialOperationScope(req.CredentialContext),
	)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return MeshTaskRunResponse{}, err
	}
	s.meshBook().CompleteTask(operation.ID, result, s.now())
	return result, nil
}

func authorizeDirectMeshTask(kind mesh.TaskKind) error {
	kind = mesh.TaskKind(strings.TrimSpace(string(kind)))
	if kind == "" || kind == mesh.TaskSurvey {
		return nil
	}
	return fmt.Errorf("%w: %q", errMeshTaskPlanRequired, kind)
}

func (s *Server) openMeshStreamRPC(
	ctx context.Context,
	req MeshStreamOpenRequest,
) (MeshStreamOpenResponse, error) {
	operation := s.meshBook().StartStream(req.ModuleID, req.Request, s.now())
	ctx, err := bindMeshCredentialContext(ctx, req.Credentials, req.CredentialContext)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return run.SessionRef{}, err
	}
	session, err := s.runs.OpenMeshStreamWithCredentialSelections(
		ctx,
		req.ModuleID,
		req.Request,
		req.Credentials,
		meshCredentialOperationScope(req.CredentialContext),
	)
	if err != nil {
		s.meshBook().Fail(operation.ID, err, s.now())
		return run.SessionRef{}, err
	}
	s.meshBook().ActivateStream(operation.ID, session, s.now())
	return session, nil
}

func (s *Server) openMeshBridgeRPC(
	ctx context.Context,
	req MeshBridgeOpenRequest,
) (MeshBridgeOpenResponse, error) {
	if s.moduleSessions == nil {
		return MeshBridgeOpenResponse{}, errors.New("session broker is not configured")
	}
	ctx, err := bindMeshCredentialContext(ctx, req.Credentials, req.CredentialContext)
	if err != nil {
		return MeshBridgeOpenResponse{}, err
	}
	return OpenMeshBridge(
		ctx,
		MeshBridgeOpenArgs{
			ModuleID:        req.ModuleID,
			Request:         req.Request,
			Host:            req.LocalHost,
			Port:            req.LocalPort,
			LocalNetwork:    req.LocalNetwork,
			Credentials:     req.Credentials,
			CredentialScope: meshCredentialOperationScope(req.CredentialContext),
			Runs:            s.runs,
			Sessions:        s.moduleSessions,
			Book:            s.meshBook(),
			Bridges:         s.meshBridgeManager(),
			Now:             s.now,
		},
	)
}

func bindMeshCredentialContext(
	ctx context.Context,
	credentials domainpki.CredentialSelections,
	request *PKIRequestContext,
) (context.Context, error) {
	if len(credentials) == 0 {
		if request != nil {
			return nil, errors.New("credential context requires at least one credential selection")
		}
		return ctx, nil
	}
	if request == nil {
		return nil, errors.New("credential selections require an authenticated credential context")
	}
	return request.bind(ctx)
}

func meshCredentialOperationScope(
	request *PKIRequestContext,
) domainpki.CredentialOperationScope {
	if request == nil {
		return domainpki.CredentialOperationScope{}
	}
	return domainpki.CredentialOperationScope{
		OperationID: domainpki.OperationID(request.OperationID),
	}
}

func (s *Server) closeMeshBridgeRPC(
	ctx context.Context,
	req MeshBridgeCloseRequest,
) (MeshBridgeCloseResponse, error) {
	operationID := strings.TrimSpace(req.OperationID)
	sessionID := strings.TrimSpace(req.SessionID)
	if (operationID == "") == (sessionID == "") {
		return MeshBridgeCloseResponse{}, errors.New("exactly one mesh bridge operation id or session id is required")
	}
	bridge, ok := s.meshBridgeManager().Find(operationID, sessionID)
	if !ok {
		return MeshBridgeCloseResponse{}, errors.New("mesh bridge does not exist")
	}
	if err := bridge.Close(ctx); err != nil {
		return MeshBridgeCloseResponse{}, err
	}
	return MeshBridgeCloseResponse{
		OperationID: bridge.OperationID(),
		SessionID:   bridge.SessionID(),
		State:       MeshOperationStateClosed,
	}, nil
}

func (s *Server) listMeshOperationsRPC(
	_ context.Context,
	req MeshOperationListRequest,
) (MeshOperationListResponse, error) {
	return MeshOperationListResponse{Operations: s.meshBook().List(req)}, nil
}

type SessionReadRequest struct {
	SessionID string
	TimeoutMs int
}

type SessionTailRequest struct {
	SessionID string
	MaxBytes  int
	MaxLines  int
	Consume   bool
}

type SessionWriteRequest struct {
	SessionID string
	Data      []byte
}

type SessionCloseRequest struct {
	SessionID string
}

type SessionCommandListRequest struct {
	SessionID string                        `json:"sessionId"`
	Request   run.PayloadCommandListRequest `json:"request"`
}

type SessionCommandListResponse struct {
	Commands []run.PayloadCommand `json:"commands"`
}

type SessionCommandRunRequest struct {
	SessionID string                    `json:"sessionId"`
	Request   run.PayloadCommandRequest `json:"request"`
}

type SessionCommandRunResponse = run.PayloadCommandResult

type ListSessionsResponse struct {
	Sessions []SessionRef
}

func (s *Server) ListSessions(_ EmptyRequest, resp *ListSessionsResponse) error {
	if s.moduleSessions == nil {
		resp.Sessions = nil
		return nil
	}
	sessions, err := s.moduleSessions.ListSessions(context.Background())
	if err != nil {
		return err
	}
	resp.Sessions = sessionRefsFromRun(sessions)
	return nil
}

func (s *Server) listSessionsRPC(ctx context.Context, _ EmptyRequest) (ListSessionsResponse, error) {
	var resp ListSessionsResponse
	if s.moduleSessions == nil {
		return resp, nil
	}
	sessions, err := s.moduleSessions.ListSessions(ctx)
	if err != nil {
		return resp, err
	}
	resp.Sessions = sessionRefsFromRun(sessions)
	return resp, nil
}

func (s *Server) ReadSession(req SessionReadRequest, resp *SessionChunk) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	chunk, err := s.moduleSessions.ReadSession(context.Background(), req.SessionID, timeout)
	if err != nil {
		return err
	}
	*resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return nil
}

func (s *Server) readSessionRPC(ctx context.Context, req SessionReadRequest) (SessionChunk, error) {
	var resp SessionChunk
	if s.moduleSessions == nil {
		return resp, errors.New("session broker is not configured")
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	chunk, err := s.moduleSessions.ReadSession(ctx, req.SessionID, timeout)
	if err != nil {
		return resp, err
	}
	resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return resp, nil
}

func (s *Server) TailSession(req SessionTailRequest, resp *SessionChunk) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	chunk, err := s.moduleSessions.TailSession(context.Background(), req.SessionID, run.SessionTailOptions{
		MaxBytes: req.MaxBytes,
		MaxLines: req.MaxLines,
		Consume:  req.Consume,
	})
	if err != nil {
		return err
	}
	*resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return nil
}

func (s *Server) tailSessionRPC(ctx context.Context, req SessionTailRequest) (SessionChunk, error) {
	var resp SessionChunk
	if s.moduleSessions == nil {
		return resp, errors.New("session broker is not configured")
	}
	chunk, err := s.moduleSessions.TailSession(ctx, req.SessionID, run.SessionTailOptions{
		MaxBytes: req.MaxBytes,
		MaxLines: req.MaxLines,
		Consume:  req.Consume,
	})
	if err != nil {
		return resp, err
	}
	resp = SessionChunk{
		SessionID: chunk.SessionID,
		Data:      append([]byte(nil), chunk.Data...),
		Closed:    chunk.Closed,
	}
	if resp.Closed {
		s.meshBook().CloseSession(req.SessionID, s.now())
	}
	return resp, nil
}

func (s *Server) WriteSession(req SessionWriteRequest, resp *EmptyResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	return s.moduleSessions.WriteSession(context.Background(), req.SessionID, req.Data)
}

func (s *Server) writeSessionRPC(ctx context.Context, req SessionWriteRequest) (EmptyResponse, error) {
	if s.moduleSessions == nil {
		return EmptyResponse{}, errors.New("session broker is not configured")
	}
	return EmptyResponse{}, s.moduleSessions.WriteSession(ctx, req.SessionID, req.Data)
}

func (s *Server) CloseSession(req SessionCloseRequest, resp *EmptyResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	if err := s.moduleSessions.CloseSession(context.Background(), req.SessionID); err != nil {
		return err
	}
	s.meshBook().CloseSession(req.SessionID, s.now())
	return nil
}

func (s *Server) closeSessionRPC(ctx context.Context, req SessionCloseRequest) (EmptyResponse, error) {
	if s.moduleSessions == nil {
		return EmptyResponse{}, errors.New("session broker is not configured")
	}
	if err := s.moduleSessions.CloseSession(ctx, req.SessionID); err != nil {
		return EmptyResponse{}, err
	}
	s.meshBook().CloseSession(req.SessionID, s.now())
	return EmptyResponse{}, nil
}

func (s *Server) ListSessionCommands(req SessionCommandListRequest, resp *SessionCommandListResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	commands, err := s.moduleSessions.ListSessionCommands(context.Background(), req.SessionID, req.Request)
	if err != nil {
		return err
	}
	resp.Commands = commands
	return nil
}

func (s *Server) listSessionCommandsRPC(ctx context.Context, req SessionCommandListRequest) (SessionCommandListResponse, error) {
	if s.moduleSessions == nil {
		return SessionCommandListResponse{}, errors.New("session broker is not configured")
	}
	commands, err := s.moduleSessions.ListSessionCommands(ctx, req.SessionID, req.Request)
	if err != nil {
		return SessionCommandListResponse{}, err
	}
	return SessionCommandListResponse{Commands: commands}, nil
}

func (s *Server) RunSessionCommand(req SessionCommandRunRequest, resp *SessionCommandRunResponse) error {
	if s.moduleSessions == nil {
		return errors.New("session broker is not configured")
	}
	result, err := s.moduleSessions.RunSessionCommand(context.Background(), req.SessionID, req.Request)
	if err != nil {
		return err
	}
	*resp = result
	return nil
}

func (s *Server) runSessionCommandRPC(ctx context.Context, req SessionCommandRunRequest) (SessionCommandRunResponse, error) {
	if s.moduleSessions == nil {
		return SessionCommandRunResponse{}, errors.New("session broker is not configured")
	}
	return s.moduleSessions.RunSessionCommand(ctx, req.SessionID, req.Request)
}

type ChainRequest struct {
	Operation string
	Chain     string
}

type RenameChainRequest struct {
	Operation string
	Chain     string
	Name      string
}

type TargetRequest struct {
	Operation string
	Target    string
	Chain     string
}

type TargetSetRequest struct {
	Operation string
	Name      string
	Target    string
	Chain     string
}

type ModuleRequest struct {
	Operation string
	ModuleID  string
	StepID    string
	Chain     string
}

type StepResponse struct {
	ID       string
	ModuleID string
	StepID   string
}

type ConfigRequest struct {
	Operation string
	Key       string
	Value     string
	Chain     string
}

type TargetConfigRequest struct {
	Operation string
	Target    string
	Key       string
	Value     string
	Chain     string
}

type SnapshotRequest struct {
	Operation string
	Chain     string
}

type SnapshotResponse struct {
	State operatorsession.PersistedState
}

type AppendLogRequest struct {
	Operation string
	Chain     string
	Entries   []OperatorLogEntry
}

type EmptyResponse struct{}

type EmptyRequest struct{}

type ActiveLogsRequest struct {
	Operation string
	Chain     string
}

type OperationRequest struct {
	Operation string
}

func (s *Server) AttachEntity(req AttachEntityRequest, resp *EntityResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	entity, err := operatordomain.NewEntity(operatordomain.EntityArgs{
		ID:           req.ID,
		Kind:         operatordomain.EntityKind(req.Kind),
		DisplayName:  req.DisplayName,
		Agent:        req.Agent,
		Operation:    req.Operation,
		ActiveChain:  req.ActiveChain,
		ConnectedAt:  now,
		LastSeenAt:   now,
		Capabilities: req.Capabilities,
		PolicyTags:   req.PolicyTags,
	})
	if err != nil {
		return err
	}
	s.ensureEntitiesLocked()
	s.entities[entity.ID] = entity
	resp.Entity = operatorEntityFromDomain(entity)
	return nil
}

func (s *Server) HeartbeatEntity(req HeartbeatEntityRequest, resp *EntityResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		return errors.New("operator entity id is required")
	}
	s.ensureEntitiesLocked()
	entity, ok := s.entities[req.ID]
	if !ok {
		return fmt.Errorf("operator entity %s is not attached", req.ID)
	}
	operation := entity.Operation
	if req.Operation != nil {
		operation = *req.Operation
	}
	activeChain := entity.ActiveChain
	if req.ActiveChain != nil {
		activeChain = *req.ActiveChain
	}
	next, err := operatordomain.NewEntity(operatordomain.EntityArgs{
		ID:           entity.ID,
		Kind:         entity.Kind,
		DisplayName:  entity.DisplayName,
		Agent:        entity.Agent,
		Operation:    operation,
		ActiveChain:  activeChain,
		ConnectedAt:  entity.ConnectedAt,
		LastSeenAt:   s.now(),
		Capabilities: entity.Capabilities,
		PolicyTags:   entity.PolicyTags,
	})
	if err != nil {
		return err
	}
	s.entities[next.ID] = next
	resp.Entity = operatorEntityFromDomain(next)
	return nil
}

func (s *Server) DetachEntity(req DetachEntityRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		return errors.New("operator entity id is required")
	}
	s.ensureEntitiesLocked()
	delete(s.entities, req.ID)
	return nil
}

func (s *Server) ListEntities(req ListEntitiesRequest, resp *ListEntitiesResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureEntitiesLocked()
	operation := strings.TrimSpace(req.Operation)
	entities := make([]operatordomain.Entity, 0, len(s.entities))
	for _, entity := range s.entities {
		if operation != "" && entity.Operation != operation {
			continue
		}
		entities = append(entities, entity)
	}
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].ID < entities[j].ID
	})
	resp.Entities = make([]OperatorEntity, 0, len(entities))
	for _, entity := range entities {
		resp.Entities = append(resp.Entities, operatorEntityFromDomain(entity))
	}
	return nil
}

func (s *Server) CreatePendingThrow(req CreatePendingThrowRequest, resp *PendingThrowResponse) error {
	operation := operationOrDefault(req.Operation)
	entities, policy, now := s.launchKeyInputs(operation)
	snapshot, err := s.launchKeyCoordinator().CreatePending(launchkey.CreatePendingRequest{
		ID:        req.ID,
		Operation: operation,
		Chain:     strings.TrimSpace(req.Chain),
		PlanHash:  req.PlanHash,
		Flags:     approvalFlags(req.AllowDangerous, req.NowBypass),
		Entities:  entities,
		Policy:    policy,
		Now:       now,
	})
	if err != nil {
		return err
	}
	*resp = pendingThrowResponse(snapshot)
	return nil
}

func (s *Server) GetLaunchKeyPolicy(req LaunchKeyPolicyRequest, resp *LaunchKeyPolicyResponse) error {
	operation := operationOrDefault(req.Operation)
	policy := s.launchKeyPolicyForOperation(operation)
	*resp = launchKeyPolicyResponse(operation, policy)
	return nil
}

func (s *Server) SetLaunchKeyPolicy(req SetLaunchKeyPolicyRequest, resp *LaunchKeyPolicyResponse) error {
	operation := operationOrDefault(req.Operation)
	policy, err := launchKeyPolicyFromRequest(req)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.launchKeyByOp == nil {
		s.launchKeyByOp = map[string]operatordomain.LaunchKeyPolicy{}
	}
	s.launchKeyByOp[operation] = policy
	s.mu.Unlock()
	*resp = launchKeyPolicyResponse(operation, policy)
	return nil
}

func (s *Server) ConfirmPendingThrow(req ConfirmPendingThrowRequest, resp *PendingThrowResponse) error {
	snapshot, err := s.launchKeyCoordinator().Confirm(launchkey.ConfirmRequest{
		PendingID:   req.ID,
		EntityID:    req.EntityID,
		PlanHash:    req.PlanHash,
		Flags:       approvalFlags(req.AllowDangerous, req.NowBypass),
		ConfirmedAt: s.now(),
	})
	if err != nil {
		return err
	}
	*resp = pendingThrowResponse(snapshot)
	return nil
}

func (s *Server) RequirePendingThrowReady(req PendingThrowRequest, resp *PendingThrowResponse) error {
	snapshot, err := s.launchKeyCoordinator().RequireReady(req.ID)
	if err != nil {
		*resp = pendingThrowResponse(snapshot)
		return err
	}
	*resp = pendingThrowResponse(snapshot)
	return nil
}

func (s *Server) CancelPendingThrow(req PendingThrowRequest, resp *EmptyResponse) error {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		return errors.New("pending throw id is required")
	}
	if !s.launchKeyCoordinator().Cancel(id) {
		return fmt.Errorf("pending throw %s does not exist", id)
	}
	return nil
}

func (s *Server) CreateOperation(req OperationRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.session.CreateOperation(req.Operation); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Server) UseOperation(req OperationRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.session.CreateOperation(req.Operation); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Server) CreateChain(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, "")
	if err := session.CreateChain(req.Chain); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, operatorlog.Info("chain", "chain created", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return s.persistLocked()
}

func (s *Server) UseChain(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, "")
	if err := session.UseChain(req.Chain); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, operatorlog.Info("chain", "chain selected", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return s.persistLocked()
}

func (s *Server) RenameChain(req RenameChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.RenameChain(req.Chain, req.Name); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Name, operatorlog.Info("chain", "chain renamed",
		operatorlog.Field{Name: "from", Value: req.Chain},
		operatorlog.Field{Name: "to", Value: req.Name},
	))
	return s.persistLocked()
}

func (s *Server) DeleteChain(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.DeleteChain(req.Chain); err != nil {
		return err
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, operatorlog.Info("chain", "chain deleted", operatorlog.Field{Name: "chain", Value: req.Chain}))
	return s.persistLocked()
}

func (s *Server) AddTarget(req TargetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.AddTarget(req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target added", operatorlog.Field{Name: "target", Value: req.Target}))
	}
	return s.persistLocked()
}

func (s *Server) BindTarget(req TargetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.BindTarget(req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target bound", operatorlog.Field{Name: "target", Value: req.Target}))
	}
	return s.persistLocked()
}

func (s *Server) UnbindTarget(req TargetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.UnbindTarget(req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target unbound", operatorlog.Field{Name: "target", Value: req.Target}))
	}
	return s.persistLocked()
}

func (s *Server) ClearTargets(req ChainRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	session.ClearTargets()
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "targets cleared"))
	}
	return s.persistLocked()
}

func (s *Server) CreateTargetSet(req TargetSetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.CreateTargetSet(req.Name); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target set created", operatorlog.Field{Name: "targetSet", Value: req.Name}))
	}
	return s.persistLocked()
}

func (s *Server) AddTargetToSet(req TargetSetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.AddTargetToSet(req.Name, req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target added to set",
			operatorlog.Field{Name: "targetSet", Value: req.Name},
			operatorlog.Field{Name: "target", Value: req.Target},
		))
	}
	return s.persistLocked()
}

func (s *Server) RemoveTargetFromSet(req TargetSetRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.RemoveTargetFromSet(req.Name, req.Target); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("target", "target removed from set",
			operatorlog.Field{Name: "targetSet", Value: req.Name},
			operatorlog.Field{Name: "target", Value: req.Target},
		))
	}
	return s.persistLocked()
}

func (s *Server) AddModule(req ModuleRequest, resp *StepResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		step, err := session.AddStep(req.ModuleID, req.StepID)
		if err != nil {
			return err
		}
		*resp = StepResponse{ID: step.ID, ModuleID: step.ModuleID, StepID: step.StepID}
		fields := []operatorlog.Field{
			operatorlog.Field{Name: "step", Value: step.ID},
			operatorlog.Field{Name: "module", Value: req.ModuleID},
		}
		if step.StepID != "" {
			fields = append(fields, operatorlog.Field{Name: "providerStep", Value: step.StepID})
		}
		s.publish(operation, chain, operatorlog.Info("chain", "module added", fields...))
		return nil
	})
}

func (s *Server) SetChainConfig(req ConfigRequest, resp *EmptyResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		if err := session.SetChainConfig(req.Key, req.Value); err != nil {
			return err
		}
		s.publish(operation, chain, operatorlog.Info("config", "chain config set", operatorlog.Field{Name: "key", Value: req.Key}))
		return nil
	})
}

func (s *Server) UnsetChainConfig(req ConfigRequest, resp *EmptyResponse) error {
	return s.withChain(req.Operation, req.Chain, func(session *operatorsession.Session, operation, chain string) error {
		if err := session.UnsetChainConfig(req.Key); err != nil {
			return err
		}
		s.publish(operation, chain, operatorlog.Info("config", "chain config unset", operatorlog.Field{Name: "key", Value: req.Key}))
		return nil
	})
}

func (s *Server) SetTargetConfig(req TargetConfigRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.SetTargetConfig(req.Target, req.Key, req.Value); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("config", "target config set",
			operatorlog.Field{Name: "target", Value: req.Target},
			operatorlog.Field{Name: "key", Value: req.Key},
		))
	}
	return s.persistLocked()
}

func (s *Server) UnsetTargetConfig(req TargetConfigRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(req.Operation, req.Chain)
	if err := session.UnsetTargetConfig(req.Target, req.Key); err != nil {
		return err
	}
	state := session.Snapshot()
	if state.ActiveChain != "" {
		s.publish(state.ActiveOperation, state.ActiveChain, operatorlog.Info("config", "target config unset",
			operatorlog.Field{Name: "target", Value: req.Target},
			operatorlog.Field{Name: "key", Value: req.Key},
		))
	}
	return s.persistLocked()
}

func (s *Server) Snapshot(req SnapshotRequest, resp *SnapshotResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp.State = s.attachment(req.Operation, req.Chain).Export()
	return nil
}

func (s *Server) ActiveLogs(req ActiveLogsRequest, resp *[]OperatorLogEntry) error {
	return s.withChainRead(req.Operation, req.Chain, func(session *operatorsession.Session, _, _ string) error {
		for _, entry := range session.ActiveLogs() {
			*resp = append(*resp, operatorLogEntry(entry))
		}
		return nil
	})
}

func (s *Server) AppendLog(req AppendLogRequest, resp *EmptyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]operatorlog.Entry, 0, len(req.Entries))
	for _, entry := range req.Entries {
		entries = append(entries, operatorLogFromRPC(entry))
	}
	session := s.attachment(req.Operation, req.Chain)
	if req.Chain == "" {
		if err := session.AppendLog(entries...); err != nil {
			return err
		}
		req.Chain = session.Snapshot().ActiveChain
	} else {
		if err := session.AppendLogToChain(req.Chain, entries...); err != nil {
			return err
		}
	}
	s.publish(session.Snapshot().ActiveOperation, req.Chain, entries...)
	return s.persistLocked()
}

func (s *Server) PollLogs(req PollLogsRequest, resp *PollLogsResponse) error {
	if req.Chain != "" {
		resp.Last, resp.Logs = s.logs.SinceChain(operationOrDefault(req.Operation), req.Chain, req.Since)
		return nil
	}
	resp.Last, resp.Logs = s.logs.Since(req.Since)
	return nil
}

func (s *Server) createOperationRPC(_ context.Context, req OperationRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CreateOperation(req, &resp)
	return resp, err
}

func (s *Server) useOperationRPC(_ context.Context, req OperationRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UseOperation(req, &resp)
	return resp, err
}

func (s *Server) createChainRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CreateChain(req, &resp)
	return resp, err
}

func (s *Server) useChainRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UseChain(req, &resp)
	return resp, err
}

func (s *Server) renameChainRPC(_ context.Context, req RenameChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.RenameChain(req, &resp)
	return resp, err
}

func (s *Server) deleteChainRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.DeleteChain(req, &resp)
	return resp, err
}

func (s *Server) addTargetRPC(_ context.Context, req TargetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.AddTarget(req, &resp)
	return resp, err
}

func (s *Server) bindTargetRPC(_ context.Context, req TargetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.BindTarget(req, &resp)
	return resp, err
}

func (s *Server) unbindTargetRPC(_ context.Context, req TargetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UnbindTarget(req, &resp)
	return resp, err
}

func (s *Server) clearTargetsRPC(_ context.Context, req ChainRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.ClearTargets(req, &resp)
	return resp, err
}

func (s *Server) createTargetSetRPC(_ context.Context, req TargetSetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CreateTargetSet(req, &resp)
	return resp, err
}

func (s *Server) addTargetToSetRPC(_ context.Context, req TargetSetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.AddTargetToSet(req, &resp)
	return resp, err
}

func (s *Server) removeTargetFromSetRPC(_ context.Context, req TargetSetRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.RemoveTargetFromSet(req, &resp)
	return resp, err
}

func (s *Server) addModuleRPC(_ context.Context, req ModuleRequest) (StepResponse, error) {
	var resp StepResponse
	err := s.AddModule(req, &resp)
	return resp, err
}

func (s *Server) setChainConfigRPC(_ context.Context, req ConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.SetChainConfig(req, &resp)
	return resp, err
}

func (s *Server) unsetChainConfigRPC(_ context.Context, req ConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UnsetChainConfig(req, &resp)
	return resp, err
}

func (s *Server) setTargetConfigRPC(_ context.Context, req TargetConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.SetTargetConfig(req, &resp)
	return resp, err
}

func (s *Server) unsetTargetConfigRPC(_ context.Context, req TargetConfigRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.UnsetTargetConfig(req, &resp)
	return resp, err
}

func (s *Server) snapshotRPC(_ context.Context, req SnapshotRequest) (SnapshotResponse, error) {
	var resp SnapshotResponse
	err := s.Snapshot(req, &resp)
	return resp, err
}

func (s *Server) activeLogsRPC(_ context.Context, req ActiveLogsRequest) ([]OperatorLogEntry, error) {
	var resp []OperatorLogEntry
	err := s.ActiveLogs(req, &resp)
	return resp, err
}

func (s *Server) appendLogRPC(_ context.Context, req AppendLogRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.AppendLog(req, &resp)
	return resp, err
}

func (s *Server) pollLogsRPC(_ context.Context, req PollLogsRequest) (PollLogsResponse, error) {
	var resp PollLogsResponse
	err := s.PollLogs(req, &resp)
	return resp, err
}

func (s *Server) attachEntityRPC(_ context.Context, req AttachEntityRequest) (EntityResponse, error) {
	var resp EntityResponse
	err := s.AttachEntity(req, &resp)
	return resp, err
}

func (s *Server) heartbeatEntityRPC(_ context.Context, req HeartbeatEntityRequest) (EntityResponse, error) {
	var resp EntityResponse
	err := s.HeartbeatEntity(req, &resp)
	return resp, err
}

func (s *Server) detachEntityRPC(_ context.Context, req DetachEntityRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.DetachEntity(req, &resp)
	return resp, err
}

func (s *Server) listEntitiesRPC(_ context.Context, req ListEntitiesRequest) (ListEntitiesResponse, error) {
	var resp ListEntitiesResponse
	err := s.ListEntities(req, &resp)
	return resp, err
}

func (s *Server) createPendingThrowRPC(_ context.Context, req CreatePendingThrowRequest) (PendingThrowResponse, error) {
	var resp PendingThrowResponse
	err := s.CreatePendingThrow(req, &resp)
	return resp, err
}

func (s *Server) confirmPendingThrowRPC(_ context.Context, req ConfirmPendingThrowRequest) (PendingThrowResponse, error) {
	var resp PendingThrowResponse
	err := s.ConfirmPendingThrow(req, &resp)
	return resp, err
}

func (s *Server) requirePendingThrowReadyRPC(_ context.Context, req PendingThrowRequest) (PendingThrowResponse, error) {
	var resp PendingThrowResponse
	err := s.RequirePendingThrowReady(req, &resp)
	return resp, err
}

func (s *Server) cancelPendingThrowRPC(_ context.Context, req PendingThrowRequest) (EmptyResponse, error) {
	var resp EmptyResponse
	err := s.CancelPendingThrow(req, &resp)
	return resp, err
}

func (s *Server) getLaunchKeyPolicyRPC(_ context.Context, req LaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	var resp LaunchKeyPolicyResponse
	err := s.GetLaunchKeyPolicy(req, &resp)
	return resp, err
}

func (s *Server) setLaunchKeyPolicyRPC(_ context.Context, req SetLaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	var resp LaunchKeyPolicyResponse
	err := s.SetLaunchKeyPolicy(req, &resp)
	return resp, err
}

func (s *Server) requirePKI() (apppki.WorkspaceControl, error) {
	if s.pki == nil {
		return nil, errors.New("workspace PKI is not configured")
	}
	return s.pki, nil
}

func (s *Server) requirePKIOperations() (apppki.OperationControl, error) {
	control, err := s.requirePKI()
	if err != nil {
		return nil, err
	}
	operations, ok := control.(apppki.OperationControl)
	if !ok {
		return nil, errors.New("workspace PKI operations are not configured")
	}
	return operations, nil
}

func (s *Server) pkiStatusRPC(ctx context.Context, _ EmptyRequest) (apppki.WorkspaceStatus, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.WorkspaceStatus{}, err
	}
	return control.Status(ctx), nil
}

func (s *Server) initializePKIRPC(ctx context.Context, req PKIInitializeRequest) (apppki.WorkspaceStatus, error) {
	if !req.Confirmed {
		return apppki.WorkspaceStatus{}, errors.New("PKI initialization requires explicit confirmation")
	}
	control, err := s.requirePKI()
	if err != nil {
		return apppki.WorkspaceStatus{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.WorkspaceStatus{}, err
	}
	return control.Initialize(ctx)
}

func (s *Server) listPKIBackendsRPC(ctx context.Context, _ EmptyRequest) (PKIBackendListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKIBackendListResponse{}, err
	}
	backends, err := control.BackendDescriptors(ctx)
	return PKIBackendListResponse{Backends: backends}, err
}

func (s *Server) listPKIProfilesRPC(_ context.Context, _ EmptyRequest) (PKIProfileListResponse, error) {
	return PKIProfileListResponse{Profiles: domainpki.BuiltInProfiles()}, nil
}

func (s *Server) listPKIAuthoritiesRPC(ctx context.Context, _ EmptyRequest) (PKIAuthorityListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKIAuthorityListResponse{}, err
	}
	authorities, err := control.ListAuthorities(ctx)
	return PKIAuthorityListResponse{Authorities: authorities}, err
}

func (s *Server) inspectPKIAuthorityRPC(ctx context.Context, req PKIAuthorityRequest) (PKIAuthorityInspectResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKIAuthorityInspectResponse{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return PKIAuthorityInspectResponse{}, err
	}
	inspection, err := control.InspectAuthority(ctx, req.ID)
	if err != nil {
		return PKIAuthorityInspectResponse{}, err
	}
	return PKIAuthorityInspectResponse{
		Authority:        inspection.Authority,
		ActiveGeneration: inspection.ActiveGeneration,
	}, nil
}

func (s *Server) createPKIAuthorityRPC(ctx context.Context, req PKIAuthorityCreateRequest) (apppki.CreateAuthorityResult, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.CreateAuthorityResult{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.CreateAuthorityResult{}, err
	}
	return control.CreateAuthority(ctx, req.Request)
}

func (s *Server) unlockPKIAuthorityRPC(ctx context.Context, req PKIAuthorityLeaseRequest) (apppki.SigningLease, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.SigningLease{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return apppki.SigningLease{}, err
	}
	duration := time.Duration(0)
	if value := strings.TrimSpace(req.Duration); value != "" {
		duration, err = time.ParseDuration(value)
		if err != nil {
			return apppki.SigningLease{}, fmt.Errorf("invalid signing lease duration: %w", err)
		}
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.SigningLease{}, err
	}
	return control.UnlockAuthoritySigning(ctx, req.ID, duration)
}

func (s *Server) lockPKIAuthorityRPC(ctx context.Context, req PKIAuthorityLockRequest) (EmptyResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return EmptyResponse{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return EmptyResponse{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return EmptyResponse{}, err
	}
	return EmptyResponse{}, control.LockAuthoritySigning(ctx, req.ID)
}

func (s *Server) listPKICertificatesRPC(ctx context.Context, _ EmptyRequest) (PKICertificateListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKICertificateListResponse{}, err
	}
	certificates, err := control.ListCertificateGenerations(ctx)
	return PKICertificateListResponse{Certificates: certificates}, err
}

func (s *Server) inspectPKICertificateRPC(ctx context.Context, req PKICertificateRequest) (domainpki.CertificateGeneration, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	return control.InspectCertificateGeneration(ctx, req.ID)
}

func (s *Server) issuePKICertificateRPC(ctx context.Context, req PKICertificateIssueRequest) (domainpki.CertificateGeneration, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return domainpki.CertificateGeneration{}, err
	}
	return control.IssueCertificate(ctx, req.Request)
}

func (s *Server) renewPKICertificateRPC(ctx context.Context, req PKIMutationRequest[apppki.RenewCertificateRequest]) (apppki.CertificateLifecycleResult, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	return control.RenewCertificate(ctx, req.Request)
}

func (s *Server) rotatePKICertificateRPC(ctx context.Context, req PKIMutationRequest[apppki.RotateCertificateRequest]) (apppki.CertificateLifecycleResult, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.CertificateLifecycleResult{}, err
	}
	return control.RotateCertificate(ctx, req.Request)
}

func (s *Server) revokePKICertificateRPC(ctx context.Context, req PKIMutationRequest[apppki.RevokeCertificateRequest]) (apppki.CertificateRevocationResult, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.CertificateRevocationResult{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.CertificateRevocationResult{}, err
	}
	return control.RevokeCertificate(ctx, req.Request)
}

func (s *Server) inspectPKIRevocationRPC(ctx context.Context, req PKIRevocationRequest) (domainpki.Revocation, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.Revocation{}, err
	}
	return control.InspectRevocation(ctx, req.ID)
}

func (s *Server) inspectPKIGenerationRevocationRPC(ctx context.Context, req PKICertificateRequest) (domainpki.Revocation, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.Revocation{}, err
	}
	return control.InspectGenerationRevocation(ctx, req.ID)
}

func (s *Server) listPKIRevocationsRPC(ctx context.Context, req PKIRevocationListRequest) (PKIRevocationListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKIRevocationListResponse{}, err
	}
	revocations, err := control.ListAuthorityRevocations(ctx, req.AuthorityID)
	if err != nil {
		return PKIRevocationListResponse{}, err
	}
	return PKIRevocationListResponse{Revocations: revocations}, nil
}

func (s *Server) publishPKICRLRPC(ctx context.Context, req PKIMutationRequest[apppki.PublishCRLRequest]) (apppki.CRLPublicationResult, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.CRLPublicationResult{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.CRLPublicationResult{}, err
	}
	return control.PublishCRL(ctx, req.Request)
}

func (s *Server) inspectPKICRLPublicationRPC(ctx context.Context, req PKICRLPublicationRequest) (apppki.CRLPublicationIntent, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	return control.InspectCRLPublication(ctx, req.ID)
}

func (s *Server) listPKICRLPublicationsRPC(ctx context.Context, req PKICRLListRequest) (PKICRLPublicationListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKICRLPublicationListResponse{}, err
	}
	publications, err := control.ListCRLPublications(ctx, req.AuthorityID)
	if err != nil {
		return PKICRLPublicationListResponse{}, err
	}
	return PKICRLPublicationListResponse{Publications: publications}, nil
}

func (s *Server) inspectPKICRLRPC(ctx context.Context, req PKICRLRequest) (domainpki.CRLGeneration, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.CRLGeneration{}, err
	}
	return control.InspectCRLGeneration(ctx, req.ID)
}

func (s *Server) listPKICRLsRPC(ctx context.Context, req PKICRLListRequest) (PKICRLListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKICRLListResponse{}, err
	}
	crls, err := control.ListCRLGenerations(ctx, req.AuthorityID)
	if err != nil {
		return PKICRLListResponse{}, err
	}
	return PKICRLListResponse{CRLs: crls}, nil
}

func (s *Server) reconcilePKICRLRPC(ctx context.Context, req PKIMutationRequest[apppki.ReconcileCRLPublicationRequest]) (apppki.CRLPublicationIntent, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.CRLPublicationIntent{}, err
	}
	return control.ReconcileCRLPublication(ctx, req.Request)
}

func (s *Server) reconcilePKICRLsRPC(ctx context.Context, req PKIMutationRequest[apppki.ReconcileCRLPublicationsRequest]) (PKICRLPublicationListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKICRLPublicationListResponse{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return PKICRLPublicationListResponse{}, err
	}
	publications, err := control.ReconcileCRLPublications(ctx, req.Request)
	if err != nil {
		return PKICRLPublicationListResponse{}, err
	}
	return PKICRLPublicationListResponse{Publications: publications}, nil
}

func (s *Server) listPKIOperationsRPC(ctx context.Context, _ EmptyRequest) (PKIOperationListResponse, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return PKIOperationListResponse{}, err
	}
	operations, err := control.ListOperations(ctx)
	return PKIOperationListResponse{Operations: operations}, err
}

func (s *Server) inspectPKIOperationRPC(
	ctx context.Context,
	req PKIOperationRequest,
) (apppki.OperationInspection, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return apppki.OperationInspection{}, err
	}
	return control.InspectOperation(ctx, req.ID)
}

func (s *Server) listPKICredentialStampsRPC(
	ctx context.Context,
	_ EmptyRequest,
) (PKICredentialStampListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKICredentialStampListResponse{}, err
	}
	stamps, err := control.ListCredentialStamps(ctx)
	return PKICredentialStampListResponse{Stamps: stamps}, err
}

func (s *Server) inspectPKICredentialStampRPC(
	ctx context.Context,
	req PKICredentialStampRequest,
) (domainpki.CredentialStamp, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.CredentialStamp{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return domainpki.CredentialStamp{}, err
	}
	return control.InspectCredentialStamp(ctx, req.ID)
}

func (s *Server) listPKICredentialExecutionsRPC(
	ctx context.Context,
	_ EmptyRequest,
) (PKICredentialExecutionListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKICredentialExecutionListResponse{}, err
	}
	executions, err := control.ListCredentialExecutions(ctx)
	return PKICredentialExecutionListResponse{Executions: executions}, err
}

func (s *Server) inspectPKICredentialExecutionRPC(
	ctx context.Context,
	req PKICredentialExecutionRequest,
) (domainpki.CredentialExecution, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.CredentialExecution{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return domainpki.CredentialExecution{}, err
	}
	return control.InspectCredentialExecution(ctx, req.ID)
}

func (s *Server) startPKIAuthorityRolloverRPC(
	ctx context.Context,
	req PKIMutationRequest[apppki.StartAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	return control.StartAuthorityRollover(ctx, req.Request)
}

func (s *Server) acknowledgePKIAuthorityRolloverRPC(
	ctx context.Context,
	req PKIMutationRequest[apppki.AcknowledgeAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	return control.AcknowledgeAuthorityRollover(ctx, req.Request)
}

func (s *Server) activatePKIAuthorityRolloverRPC(
	ctx context.Context,
	req PKIMutationRequest[apppki.ActivateAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	return control.ActivateAuthorityRollover(ctx, req.Request)
}

func (s *Server) beginPKIAuthorityRolloverFinalTrustRPC(
	ctx context.Context,
	req PKIMutationRequest[apppki.BeginAuthorityRolloverFinalTrustRequest],
) (apppki.OperationInspection, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	return control.BeginAuthorityRolloverFinalTrust(ctx, req.Request)
}

func (s *Server) completePKIAuthorityRolloverRPC(
	ctx context.Context,
	req PKIMutationRequest[apppki.CompleteAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	return control.CompleteAuthorityRollover(ctx, req.Request)
}

func (s *Server) cancelPKIAuthorityRolloverRPC(
	ctx context.Context,
	req PKIMutationRequest[apppki.CancelAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	control, err := s.requirePKIOperations()
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.OperationInspection{}, err
	}
	return control.CancelAuthorityRollover(ctx, req.Request)
}

func (s *Server) exportPKIBundleRPC(ctx context.Context, req PKIBundleExportRequest) (domainpki.Bundle, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.Bundle{}, err
	}
	if req.IncludePrivate && !s.pkiSecrets {
		return domainpki.Bundle{}, errors.New("private PKI export is unavailable on this daemon transport")
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	return control.ExportBundle(ctx, req.GenerationID, req.Purpose, req.IncludePrivate)
}

func (s *Server) listPKIAssignmentsRPC(ctx context.Context, _ EmptyRequest) (PKIAssignmentListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKIAssignmentListResponse{}, err
	}
	assignments, err := control.ListAssignments(ctx)
	return PKIAssignmentListResponse{Assignments: assignments}, err
}

func (s *Server) inspectPKIAssignmentRPC(ctx context.Context, req PKIAssignmentRequest) (apppki.AssignmentInspection, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return apppki.AssignmentInspection{}, err
	}
	return control.InspectAssignment(ctx, req.ID)
}

func (s *Server) bindPKIAssignmentRPC(ctx context.Context, req PKIMutationRequest[apppki.BindAssignmentRequest]) (domainpki.Assignment, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.Assignment{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	return control.BindAssignment(ctx, req.Request)
}

func (s *Server) stagePKIAssignmentRPC(ctx context.Context, req PKIMutationRequest[apppki.StageAssignmentRequest]) (apppki.AssignmentInspection, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	return control.StageAssignment(ctx, req.Request)
}

func (s *Server) activatePKIAssignmentRPC(ctx context.Context, req PKIMutationRequest[apppki.ActivateAssignmentRequest]) (apppki.AssignmentInspection, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.AssignmentInspection{}, err
	}
	return control.ActivateAssignment(ctx, req.Request)
}

func (s *Server) unbindPKIAssignmentRPC(ctx context.Context, req PKIMutationRequest[apppki.UnbindAssignmentRequest]) (domainpki.Assignment, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.Assignment{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return domainpki.Assignment{}, err
	}
	return control.UnbindAssignment(ctx, req.Request)
}

func (s *Server) listPKITrustSetsRPC(ctx context.Context, _ EmptyRequest) (PKITrustSetListResponse, error) {
	control, err := s.requirePKI()
	if err != nil {
		return PKITrustSetListResponse{}, err
	}
	trustSets, err := control.ListTrustSets(ctx)
	return PKITrustSetListResponse{TrustSets: trustSets}, err
}

func (s *Server) inspectPKITrustSetRPC(ctx context.Context, req PKITrustSetRequest) (apppki.TrustSetInspection, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	if err := req.ID.Validate(); err != nil {
		return apppki.TrustSetInspection{}, err
	}
	return control.InspectTrustSet(ctx, req.ID)
}

func (s *Server) createPKITrustSetRPC(ctx context.Context, req PKIMutationRequest[apppki.CreateTrustSetRequest]) (domainpki.TrustSet, error) {
	control, err := s.requirePKI()
	if err != nil {
		return domainpki.TrustSet{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return domainpki.TrustSet{}, err
	}
	return control.CreateTrustSet(ctx, req.Request)
}

func (s *Server) stagePKITrustSetRPC(ctx context.Context, req PKIMutationRequest[apppki.StageTrustSetRequest]) (apppki.TrustSetInspection, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	return control.StageTrustSet(ctx, req.Request)
}

func (s *Server) activatePKITrustSetRPC(ctx context.Context, req PKIMutationRequest[apppki.ActivateTrustSetRequest]) (apppki.TrustSetInspection, error) {
	control, err := s.requirePKI()
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	ctx, err = req.Context.bind(ctx)
	if err != nil {
		return apppki.TrustSetInspection{}, err
	}
	return control.ActivateTrustSet(ctx, req.Request)
}

func (s *Server) publish(operation, chain string, entries ...operatorlog.Entry) {
	s.logs.Publish(operation, chain, entries...)
}

func (s *Server) withChain(operation, chain string, fn func(*operatorsession.Session, string, string) error) error {
	return s.withChainAccess(operation, chain, true, fn)
}

func (s *Server) withChainRead(operation, chain string, fn func(*operatorsession.Session, string, string) error) error {
	return s.withChainAccess(operation, chain, false, fn)
}

func (s *Server) withChainAccess(operation, chain string, persist bool, fn func(*operatorsession.Session, string, string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.attachment(operation, chain)
	if chain == "" {
		chain = session.Snapshot().ActiveChain
	}
	if chain == "" {
		return errors.New("active chain is required")
	}
	if err := fn(session, session.Snapshot().ActiveOperation, chain); err != nil {
		return err
	}
	if !persist {
		return nil
	}
	return s.persistLocked()
}

func (s *Server) attachment(operation, chain string) *operatorsession.Session {
	operation = operationOrDefault(operation)
	return s.session.Attachment(operation, chain)
}

func (s *Server) persistLocked() error {
	if s.persistSession == nil {
		return nil
	}
	return s.persistSession(s.session.Export())
}

func operationOrDefault(operation string) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return operatorsession.DefaultOperation
	}
	return operation
}

func (s *Server) ensureEntitiesLocked() {
	if s.entities == nil {
		s.entities = map[string]operatordomain.Entity{}
	}
}

func (s *Server) launchKeyInputs(operation string) ([]operatordomain.Entity, operatordomain.LaunchKeyPolicy, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureEntitiesLocked()
	entities := make([]operatordomain.Entity, 0, len(s.entities))
	for _, entity := range s.entities {
		entities = append(entities, entity)
	}
	return entities, s.launchKeyPolicyForOperationLocked(operation), s.now()
}

func (s *Server) launchKeyCoordinator() *launchkey.Coordinator {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.launchKeys == nil {
		s.launchKeys = launchkey.NewCoordinator()
	}
	return s.launchKeys
}

func approvalFlags(allowDangerous, nowBypass bool) operatordomain.ApprovalFlags {
	return operatordomain.ApprovalFlags{
		AllowDangerous: allowDangerous,
		NowBypass:      nowBypass,
	}
}

func pendingThrowResponse(snapshot launchkey.PendingSnapshot) PendingThrowResponse {
	createdAt := ""
	if !snapshot.CreatedAt.IsZero() {
		createdAt = snapshot.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	return PendingThrowResponse{
		ID:                  snapshot.ID,
		Operation:           snapshot.Operation,
		Chain:               snapshot.Chain,
		PlanHash:            snapshot.PlanHash,
		AllowDangerous:      snapshot.Flags.AllowDangerous,
		NowBypass:           snapshot.Flags.NowBypass,
		CreatedAt:           createdAt,
		Ready:               snapshot.Ready,
		RequiredApproverIDs: append([]string(nil), snapshot.RequiredApproverIDs...),
		MissingApproverIDs:  append([]string(nil), snapshot.MissingApproverIDs...),
	}
}

func (s *Server) launchKeyPolicyForOperation(operation string) operatordomain.LaunchKeyPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.launchKeyPolicyForOperationLocked(operation)
}

func (s *Server) launchKeyPolicyForOperationLocked(operation string) operatordomain.LaunchKeyPolicy {
	operation = operationOrDefault(operation)
	if s.launchKeyByOp != nil {
		if policy, ok := s.launchKeyByOp[operation]; ok {
			return operatordomain.NormalizeLaunchKeyPolicy(policy)
		}
	}
	return operatordomain.NormalizeLaunchKeyPolicy(s.launchKeyPolicy)
}

func launchKeyPolicyFromRequest(req SetLaunchKeyPolicyRequest) (operatordomain.LaunchKeyPolicy, error) {
	policy := operatordomain.LaunchKeyPolicy{
		Mode:   operatordomain.LaunchKeyMode(strings.TrimSpace(req.Mode)),
		Quorum: req.Quorum,
	}
	switch policy.Mode {
	case operatordomain.LaunchKeyAnyone, operatordomain.LaunchKeyAllConnected:
	case operatordomain.LaunchKeyQuorum:
		if policy.Quorum < 1 {
			return operatordomain.LaunchKeyPolicy{}, errors.New("launch-key quorum must be at least 1")
		}
	default:
		return operatordomain.LaunchKeyPolicy{}, fmt.Errorf("unsupported launch-key mode %q", req.Mode)
	}
	if timeout := strings.TrimSpace(req.HeartbeatTimeout); timeout != "" {
		parsed, err := time.ParseDuration(timeout)
		if err != nil {
			return operatordomain.LaunchKeyPolicy{}, fmt.Errorf("invalid launch-key heartbeat timeout: %w", err)
		}
		policy.HeartbeatTimeout = parsed
	}
	return operatordomain.NormalizeLaunchKeyPolicy(policy), nil
}

func launchKeyPolicyResponse(operation string, policy operatordomain.LaunchKeyPolicy) LaunchKeyPolicyResponse {
	policy = operatordomain.NormalizeLaunchKeyPolicy(policy)
	timeout := ""
	if policy.HeartbeatTimeout != 0 {
		timeout = policy.HeartbeatTimeout.String()
	}
	return LaunchKeyPolicyResponse{
		Operation: operationOrDefault(operation),
		Policy: LaunchKeyPolicyOutput{
			Mode:             string(policy.Mode),
			Quorum:           policy.Quorum,
			HeartbeatTimeout: timeout,
		},
	}
}

func operatorEntityFromDomain(entity operatordomain.Entity) OperatorEntity {
	return OperatorEntity{
		ID:           entity.ID,
		Kind:         string(entity.Kind),
		DisplayName:  entity.DisplayName,
		Agent:        entity.Agent,
		Operation:    entity.Operation,
		ActiveChain:  entity.ActiveChain,
		ConnectedAt:  entity.ConnectedAt.UTC().Format(time.RFC3339Nano),
		LastSeenAt:   entity.LastSeenAt.UTC().Format(time.RFC3339Nano),
		Capabilities: append([]string(nil), entity.Capabilities...),
		PolicyTags:   append([]string(nil), entity.PolicyTags...),
	}
}

type Client struct {
	httpClient *http.Client
	baseURL    string
}

func Dial(socketPath string) (*Client, error) {
	endpoint, err := ParseEndpoint(socketPath)
	if err != nil {
		return nil, err
	}
	client := NewClient(endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := client.PollLogs(ctx, 0); err != nil {
		logDaemonRPCError("close daemon client after failed dial", client.Close())
		return nil, err
	}
	return client, nil
}

func NewClient(endpoint Endpoint) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	baseURL := endpoint.BaseURL()
	if endpoint.Network == "unix" {
		address := endpoint.Address
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", address)
		}
	}
	return &Client{
		httpClient: &http.Client{Transport: transport},
		baseURL:    baseURL,
	}
}

func (c *Client) Close() error {
	if c == nil || c.httpClient == nil {
		return nil
	}
	c.httpClient.CloseIdleConnections()
	return nil
}

func (c *Client) RunMockExploit(ctx context.Context, req RunMockExploitRequest) (RunMockExploitResponse, error) {
	return c.ExecuteModule(ctx, ExecuteModuleRequest(req))
}

func (c *Client) ExecuteModule(ctx context.Context, req ExecuteModuleRequest) (ExecuteModuleResponse, error) {
	return invoke[ExecuteModuleRequest, ExecuteModuleResponse](c, ctx, "ExecuteModule", req)
}

func (c *Client) GeneratePayload(ctx context.Context, req PayloadGenerateRequest) (PayloadGenerateResponse, error) {
	return invoke[PayloadGenerateRequest, PayloadGenerateResponse](c, ctx, "GeneratePayload", req)
}

func (c *Client) ListPayloadCommands(ctx context.Context, req PayloadCommandListRequest) (PayloadCommandListResponse, error) {
	return invoke[PayloadCommandListRequest, PayloadCommandListResponse](c, ctx, "ListPayloadCommands", req)
}

func (c *Client) RunPayloadCommand(ctx context.Context, req PayloadCommandRunRequest) (PayloadCommandRunResponse, error) {
	return invoke[PayloadCommandRunRequest, PayloadCommandRunResponse](c, ctx, "RunPayloadCommand", req)
}

func (c *Client) DescribeMesh(
	ctx context.Context,
	req MeshDescribeRequest,
) (MeshDescribeResponse, error) {
	return invoke[MeshDescribeRequest, MeshDescribeResponse](c, ctx, rpcMethodDescribeMesh, req)
}

func (c *Client) MeshTopology(
	ctx context.Context,
	req MeshTopologyRequest,
) (MeshTopologyResponse, error) {
	return invoke[MeshTopologyRequest, MeshTopologyResponse](c, ctx, rpcMethodMeshTopology, req)
}

func (c *Client) ListMeshBeacons(
	ctx context.Context,
	req MeshBeaconListRequest,
) (MeshBeaconListResponse, error) {
	return invoke[MeshBeaconListRequest, MeshBeaconListResponse](c, ctx, rpcMethodListMeshBeacons, req)
}

func (c *Client) ListMeshListeners(
	ctx context.Context,
	req MeshListenerListRequest,
) (MeshListenerListResponse, error) {
	return invoke[MeshListenerListRequest, MeshListenerListResponse](c, ctx, rpcMethodListMeshListeners, req)
}

func (c *Client) StartMeshListener(
	ctx context.Context,
	req MeshListenerStartRequest,
) (MeshListenerStartResponse, error) {
	return invoke[MeshListenerStartRequest, MeshListenerStartResponse](c, ctx, rpcMethodStartMeshListener, req)
}

func (c *Client) StopMeshListener(
	ctx context.Context,
	req MeshListenerStopRequest,
) (MeshListenerStopResponse, error) {
	return invoke[MeshListenerStopRequest, MeshListenerStopResponse](c, ctx, rpcMethodStopMeshListener, req)
}

func (c *Client) RunMeshTask(
	ctx context.Context,
	req MeshTaskRunRequest,
) (MeshTaskRunResponse, error) {
	return invoke[MeshTaskRunRequest, MeshTaskRunResponse](c, ctx, rpcMethodRunMeshTask, req)
}

func (c *Client) OpenMeshStream(
	ctx context.Context,
	req MeshStreamOpenRequest,
) (MeshStreamOpenResponse, error) {
	return invoke[MeshStreamOpenRequest, MeshStreamOpenResponse](c, ctx, rpcMethodOpenMeshStream, req)
}

func (c *Client) OpenMeshBridge(
	ctx context.Context,
	req MeshBridgeOpenRequest,
) (MeshBridgeOpenResponse, error) {
	return invoke[MeshBridgeOpenRequest, MeshBridgeOpenResponse](c, ctx, rpcMethodOpenMeshBridge, req)
}

func (c *Client) CloseMeshBridge(
	ctx context.Context,
	req MeshBridgeCloseRequest,
) (MeshBridgeCloseResponse, error) {
	return invoke[MeshBridgeCloseRequest, MeshBridgeCloseResponse](c, ctx, rpcMethodCloseMeshBridge, req)
}

func (c *Client) ListMeshOperations(
	ctx context.Context,
	req MeshOperationListRequest,
) (MeshOperationListResponse, error) {
	return invoke[MeshOperationListRequest, MeshOperationListResponse](c, ctx, rpcMethodListMeshOperations, req)
}

func (c *Client) PKIStatus(ctx context.Context) (apppki.WorkspaceStatus, error) {
	return invoke[EmptyRequest, apppki.WorkspaceStatus](c, ctx, rpcMethodPKIStatus, EmptyRequest{})
}

func (c *Client) InitializePKI(ctx context.Context, req PKIInitializeRequest) (apppki.WorkspaceStatus, error) {
	return invoke[PKIInitializeRequest, apppki.WorkspaceStatus](c, ctx, rpcMethodInitializePKI, req)
}

func (c *Client) ListPKIBackends(ctx context.Context) (PKIBackendListResponse, error) {
	return invoke[EmptyRequest, PKIBackendListResponse](c, ctx, rpcMethodListPKIBackends, EmptyRequest{})
}

func (c *Client) ListPKIProfiles(ctx context.Context) (PKIProfileListResponse, error) {
	return invoke[EmptyRequest, PKIProfileListResponse](c, ctx, rpcMethodListPKIProfiles, EmptyRequest{})
}

func (c *Client) ListPKIAuthorities(ctx context.Context) (PKIAuthorityListResponse, error) {
	return invoke[EmptyRequest, PKIAuthorityListResponse](c, ctx, rpcMethodListAuthorities, EmptyRequest{})
}

func (c *Client) InspectPKIAuthority(ctx context.Context, req PKIAuthorityRequest) (PKIAuthorityInspectResponse, error) {
	return invoke[PKIAuthorityRequest, PKIAuthorityInspectResponse](c, ctx, rpcMethodInspectAuthority, req)
}

func (c *Client) CreatePKIAuthority(ctx context.Context, req PKIAuthorityCreateRequest) (apppki.CreateAuthorityResult, error) {
	return invoke[PKIAuthorityCreateRequest, apppki.CreateAuthorityResult](c, ctx, rpcMethodCreateAuthority, req)
}

func (c *Client) UnlockPKIAuthority(ctx context.Context, req PKIAuthorityLeaseRequest) (apppki.SigningLease, error) {
	return invoke[PKIAuthorityLeaseRequest, apppki.SigningLease](c, ctx, rpcMethodUnlockAuthority, req)
}

func (c *Client) LockPKIAuthority(ctx context.Context, req PKIAuthorityLockRequest) error {
	_, err := invoke[PKIAuthorityLockRequest, EmptyResponse](c, ctx, rpcMethodLockAuthority, req)
	return err
}

func (c *Client) ListPKICertificates(ctx context.Context) (PKICertificateListResponse, error) {
	return invoke[EmptyRequest, PKICertificateListResponse](c, ctx, rpcMethodListCertificates, EmptyRequest{})
}

func (c *Client) InspectPKICertificate(ctx context.Context, req PKICertificateRequest) (domainpki.CertificateGeneration, error) {
	return invoke[PKICertificateRequest, domainpki.CertificateGeneration](c, ctx, rpcMethodInspectCertificate, req)
}

func (c *Client) IssuePKICertificate(ctx context.Context, req PKICertificateIssueRequest) (domainpki.CertificateGeneration, error) {
	return invoke[PKICertificateIssueRequest, domainpki.CertificateGeneration](c, ctx, rpcMethodIssueCertificate, req)
}

func (c *Client) RenewPKICertificate(ctx context.Context, req PKIMutationRequest[apppki.RenewCertificateRequest]) (apppki.CertificateLifecycleResult, error) {
	return invoke[PKIMutationRequest[apppki.RenewCertificateRequest], apppki.CertificateLifecycleResult](c, ctx, rpcMethodRenewCertificate, req)
}

func (c *Client) RotatePKICertificate(ctx context.Context, req PKIMutationRequest[apppki.RotateCertificateRequest]) (apppki.CertificateLifecycleResult, error) {
	return invoke[PKIMutationRequest[apppki.RotateCertificateRequest], apppki.CertificateLifecycleResult](c, ctx, rpcMethodRotateCertificate, req)
}

func (c *Client) RevokePKICertificate(ctx context.Context, req PKIMutationRequest[apppki.RevokeCertificateRequest]) (apppki.CertificateRevocationResult, error) {
	return invoke[PKIMutationRequest[apppki.RevokeCertificateRequest], apppki.CertificateRevocationResult](c, ctx, rpcMethodRevokeCertificate, req)
}

func (c *Client) InspectPKIRevocation(ctx context.Context, req PKIRevocationRequest) (domainpki.Revocation, error) {
	return invoke[PKIRevocationRequest, domainpki.Revocation](c, ctx, rpcMethodInspectRevocation, req)
}

func (c *Client) InspectPKIGenerationRevocation(ctx context.Context, req PKICertificateRequest) (domainpki.Revocation, error) {
	return invoke[PKICertificateRequest, domainpki.Revocation](c, ctx, rpcMethodGenerationRevocation, req)
}

func (c *Client) ListPKIRevocations(ctx context.Context, req PKIRevocationListRequest) (PKIRevocationListResponse, error) {
	return invoke[PKIRevocationListRequest, PKIRevocationListResponse](c, ctx, rpcMethodListRevocations, req)
}

func (c *Client) PublishPKICRL(ctx context.Context, req PKIMutationRequest[apppki.PublishCRLRequest]) (apppki.CRLPublicationResult, error) {
	return invoke[PKIMutationRequest[apppki.PublishCRLRequest], apppki.CRLPublicationResult](c, ctx, rpcMethodPublishCRL, req)
}

func (c *Client) InspectPKICRLPublication(ctx context.Context, req PKICRLPublicationRequest) (apppki.CRLPublicationIntent, error) {
	return invoke[PKICRLPublicationRequest, apppki.CRLPublicationIntent](c, ctx, rpcMethodInspectCRLPublication, req)
}

func (c *Client) ListPKICRLPublications(ctx context.Context, req PKICRLListRequest) (PKICRLPublicationListResponse, error) {
	return invoke[PKICRLListRequest, PKICRLPublicationListResponse](c, ctx, rpcMethodListCRLPublications, req)
}

func (c *Client) InspectPKICRL(ctx context.Context, req PKICRLRequest) (domainpki.CRLGeneration, error) {
	return invoke[PKICRLRequest, domainpki.CRLGeneration](c, ctx, rpcMethodInspectCRL, req)
}

func (c *Client) ListPKICRLs(ctx context.Context, req PKICRLListRequest) (PKICRLListResponse, error) {
	return invoke[PKICRLListRequest, PKICRLListResponse](c, ctx, rpcMethodListCRLs, req)
}

func (c *Client) ReconcilePKICRL(ctx context.Context, req PKIMutationRequest[apppki.ReconcileCRLPublicationRequest]) (apppki.CRLPublicationIntent, error) {
	return invoke[PKIMutationRequest[apppki.ReconcileCRLPublicationRequest], apppki.CRLPublicationIntent](c, ctx, rpcMethodReconcileCRL, req)
}

func (c *Client) ReconcilePKICRLs(ctx context.Context, req PKIMutationRequest[apppki.ReconcileCRLPublicationsRequest]) (PKICRLPublicationListResponse, error) {
	return invoke[PKIMutationRequest[apppki.ReconcileCRLPublicationsRequest], PKICRLPublicationListResponse](c, ctx, rpcMethodReconcileCRLs, req)
}

func (c *Client) ListPKIOperations(ctx context.Context) (PKIOperationListResponse, error) {
	return invoke[EmptyRequest, PKIOperationListResponse](c, ctx, rpcMethodListPKIOperations, EmptyRequest{})
}

func (c *Client) InspectPKIOperation(
	ctx context.Context,
	req PKIOperationRequest,
) (apppki.OperationInspection, error) {
	return invoke[PKIOperationRequest, apppki.OperationInspection](c, ctx, rpcMethodInspectPKIOperation, req)
}

func (c *Client) ListPKICredentialStamps(
	ctx context.Context,
) (PKICredentialStampListResponse, error) {
	return invoke[EmptyRequest, PKICredentialStampListResponse](
		c, ctx, rpcMethodListCredentialStamps, EmptyRequest{},
	)
}

func (c *Client) InspectPKICredentialStamp(
	ctx context.Context,
	req PKICredentialStampRequest,
) (domainpki.CredentialStamp, error) {
	return invoke[PKICredentialStampRequest, domainpki.CredentialStamp](
		c, ctx, rpcMethodInspectCredentialStamp, req,
	)
}

func (c *Client) ListPKICredentialExecutions(
	ctx context.Context,
) (PKICredentialExecutionListResponse, error) {
	return invoke[EmptyRequest, PKICredentialExecutionListResponse](
		c, ctx, rpcMethodListCredentialExecutions, EmptyRequest{},
	)
}

func (c *Client) InspectPKICredentialExecution(
	ctx context.Context,
	req PKICredentialExecutionRequest,
) (domainpki.CredentialExecution, error) {
	return invoke[PKICredentialExecutionRequest, domainpki.CredentialExecution](
		c, ctx, rpcMethodInspectCredentialExecution, req,
	)
}

func (c *Client) StartPKIAuthorityRollover(
	ctx context.Context,
	req PKIMutationRequest[apppki.StartAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	return invoke[PKIMutationRequest[apppki.StartAuthorityRolloverRequest], apppki.OperationInspection](
		c, ctx, rpcMethodStartRollover, req,
	)
}

func (c *Client) AcknowledgePKIAuthorityRollover(
	ctx context.Context,
	req PKIMutationRequest[apppki.AcknowledgeAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	return invoke[PKIMutationRequest[apppki.AcknowledgeAuthorityRolloverRequest], apppki.OperationInspection](
		c, ctx, rpcMethodAcknowledgeRollover, req,
	)
}

func (c *Client) ActivatePKIAuthorityRollover(
	ctx context.Context,
	req PKIMutationRequest[apppki.ActivateAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	return invoke[PKIMutationRequest[apppki.ActivateAuthorityRolloverRequest], apppki.OperationInspection](
		c, ctx, rpcMethodActivateRollover, req,
	)
}

func (c *Client) BeginPKIAuthorityRolloverFinalTrust(
	ctx context.Context,
	req PKIMutationRequest[apppki.BeginAuthorityRolloverFinalTrustRequest],
) (apppki.OperationInspection, error) {
	return invoke[PKIMutationRequest[apppki.BeginAuthorityRolloverFinalTrustRequest], apppki.OperationInspection](
		c, ctx, rpcMethodBeginRolloverFinal, req,
	)
}

func (c *Client) CompletePKIAuthorityRollover(
	ctx context.Context,
	req PKIMutationRequest[apppki.CompleteAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	return invoke[PKIMutationRequest[apppki.CompleteAuthorityRolloverRequest], apppki.OperationInspection](
		c, ctx, rpcMethodCompleteRollover, req,
	)
}

func (c *Client) CancelPKIAuthorityRollover(
	ctx context.Context,
	req PKIMutationRequest[apppki.CancelAuthorityRolloverRequest],
) (apppki.OperationInspection, error) {
	return invoke[PKIMutationRequest[apppki.CancelAuthorityRolloverRequest], apppki.OperationInspection](
		c, ctx, rpcMethodCancelRollover, req,
	)
}

func (c *Client) ExportPKIBundle(ctx context.Context, req PKIBundleExportRequest) (domainpki.Bundle, error) {
	return invoke[PKIBundleExportRequest, domainpki.Bundle](c, ctx, rpcMethodExportBundle, req)
}

func (c *Client) ListPKIAssignments(ctx context.Context) (PKIAssignmentListResponse, error) {
	return invoke[EmptyRequest, PKIAssignmentListResponse](c, ctx, rpcMethodListAssignments, EmptyRequest{})
}

func (c *Client) InspectPKIAssignment(ctx context.Context, req PKIAssignmentRequest) (apppki.AssignmentInspection, error) {
	return invoke[PKIAssignmentRequest, apppki.AssignmentInspection](c, ctx, rpcMethodInspectAssignment, req)
}

func (c *Client) BindPKIAssignment(ctx context.Context, req PKIMutationRequest[apppki.BindAssignmentRequest]) (domainpki.Assignment, error) {
	return invoke[PKIMutationRequest[apppki.BindAssignmentRequest], domainpki.Assignment](c, ctx, rpcMethodBindAssignment, req)
}

func (c *Client) StagePKIAssignment(ctx context.Context, req PKIMutationRequest[apppki.StageAssignmentRequest]) (apppki.AssignmentInspection, error) {
	return invoke[PKIMutationRequest[apppki.StageAssignmentRequest], apppki.AssignmentInspection](c, ctx, rpcMethodStageAssignment, req)
}

func (c *Client) ActivatePKIAssignment(ctx context.Context, req PKIMutationRequest[apppki.ActivateAssignmentRequest]) (apppki.AssignmentInspection, error) {
	return invoke[PKIMutationRequest[apppki.ActivateAssignmentRequest], apppki.AssignmentInspection](c, ctx, rpcMethodActivateAssignment, req)
}

func (c *Client) UnbindPKIAssignment(ctx context.Context, req PKIMutationRequest[apppki.UnbindAssignmentRequest]) (domainpki.Assignment, error) {
	return invoke[PKIMutationRequest[apppki.UnbindAssignmentRequest], domainpki.Assignment](c, ctx, rpcMethodUnbindAssignment, req)
}

func (c *Client) ListPKITrustSets(ctx context.Context) (PKITrustSetListResponse, error) {
	return invoke[EmptyRequest, PKITrustSetListResponse](c, ctx, rpcMethodListTrustSets, EmptyRequest{})
}

func (c *Client) InspectPKITrustSet(ctx context.Context, req PKITrustSetRequest) (apppki.TrustSetInspection, error) {
	return invoke[PKITrustSetRequest, apppki.TrustSetInspection](c, ctx, rpcMethodInspectTrustSet, req)
}

func (c *Client) CreatePKITrustSet(ctx context.Context, req PKIMutationRequest[apppki.CreateTrustSetRequest]) (domainpki.TrustSet, error) {
	return invoke[PKIMutationRequest[apppki.CreateTrustSetRequest], domainpki.TrustSet](c, ctx, rpcMethodCreateTrustSet, req)
}

func (c *Client) StagePKITrustSet(ctx context.Context, req PKIMutationRequest[apppki.StageTrustSetRequest]) (apppki.TrustSetInspection, error) {
	return invoke[PKIMutationRequest[apppki.StageTrustSetRequest], apppki.TrustSetInspection](c, ctx, rpcMethodStageTrustSet, req)
}

func (c *Client) ActivatePKITrustSet(ctx context.Context, req PKIMutationRequest[apppki.ActivateTrustSetRequest]) (apppki.TrustSetInspection, error) {
	return invoke[PKIMutationRequest[apppki.ActivateTrustSetRequest], apppki.TrustSetInspection](c, ctx, rpcMethodActivateTrustSet, req)
}

func (c *Client) ListSessions(ctx context.Context) ([]SessionRef, error) {
	resp, err := invoke[EmptyRequest, ListSessionsResponse](c, ctx, "ListSessions", EmptyRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

func (c *Client) ReadSession(ctx context.Context, sessionID string, timeout time.Duration) (SessionChunk, error) {
	return invoke[SessionReadRequest, SessionChunk](c, ctx, "ReadSession", SessionReadRequest{
		SessionID: sessionID,
		TimeoutMs: int(timeout / time.Millisecond),
	})
}

func (c *Client) TailSession(ctx context.Context, sessionID string, options run.SessionTailOptions) (SessionChunk, error) {
	return invoke[SessionTailRequest, SessionChunk](c, ctx, "TailSession", SessionTailRequest{
		SessionID: sessionID,
		MaxBytes:  options.MaxBytes,
		MaxLines:  options.MaxLines,
		Consume:   options.Consume,
	})
}

func (c *Client) WriteSession(ctx context.Context, sessionID string, data []byte) error {
	_, err := invoke[SessionWriteRequest, EmptyResponse](c, ctx, "WriteSession", SessionWriteRequest{
		SessionID: sessionID,
		Data:      append([]byte(nil), data...),
	})
	return err
}

func (c *Client) CloseSession(ctx context.Context, sessionID string) error {
	_, err := invoke[SessionCloseRequest, EmptyResponse](c, ctx, "CloseSession", SessionCloseRequest{SessionID: sessionID})
	return err
}

func (c *Client) ListSessionCommands(ctx context.Context, req SessionCommandListRequest) (SessionCommandListResponse, error) {
	return invoke[SessionCommandListRequest, SessionCommandListResponse](c, ctx, "ListSessionCommands", req)
}

func (c *Client) RunSessionCommand(ctx context.Context, req SessionCommandRunRequest) (SessionCommandRunResponse, error) {
	return invoke[SessionCommandRunRequest, SessionCommandRunResponse](c, ctx, "RunSessionCommand", req)
}

func (c *Client) PollLogs(ctx context.Context, since uint64) (PollLogsResponse, error) {
	return c.pollLogs(ctx, "", "", since)
}

func (c *Client) PollChainLogs(ctx context.Context, chain string, since uint64) (PollLogsResponse, error) {
	return c.PollOperationChainLogs(ctx, operatorsession.DefaultOperation, chain, since)
}

func (c *Client) PollOperationChainLogs(ctx context.Context, operation, chain string, since uint64) (PollLogsResponse, error) {
	return c.pollLogs(ctx, operation, chain, since)
}

func (c *Client) pollLogs(ctx context.Context, operation, chain string, since uint64) (PollLogsResponse, error) {
	return invoke[PollLogsRequest, PollLogsResponse](c, ctx, "PollLogs", PollLogsRequest{Since: since, Operation: operation, Chain: chain})
}

func (c *Client) AttachEntity(ctx context.Context, req AttachEntityRequest) (EntityResponse, error) {
	return invoke[AttachEntityRequest, EntityResponse](c, ctx, "AttachEntity", req)
}

func (c *Client) HeartbeatEntity(ctx context.Context, req HeartbeatEntityRequest) (EntityResponse, error) {
	return invoke[HeartbeatEntityRequest, EntityResponse](c, ctx, "HeartbeatEntity", req)
}

func (c *Client) DetachEntity(ctx context.Context, req DetachEntityRequest) error {
	_, err := invoke[DetachEntityRequest, EmptyResponse](c, ctx, "DetachEntity", req)
	return err
}

func (c *Client) ListEntities(ctx context.Context, req ListEntitiesRequest) (ListEntitiesResponse, error) {
	return invoke[ListEntitiesRequest, ListEntitiesResponse](c, ctx, "ListEntities", req)
}

func (c *Client) Snapshot(ctx context.Context, req SnapshotRequest) (SnapshotResponse, error) {
	return invoke[SnapshotRequest, SnapshotResponse](c, ctx, "Snapshot", req)
}

func (c *Client) CreatePendingThrow(ctx context.Context, req CreatePendingThrowRequest) (PendingThrowResponse, error) {
	return invoke[CreatePendingThrowRequest, PendingThrowResponse](c, ctx, "CreatePendingThrow", req)
}

func (c *Client) ConfirmPendingThrow(ctx context.Context, req ConfirmPendingThrowRequest) (PendingThrowResponse, error) {
	return invoke[ConfirmPendingThrowRequest, PendingThrowResponse](c, ctx, "ConfirmPendingThrow", req)
}

func (c *Client) RequirePendingThrowReady(ctx context.Context, req PendingThrowRequest) (PendingThrowResponse, error) {
	return invoke[PendingThrowRequest, PendingThrowResponse](c, ctx, "RequirePendingThrowReady", req)
}

func (c *Client) CancelPendingThrow(ctx context.Context, req PendingThrowRequest) error {
	_, err := invoke[PendingThrowRequest, EmptyResponse](c, ctx, "CancelPendingThrow", req)
	return err
}

func (c *Client) GetLaunchKeyPolicy(ctx context.Context, req LaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	return invoke[LaunchKeyPolicyRequest, LaunchKeyPolicyResponse](c, ctx, "GetLaunchKeyPolicy", req)
}

func (c *Client) SetLaunchKeyPolicy(ctx context.Context, req SetLaunchKeyPolicyRequest) (LaunchKeyPolicyResponse, error) {
	return invoke[SetLaunchKeyPolicyRequest, LaunchKeyPolicyResponse](c, ctx, "SetLaunchKeyPolicy", req)
}

type SessionClient struct {
	client          *Client
	ctx             context.Context
	mu              sync.Mutex
	activeOperation string
	activeChains    map[string]string
}

func NewSessionClient(ctx context.Context, client *Client) *SessionClient {
	return &SessionClient{
		client:       client,
		ctx:          ctx,
		activeChains: map[string]string{},
	}
}

func (s *SessionClient) RemoteFeedback() bool {
	return true
}

func (s *SessionClient) CreateOperation(operation string) error {
	_, err := invoke[OperationRequest, EmptyResponse](s.client, s.ctx, "CreateOperation", OperationRequest{Operation: operation})
	return err
}

func (s *SessionClient) UseOperation(operation string) error {
	if _, err := invoke[OperationRequest, EmptyResponse](s.client, s.ctx, "UseOperation", OperationRequest{Operation: operation}); err != nil {
		return err
	}
	s.setActiveOperation(operation)
	return nil
}

func (s *SessionClient) CreateChain(chain string) error {
	_, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "CreateChain", ChainRequest{Operation: s.operation(), Chain: chain})
	return err
}

func (s *SessionClient) UseChain(chain string) error {
	if _, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "UseChain", ChainRequest{Operation: s.operation(), Chain: chain}); err != nil {
		return err
	}
	s.setActiveChain(chain)
	return nil
}

func (s *SessionClient) RenameChain(chain, name string) error {
	if _, err := invoke[RenameChainRequest, EmptyResponse](s.client, s.ctx, "RenameChain", RenameChainRequest{Operation: s.operation(), Chain: chain, Name: name}); err != nil {
		return err
	}
	if s.active() == chain {
		s.setActiveChain(name)
	}
	return nil
}

func (s *SessionClient) DeleteChain(chain string) error {
	if _, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "DeleteChain", ChainRequest{Operation: s.operation(), Chain: chain}); err != nil {
		return err
	}
	if s.active() == chain {
		s.setActiveChain("")
	}
	return nil
}

func (s *SessionClient) AddTarget(target string) error {
	_, err := invoke[TargetRequest, EmptyResponse](s.client, s.ctx, "AddTarget", TargetRequest{Operation: s.operation(), Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) BindTarget(target string) error {
	_, err := invoke[TargetRequest, EmptyResponse](s.client, s.ctx, "BindTarget", TargetRequest{Operation: s.operation(), Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) UnbindTarget(target string) error {
	_, err := invoke[TargetRequest, EmptyResponse](s.client, s.ctx, "UnbindTarget", TargetRequest{Operation: s.operation(), Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) ClearTargets() {
	_, err := invoke[ChainRequest, EmptyResponse](s.client, s.ctx, "ClearTargets", ChainRequest{Operation: s.operation(), Chain: s.active()})
	logDaemonRPCError("clear session targets", err)
}

func (s *SessionClient) CreateTargetSet(name string) error {
	_, err := invoke[TargetSetRequest, EmptyResponse](s.client, s.ctx, "CreateTargetSet", TargetSetRequest{Operation: s.operation(), Name: name, Chain: s.active()})
	return err
}

func (s *SessionClient) AddTargetToSet(name, target string) error {
	_, err := invoke[TargetSetRequest, EmptyResponse](s.client, s.ctx, "AddTargetToSet", TargetSetRequest{Operation: s.operation(), Name: name, Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) RemoveTargetFromSet(name, target string) error {
	_, err := invoke[TargetSetRequest, EmptyResponse](s.client, s.ctx, "RemoveTargetFromSet", TargetSetRequest{Operation: s.operation(), Name: name, Target: target, Chain: s.active()})
	return err
}

func (s *SessionClient) AddModule(moduleID string) (operatorsession.Step, error) {
	return s.AddStep(moduleID, "")
}

func (s *SessionClient) AddStep(moduleID, stepID string) (operatorsession.Step, error) {
	resp, err := invoke[ModuleRequest, StepResponse](s.client, s.ctx, "AddModule", ModuleRequest{Operation: s.operation(), ModuleID: moduleID, StepID: stepID, Chain: s.active()})
	return operatorsession.Step{ID: resp.ID, ModuleID: resp.ModuleID, StepID: resp.StepID}, err
}

func (s *SessionClient) SetChainConfig(key, value string) error {
	_, err := invoke[ConfigRequest, EmptyResponse](s.client, s.ctx, "SetChainConfig", ConfigRequest{Operation: s.operation(), Key: key, Value: value, Chain: s.active()})
	return err
}

func (s *SessionClient) UnsetChainConfig(key string) error {
	_, err := invoke[ConfigRequest, EmptyResponse](s.client, s.ctx, "UnsetChainConfig", ConfigRequest{Operation: s.operation(), Key: key, Chain: s.active()})
	return err
}

func (s *SessionClient) SetTargetConfig(target, key, value string) error {
	_, err := invoke[TargetConfigRequest, EmptyResponse](s.client, s.ctx, "SetTargetConfig", TargetConfigRequest{Operation: s.operation(), Target: target, Key: key, Value: value, Chain: s.active()})
	return err
}

func (s *SessionClient) UnsetTargetConfig(target, key string) error {
	_, err := invoke[TargetConfigRequest, EmptyResponse](s.client, s.ctx, "UnsetTargetConfig", TargetConfigRequest{Operation: s.operation(), Target: target, Key: key, Chain: s.active()})
	return err
}

func (s *SessionClient) AppendLog(entries ...operatorlog.Entry) error {
	_, err := invoke[AppendLogRequest, EmptyResponse](s.client, s.ctx, "AppendLog", AppendLogRequest{Operation: s.operation(), Chain: s.active(), Entries: operatorLogEntries(entries)})
	return err
}

func (s *SessionClient) AppendLogToChain(chain string, entries ...operatorlog.Entry) error {
	_, err := invoke[AppendLogRequest, EmptyResponse](s.client, s.ctx, "AppendLog", AppendLogRequest{Operation: s.operation(), Chain: chain, Entries: operatorLogEntries(entries)})
	return err
}

func (s *SessionClient) ActiveLogs() []operatorlog.Entry {
	resp, err := invoke[ActiveLogsRequest, []OperatorLogEntry](s.client, s.ctx, "ActiveLogs", ActiveLogsRequest{Operation: s.operation(), Chain: s.active()})
	if err != nil {
		return nil
	}
	out := make([]operatorlog.Entry, 0, len(resp))
	for _, entry := range resp {
		out = append(out, operatorLogFromRPC(entry))
	}
	return out
}

func (s *SessionClient) Snapshot() operatorsession.State {
	resp, err := invoke[SnapshotRequest, SnapshotResponse](s.client, s.ctx, "Snapshot", SnapshotRequest{Operation: s.operation(), Chain: s.active()})
	if err != nil {
		return operatorsession.State{}
	}
	session := operatorsession.New()
	session.Import(resp.State)
	return session.Snapshot()
}

func (s *SessionClient) ActiveOperationSelected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimSpace(s.activeOperation) != ""
}

func (s *SessionClient) active() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeChains[s.operationLocked()]
}

func (s *SessionClient) setActiveChain(chain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
	s.activeChains[s.operationLocked()] = chain
}

func (s *SessionClient) operation() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.operationLocked()
}

func (s *SessionClient) operationLocked() string {
	operation := strings.TrimSpace(s.activeOperation)
	if operation == "" {
		return operatorsession.DefaultOperation
	}
	return operation
}

func (s *SessionClient) setActiveOperation(operation string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = operatorsession.DefaultOperation
	}
	s.activeOperation = operation
	if s.activeChains == nil {
		s.activeChains = map[string]string{}
	}
}

func invoke[Req, Res any](c *Client, ctx context.Context, method string, req Req) (Res, error) {
	var zero Res
	if c == nil || c.httpClient == nil || c.baseURL == "" {
		return zero, errors.New("daemon rpc client is not configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+serviceURLPrefix+method, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("%s: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", method, err)
	}
	defer func() { logDaemonRPCError("close response body", resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maximumRPCErrorBytes+1))
		if readErr != nil {
			return zero, fmt.Errorf("%s: %s; additionally failed to read error response: %v", method, resp.Status, readErr)
		}
		if len(body) > maximumRPCErrorBytes {
			return zero, fmt.Errorf("%s: %s; error response exceeds size limit", method, resp.Status)
		}
		var envelope RPCErrorEnvelope
		if err := json.Unmarshal(body, &envelope); err == nil && envelope.Validate() == nil {
			return zero, decodeRPCError(method, resp.StatusCode, envelope)
		}
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = resp.Status
		}
		return zero, fmt.Errorf("%s: %s", method, message)
	}
	if err := json.NewDecoder(resp.Body).Decode(&zero); err != nil {
		return zero, fmt.Errorf("%s: %w", method, err)
	}
	return zero, nil
}

func decodeRPCError(method string, statusCode int, envelope RPCErrorEnvelope) error {
	switch envelope.Code {
	case RPCErrorCodeRolloverPrecondition:
		return fmt.Errorf("%s: %w", method, apppki.NewRolloverPreconditionError(envelope.RolloverReason, envelope.RolloverDetail))
	case RPCErrorCodeRevisionConflict:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrRevisionConflict)
	case RPCErrorCodeAcknowledgementExists:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrAcknowledgementExists)
	case RPCErrorCodeIdempotencyConflict:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrIdempotencyConflict)
	case RPCErrorCodeMutationExists:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrMutationExists)
	case RPCErrorCodeIssuanceInProgress:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrIssuanceInProgress)
	case RPCErrorCodeCRLPublicationInProgress:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrCRLPublicationInProgress)
	case RPCErrorCodePrivateKeyExportDenied:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrPrivateKeyExportDenied)
	case RPCErrorCodeAuthoritySigningLocked:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrAuthoritySigningLocked)
	case RPCErrorCodeAuthoritySigningLeaseOwned:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrAuthoritySigningLeaseOwned)
	case RPCErrorCodePermissionDenied:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, errPrivilegedControlUnavailable)
	case RPCErrorCodeNotFound:
		return fmt.Errorf("%s: %s: %w", method, envelope.Message, apppki.ErrNotFound)
	default:
		return &RemoteError{Method: method, StatusCode: statusCode, Envelope: envelope}
	}
}

type Endpoint struct {
	Network string
	Address string
}

func ParseEndpoint(value string) (Endpoint, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Endpoint{}, errors.New("daemon rpc endpoint is required")
	}
	switch {
	case strings.HasPrefix(value, "unix://"):
		path := strings.TrimPrefix(value, "unix://")
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return unixEndpoint(path)
	case strings.HasPrefix(value, "unix:"):
		return unixEndpoint(strings.TrimPrefix(value, "unix:"))
	case strings.HasPrefix(value, "tcp://"):
		return tcpEndpoint(strings.TrimPrefix(value, "tcp://"))
	case strings.HasPrefix(value, "http://"):
		return tcpEndpoint(strings.TrimPrefix(value, "http://"))
	case strings.HasPrefix(value, "https://"):
		return Endpoint{}, errors.New("daemon rpc tcp endpoint must use http, not https")
	case strings.Contains(value, "/"):
		return unixEndpoint(value)
	default:
		if _, _, err := net.SplitHostPort(value); err == nil {
			return tcpEndpoint(value)
		}
		return unixEndpoint(value)
	}
}

func unixEndpoint(path string) (Endpoint, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Endpoint{}, errors.New("daemon unix socket path is required")
	}
	return Endpoint{Network: "unix", Address: path}, nil
}

func tcpEndpoint(address string) (Endpoint, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return Endpoint{}, errors.New("daemon tcp address is required")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return Endpoint{}, err
	}
	if !isLoopbackDaemonHost(host) {
		return Endpoint{}, fmt.Errorf("daemon tcp host %q must be loopback", host)
	}
	return Endpoint{Network: "tcp", Address: address}, nil
}

func isLoopbackDaemonHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (e Endpoint) BaseURL() string {
	if e.Network == "unix" {
		return "http://hoveld"
	}
	return "http://" + e.Address
}

func (e Endpoint) String() string {
	if e.Network == "tcp" {
		return "tcp://" + e.Address
	}
	if strings.HasPrefix(e.Address, "unix:") {
		return e.Address
	}
	return e.Address
}

type LogBroker struct {
	mu    sync.Mutex
	next  uint64
	logs  []PublishedLog
	limit int
	start int
	count int
}

const defaultLogBrokerLimit = 4096

func NewLogBroker() *LogBroker {
	return NewLogBrokerWithLimit(defaultLogBrokerLimit)
}

func NewLogBrokerWithLimit(limit int) *LogBroker {
	if limit <= 0 {
		limit = defaultLogBrokerLimit
	}
	return &LogBroker{limit: limit}
}

func (b *LogBroker) Publish(operation, chain string, entries ...operatorlog.Entry) {
	if b == nil {
		return
	}
	operation = operationOrDefault(operation)
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, entry := range entries {
		b.next++
		log := PublishedLog{
			Seq:       b.next,
			Operation: operation,
			Chain:     chain,
			Entry:     operatorLogEntry(entry),
		}
		if b.count < b.limit {
			b.logs = append(b.logs, log)
			b.count++
			continue
		}
		b.logs[b.start] = log
		b.start = (b.start + 1) % b.limit
	}
}

func (b *LogBroker) Since(since uint64) (uint64, []PublishedLog) {
	if b == nil {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var logs []PublishedLog
	for i := 0; i < b.count; i++ {
		log := b.logs[(b.start+i)%len(b.logs)]
		if log.Seq > since {
			logs = append(logs, log)
		}
	}
	return b.next, logs
}

func (b *LogBroker) SinceChain(operation, chain string, since uint64) (uint64, []PublishedLog) {
	if b == nil {
		return 0, nil
	}
	operation = operationOrDefault(operation)
	b.mu.Lock()
	defer b.mu.Unlock()
	var logs []PublishedLog
	for i := 0; i < b.count; i++ {
		log := b.logs[(b.start+i)%len(b.logs)]
		if log.Seq > since && log.Operation == operation && log.Chain == chain {
			logs = append(logs, log)
		}
	}
	return b.next, logs
}

func responseFromResult(result run.Result) RunMockExploitResponse {
	resp := RunMockExploitResponse{
		RunID:    result.ID,
		ModuleID: result.ModuleID,
		Target:   result.Target,
		State:    string(result.State),
		Summary:  result.Summary,
	}
	for _, finding := range result.Findings {
		resp.Findings = append(resp.Findings, Finding{
			Title:    finding.Title,
			Severity: string(finding.Severity),
			Detail:   finding.Detail,
		})
	}
	for _, artifact := range result.Artifacts {
		resp.Artifacts = append(resp.Artifacts, Artifact{
			Name: artifact.Name,
			Kind: artifact.Kind,
			Data: artifact.Data,
			Path: artifact.Path,
		})
	}
	resp.Sessions = sessionRefsFromRun(result.Sessions)
	resp.InstalledPayloads = run.CloneInstalledPayloads(result.InstalledPayloads)
	for _, log := range result.Logs {
		resp.Logs = append(resp.Logs, LogEntry{
			ID:             log.ID,
			Time:           log.Time,
			Topic:          log.Topic,
			Kind:           log.Kind,
			Level:          log.Level,
			Source:         sourceOrDefault(log.Source, "module"),
			Message:        log.Message,
			Logger:         log.Logger,
			ChainID:        log.ChainID,
			ChainName:      log.ChainName,
			RunID:          log.RunID,
			Target:         log.Target,
			ModuleID:       log.ModuleID,
			ElapsedSeconds: cloneFloat64(log.ElapsedSeconds),
			Fields:         cloneStringMap(log.Fields),
			Attributes:     cloneStringMap(log.Attributes),
		})
	}
	return resp
}

func sessionRefsFromRun(sessions []run.SessionRef) []SessionRef {
	out := make([]SessionRef, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, SessionRef{
			ID:                 session.ID,
			RunID:              session.RunID,
			ModuleID:           session.ModuleID,
			Target:             session.Target,
			Name:               session.Name,
			Kind:               session.Kind,
			State:              session.State,
			Transport:          session.Transport,
			InstalledPayloadID: session.InstalledPayloadID,
			Capabilities:       append([]string(nil), session.Capabilities...),
		})
	}
	return out
}

func sourceOrDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func operatorLogEntry(entry operatorlog.Entry) OperatorLogEntry {
	return OperatorLogEntry{
		ID:             entry.ID,
		Time:           entry.Time.Format(time.RFC3339Nano),
		Topic:          entry.Topic,
		Kind:           string(entry.Kind),
		Level:          string(entry.Level),
		Source:         entry.Source,
		Message:        entry.Message,
		ChainID:        entry.ChainID,
		ChainName:      entry.ChainName,
		RunID:          entry.RunID,
		Target:         entry.Target,
		ModuleID:       entry.ModuleID,
		ElapsedSeconds: cloneFloat64(entry.ElapsedSeconds),
		Fields:         fieldsToMap(entry.Fields),
		Attributes:     cloneStringMap(entry.Attributes),
	}
}

func operatorLogEntries(entries []operatorlog.Entry) []OperatorLogEntry {
	out := make([]OperatorLogEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, operatorLogEntry(entry))
	}
	return out
}

func operatorLogFromRPC(entry OperatorLogEntry) operatorlog.Entry {
	fields := make([]operatorlog.Field, 0, len(entry.Fields))
	for name, value := range entry.Fields {
		fields = append(fields, operatorlog.Field{Name: name, Value: value})
	}
	timestamp, err := time.Parse(time.RFC3339Nano, entry.Time)
	logDaemonRPCError("parse operator log timestamp", err)
	return operatorlog.Entry{
		ID:             entry.ID,
		Time:           timestamp,
		Topic:          entry.Topic,
		Kind:           operatorlog.Kind(entry.Kind),
		Level:          operatorlog.Level(entry.Level),
		Source:         entry.Source,
		Message:        entry.Message,
		ChainID:        entry.ChainID,
		ChainName:      entry.ChainName,
		RunID:          entry.RunID,
		Target:         entry.Target,
		ModuleID:       entry.ModuleID,
		ElapsedSeconds: cloneFloat64(entry.ElapsedSeconds),
		Fields:         fields,
		Attributes:     cloneStringMap(entry.Attributes),
	}
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func fieldsToMap(fields []operatorlog.Field) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for _, field := range fields {
		out[field.Name] = field.Value
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func logDaemonRPCError(action string, err error) {
	if err != nil {
		log.Printf("hovel daemon rpc: %s: %v", action, err)
	}
}
