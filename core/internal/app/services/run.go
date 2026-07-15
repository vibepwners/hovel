package services

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	"github.com/vibepwners/hovel/internal/domain/event"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
)

type ModuleRunner interface {
	Run(context.Context, run.Request) (run.Result, error)
}

type PayloadCommandRunner interface {
	ListPayloadCommands(context.Context, string, run.PayloadCommandListRequest) ([]run.PayloadCommand, error)
	RunPayloadCommand(context.Context, string, run.PayloadCommandRequest) (run.PayloadCommandResult, error)
}

type PayloadGenerator interface {
	GeneratePayload(context.Context, string, run.GeneratePayloadRequest) (run.PayloadArtifactSet, error)
}

// MeshDescriber is the optional application port for static Mesh capabilities.
type MeshDescriber interface {
	DescribeMesh(context.Context, string, mesh.DescribeRequest) (mesh.Descriptor, error)
}

// MeshTopologyReader is the optional application port for live Mesh topology.
type MeshTopologyReader interface {
	MeshTopology(context.Context, string, mesh.TopologyRequest) (mesh.Topology, error)
}

// MeshBeaconLister is the optional application port for recent Mesh beacons.
type MeshBeaconLister interface {
	ListMeshBeacons(context.Context, string, mesh.BeaconRequest) ([]mesh.Beacon, error)
}

// MeshTaskRunner is the optional application port for provider-owned Mesh tasks.
type MeshTaskRunner interface {
	RunMeshTask(context.Context, string, mesh.TaskRequest) (mesh.TaskResult, error)
}

// MeshStreamRunner is the optional application port for provider-owned Mesh sessions.
type MeshStreamRunner interface {
	OpenMeshStream(context.Context, string, mesh.StreamRequest) (run.SessionRef, error)
}

// MeshListenerLister is the optional application port for reading listener state.
type MeshListenerLister interface {
	ListMeshListeners(context.Context, string, mesh.ListenerListRequest) ([]mesh.Listener, error)
}

// MeshListenerLifecycleRunner is the optional application port for mutating listener state.
type MeshListenerLifecycleRunner interface {
	StartMeshListener(context.Context, string, mesh.ListenerStartRequest) (mesh.Listener, error)
	StopMeshListener(context.Context, string, mesh.ListenerStopRequest) (mesh.Listener, error)
}

// CredentialMeshListenerRunner executes credential hooks and listener start in
// the same provider process.
type CredentialMeshListenerRunner interface {
	StartMeshListenerWithCredentials(
		context.Context,
		string,
		*CredentialOperationResolution,
		mesh.ListenerStartRequest,
	) (MeshListenerExecution, error)
}

// CredentialMeshTaskRunner executes credential hooks and a Mesh task in the
// same provider process.
type CredentialMeshTaskRunner interface {
	RunMeshTaskWithCredentials(
		context.Context,
		string,
		*CredentialOperationResolution,
		mesh.TaskRequest,
	) (MeshTaskExecution, error)
}

// CredentialMeshStreamRunner executes credential hooks and stream open in the
// same provider process.
type CredentialMeshStreamRunner interface {
	OpenMeshStreamWithCredentials(
		context.Context,
		string,
		*CredentialOperationResolution,
		mesh.StreamRequest,
	) (MeshStreamExecution, error)
}

// MeshListenerExecution contains a listener result and secret-free credential
// receipts from the same process invocation.
type MeshListenerExecution struct {
	Listener           mesh.Listener
	CredentialReceipts []domainpki.CredentialDeliveryReceipt
}

// MeshTaskExecution contains a task result and secret-free credential receipts
// from the same process invocation.
type MeshTaskExecution struct {
	Result             mesh.TaskResult
	CredentialReceipts []domainpki.CredentialDeliveryReceipt
}

// MeshStreamExecution contains a stream session and secret-free credential
// receipts from the same process invocation.
type MeshStreamExecution struct {
	Session            run.SessionRef
	CredentialReceipts []domainpki.CredentialDeliveryReceipt
}

// ModuleInspector discovers the exact installed module contract used for an
// invocation.
type ModuleInspector interface {
	Inspect(context.Context, string) (modulecatalog.Module, error)
}

type credentialOperationLease interface {
	BorrowedDeliveries() (domainpki.CredentialOperationDeliveries, error)
	Revalidate(context.Context) error
	Close()
}

var ErrCredentialOperationResolutionClosed = errors.New(
	"credential operation resolution is closed",
)

// CredentialOperationResolution owns a credential lease across live provider
// reconciliation and delivery. BorrowedDeliveries does not copy secret data;
// callers must not retain or mutate it and must close the resolution exactly
// after the provider operation finishes.
type CredentialOperationResolution struct {
	mu       sync.Mutex
	lease    credentialOperationLease
	isClosed bool
}

// NewCredentialOperationResolution wraps a concrete lease without copying its
// secret deliveries.
func NewCredentialOperationResolution(
	lease credentialOperationLease,
) (*CredentialOperationResolution, error) {
	if isNilCredentialOperationLease(lease) {
		return nil, errors.New("credential operation lease is required")
	}
	return &CredentialOperationResolution{lease: lease}, nil
}

// BorrowedDeliveries returns the underlying lease-owned deliveries.
func (r *CredentialOperationResolution) BorrowedDeliveries() (
	domainpki.CredentialOperationDeliveries,
	error,
) {
	if r == nil {
		return nil, errors.New("credential operation resolution is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isClosed || isNilCredentialOperationLease(r.lease) {
		return nil, ErrCredentialOperationResolutionClosed
	}
	return r.lease.BorrowedDeliveries()
}

// Revalidate checks the complete credential snapshot through its owning
// adapter. Provider runtimes must call it after exact live reconciliation and
// immediately before sending any credential material.
func (r *CredentialOperationResolution) Revalidate(ctx context.Context) error {
	if r == nil {
		return errors.New("credential operation resolution is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isClosed || isNilCredentialOperationLease(r.lease) {
		return ErrCredentialOperationResolutionClosed
	}
	return r.lease.Revalidate(ctx)
}

// Close clears the underlying lease and is safe to call repeatedly.
func (r *CredentialOperationResolution) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.isClosed {
		r.mu.Unlock()
		return
	}
	lease := r.lease
	r.lease = nil
	r.isClosed = true
	r.mu.Unlock()
	if !isNilCredentialOperationLease(lease) {
		lease.Close()
	}
}

// Clear is an alias for Close for secret-owning call sites.
func (r *CredentialOperationResolution) Clear() {
	r.Close()
}

func isNilCredentialOperationLease(lease credentialOperationLease) bool {
	if lease == nil {
		return true
	}
	value := reflect.ValueOf(lease)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// CredentialOperationResolver turns non-secret selections into one ephemeral,
// revalidatable credential operation resolution.
type CredentialOperationResolver interface {
	ResolveCredentialOperation(
		context.Context,
		domainpki.CredentialProviderTarget,
		domainpki.CredentialDeliveryDescriptor,
		domainpki.CredentialSelections,
		domainpki.CredentialOperationScope,
		[]domainpki.CredentialConsumerBinding,
	) (*CredentialOperationResolution, error)
}

type SessionBroker interface {
	ListSessions(context.Context) ([]run.SessionRef, error)
	WriteSession(context.Context, string, []byte) error
	ReadSession(context.Context, string, time.Duration) (run.SessionChunk, error)
	TailSession(context.Context, string, run.SessionTailOptions) (run.SessionChunk, error)
	CloseSession(context.Context, string) error
	ListSessionCommands(context.Context, string, run.PayloadCommandListRequest) ([]run.PayloadCommand, error)
	RunSessionCommand(context.Context, string, run.PayloadCommandRequest) (run.PayloadCommandResult, error)
}

type ModuleExecutionFailure interface {
	error
	ModuleFailureSummary() string
	ModuleFailureDetail() string
}

type moduleExecutionFailure struct {
	summary string
	err     error
}

func NewModuleExecutionFailure(summary string, err error) error {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		summary = "module execution failed"
	}
	return moduleExecutionFailure{summary: summary, err: err}
}

func (e moduleExecutionFailure) Error() string {
	if e.err == nil {
		return e.summary
	}
	return e.summary + ": " + e.err.Error()
}

func (e moduleExecutionFailure) Unwrap() error {
	return e.err
}

func (e moduleExecutionFailure) ModuleFailureSummary() string {
	return e.summary
}

func (e moduleExecutionFailure) ModuleFailureDetail() string {
	if e.err == nil {
		return e.summary
	}
	return e.err.Error()
}

type ExecuteMockExploitRequest struct {
	Operation    string
	Chain        string
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	ThrowStarted time.Time
}

type RunService struct {
	runner             ModuleRunner
	events             EventSink
	ids                IDGenerator
	clock              Clock
	credentialResolver CredentialOperationResolver
}

// RunServiceOption configures an optional RunService capability.
type RunServiceOption func(*RunService)

// WithCredentialOperationResolver enables daemon-owned credential selections
// for Mesh mutation methods. The zero-value service remains credential-free.
func WithCredentialOperationResolver(resolver CredentialOperationResolver) RunServiceOption {
	return func(service *RunService) {
		service.credentialResolver = resolver
	}
}

func NewRunService(
	runner ModuleRunner,
	events EventSink,
	ids IDGenerator,
	clock Clock,
	options ...RunServiceOption,
) RunService {
	service := RunService{
		runner: runner,
		events: events,
		ids:    ids,
		clock:  clock,
	}
	for _, option := range options {
		if option != nil {
			option(&service)
		}
	}
	return service
}

func (s RunService) ExecuteMockExploit(ctx context.Context, req ExecuteMockExploitRequest) (run.Result, error) {
	return s.ExecuteModule(ctx, ExecuteModuleRequest(req))
}

type ExecuteModuleRequest struct {
	Operation    string
	Chain        string
	ModuleID     string
	Target       string
	Inputs       map[string]string
	ChainConfig  map[string]string
	TargetConfig map[string]string
	ThrowStarted time.Time
}

type PayloadCommandListRequest struct {
	ModuleID string
	Request  run.PayloadCommandListRequest
}

type PayloadCommandRunRequest struct {
	Operation string
	Chain     string
	ModuleID  string
	Request   run.PayloadCommandRequest
}

type GeneratePayloadRequest struct {
	ModuleID string
	Request  run.GeneratePayloadRequest
}

func (s RunService) GeneratePayload(ctx context.Context, req GeneratePayloadRequest) (run.PayloadArtifactSet, error) {
	runner, ok := s.runner.(PayloadGenerator)
	if !ok {
		return run.PayloadArtifactSet{}, errors.New("payload generator is not configured")
	}
	return runner.GeneratePayload(ctx, req.ModuleID, req.Request)
}

func (s RunService) DescribeMesh(
	ctx context.Context,
	moduleID string,
	req mesh.DescribeRequest,
) (mesh.Descriptor, error) {
	runner, err := s.meshDescriber()
	if err != nil {
		return mesh.Descriptor{}, err
	}
	descriptor, err := runner.DescribeMesh(ctx, moduleID, req.Clone())
	if err != nil {
		return mesh.Descriptor{}, err
	}
	descriptor = descriptor.Clone()
	if err := descriptor.Validate(); err != nil {
		return mesh.Descriptor{}, fmt.Errorf("validate mesh descriptor: %w", err)
	}
	return descriptor, nil
}

func (s RunService) MeshTopology(
	ctx context.Context,
	moduleID string,
	req mesh.TopologyRequest,
) (mesh.Topology, error) {
	req = req.Clone()
	if err := req.Validate(); err != nil {
		return mesh.Topology{}, err
	}
	runner, err := s.meshTopologyReader()
	if err != nil {
		return mesh.Topology{}, err
	}
	topology, err := runner.MeshTopology(ctx, moduleID, req)
	if err != nil {
		return mesh.Topology{}, err
	}
	topology = topology.Clone()
	if err := topology.Validate(); err != nil {
		return mesh.Topology{}, fmt.Errorf("validate mesh topology: %w", err)
	}
	return topology, nil
}

func (s RunService) ListMeshBeacons(
	ctx context.Context,
	moduleID string,
	req mesh.BeaconRequest,
) ([]mesh.Beacon, error) {
	request := req.Clone()
	if err := request.Validate(); err != nil {
		return nil, err
	}
	runner, err := s.meshBeaconLister()
	if err != nil {
		return nil, err
	}
	beacons, err := runner.ListMeshBeacons(ctx, moduleID, request)
	if err != nil {
		return nil, err
	}
	result := make([]mesh.Beacon, len(beacons))
	seen := make(map[string]struct{}, len(beacons))
	for index, beacon := range beacons {
		result[index] = beacon.Clone()
		if err := result[index].Validate(); err != nil {
			return nil, fmt.Errorf("validate mesh beacon: %w", err)
		}
		if _, exists := seen[result[index].ID]; exists {
			return nil, fmt.Errorf("mesh beacon id %q is duplicated", result[index].ID)
		}
		seen[result[index].ID] = struct{}{}
	}
	return result, nil
}

func (s RunService) ListMeshListeners(
	ctx context.Context,
	moduleID string,
	req mesh.ListenerListRequest,
) ([]mesh.Listener, error) {
	runner, err := s.meshListenerLister()
	if err != nil {
		return nil, err
	}
	req = req.Clone()
	req.ListenerID = strings.TrimSpace(req.ListenerID)
	req.State = mesh.ListenerState(strings.TrimSpace(string(req.State)))
	listeners, err := runner.ListMeshListeners(ctx, moduleID, req)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(listeners))
	normalized := make([]mesh.Listener, len(listeners))
	for index, listener := range listeners {
		normalized[index], err = normalizeMeshListener(listener)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[normalized[index].ID]; exists {
			return nil, fmt.Errorf("mesh listener id %q is duplicated", normalized[index].ID)
		}
		seen[normalized[index].ID] = struct{}{}
	}
	return normalized, nil
}

func (s RunService) StartMeshListener(
	ctx context.Context,
	moduleID string,
	req mesh.ListenerStartRequest,
) (mesh.Listener, error) {
	return s.StartMeshListenerWithCredentialSelections(ctx, moduleID, req, nil, domainpki.CredentialOperationScope{})
}

func (s RunService) StartMeshListenerWithCredentialSelections(
	ctx context.Context,
	moduleID string,
	req mesh.ListenerStartRequest,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
) (mesh.Listener, error) {
	runner, err := s.meshListenerLifecycleRunner()
	if err != nil {
		return mesh.Listener{}, err
	}
	req, err = normalizeMeshListenerStartRequest(req)
	if err != nil {
		return mesh.Listener{}, err
	}
	var listener mesh.Listener
	if len(selections) == 0 {
		listener, err = runner.StartMeshListener(ctx, moduleID, req)
	} else {
		credentialRunner, ok := s.runner.(CredentialMeshListenerRunner)
		if !ok {
			return mesh.Listener{}, errors.New("credential-aware mesh runner is not configured")
		}
		scope.ListenerID = req.ListenerID
		resolvedModuleID, resolution, resolveErr := s.resolveMeshCredentials(
			ctx, moduleID, selections, scope, req.ListenerID, "",
		)
		if resolveErr != nil {
			return mesh.Listener{}, resolveErr
		}
		defer resolution.Close()
		execution, executeErr := credentialRunner.StartMeshListenerWithCredentials(
			ctx, resolvedModuleID, resolution, req,
		)
		if executeErr != nil {
			return mesh.Listener{}, executeErr
		}
		listener = execution.Listener
	}
	if err != nil {
		return mesh.Listener{}, err
	}
	listener, err = normalizeMeshListener(listener)
	if err != nil {
		return mesh.Listener{}, err
	}
	if listener.ID != req.ListenerID {
		return mesh.Listener{}, fmt.Errorf(
			"mesh listener result id %q does not match requested id %q",
			listener.ID,
			req.ListenerID,
		)
	}
	return listener, nil
}

func (s RunService) StopMeshListener(
	ctx context.Context,
	moduleID string,
	req mesh.ListenerStopRequest,
) (mesh.Listener, error) {
	runner, err := s.meshListenerLifecycleRunner()
	if err != nil {
		return mesh.Listener{}, err
	}
	req = req.Clone()
	req.ListenerID = strings.TrimSpace(req.ListenerID)
	if req.ListenerID == "" {
		return mesh.Listener{}, errors.New("mesh listener id is required")
	}
	listener, err := runner.StopMeshListener(ctx, moduleID, req)
	if err != nil {
		return mesh.Listener{}, err
	}
	listener, err = normalizeMeshListener(listener)
	if err != nil {
		return mesh.Listener{}, err
	}
	if listener.ID != req.ListenerID {
		return mesh.Listener{}, fmt.Errorf(
			"mesh listener result id %q does not match requested id %q",
			listener.ID,
			req.ListenerID,
		)
	}
	return listener, nil
}

func normalizeMeshListener(listener mesh.Listener) (mesh.Listener, error) {
	listener = listener.Clone()
	listener.ID = strings.TrimSpace(listener.ID)
	if listener.ID == "" {
		return mesh.Listener{}, errors.New("mesh listener result id is required")
	}
	listener.State = mesh.ListenerState(strings.TrimSpace(string(listener.State)))
	listener.Deployment = mesh.ListenerDeployment(strings.TrimSpace(string(listener.Deployment)))
	listener.Management = mesh.ListenerManagement(strings.TrimSpace(string(listener.Management)))
	if err := validateMeshListenerDeployment(listener.Deployment); err != nil {
		return mesh.Listener{}, err
	}
	if err := validateMeshListenerManagement(listener.Management); err != nil {
		return mesh.Listener{}, err
	}
	return listener, nil
}

func normalizeMeshListenerStartRequest(req mesh.ListenerStartRequest) (mesh.ListenerStartRequest, error) {
	req = req.Clone()
	req.ListenerID = strings.TrimSpace(req.ListenerID)
	if req.ListenerID == "" {
		return mesh.ListenerStartRequest{}, errors.New("mesh listener id is required")
	}
	req.Deployment = mesh.ListenerDeployment(strings.TrimSpace(string(req.Deployment)))
	if err := validateMeshListenerDeployment(req.Deployment); err != nil {
		return mesh.ListenerStartRequest{}, err
	}
	req.Management = mesh.ListenerManagement(strings.TrimSpace(string(req.Management)))
	if err := validateMeshListenerManagement(req.Management); err != nil {
		return mesh.ListenerStartRequest{}, err
	}
	return req, nil
}

func validateMeshListenerDeployment(deployment mesh.ListenerDeployment) error {
	switch deployment {
	case "", mesh.ListenerDeploymentEmbedded, mesh.ListenerDeploymentSeparate:
		return nil
	default:
		return fmt.Errorf("mesh listener deployment %q is unsupported", deployment)
	}
}

func validateMeshListenerManagement(management mesh.ListenerManagement) error {
	switch management {
	case "", mesh.ListenerManagementProvider, mesh.ListenerManagementExternal:
		return nil
	default:
		return fmt.Errorf("mesh listener management %q is unsupported", management)
	}
}

func (s RunService) RunMeshTask(
	ctx context.Context,
	moduleID string,
	req mesh.TaskRequest,
) (mesh.TaskResult, error) {
	return s.RunMeshTaskWithCredentialSelections(ctx, moduleID, req, nil, domainpki.CredentialOperationScope{})
}

func (s RunService) RunMeshTaskWithCredentialSelections(
	ctx context.Context,
	moduleID string,
	req mesh.TaskRequest,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
) (mesh.TaskResult, error) {
	req = req.Clone()
	if err := req.Validate(); err != nil {
		return mesh.TaskResult{}, err
	}
	runner, err := s.meshTaskRunner()
	if err != nil {
		return mesh.TaskResult{}, err
	}
	var result mesh.TaskResult
	if len(selections) == 0 {
		result, err = runner.RunMeshTask(ctx, moduleID, req)
	} else {
		credentialRunner, ok := s.runner.(CredentialMeshTaskRunner)
		if !ok {
			return mesh.TaskResult{}, errors.New("credential-aware mesh runner is not configured")
		}
		scope.RunID = req.RunID
		scope.Target = meshCredentialTarget(req.Target, req.DestinationHost, req.NodeID)
		scope.ListenerID = req.ListenerID
		scope.NodeID = req.NodeID
		resolvedModuleID, resolution, resolveErr := s.resolveMeshCredentials(
			ctx, moduleID, selections, scope, req.ListenerID, req.NodeID,
		)
		if resolveErr != nil {
			return mesh.TaskResult{}, resolveErr
		}
		defer resolution.Close()
		execution, executeErr := credentialRunner.RunMeshTaskWithCredentials(
			ctx, resolvedModuleID, resolution, req,
		)
		if executeErr != nil {
			return mesh.TaskResult{}, executeErr
		}
		result = execution.Result
	}
	if err != nil {
		return mesh.TaskResult{}, err
	}
	result = result.Clone()
	result.Status = mesh.TaskStatus(strings.TrimSpace(string(result.Status)))
	if err := result.Validate(); err != nil {
		return mesh.TaskResult{}, fmt.Errorf("validate mesh task result: %w", err)
	}
	return result, nil
}

func (s RunService) OpenMeshStream(
	ctx context.Context,
	moduleID string,
	req mesh.StreamRequest,
) (run.SessionRef, error) {
	return s.OpenMeshStreamWithCredentialSelections(ctx, moduleID, req, nil, domainpki.CredentialOperationScope{})
}

func (s RunService) OpenMeshStreamWithCredentialSelections(
	ctx context.Context,
	moduleID string,
	req mesh.StreamRequest,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
) (run.SessionRef, error) {
	req = req.Clone()
	if err := req.Validate(); err != nil {
		return run.SessionRef{}, err
	}
	runner, err := s.meshStreamRunner()
	if err != nil {
		return run.SessionRef{}, err
	}
	var session run.SessionRef
	if len(selections) == 0 {
		session, err = runner.OpenMeshStream(ctx, moduleID, req)
	} else {
		credentialRunner, ok := s.runner.(CredentialMeshStreamRunner)
		if !ok {
			return run.SessionRef{}, errors.New("credential-aware mesh runner is not configured")
		}
		scope.RunID = req.RunID
		scope.Target = meshCredentialTarget(req.Target, req.DestinationHost, req.NodeID)
		scope.ListenerID = req.ListenerID
		scope.NodeID = req.NodeID
		resolvedModuleID, resolution, resolveErr := s.resolveMeshCredentials(
			ctx, moduleID, selections, scope, req.ListenerID, req.NodeID,
		)
		if resolveErr != nil {
			return run.SessionRef{}, resolveErr
		}
		defer resolution.Close()
		execution, executeErr := credentialRunner.OpenMeshStreamWithCredentials(
			ctx, resolvedModuleID, resolution, req,
		)
		if executeErr != nil {
			return run.SessionRef{}, executeErr
		}
		session = execution.Session
	}
	if err != nil {
		return run.SessionRef{}, err
	}
	session.ID = strings.TrimSpace(session.ID)
	if session.ID == "" {
		return run.SessionRef{}, errors.New("mesh stream session id is required")
	}
	session.Capabilities = append([]string(nil), session.Capabilities...)
	return session, nil
}

func (s RunService) resolveMeshCredentials(
	ctx context.Context,
	moduleID string,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
	listenerID string,
	nodeID string,
) (string, *CredentialOperationResolution, error) {
	if s.credentialResolver == nil {
		return "", nil, errors.New("credential operation resolver is not configured")
	}
	inspector, ok := s.runner.(ModuleInspector)
	if !ok {
		return "", nil, errors.New("module inspector is not configured")
	}
	module, err := inspector.Inspect(ctx, moduleID)
	if err != nil {
		return "", nil, err
	}
	if module.CredentialDelivery == nil {
		return "", nil, errors.New("mesh provider does not advertise credential delivery")
	}
	providerName := modulecatalog.ReferenceName(module.ID)
	providerID, err := domainpki.NewDeliveryProviderID(providerName)
	if err != nil {
		return "", nil, err
	}
	digest, err := module.CredentialDelivery.DigestSHA256()
	if err != nil {
		return "", nil, err
	}
	provider := domainpki.CredentialProviderTarget{
		ModuleID:         module.ID,
		ProviderID:       providerID,
		ProviderVersion:  module.Version,
		DescriptorSHA256: digest,
	}
	consumers, err := meshCredentialConsumers(providerName, listenerID, nodeID)
	if err != nil {
		return "", nil, err
	}
	resolution, err := s.credentialResolver.ResolveCredentialOperation(
		ctx, provider, module.CredentialDelivery.Clone(), selections.Clone(), scope, consumers,
	)
	if err != nil {
		return "", nil, err
	}
	if resolution == nil {
		return "", nil, errors.New("credential operation resolver returned no resolution")
	}
	if err := resolution.Revalidate(ctx); err != nil {
		resolution.Close()
		return "", nil, fmt.Errorf("revalidate credential operation: %w", err)
	}
	deliveries, err := resolution.BorrowedDeliveries()
	if err != nil {
		resolution.Close()
		return "", nil, fmt.Errorf("borrow credential operation deliveries: %w", err)
	}
	if len(deliveries) != len(selections) {
		resolution.Close()
		return "", nil, fmt.Errorf(
			"credential operation resolver returned %d deliveries for %d selections",
			len(deliveries),
			len(selections),
		)
	}
	if err := deliveries.ValidateForModule(module.ID); err != nil {
		resolution.Close()
		return "", nil, fmt.Errorf("validate credential operation deliveries: %w", err)
	}
	return module.ID, resolution, nil
}

func meshCredentialTarget(target, destinationHost, nodeID string) string {
	for _, candidate := range []string{target, destinationHost, nodeID} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return ""
}

func meshCredentialConsumers(
	providerName string,
	listenerID string,
	nodeID string,
) ([]domainpki.CredentialConsumerBinding, error) {
	provider, err := domainpki.NewMeshProviderConsumer(providerName)
	if err != nil {
		return nil, err
	}
	consumers := []domainpki.CredentialConsumerBinding{provider}
	if listenerID != "" {
		listener, listenerErr := domainpki.NewMeshListenerConsumer(providerName, listenerID)
		if listenerErr != nil {
			return nil, listenerErr
		}
		consumers = append(consumers, listener)
	}
	if nodeID != "" {
		node, nodeErr := domainpki.NewMeshNodeConsumer(providerName, nodeID)
		if nodeErr != nil {
			return nil, nodeErr
		}
		consumers = append(consumers, node)
	}
	return consumers, nil
}

func (s RunService) meshDescriber() (MeshDescriber, error) {
	runner, ok := s.runner.(MeshDescriber)
	if !ok {
		return nil, errors.New("mesh description is not configured")
	}
	return runner, nil
}

func (s RunService) meshTopologyReader() (MeshTopologyReader, error) {
	runner, ok := s.runner.(MeshTopologyReader)
	if !ok {
		return nil, errors.New("mesh topology is not configured")
	}
	return runner, nil
}

func (s RunService) meshBeaconLister() (MeshBeaconLister, error) {
	runner, ok := s.runner.(MeshBeaconLister)
	if !ok {
		return nil, errors.New("mesh beacon listing is not configured")
	}
	return runner, nil
}

func (s RunService) meshTaskRunner() (MeshTaskRunner, error) {
	runner, ok := s.runner.(MeshTaskRunner)
	if !ok {
		return nil, errors.New("mesh task runner is not configured")
	}
	return runner, nil
}

func (s RunService) meshStreamRunner() (MeshStreamRunner, error) {
	runner, ok := s.runner.(MeshStreamRunner)
	if !ok {
		return nil, errors.New("mesh stream runner is not configured")
	}
	return runner, nil
}

func (s RunService) meshListenerLister() (MeshListenerLister, error) {
	runner, ok := s.runner.(MeshListenerLister)
	if !ok {
		return nil, errors.New("mesh listener listing is not configured")
	}
	return runner, nil
}

func (s RunService) meshListenerLifecycleRunner() (MeshListenerLifecycleRunner, error) {
	runner, ok := s.runner.(MeshListenerLifecycleRunner)
	if !ok {
		return nil, errors.New("mesh listener lifecycle is not configured")
	}
	return runner, nil
}

func (s RunService) ListPayloadCommands(ctx context.Context, req PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	runner, ok := s.runner.(PayloadCommandRunner)
	if !ok {
		return nil, errors.New("payload command runner is not configured")
	}
	return runner.ListPayloadCommands(ctx, req.ModuleID, req.Request)
}

func (s RunService) RunPayloadCommand(ctx context.Context, req PayloadCommandRunRequest) (run.PayloadCommandResult, error) {
	runner, ok := s.runner.(PayloadCommandRunner)
	if !ok {
		return run.PayloadCommandResult{}, errors.New("payload command runner is not configured")
	}
	result, err := runner.RunPayloadCommand(ctx, req.ModuleID, req.Request)
	if err != nil {
		return run.PayloadCommandResult{}, err
	}
	if s.events != nil {
		logServiceError("append payload command event", s.appendPayloadCommandEvent(ctx, req, result))
	}
	return result, nil
}

func (s RunService) ExecuteModule(ctx context.Context, req ExecuteModuleRequest) (run.Result, error) {
	runID := s.ids.NewID()
	request, err := run.NewRequest(run.RequestArgs{
		ID:           runID,
		Operation:    req.Operation,
		Chain:        req.Chain,
		ModuleID:     req.ModuleID,
		Target:       req.Target,
		Inputs:       req.Inputs,
		ChainConfig:  req.ChainConfig,
		TargetConfig: req.TargetConfig,
	})
	if err != nil {
		return run.Result{}, err
	}
	startFields := map[string]string{}
	if !req.ThrowStarted.IsZero() {
		startFields["throwStarted"] = req.ThrowStarted.Format(time.RFC3339Nano)
	}
	if err := s.appendRunEvent(ctx, "hovel.run.started", "run started", request, startFields); err != nil {
		return run.Result{}, err
	}
	result, err := s.runner.Run(ctx, request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return run.Result{}, ctxErr
		}
		var moduleFailure ModuleExecutionFailure
		if !errors.As(err, &moduleFailure) {
			return run.Result{}, err
		}
		result, err = failedModuleResult(s.clock, request, moduleFailure)
		if err != nil {
			return run.Result{}, err
		}
	}
	eventType := "hovel.run.completed"
	message := "run completed"
	if result.State == run.StateFailed {
		eventType = "hovel.run.failed"
		message = "run failed"
	}
	if err := s.appendRunEvent(ctx, eventType, message, request, map[string]string{
		"summary": result.Summary,
	}); err != nil {
		return run.Result{}, err
	}
	return result, nil
}

func failedModuleResult(clock Clock, request run.Request, failure ModuleExecutionFailure) (run.Result, error) {
	summary := failure.ModuleFailureSummary()
	detail := failure.ModuleFailureDetail()
	return run.Failed(request, run.ResultArgs{
		Summary: summary,
		Logs: []run.LogEntry{{
			Kind:     "event",
			Time:     clock.Now().Format(time.RFC3339Nano),
			Level:    "error",
			Source:   "host",
			Message:  "module execution failed",
			RunID:    request.ID,
			Target:   request.Target,
			ModuleID: request.ModuleID,
			Fields:   map[string]string{"error": detail},
		}},
	})
}

func (s RunService) appendRunEvent(ctx context.Context, typ, message string, request run.Request, fields map[string]string) error {
	id, err := event.NewID(s.ids.NewID())
	if err != nil {
		return err
	}
	eventType, err := event.NewType(typ)
	if err != nil {
		return err
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Message:   message,
		Timestamp: s.clock.Now(),
		Refs: event.Refs{
			Operation: request.Operation,
			Chain:     request.Chain,
			RunID:     request.ID,
			ModuleID:  request.ModuleID,
			TargetID:  request.Target,
		},
		Fields: fields,
	})
	if err != nil {
		return err
	}
	return s.events.Append(ctx, evt)
}

func (s RunService) appendPayloadCommandEvent(ctx context.Context, req PayloadCommandRunRequest, result run.PayloadCommandResult) error {
	if s.ids == nil || s.clock == nil {
		return nil
	}
	id, err := event.NewID(s.ids.NewID())
	if err != nil {
		return err
	}
	eventType, err := event.NewType("hovel.payload.command.completed")
	if err != nil {
		return err
	}
	fields := map[string]string{
		"payload": req.Request.InstalledPayloadID,
		"command": req.Request.Command,
		"summary": result.Summary,
	}
	for key, value := range result.Fields {
		fields[key] = value
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Message:   "payload command completed",
		Timestamp: s.clock.Now(),
		Refs: event.Refs{
			Operation: req.Operation,
			Chain:     req.Chain,
			ModuleID:  req.ModuleID,
			TargetID:  req.Request.Target,
		},
		Fields: fields,
	})
	if err != nil {
		return err
	}
	return s.events.Append(ctx, evt)
}
