package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

type MeshRunner interface {
	DescribeMesh(context.Context, string, mesh.DescribeRequest) (mesh.Descriptor, error)
	MeshTopology(context.Context, string, mesh.TopologyRequest) (mesh.Topology, error)
	ListMeshBeacons(context.Context, string, mesh.BeaconRequest) ([]mesh.Beacon, error)
	RunMeshTask(context.Context, string, mesh.TaskRequest) (mesh.TaskResult, error)
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
		domainpki.CredentialOperationDeliveries,
		mesh.ListenerStartRequest,
	) (MeshListenerExecution, error)
}

// CredentialMeshTaskRunner executes credential hooks and a Mesh task in the
// same provider process.
type CredentialMeshTaskRunner interface {
	RunMeshTaskWithCredentials(
		context.Context,
		string,
		domainpki.CredentialOperationDeliveries,
		mesh.TaskRequest,
	) (MeshTaskExecution, error)
}

// CredentialMeshStreamRunner executes credential hooks and stream open in the
// same provider process.
type CredentialMeshStreamRunner interface {
	OpenMeshStreamWithCredentials(
		context.Context,
		string,
		domainpki.CredentialOperationDeliveries,
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

// CredentialOperationResolver turns non-secret selections into ephemeral
// provider deliveries and returns their mandatory cleanup function.
type CredentialOperationResolver interface {
	ResolveCredentialOperation(
		context.Context,
		domainpki.CredentialProviderTarget,
		domainpki.CredentialDeliveryDescriptor,
		domainpki.CredentialSelections,
		domainpki.CredentialOperationScope,
		[]domainpki.CredentialConsumerBinding,
	) (domainpki.CredentialOperationDeliveries, func(), error)
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
	runner, err := s.meshRunner()
	if err != nil {
		return mesh.Descriptor{}, err
	}
	return runner.DescribeMesh(ctx, moduleID, req)
}

func (s RunService) MeshTopology(
	ctx context.Context,
	moduleID string,
	req mesh.TopologyRequest,
) (mesh.Topology, error) {
	runner, err := s.meshRunner()
	if err != nil {
		return mesh.Topology{}, err
	}
	return runner.MeshTopology(ctx, moduleID, req)
}

func (s RunService) ListMeshBeacons(
	ctx context.Context,
	moduleID string,
	req mesh.BeaconRequest,
) ([]mesh.Beacon, error) {
	runner, err := s.meshRunner()
	if err != nil {
		return nil, err
	}
	return runner.ListMeshBeacons(ctx, moduleID, req)
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
		resolvedModuleID, deliveries, cleanup, resolveErr := s.resolveMeshCredentials(
			ctx, moduleID, selections, scope, req.ListenerID, "",
		)
		if resolveErr != nil {
			return mesh.Listener{}, resolveErr
		}
		defer cleanup()
		execution, executeErr := credentialRunner.StartMeshListenerWithCredentials(
			ctx, resolvedModuleID, deliveries, req,
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
	listener.Addresses = append([]string(nil), listener.Addresses...)
	listener.Protocols = append([]string(nil), listener.Protocols...)
	listener.Capabilities = append([]string(nil), listener.Capabilities...)
	listener.Labels = cloneMeshAnyMap(listener.Labels)
	listener.Attributes = cloneMeshAnyMap(listener.Attributes)
	return listener, nil
}

func normalizeMeshListenerStartRequest(req mesh.ListenerStartRequest) (mesh.ListenerStartRequest, error) {
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
	req.Config = cloneMeshAnyMap(req.Config)
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

func cloneMeshAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = cloneMeshAnyValue(value)
	}
	return out
}

func cloneMeshAnyValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneMeshAnyMap(value)
	case []any:
		out := make([]any, len(value))
		for index, item := range value {
			out[index] = cloneMeshAnyValue(item)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(value))
		for key, item := range value {
			out[key] = item
		}
		return out
	case []string:
		return append([]string(nil), value...)
	default:
		return value
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
	runner, err := s.meshRunner()
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
		scope.Target = req.Target
		scope.ListenerID = req.ListenerID
		scope.NodeID = req.NodeID
		resolvedModuleID, deliveries, cleanup, resolveErr := s.resolveMeshCredentials(
			ctx, moduleID, selections, scope, req.ListenerID, req.NodeID,
		)
		if resolveErr != nil {
			return mesh.TaskResult{}, resolveErr
		}
		defer cleanup()
		execution, executeErr := credentialRunner.RunMeshTaskWithCredentials(
			ctx, resolvedModuleID, deliveries, req,
		)
		if executeErr != nil {
			return mesh.TaskResult{}, executeErr
		}
		result = execution.Result
	}
	if err != nil {
		return mesh.TaskResult{}, err
	}
	result.Status = mesh.TaskStatus(strings.TrimSpace(string(result.Status)))
	if result.Status == "" {
		result.Status = mesh.TaskStatusSucceeded
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
	runner, err := s.meshRunner()
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
		scope.ListenerID = req.ListenerID
		scope.NodeID = req.NodeID
		resolvedModuleID, deliveries, cleanup, resolveErr := s.resolveMeshCredentials(
			ctx, moduleID, selections, scope, req.ListenerID, req.NodeID,
		)
		if resolveErr != nil {
			return run.SessionRef{}, resolveErr
		}
		defer cleanup()
		execution, executeErr := credentialRunner.OpenMeshStreamWithCredentials(
			ctx, resolvedModuleID, deliveries, req,
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
	return session, nil
}

func (s RunService) resolveMeshCredentials(
	ctx context.Context,
	moduleID string,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
	listenerID string,
	nodeID string,
) (string, domainpki.CredentialOperationDeliveries, func(), error) {
	if s.credentialResolver == nil {
		return "", nil, func() {}, errors.New("credential operation resolver is not configured")
	}
	inspector, ok := s.runner.(ModuleInspector)
	if !ok {
		return "", nil, func() {}, errors.New("module inspector is not configured")
	}
	module, err := inspector.Inspect(ctx, moduleID)
	if err != nil {
		return "", nil, func() {}, err
	}
	if module.CredentialDelivery == nil {
		return "", nil, func() {}, errors.New("mesh provider does not advertise credential delivery")
	}
	providerName := modulecatalog.ReferenceName(module.ID)
	providerID, err := domainpki.NewDeliveryProviderID(providerName)
	if err != nil {
		return "", nil, func() {}, err
	}
	digest, err := module.CredentialDelivery.DigestSHA256()
	if err != nil {
		return "", nil, func() {}, err
	}
	provider := domainpki.CredentialProviderTarget{
		ModuleID:         module.ID,
		ProviderID:       providerID,
		ProviderVersion:  module.Version,
		DescriptorSHA256: digest,
	}
	consumers, err := meshCredentialConsumers(providerName, listenerID, nodeID)
	if err != nil {
		return "", nil, func() {}, err
	}
	deliveries, cleanup, err := s.credentialResolver.ResolveCredentialOperation(
		ctx, provider, module.CredentialDelivery.Clone(), selections.Clone(), scope, consumers,
	)
	if err != nil {
		return "", nil, func() {}, err
	}
	if cleanup == nil {
		deliveries.Clear()
		return "", nil, func() {}, errors.New("credential operation resolver returned no cleanup")
	}
	return module.ID, deliveries, cleanup, nil
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

func (s RunService) meshRunner() (MeshRunner, error) {
	runner, ok := s.runner.(MeshRunner)
	if !ok {
		return nil, errors.New("mesh runner is not configured")
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
