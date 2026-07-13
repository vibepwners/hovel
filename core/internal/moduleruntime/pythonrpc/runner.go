package pythonrpc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibepwners/hovel/internal/app/hovelconfig"
	"github.com/vibepwners/hovel/internal/app/modulecatalog"
	"github.com/vibepwners/hovel/internal/app/modulepackage"
	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/domain/event"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
	workspacepath "github.com/vibepwners/hovel/internal/domain/workspace"
	"github.com/vibepwners/hovel/internal/protocol/framing"
)

const (
	defaultTimeout             = 60 * time.Second
	moduleShutdownTimeout      = 5 * time.Second
	stderrSettleTimeout        = 50 * time.Millisecond
	maxFrameBytes              = framing.DefaultMaxBytes
	maxCapturedStderrBytes     = 64 * 1024
	maxModuleNotificationBytes = 256 * 1024
	maxBufferedModuleLogs      = 256
	stderrTruncationMarker     = "[... stderr truncated ...]\n"

	rpcShutdownMethod    = "shutdown"
	rpcSessionReadMethod = "session/read"

	sessionPumpReadTimeoutMilliseconds = 250

	meshRPCDescribeMethod      = "mesh.describe"
	meshRPCTopologyMethod      = "mesh.topology"
	meshRPCBeaconsMethod       = "mesh.beacons"
	meshRPCListenersMethod     = "mesh.listeners"
	meshRPCListenerStartMethod = "mesh.listener.start"
	meshRPCListenerStopMethod  = "mesh.listener.stop"
	meshRPCTaskMethod          = "mesh.task"
	meshRPCOpenStreamMethod    = "mesh.open_stream"

	credentialRPCRuntimeMethod  = "credential.runtime"
	credentialRPCFilesMethod    = "credential.files"
	credentialRPCEncodeMethod   = "credential.encode"
	credentialRPCStampMethod    = "credential.stamp"
	credentialRPCDescribeMethod = "credential.describe"

	meshProviderLabel       = "mesh"
	credentialProviderLabel = "credential"

	credentialExecutionIdempotencyPrefix  = "pythonrpc:credential-execution:v1:"
	credentialExecutionPlanPhase          = "plan"
	credentialExecutionSucceededPhase     = "succeeded"
	credentialExecutionFailedPhase        = "failed"
	credentialExecutionBookkeepingTimeout = 5 * time.Second

	credentialRuntimeFailureReason  = "credential runtime delivery failed"
	credentialFilesFailureReason    = "credential file delivery failed"
	credentialEncodingFailureReason = "credential encoding failed"
	credentialOperationAbortReason  = "credential operation delivery aborted"

	ModuleConfigEnv = "HOVEL_MODULE_CONFIG"
)

var errCredentialProviderDiagnosticsSuppressed = errors.New(
	"credential-bearing provider diagnostics suppressed",
)

var errCredentialExecutionRecorderRequired = errors.New(
	"python rpc: credential execution recorder is required",
)

var errCredentialOperationResolutionRequired = errors.New(
	"python rpc: credential operation resolution is required",
)

func logPythonRPCError(action string, err error) {
	if err != nil {
		log.Printf("python rpc: %s: %v", action, err)
	}
}

type ModuleConfig struct {
	Modules []ModuleEntry `json:"modules"`
}

type ModuleEntry struct {
	ID         string   `json:"id"`
	Runtime    string   `json:"runtime"`
	ProjectDir string   `json:"project_dir"`
	Module     string   `json:"module"`
	Command    []string `json:"command"`
}

type CatalogInfo struct {
	ConfigPath string
	Modules    []modulecatalog.Module
}

// usesCommand reports whether the entry launches an arbitrary executable
// (any language that speaks the stdio JSON-RPC protocol) rather than the
// built-in Python interpreter path.
func (e ModuleEntry) usesCommand() bool {
	return len(e.Command) > 0
}

type Runner struct {
	PythonPath           string
	SDKRoot              string
	ConfigPath           string
	HovelConfig          string
	WorkspacePath        string
	Events               services.EventSink
	IDs                  services.IDGenerator
	Clock                services.Clock
	Timeout              time.Duration
	Sessions             *SessionBroker
	StepProcesses        *StepProcessBroker
	CredentialExecutions CredentialExecutionRecorder
}

type CredentialExecutionRecorder interface {
	// RecordCredentialExecutionPlan claims a request before provider launch.
	// Implementations return ErrCredentialExecutionInProgress for an identical
	// pending request, a terminal execution for an identical completed request,
	// and an idempotency conflict when the request identity changed.
	RecordCredentialExecutionPlan(
		context.Context,
		string,
		domainpki.CredentialExecution,
	) (domainpki.CredentialExecution, error)
	RecordCredentialExecutionTransition(
		context.Context,
		string,
		domainpki.CredentialExecution,
	) (domainpki.CredentialExecution, error)
}

type StepCallRequest struct {
	ModuleID string
	Params   map[string]any
}

type MeshListenerExecution = services.MeshListenerExecution

type MeshTaskExecution = services.MeshTaskExecution

type MeshStreamExecution = services.MeshStreamExecution

func ConfiguredCatalog(ctx context.Context) (modulecatalog.Catalog, error) {
	return Runner{}.Catalog(ctx)
}

func ConfiguredCatalogInfo(ctx context.Context) (CatalogInfo, error) {
	return CatalogInfoForConfig(ctx, "")
}

func CatalogInfoForConfig(ctx context.Context, configPath string) (CatalogInfo, error) {
	runner := Runner{ConfigPath: configPath}
	path, pathErr := resolveConfigPath(runner.configPath())
	info := CatalogInfo{ConfigPath: path}
	if pathErr != nil {
		return info, pathErr
	}
	catalog, err := runner.Catalog(ctx)
	if err != nil {
		return info, err
	}
	info.Modules = catalog.List()
	return info, nil
}

func MustConfiguredCatalog() modulecatalog.Catalog {
	return MustConfiguredCatalogWithWarning(os.Stderr)
}

// MustConfiguredCatalogWithWarning loads the configured module catalog, falling
// back to an empty catalog if loading fails. Unlike a silent fallback, the
// underlying error is reported to warn so operators can tell "no modules
// configured" apart from "module configuration failed to load".
func MustConfiguredCatalogWithWarning(warn io.Writer) modulecatalog.Catalog {
	catalog, err := ConfiguredCatalog(context.Background())
	if err != nil {
		if warn != nil {
			if _, writeErr := fmt.Fprintf(warn, "hovel: failed to load module catalog: %v\n", err); writeErr != nil {
				log.Printf("hovel pythonrpc: write catalog warning: %v", writeErr)
			}
		}
		return modulecatalog.New()
	}
	return catalog
}

func (r Runner) Catalog(ctx context.Context) (modulecatalog.Catalog, error) {
	entries, err := r.moduleEntries()
	if err != nil {
		return modulecatalog.Catalog{}, err
	}
	modules := make([]modulecatalog.Module, 0, len(entries))
	for _, entry := range entries {
		module, err := r.Inspect(ctx, entry.ID)
		if err != nil {
			return modulecatalog.Catalog{}, err
		}
		modules = append(modules, module)
	}
	return modulecatalog.New(modules...), nil
}

func (r Runner) Inspect(ctx context.Context, moduleID string) (modulecatalog.Module, error) {
	return r.inspect(ctx, func(ctx context.Context) (*moduleProcess, error) {
		return r.start(ctx, moduleID)
	})
}

func (r Runner) InspectEntry(ctx context.Context, entry ModuleEntry) (modulecatalog.Module, error) {
	entry.ID = strings.TrimSpace(entry.ID)
	return r.inspect(ctx, func(ctx context.Context) (*moduleProcess, error) {
		return r.startEntry(ctx, entry)
	})
}

func (r Runner) inspect(ctx context.Context, start func(context.Context) (*moduleProcess, error)) (modulecatalog.Module, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	process, err := start(ctx)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	defer process.killAndWait()

	info, err := process.client.call(ctx, "handshake", nil)
	if err != nil {
		return modulecatalog.Module{}, moduleFailure("module failed during startup", "module handshake failed", err, process.stderrString())
	}
	schema, err := process.client.call(ctx, "schema", nil)
	if err != nil {
		return modulecatalog.Module{}, moduleFailure("module failed while reporting schema", "module schema failed", err, process.stderrString())
	}
	module, err := moduleFromRPC(info, schema)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	stepContracts, err := process.client.call(ctx, "step.describe", nil)
	if err != nil {
		if isMissingStepProvider(err) {
			stepContracts = map[string]any{"steps": []any{}}
		} else {
			return modulecatalog.Module{}, moduleFailure("module failed while reporting step contracts", "module step describe failed", err, process.stderrString())
		}
	}
	module.StepContracts, err = stepContractsFromRPC(stepContracts)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	if issues := modulecatalog.ValidateStepContracts(module); len(issues) > 0 {
		return modulecatalog.Module{}, fmt.Errorf("step contract invalid: %s", formatStepContractIssue(issues[0]))
	}
	meshDescriptor, err := process.client.call(ctx, meshRPCDescribeMethod, nil)
	if err != nil {
		if isMissingMeshProvider(err) {
			meshDescriptor = nil
		} else {
			return modulecatalog.Module{}, moduleFailure(
				"module failed while reporting mesh",
				"module mesh describe failed",
				err,
				process.stderrString(),
			)
		}
	}
	if meshDescriptor != nil {
		module.Mesh, err = meshDescriptorFromRPC(meshDescriptor)
		if err != nil {
			return modulecatalog.Module{}, err
		}
	}
	credentialDescriptor, err := credentialDeliveryDescriptorForProcess(ctx, process, true)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	module.CredentialDelivery = credentialDescriptor
	if err := reconcileCredentialDeliveryDescriptors(&module); err != nil {
		return modulecatalog.Module{}, err
	}
	shutdownErr, waitErr := process.shutdownAndWait(ctx, moduleShutdownTimeout)
	logPythonRPCError("shut down module after catalog load", shutdownErr)
	if waitErr != nil {
		return modulecatalog.Module{}, moduleFailure("module exited with error", "module exited with error", waitErr, process.stderrString())
	}
	return module, nil
}

func isMissingStepProvider(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "unknown method step.describe") ||
		strings.Contains(message, `unknown method "step.describe"`) ||
		strings.Contains(message, "unknown method 'step.describe'") ||
		strings.Contains(message, "not a step provider")
}

func isMissingMeshProvider(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "unknown method "+meshRPCDescribeMethod) ||
		strings.Contains(message, `unknown method "`+meshRPCDescribeMethod+`"`) ||
		strings.Contains(message, "unknown method '"+meshRPCDescribeMethod+"'") ||
		strings.Contains(message, "not a mesh provider")
}

func isMissingCredentialDescriber(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "unknown method "+credentialRPCDescribeMethod) ||
		strings.Contains(message, `unknown method "`+credentialRPCDescribeMethod+`"`) ||
		strings.Contains(message, "unknown method '"+credentialRPCDescribeMethod+"'") ||
		strings.Contains(message, "not a credential provider")
}

func credentialDeliveryDescriptorForProcess(
	ctx context.Context,
	process *moduleProcess,
	optional bool,
) (*domainpki.CredentialDeliveryDescriptor, error) {
	raw, err := process.client.callRaw(ctx, credentialRPCDescribeMethod, nil)
	if err != nil {
		if optional && isMissingCredentialDescriber(err) {
			return nil, nil
		}
		return nil, moduleFailure(
			"module failed while reporting credential delivery",
			"module credential describe failed",
			err,
			process.stderrString(),
		)
	}
	descriptor, err := credentialDeliveryDescriptorFromRawRPC(raw)
	if err != nil {
		return nil, err
	}
	return &descriptor, nil
}

func (r Runner) PrepareStep(ctx context.Context, request StepCallRequest) (map[string]any, error) {
	return r.callStep(ctx, request, "step.prepare", "module failed while preparing step", "module step prepare failed")
}

func (r Runner) ExecuteStep(ctx context.Context, request StepCallRequest) (map[string]any, error) {
	return r.callStep(ctx, request, "step.execute", "module failed while executing step", "module step execute failed")
}

func (r Runner) CleanupStep(ctx context.Context, request StepCallRequest) (map[string]any, error) {
	return r.callStep(ctx, request, "step.cleanup", "module failed while cleaning up step", "module step cleanup failed")
}

func (r Runner) ListPayloadCommands(ctx context.Context, moduleID string, request run.PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	result, err := r.callPayloadCommand(ctx, moduleID, "payload.command.list", request)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Commands []run.PayloadCommand `json:"commands"`
	}
	if err := decodeRPCMap(result, &decoded); err != nil {
		return nil, services.NewModuleExecutionFailure("module returned invalid payload command list", err)
	}
	return decoded.Commands, nil
}

func (r Runner) ListPayloads(ctx context.Context, moduleID string, query run.PayloadQuery) ([]run.PayloadInfo, error) {
	result, err := r.callPayloadProvider(ctx, moduleID, "list_payloads", query)
	if err != nil {
		return nil, err
	}
	var decoded []run.PayloadInfo
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, services.NewModuleExecutionFailure("module returned invalid payload list", err)
	}
	return decoded, nil
}

func (r Runner) GeneratePayload(ctx context.Context, moduleID string, request run.GeneratePayloadRequest) (run.PayloadArtifactSet, error) {
	result, err := r.callPayloadProvider(ctx, moduleID, "generate_payload", request)
	if err != nil {
		return run.PayloadArtifactSet{}, err
	}
	var decoded run.PayloadArtifactSet
	if err := json.Unmarshal(result, &decoded); err != nil {
		return run.PayloadArtifactSet{}, services.NewModuleExecutionFailure("module returned invalid payload artifact set", err)
	}
	return decoded, nil
}

func (r Runner) RunPayloadCommand(ctx context.Context, moduleID string, request run.PayloadCommandRequest) (run.PayloadCommandResult, error) {
	result, err := r.callPayloadCommand(ctx, moduleID, "payload.command.run", request)
	if err != nil {
		return run.PayloadCommandResult{}, err
	}
	var decoded run.PayloadCommandResult
	if err := decodeRPCMap(result, &decoded); err != nil {
		return run.PayloadCommandResult{}, services.NewModuleExecutionFailure("module returned invalid payload command result", err)
	}
	return decoded, nil
}

func (r Runner) DescribeMesh(
	ctx context.Context,
	moduleID string,
	request mesh.DescribeRequest,
) (mesh.Descriptor, error) {
	result, err := r.callMeshProvider(ctx, moduleID, meshRPCDescribeMethod, request)
	if err != nil {
		return mesh.Descriptor{}, err
	}
	var decoded mesh.Descriptor
	if err := json.Unmarshal(result, &decoded); err != nil {
		return mesh.Descriptor{}, services.NewModuleExecutionFailure("module returned invalid mesh descriptor", err)
	}
	return decoded, nil
}

func (r Runner) MeshTopology(
	ctx context.Context,
	moduleID string,
	request mesh.TopologyRequest,
) (mesh.Topology, error) {
	result, err := r.callMeshProvider(ctx, moduleID, meshRPCTopologyMethod, request)
	if err != nil {
		return mesh.Topology{}, err
	}
	var decoded mesh.Topology
	if err := json.Unmarshal(result, &decoded); err != nil {
		return mesh.Topology{}, services.NewModuleExecutionFailure("module returned invalid mesh topology", err)
	}
	return decoded, nil
}

func (r Runner) ListMeshBeacons(
	ctx context.Context,
	moduleID string,
	request mesh.BeaconRequest,
) ([]mesh.Beacon, error) {
	result, err := r.callMeshProvider(ctx, moduleID, meshRPCBeaconsMethod, request)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Beacons []mesh.Beacon `json:"beacons"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, services.NewModuleExecutionFailure("module returned invalid mesh beacons", err)
	}
	return decoded.Beacons, nil
}

func (r Runner) ListMeshListeners(
	ctx context.Context,
	moduleID string,
	request mesh.ListenerListRequest,
) ([]mesh.Listener, error) {
	result, err := r.callMeshProvider(ctx, moduleID, meshRPCListenersMethod, request)
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Listeners []mesh.Listener `json:"listeners"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil, services.NewModuleExecutionFailure("module returned invalid mesh listeners", err)
	}
	return decoded.Listeners, nil
}

func (r Runner) StartMeshListener(
	ctx context.Context,
	moduleID string,
	request mesh.ListenerStartRequest,
) (mesh.Listener, error) {
	execution, err := r.callMeshListenerWithCredentials(ctx, moduleID, nil, request)
	return execution.Listener, err
}

func (r Runner) StartMeshListenerWithCredentials(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
	request mesh.ListenerStartRequest,
) (MeshListenerExecution, error) {
	if resolution == nil {
		return MeshListenerExecution{}, errCredentialOperationResolutionRequired
	}
	return r.callMeshListenerWithCredentials(ctx, moduleID, resolution, request)
}

func (r Runner) StopMeshListener(
	ctx context.Context,
	moduleID string,
	request mesh.ListenerStopRequest,
) (mesh.Listener, error) {
	return r.callMeshListener(ctx, moduleID, meshRPCListenerStopMethod, request)
}

func (r Runner) callMeshListener(
	ctx context.Context,
	moduleID string,
	method string,
	request any,
) (mesh.Listener, error) {
	result, err := r.callMeshProvider(ctx, moduleID, method, request)
	if err != nil {
		return mesh.Listener{}, err
	}
	var listener mesh.Listener
	decodeErr := json.Unmarshal(result, &listener)
	clearBytes(result)
	if decodeErr != nil {
		return mesh.Listener{}, services.NewModuleExecutionFailure("module returned invalid mesh listener", decodeErr)
	}
	return listener, nil
}

func (r Runner) callMeshListenerWithCredentials(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
	request mesh.ListenerStartRequest,
) (MeshListenerExecution, error) {
	execution := MeshListenerExecution{}
	operationCtx, cancel, process, receipts, err := r.startCredentialOperation(
		ctx, moduleID, resolution,
	)
	execution.CredentialReceipts = receipts
	if err != nil {
		return execution, err
	}
	defer cancel()
	defer process.killAndWait()

	result, err := process.client.callRaw(operationCtx, meshRPCListenerStartMethod, request)
	if err != nil {
		return execution, moduleFailure(
			"module failed while starting mesh listener",
			"module mesh listener start failed",
			err,
			process.stderrString(),
		)
	}
	decodeErr := json.Unmarshal(result, &execution.Listener)
	clearBytes(result)
	if decodeErr != nil {
		failed := MeshListenerExecution{CredentialReceipts: execution.CredentialReceipts}
		return failed, process.resultFailure("module returned invalid mesh listener", decodeErr)
	}
	shutdownErr, waitErr := process.shutdownAndWait(operationCtx, moduleShutdownTimeout)
	logPythonRPCError("shut down module after mesh listener start", shutdownErr)
	if waitErr != nil {
		return execution, moduleFailure(
			"module exited with error", "module exited with error", waitErr, process.stderrString(),
		)
	}
	return execution, nil
}

func (r Runner) RunMeshTask(
	ctx context.Context,
	moduleID string,
	request mesh.TaskRequest,
) (mesh.TaskResult, error) {
	execution, err := r.callMeshTask(ctx, moduleID, nil, request)
	if err != nil {
		return mesh.TaskResult{}, err
	}
	return execution.Result, nil
}

func (r Runner) RunMeshTaskWithCredentials(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
	request mesh.TaskRequest,
) (MeshTaskExecution, error) {
	if resolution == nil {
		return MeshTaskExecution{}, errCredentialOperationResolutionRequired
	}
	return r.callMeshTask(ctx, moduleID, resolution, request)
}

func (r Runner) OpenMeshStream(
	ctx context.Context,
	moduleID string,
	request mesh.StreamRequest,
) (run.SessionRef, error) {
	execution, err := r.callMeshStream(ctx, moduleID, nil, request)
	return execution.Session, err
}

func (r Runner) OpenMeshStreamWithCredentials(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
	request mesh.StreamRequest,
) (MeshStreamExecution, error) {
	if resolution == nil {
		return MeshStreamExecution{}, errCredentialOperationResolutionRequired
	}
	return r.callMeshStream(ctx, moduleID, resolution, request)
}

func (r Runner) LoadRuntimeCredential(
	ctx context.Context,
	moduleID string,
	request domainpki.CredentialRuntimeRequest,
) (domainpki.CredentialDeliveryReceipt, error) {
	if err := request.Validate(); err != nil {
		return domainpki.CredentialDeliveryReceipt{}, err
	}
	if err := validateCredentialProviderModule(moduleID, request.Provider); err != nil {
		return domainpki.CredentialDeliveryReceipt{}, err
	}
	pending, err := r.beginCredentialExecution(
		ctx,
		func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewRuntimeCredentialExecution(request, now)
		},
	)
	if err != nil {
		return domainpki.CredentialDeliveryReceipt{}, err
	}
	if pending != nil && pending.Status != domainpki.CredentialExecutionPending {
		return credentialDeliveryReplay(*pending)
	}
	receipt, deliveryErr := r.deliverCredential(
		ctx,
		moduleID,
		credentialRPCRuntimeMethod,
		request.RequestID,
		request.Provider,
		request,
	)
	bookkeepingErr := r.finishCredentialDeliveryExecution(
		ctx, pending, receipt, deliveryErr, credentialRuntimeFailureReason,
	)
	return receipt, errors.Join(deliveryErr, bookkeepingErr)
}

func (r Runner) LoadCredentialFiles(
	ctx context.Context,
	moduleID string,
	request domainpki.CredentialFilesRequest,
) (domainpki.CredentialDeliveryReceipt, error) {
	if err := request.Validate(); err != nil {
		return domainpki.CredentialDeliveryReceipt{}, err
	}
	if err := validateCredentialProviderModule(moduleID, request.Provider); err != nil {
		return domainpki.CredentialDeliveryReceipt{}, err
	}
	pending, err := r.beginCredentialExecution(
		ctx,
		func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewFilesCredentialExecution(request, now)
		},
	)
	if err != nil {
		return domainpki.CredentialDeliveryReceipt{}, err
	}
	if pending != nil && pending.Status != domainpki.CredentialExecutionPending {
		return credentialDeliveryReplay(*pending)
	}
	receipt, deliveryErr := r.deliverCredential(
		ctx,
		moduleID,
		credentialRPCFilesMethod,
		request.RequestID,
		request.Provider,
		request,
	)
	bookkeepingErr := r.finishCredentialDeliveryExecution(
		ctx, pending, receipt, deliveryErr, credentialFilesFailureReason,
	)
	return receipt, errors.Join(deliveryErr, bookkeepingErr)
}

func (r Runner) deliverCredential(
	ctx context.Context,
	moduleID string,
	method string,
	requestID domainpki.CredentialExecutionRequestID,
	provider domainpki.CredentialProviderTarget,
	request any,
) (domainpki.CredentialDeliveryReceipt, error) {
	result, err := r.callCredentialProvider(ctx, moduleID, provider, method, request)
	if err != nil {
		return domainpki.CredentialDeliveryReceipt{}, err
	}
	defer clearBytes(result)
	return credentialDeliveryReceiptFromRPC(result, requestID)
}

func credentialDeliveryReceiptFromRPC(
	result json.RawMessage,
	requestID domainpki.CredentialExecutionRequestID,
) (domainpki.CredentialDeliveryReceipt, error) {
	var receipt domainpki.CredentialDeliveryReceipt
	if err := json.Unmarshal(result, &receipt); err != nil {
		return domainpki.CredentialDeliveryReceipt{}, credentialProviderResultFailure(
			"module returned invalid credential delivery receipt",
		)
	}
	if receipt.RequestID != requestID {
		return domainpki.CredentialDeliveryReceipt{}, credentialProviderResultFailure(
			"module returned mismatched credential delivery receipt",
		)
	}
	return receipt, nil
}

func (r Runner) EncodeCredentialMaterial(
	ctx context.Context,
	moduleID string,
	request domainpki.CredentialEncodingRequest,
) (domainpki.CredentialEncodingResult, error) {
	if err := request.Validate(); err != nil {
		return domainpki.CredentialEncodingResult{}, err
	}
	if err := validateCredentialProviderModule(moduleID, request.Provider); err != nil {
		return domainpki.CredentialEncodingResult{}, err
	}
	pending, err := r.beginCredentialExecution(
		ctx,
		func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewEncodingCredentialExecution(request, now)
		},
	)
	if err != nil {
		return domainpki.CredentialEncodingResult{}, err
	}
	if pending != nil && pending.Status != domainpki.CredentialExecutionPending {
		return domainpki.CredentialEncodingResult{}, credentialEncodingReplayError(*pending)
	}
	result, err := r.callCredentialProvider(
		ctx,
		moduleID,
		request.Provider,
		credentialRPCEncodeMethod,
		request,
	)
	if err != nil {
		bookkeepingErr := r.finishCredentialEncodingExecution(
			ctx, pending, domainpki.CredentialEncodingResult{}, err,
		)
		return domainpki.CredentialEncodingResult{}, errors.Join(err, bookkeepingErr)
	}
	defer clearBytes(result)
	var decoded domainpki.CredentialEncodingResult
	defer clearCredentialEncodingResult(&decoded)
	if err := json.Unmarshal(result, &decoded); err != nil {
		resultErr := credentialProviderResultFailure(
			"module returned invalid credential encoding result",
		)
		bookkeepingErr := r.finishCredentialEncodingExecution(
			ctx, pending, domainpki.CredentialEncodingResult{}, resultErr,
		)
		return domainpki.CredentialEncodingResult{}, errors.Join(resultErr, bookkeepingErr)
	}
	if err := decoded.ValidateFor(request); err != nil {
		resultErr := credentialProviderResultFailure(
			"module returned mismatched credential encoding result",
		)
		bookkeepingErr := r.finishCredentialEncodingExecution(ctx, pending, decoded, resultErr)
		return domainpki.CredentialEncodingResult{}, errors.Join(resultErr, bookkeepingErr)
	}
	bookkeepingErr := r.finishCredentialEncodingExecution(ctx, pending, decoded, nil)
	return decoded.Clone(), bookkeepingErr
}

type credentialExecutionConstructor func(time.Time) (domainpki.CredentialExecution, error)

func (r Runner) beginCredentialExecution(
	ctx context.Context,
	construct credentialExecutionConstructor,
) (*domainpki.CredentialExecution, error) {
	if r.CredentialExecutions == nil {
		return nil, errCredentialExecutionRecorderRequired
	}
	if r.Clock == nil {
		return nil, errors.New("python rpc: credential execution recorder requires a clock")
	}
	execution, err := construct(r.Clock.Now())
	if err != nil {
		return nil, err
	}
	recorded, err := r.CredentialExecutions.RecordCredentialExecutionPlan(
		ctx,
		credentialExecutionIdempotencyKey(execution.ID, credentialExecutionPlanPhase),
		execution,
	)
	if err != nil {
		return nil, fmt.Errorf("record credential execution plan: %w", err)
	}
	return pointerToCredentialExecution(recorded), nil
}

func pointerToCredentialExecution(
	execution domainpki.CredentialExecution,
) *domainpki.CredentialExecution {
	value := execution.Clone()
	return &value
}

func credentialDeliveryReplay(
	execution domainpki.CredentialExecution,
) (domainpki.CredentialDeliveryReceipt, error) {
	if execution.Status == domainpki.CredentialExecutionFailed {
		return domainpki.CredentialDeliveryReceipt{}, fmt.Errorf(
			"credential execution %q previously failed: %s", execution.ID, execution.Failure,
		)
	}
	if execution.Status != domainpki.CredentialExecutionSucceeded ||
		execution.Result == nil || execution.Result.Output != nil {
		return domainpki.CredentialDeliveryReceipt{}, errors.New(
			"python rpc: credential execution replay is not a completed delivery",
		)
	}
	receipt := domainpki.CredentialDeliveryReceipt{
		RequestID:     execution.ID,
		ReceiptSHA256: execution.Result.ReceiptSHA256,
	}
	if err := receipt.Validate(); err != nil {
		return domainpki.CredentialDeliveryReceipt{}, fmt.Errorf(
			"python rpc: validate credential delivery replay: %w", err,
		)
	}
	return receipt, nil
}

func credentialEncodingReplayError(execution domainpki.CredentialExecution) error {
	if execution.Status == domainpki.CredentialExecutionFailed {
		return fmt.Errorf(
			"credential execution %q previously failed: %s", execution.ID, execution.Failure,
		)
	}
	return fmt.Errorf(
		"credential execution %q already completed; encoded credential bytes are not persisted and cannot be replayed",
		execution.ID,
	)
}

func (r Runner) finishCredentialDeliveryExecution(
	ctx context.Context,
	pending *domainpki.CredentialExecution,
	receipt domainpki.CredentialDeliveryReceipt,
	executionErr error,
	failureReason string,
) error {
	if pending == nil {
		return nil
	}
	if executionErr != nil {
		return r.failCredentialExecution(ctx, *pending, failureReason)
	}
	completed, err := domainpki.CompleteCredentialDeliveryExecution(
		*pending, receipt, r.Clock.Now(),
	)
	if err != nil {
		return fmt.Errorf("complete credential delivery bookkeeping: %w", err)
	}
	return r.recordCredentialExecutionTransition(ctx, completed)
}

func (r Runner) finishCredentialEncodingExecution(
	ctx context.Context,
	pending *domainpki.CredentialExecution,
	result domainpki.CredentialEncodingResult,
	executionErr error,
) error {
	if pending == nil {
		return nil
	}
	if executionErr != nil {
		return r.failCredentialExecution(ctx, *pending, credentialEncodingFailureReason)
	}
	completed, err := domainpki.CompleteCredentialEncodingExecution(
		*pending, result, r.Clock.Now(),
	)
	if err != nil {
		return fmt.Errorf("complete credential encoding bookkeeping: %w", err)
	}
	return r.recordCredentialExecutionTransition(ctx, completed)
}

func (r Runner) failCredentialExecution(
	ctx context.Context,
	pending domainpki.CredentialExecution,
	failureReason string,
) error {
	failed, err := domainpki.FailCredentialExecution(pending, failureReason, r.Clock.Now())
	if err != nil {
		return fmt.Errorf("fail credential execution bookkeeping: %w", err)
	}
	return r.recordCredentialExecutionTransition(ctx, failed)
}

func (r Runner) recordCredentialExecutionTransition(
	ctx context.Context,
	execution domainpki.CredentialExecution,
) error {
	phase := credentialExecutionSucceededPhase
	if execution.Status == domainpki.CredentialExecutionFailed {
		phase = credentialExecutionFailedPhase
	}
	bookkeepingCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), credentialExecutionBookkeepingTimeout,
	)
	defer cancel()
	_, err := r.CredentialExecutions.RecordCredentialExecutionTransition(
		bookkeepingCtx, credentialExecutionIdempotencyKey(execution.ID, phase), execution,
	)
	if err != nil {
		return fmt.Errorf("record credential execution transition: %w", err)
	}
	return nil
}

func credentialExecutionIdempotencyKey(
	id domainpki.CredentialExecutionRequestID,
	phase string,
) string {
	digest := sha256.Sum256([]byte(string(id) + "\x00" + phase))
	return credentialExecutionIdempotencyPrefix + hex.EncodeToString(digest[:])
}

func (r Runner) StampCredential(
	ctx context.Context,
	moduleID string,
	request domainpki.CredentialStampExecutionRequest,
) (domainpki.CredentialStampExecutionResult, error) {
	if err := request.Validate(); err != nil {
		return domainpki.CredentialStampExecutionResult{}, err
	}
	if err := validateCredentialProviderModule(moduleID, request.Provider); err != nil {
		return domainpki.CredentialStampExecutionResult{}, err
	}
	result, err := r.callCredentialProvider(
		ctx,
		moduleID,
		request.Provider,
		credentialRPCStampMethod,
		request,
	)
	if err != nil {
		return domainpki.CredentialStampExecutionResult{}, err
	}
	defer clearBytes(result)
	var decoded domainpki.CredentialStampExecutionResult
	defer clearCredentialStampExecutionResult(&decoded)
	if err := json.Unmarshal(result, &decoded); err != nil {
		return domainpki.CredentialStampExecutionResult{}, credentialProviderResultFailure(
			"module returned invalid credential stamp result",
		)
	}
	if err := decoded.ValidateFor(request); err != nil {
		return domainpki.CredentialStampExecutionResult{}, credentialProviderResultFailure(
			"module returned mismatched credential stamp result",
		)
	}
	return decoded.Clone(), nil
}

func (r Runner) callPayloadCommand(ctx context.Context, moduleID, method string, params any) (map[string]any, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	process, err := r.start(ctx, moduleID)
	if err != nil {
		return nil, err
	}
	defer process.killAndWait()
	result, err := process.client.call(ctx, method, params)
	if err != nil {
		return nil, moduleFailure("module failed during payload command", "module payload command failed", err, process.stderrString())
	}
	shutdownErr, waitErr := process.shutdownAndWait(ctx, moduleShutdownTimeout)
	logPythonRPCError("shut down module after payload command", shutdownErr)
	if waitErr != nil {
		return nil, moduleFailure("module exited with error", "module exited with error", waitErr, process.stderrString())
	}
	return result, nil
}

func validateCredentialProviderModule(
	moduleID string,
	provider domainpki.CredentialProviderTarget,
) error {
	if moduleID != provider.ModuleID {
		return fmt.Errorf(
			"credential provider module %q does not match descriptor-bound module %q",
			moduleID, provider.ModuleID,
		)
	}
	return nil
}

func (r Runner) callMeshProvider(ctx context.Context, moduleID, method string, params any) (json.RawMessage, error) {
	return r.callProvider(ctx, moduleID, providerCall{
		method: method,
		params: params,
		label:  meshProviderLabel,
	})
}

func (r Runner) callCredentialProvider(
	ctx context.Context,
	moduleID string,
	provider domainpki.CredentialProviderTarget,
	method string,
	params any,
) (json.RawMessage, error) {
	return r.callProvider(ctx, moduleID, providerCall{
		method:           method,
		params:           params,
		label:            credentialProviderLabel,
		credentialTarget: &provider,
	})
}

type providerCall struct {
	method           string
	params           any
	label            string
	credentialTarget *domainpki.CredentialProviderTarget
}

func (r Runner) callProvider(
	ctx context.Context,
	moduleID string,
	call providerCall,
) (json.RawMessage, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	process, err := r.start(ctx, moduleID)
	if err != nil {
		return nil, err
	}
	defer process.killAndWait()
	if call.credentialTarget != nil {
		if err := reconcileCredentialProviderTarget(ctx, process, *call.credentialTarget); err != nil {
			return nil, err
		}
		process.markCredentialBearing()
	}
	result, err := process.client.callRaw(ctx, call.method, call.params)
	if err != nil {
		return nil, moduleFailure(
			"module failed during "+call.label+" provider call",
			"module "+call.label+" provider call failed",
			err,
			process.stderrString(),
		)
	}
	shutdownErr, waitErr := process.shutdownAndWait(ctx, moduleShutdownTimeout)
	logPythonRPCError("shut down module after "+call.label+" provider call", shutdownErr)
	if waitErr != nil {
		clearBytes(result)
		return nil, moduleFailure("module exited with error", "module exited with error", waitErr, process.stderrString())
	}
	return result, nil
}

func reconcileCredentialProviderTarget(
	ctx context.Context,
	process *moduleProcess,
	expected domainpki.CredentialProviderTarget,
) error {
	actual, err := credentialProviderTargetForProcess(ctx, process)
	if err != nil {
		return err
	}
	return validateCredentialProviderTarget(expected, actual)
}

func validateCredentialProviderTarget(
	expected domainpki.CredentialProviderTarget,
	actual domainpki.CredentialProviderTarget,
) error {
	if actual != expected {
		return errors.New("credential provider target does not match the running provider")
	}
	return nil
}

func (r Runner) startCredentialOperation(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
) (
	context.Context,
	context.CancelFunc,
	*moduleProcess,
	[]domainpki.CredentialDeliveryReceipt,
	error,
) {
	pending, err := r.prepareCredentialOperationResolution(ctx, moduleID, resolution)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	process, err := r.start(context.Background(), moduleID)
	if err != nil {
		cancel()
		bookkeepingErr := r.failPendingCredentialExecutions(
			ctx, pending, 0, credentialOperationAbortReason,
		)
		return nil, nil, nil, nil, errors.Join(err, bookkeepingErr)
	}
	if resolution != nil {
		target, targetErr := credentialProviderTargetForProcess(operationCtx, process)
		if targetErr == nil {
			targetErr = validateCredentialOperationExecutionTargets(pending, target)
		}
		if targetErr != nil {
			return nil, nil, nil, nil, r.abortCredentialOperation(
				ctx, cancel, process, pending, targetErr,
			)
		}
		receipts, deliveryErr := r.deliverCredentialsToProcess(
			operationCtx,
			ctx,
			process,
			moduleID,
			resolution,
			pending,
		)
		if deliveryErr != nil {
			cancel()
			process.killAndWait()
			return nil, nil, nil, receipts, deliveryErr
		}
		return operationCtx, cancel, process, receipts, nil
	}
	return operationCtx, cancel, process, nil, nil
}

func (r Runner) prepareCredentialOperationResolution(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
) ([]*domainpki.CredentialExecution, error) {
	if resolution == nil {
		return nil, nil
	}
	deliveries, err := resolution.BorrowedDeliveries()
	if err != nil {
		return nil, fmt.Errorf("borrow credential operation deliveries: %w", err)
	}
	if len(deliveries) == 0 {
		return nil, errors.New("python rpc: credential operation resolution returned no deliveries")
	}
	if err := deliveries.ValidateForModule(moduleID); err != nil {
		return nil, fmt.Errorf("validate credential operation deliveries: %w", err)
	}
	return r.prepareCredentialOperationExecutions(ctx, deliveries)
}

func (r Runner) abortCredentialOperation(
	ctx context.Context,
	cancel context.CancelFunc,
	process *moduleProcess,
	pending []*domainpki.CredentialExecution,
	cause error,
) error {
	cancel()
	process.killAndWait()
	bookkeepingErr := r.failPendingCredentialExecutions(
		ctx, pending, 0, credentialOperationAbortReason,
	)
	return errors.Join(cause, bookkeepingErr)
}

func credentialProviderTargetForProcess(
	ctx context.Context,
	process *moduleProcess,
) (domainpki.CredentialProviderTarget, error) {
	handshake, err := process.client.callRaw(ctx, "handshake", nil)
	if err != nil {
		return domainpki.CredentialProviderTarget{}, moduleFailure(
			"module failed during credential operation startup",
			"module handshake failed",
			err,
			process.stderrString(),
		)
	}
	module, err := credentialProviderModuleFromRawHandshake(handshake)
	if err != nil {
		return domainpki.CredentialProviderTarget{}, services.NewModuleExecutionFailure(
			"module returned invalid credential operation handshake",
			err,
		)
	}
	credentialDescriptor, err := credentialDeliveryDescriptorForProcess(ctx, process, false)
	if err != nil {
		return domainpki.CredentialProviderTarget{}, err
	}
	module.CredentialDelivery = credentialDescriptor

	meshDescriptor, err := process.client.callRaw(ctx, meshRPCDescribeMethod, nil)
	if err != nil {
		return domainpki.CredentialProviderTarget{}, moduleFailure(
			"module failed while reconciling credential delivery",
			"module mesh describe failed",
			err,
			process.stderrString(),
		)
	}
	if err := json.Unmarshal(meshDescriptor, &module.Mesh); err != nil {
		return domainpki.CredentialProviderTarget{}, services.NewModuleExecutionFailure(
			"module returned invalid mesh descriptor during credential operation",
			err,
		)
	}
	if err := reconcileCredentialDeliveryDescriptors(&module); err != nil {
		return domainpki.CredentialProviderTarget{}, services.NewModuleExecutionFailure(
			"module returned inconsistent credential delivery descriptors",
			err,
		)
	}
	if module.CredentialDelivery == nil {
		return domainpki.CredentialProviderTarget{}, services.NewModuleExecutionFailure(
			"module omitted credential delivery descriptor",
			errors.New("credential delivery descriptor is required"),
		)
	}
	digest, err := module.CredentialDelivery.DigestSHA256()
	if err != nil {
		return domainpki.CredentialProviderTarget{}, services.NewModuleExecutionFailure(
			"module returned invalid credential delivery descriptor",
			err,
		)
	}
	providerID, err := domainpki.NewDeliveryProviderID(modulecatalog.ReferenceName(module.ID))
	if err != nil {
		return domainpki.CredentialProviderTarget{}, services.NewModuleExecutionFailure(
			"module returned invalid credential provider identity",
			err,
		)
	}
	target := domainpki.CredentialProviderTarget{
		ModuleID:         module.ID,
		ProviderID:       providerID,
		ProviderVersion:  module.Version,
		DescriptorSHA256: digest,
	}
	if err := target.Validate(); err != nil {
		return domainpki.CredentialProviderTarget{}, services.NewModuleExecutionFailure(
			"module returned invalid credential provider target",
			err,
		)
	}
	return target, nil
}

func credentialProviderModuleFromRawHandshake(raw json.RawMessage) (modulecatalog.Module, error) {
	var info map[string]any
	if err := json.Unmarshal(raw, &info); err != nil {
		return modulecatalog.Module{}, fmt.Errorf("decode module handshake: %w", err)
	}
	if info == nil {
		return modulecatalog.Module{}, errors.New("module handshake must be an object")
	}
	for _, field := range []string{"name", "version", "moduleType"} {
		if _, ok := info[field].(string); !ok {
			return modulecatalog.Module{}, fmt.Errorf("module handshake %s must be a string", field)
		}
	}
	return moduleFromRPC(info, map[string]any{
		"chainConfig":  []any{},
		"targetConfig": []any{},
	})
}

func validateCredentialOperationExecutionTargets(
	pending []*domainpki.CredentialExecution,
	target domainpki.CredentialProviderTarget,
) error {
	for index, execution := range pending {
		if execution == nil {
			return fmt.Errorf("credential operation execution %d is missing", index+1)
		}
		if err := validateCredentialProviderTarget(execution.Plan.Provider, target); err != nil {
			return fmt.Errorf(
				"credential operation execution %d: %w",
				index+1,
				err,
			)
		}
	}
	return nil
}

func validateCredentialOperationDeliveryPlans(
	moduleID string,
	deliveries domainpki.CredentialOperationDeliveries,
	pending []*domainpki.CredentialExecution,
) error {
	if err := deliveries.ValidateForModule(moduleID); err != nil {
		return fmt.Errorf("validate re-borrowed credential operation deliveries: %w", err)
	}
	if len(deliveries) != len(pending) {
		return errors.New("python rpc: re-borrowed credential deliveries do not match execution plans")
	}
	for index, delivery := range deliveries {
		if pending[index] == nil {
			return fmt.Errorf("credential operation execution %d is missing", index+1)
		}
		construct, err := credentialExecutionConstructorForDelivery(delivery)
		if err != nil {
			return err
		}
		execution, err := construct(pending[index].CreatedAt)
		if err != nil {
			return fmt.Errorf("validate re-borrowed credential delivery %d: %w", index+1, err)
		}
		if execution.ID != pending[index].ID ||
			!reflect.DeepEqual(execution.Plan, pending[index].Plan) {
			return fmt.Errorf(
				"credential operation delivery %d does not match its persisted execution plan",
				index+1,
			)
		}
	}
	return nil
}

func (r Runner) prepareCredentialOperationExecutions(
	ctx context.Context,
	deliveries domainpki.CredentialOperationDeliveries,
) ([]*domainpki.CredentialExecution, error) {
	pending := make([]*domainpki.CredentialExecution, 0, len(deliveries))
	for _, delivery := range deliveries {
		construct, err := credentialExecutionConstructorForDelivery(delivery)
		if err != nil {
			bookkeepingErr := r.failPendingCredentialExecutions(
				ctx, pending, 0, credentialOperationAbortReason,
			)
			return nil, errors.Join(err, bookkeepingErr)
		}
		execution, err := r.beginCredentialExecution(ctx, construct)
		if err != nil {
			bookkeepingErr := r.failPendingCredentialExecutions(
				ctx, pending, 0, credentialOperationAbortReason,
			)
			return nil, errors.Join(err, bookkeepingErr)
		}
		if execution != nil && execution.Status != domainpki.CredentialExecutionPending {
			bookkeepingErr := r.failPendingCredentialExecutions(
				ctx, pending, 0, credentialOperationAbortReason,
			)
			return nil, errors.Join(fmt.Errorf(
				"credential execution %q already completed and cannot be reused for a new provider process",
				execution.ID,
			), bookkeepingErr)
		}
		pending = append(pending, execution)
	}
	return pending, nil
}

func credentialExecutionConstructorForDelivery(
	delivery domainpki.CredentialOperationDelivery,
) (credentialExecutionConstructor, error) {
	switch delivery.Capability {
	case domainpki.DeliveryCapabilityRuntime:
		return func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewRuntimeCredentialExecution(*delivery.Runtime, now)
		}, nil
	case domainpki.DeliveryCapabilityFiles:
		return func(now time.Time) (domainpki.CredentialExecution, error) {
			return domainpki.NewFilesCredentialExecution(*delivery.Files, now)
		}, nil
	default:
		return nil, fmt.Errorf(
			"unsupported credential operation delivery capability %q",
			delivery.Capability,
		)
	}
}

func (r Runner) deliverCredentialsToProcess(
	ctx context.Context,
	bookkeepingCtx context.Context,
	process *moduleProcess,
	moduleID string,
	resolution *services.CredentialOperationResolution,
	pending []*domainpki.CredentialExecution,
) ([]domainpki.CredentialDeliveryReceipt, error) {
	if resolution == nil {
		return nil, errors.New("python rpc: credential operation resolution is required")
	}
	receipts := make([]domainpki.CredentialDeliveryReceipt, 0, len(pending))
	for index := range pending {
		if err := resolution.Revalidate(ctx); err != nil {
			revalidationErr := fmt.Errorf("revalidate credential operation: %w", err)
			bookkeepingErr := r.failPendingCredentialExecutions(
				bookkeepingCtx,
				pending,
				index,
				credentialOperationAbortReason,
			)
			return receipts, errors.Join(revalidationErr, bookkeepingErr)
		}
		deliveries, err := resolution.BorrowedDeliveries()
		if err != nil {
			borrowErr := fmt.Errorf("borrow credential operation deliveries: %w", err)
			bookkeepingErr := r.failPendingCredentialExecutions(
				bookkeepingCtx,
				pending,
				index,
				credentialOperationAbortReason,
			)
			return receipts, errors.Join(borrowErr, bookkeepingErr)
		}
		if err := validateCredentialOperationDeliveryPlans(
			moduleID,
			deliveries,
			pending,
		); err != nil {
			bookkeepingErr := r.failPendingCredentialExecutions(
				bookkeepingCtx,
				pending,
				index,
				credentialOperationAbortReason,
			)
			return receipts, errors.Join(err, bookkeepingErr)
		}
		delivery := deliveries[index]
		var method string
		var request any
		var failureReason string
		switch delivery.Capability {
		case domainpki.DeliveryCapabilityRuntime:
			method = credentialRPCRuntimeMethod
			request = delivery.Runtime
			failureReason = credentialRuntimeFailureReason
		case domainpki.DeliveryCapabilityFiles:
			method = credentialRPCFilesMethod
			request = delivery.Files
			failureReason = credentialFilesFailureReason
		default:
			return receipts, fmt.Errorf(
				"unsupported credential operation delivery capability %q",
				delivery.Capability,
			)
		}
		process.markCredentialBearing()
		result, err := process.client.callRaw(ctx, method, request)
		if err != nil {
			deliveryErr := moduleFailure(
				"module failed while loading operation credentials",
				"module credential operation delivery failed",
				err,
				process.stderrString(),
			)
			bookkeepingErr := r.finishCredentialDeliveryExecution(
				ctx, pending[index], domainpki.CredentialDeliveryReceipt{}, deliveryErr, failureReason,
			)
			abortErr := r.failPendingCredentialExecutions(
				ctx, pending, index+1, credentialOperationAbortReason,
			)
			return receipts, errors.Join(deliveryErr, bookkeepingErr, abortErr)
		}
		receipt, receiptErr := credentialDeliveryReceiptFromRPC(result, delivery.RequestID())
		clearBytes(result)
		if receiptErr != nil {
			bookkeepingErr := r.finishCredentialDeliveryExecution(
				ctx, pending[index], domainpki.CredentialDeliveryReceipt{}, receiptErr, failureReason,
			)
			abortErr := r.failPendingCredentialExecutions(
				ctx, pending, index+1, credentialOperationAbortReason,
			)
			return receipts, errors.Join(receiptErr, bookkeepingErr, abortErr)
		}
		if err := r.finishCredentialDeliveryExecution(
			ctx, pending[index], receipt, nil, failureReason,
		); err != nil {
			abortErr := r.failPendingCredentialExecutions(
				ctx, pending, index+1, credentialOperationAbortReason,
			)
			return receipts, errors.Join(err, abortErr)
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

func (r Runner) failPendingCredentialExecutions(
	ctx context.Context,
	pending []*domainpki.CredentialExecution,
	start int,
	failureReason string,
) error {
	var result error
	for index := start; index < len(pending); index++ {
		if pending[index] == nil {
			continue
		}
		result = errors.Join(result, r.failCredentialExecution(ctx, *pending[index], failureReason))
	}
	return result
}

func (r Runner) callMeshTask(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
	request mesh.TaskRequest,
) (MeshTaskExecution, error) {
	execution := MeshTaskExecution{}
	operationCtx, cancel, process, receipts, err := r.startCredentialOperation(
		ctx, moduleID, resolution,
	)
	execution.CredentialReceipts = receipts
	if err != nil {
		return execution, err
	}
	defer cancel()
	keepProcess := false
	defer func() {
		if !keepProcess {
			process.killAndWait()
		}
	}()
	result, err := process.client.callRaw(operationCtx, meshRPCTaskMethod, request)
	if err != nil {
		return execution, moduleFailure(
			"module failed during mesh task",
			"module mesh task failed",
			err,
			process.stderrString(),
		)
	}
	decodeErr := json.Unmarshal(result, &execution.Result)
	clearBytes(result)
	if decodeErr != nil {
		failed := MeshTaskExecution{CredentialReceipts: execution.CredentialReceipts}
		return failed, process.resultFailure("module returned invalid mesh task result", decodeErr)
	}
	execution.Result.Sessions, err = normalizeSessionRefs(execution.Result.Sessions)
	if err != nil {
		failed := MeshTaskExecution{CredentialReceipts: execution.CredentialReceipts}
		return failed, process.resultFailure("module returned invalid mesh task sessions", err)
	}
	if len(execution.Result.Sessions) > 0 && r.Sessions != nil {
		if err := r.Sessions.adopt(process, execution.Result.Sessions); err != nil {
			failed := MeshTaskExecution{CredentialReceipts: execution.CredentialReceipts}
			return failed, process.resultFailure("module returned invalid mesh task sessions", err)
		}
		keepProcess = true
		return execution, nil
	}
	shutdownErr, waitErr := process.shutdownAndWait(operationCtx, moduleShutdownTimeout)
	logPythonRPCError("shut down module after mesh task", shutdownErr)
	if waitErr != nil {
		return execution, moduleFailure(
			"module exited with error",
			"module exited with error",
			waitErr,
			process.stderrString(),
		)
	}
	return execution, nil
}

func (r Runner) callMeshStream(
	ctx context.Context,
	moduleID string,
	resolution *services.CredentialOperationResolution,
	request mesh.StreamRequest,
) (MeshStreamExecution, error) {
	execution := MeshStreamExecution{}
	operationCtx, cancel, process, receipts, err := r.startCredentialOperation(
		ctx, moduleID, resolution,
	)
	execution.CredentialReceipts = receipts
	if err != nil {
		return execution, err
	}
	defer cancel()
	keepProcess := false
	defer func() {
		if !keepProcess {
			process.killAndWait()
		}
	}()
	result, err := process.client.callRaw(operationCtx, meshRPCOpenStreamMethod, request)
	if err != nil {
		return execution, moduleFailure(
			"module failed while opening mesh stream",
			"module mesh stream failed",
			err,
			process.stderrString(),
		)
	}
	decodeErr := json.Unmarshal(result, &execution.Session)
	clearBytes(result)
	if decodeErr != nil {
		failed := MeshStreamExecution{CredentialReceipts: execution.CredentialReceipts}
		return failed, process.resultFailure("module returned invalid mesh stream session", decodeErr)
	}
	execution.Session.ID = strings.TrimSpace(execution.Session.ID)
	if execution.Session.ID == "" {
		failed := MeshStreamExecution{CredentialReceipts: execution.CredentialReceipts}
		return failed, process.resultFailure(
			"module returned invalid mesh stream session",
			errors.New("session id is required"),
		)
	}
	if r.Sessions != nil {
		if err := r.Sessions.adopt(process, []run.SessionRef{execution.Session}); err != nil {
			failed := MeshStreamExecution{CredentialReceipts: execution.CredentialReceipts}
			return failed, process.resultFailure("module returned invalid mesh stream session", err)
		}
		keepProcess = true
		return execution, nil
	}
	shutdownErr, waitErr := process.shutdownAndWait(operationCtx, moduleShutdownTimeout)
	logPythonRPCError("shut down module after mesh stream", shutdownErr)
	if waitErr != nil {
		return execution, moduleFailure(
			"module exited with error",
			"module exited with error",
			waitErr,
			process.stderrString(),
		)
	}
	return execution, nil
}

func (r Runner) callPayloadProvider(ctx context.Context, moduleID, method string, params any) (json.RawMessage, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	process, err := r.start(ctx, moduleID)
	if err != nil {
		return nil, err
	}
	defer process.killAndWait()
	result, err := process.client.callRaw(ctx, method, params)
	if err != nil {
		return nil, moduleFailure("module failed during payload provider call", "module payload provider call failed", err, process.stderrString())
	}
	shutdownErr, waitErr := process.shutdownAndWait(ctx, moduleShutdownTimeout)
	logPythonRPCError("shut down module after payload provider call", shutdownErr)
	if waitErr != nil {
		return nil, moduleFailure("module exited with error", "module exited with error", waitErr, process.stderrString())
	}
	return result, nil
}

func decodeRPCMap(value map[string]any, out any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (r Runner) callStep(ctx context.Context, request StepCallRequest, method, summary, prefix string) (map[string]any, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var process *moduleProcess
	var err error
	owned := true
	runID := stepCallRunID(request.Params)
	if r.StepProcesses != nil && runID != "" {
		process, err = r.StepProcesses.process(ctx, r, runID, request.ModuleID)
		owned = false
	} else {
		process, err = r.start(ctx, request.ModuleID)
	}
	if err != nil {
		return nil, err
	}
	if owned {
		defer process.killAndWait()
	}

	result, err := process.client.call(ctx, method, request.Params)
	if err != nil {
		return nil, moduleFailure(summary, prefix, err, process.stderrString())
	}
	if method == "step.execute" {
		sessions, err := sessionsFromStepRPC(request, result["sessions"])
		if err != nil {
			return nil, services.NewModuleExecutionFailure("module returned invalid step result", err)
		}
		if len(sessions) > 0 && r.Sessions != nil {
			if err := r.Sessions.adopt(process, sessions); err != nil {
				return nil, services.NewModuleExecutionFailure("module returned invalid step sessions", err)
			}
			if r.StepProcesses != nil {
				r.StepProcesses.release(process)
			}
		}
	}
	if owned {
		shutdownErr, waitErr := process.shutdownAndWait(ctx, moduleShutdownTimeout)
		logPythonRPCError("shut down owned module process", shutdownErr)
		if waitErr != nil {
			return nil, moduleFailure("module exited with error", "module exited with error", waitErr, process.stderrString())
		}
	}
	return result, nil
}

func stepCallRunID(params map[string]any) string {
	if params == nil {
		return ""
	}
	if text := stringValue(params["runId"]); text != "" {
		return text
	}
	return stringValue(params["preparedPlanId"])
}

func formatStepContractIssue(issue modulecatalog.StepContractIssue) string {
	if issue.StepID == "" {
		return issue.Message
	}
	return issue.StepID + ": " + issue.Message
}

func (r Runner) Run(ctx context.Context, request run.Request) (run.Result, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	entry, ok, err := r.moduleEntry(request.ModuleID)
	if err != nil {
		return run.Result{}, err
	}
	if !ok {
		return run.Result{}, fmt.Errorf("unknown module %q", request.ModuleID)
	}
	request.ModuleID = entry.ID
	process, err := r.startEntry(context.Background(), entry)
	if err != nil {
		return run.Result{}, err
	}
	keepProcess := false
	defer func() {
		if !keepProcess {
			process.killAndWait()
		}
	}()
	process.client.setOnLog(func(log rpcLog) error {
		return r.appendLog(context.Background(), request, log)
	})

	info, err := process.client.call(ctx, "handshake", nil)
	if err != nil {
		return run.Result{}, moduleFailure("module failed during startup", "module handshake failed", err, process.stderrString())
	}
	schema, err := process.client.call(ctx, "schema", nil)
	if err != nil {
		return run.Result{}, moduleFailure("module failed while reporting schema", "module schema failed", err, process.stderrString())
	}
	module, err := moduleFromRPC(info, schema)
	if err != nil {
		return run.Result{}, moduleFailure("module failed while reporting metadata", "module metadata invalid", err, process.stderrString())
	}
	request.ModuleID = module.ID
	executeParams := map[string]any{
		"runId":        request.ID,
		"moduleId":     request.ModuleID,
		"target":       request.Target,
		"inputs":       request.Inputs,
		"chainConfig":  request.ChainConfig,
		"targetConfig": request.TargetConfig,
	}
	if request.Agent != nil {
		executeParams["agentContext"] = request.Agent
	}
	executeResult, err := process.client.call(ctx, "execute", executeParams)
	if err != nil {
		return run.Result{}, moduleFailure("module failed during execution", "module execute failed", err, process.stderrString())
	}
	result, err := resultFromRPC(request, executeResult, process.client.logsSnapshot())
	if err != nil {
		return run.Result{}, services.NewModuleExecutionFailure("module returned invalid result", err)
	}
	for _, session := range result.Sessions {
		if err := r.appendSessionCreated(context.Background(), request, session); err != nil {
			return run.Result{}, err
		}
	}
	if len(result.Sessions) > 0 && r.Sessions != nil {
		if err := r.Sessions.adopt(process, result.Sessions); err != nil {
			return run.Result{}, services.NewModuleExecutionFailure("module returned invalid sessions", err)
		}
		keepProcess = true
	} else {
		shutdownErr, waitErr := process.shutdownAndWait(ctx, moduleShutdownTimeout)
		logPythonRPCError("shut down module without sessions", shutdownErr)
		if waitErr != nil {
			return run.Result{}, moduleFailure("module exited with error", "module exited with error", waitErr, process.stderrString())
		}
	}
	return result, nil
}

type moduleProcess struct {
	cmd    *exec.Cmd
	client *rpcClient
	stderr *capturedStderr

	waitOnce sync.Once
	waitDone chan struct{}
	waitErr  error
}

func credentialProviderResultFailure(summary string) error {
	return services.NewModuleExecutionFailure(summary, errCredentialProviderDiagnosticsSuppressed)
}

func clearBytes(data []byte) {
	clear(data)
}

func clearCredentialEncodingResult(result *domainpki.CredentialEncodingResult) {
	if result == nil {
		return
	}
	clearBytes(result.Data)
	*result = domainpki.CredentialEncodingResult{}
}

func clearCredentialStampExecutionResult(result *domainpki.CredentialStampExecutionResult) {
	if result == nil {
		return
	}
	if result.Output.Artifact != nil {
		clearBytes(result.Output.Artifact.Data)
	}
	if result.Output.Deployment != nil {
		clearBytes(result.Output.Deployment.Receipt)
	}
	*result = domainpki.CredentialStampExecutionResult{}
}

func (p *moduleProcess) resultFailure(summary string, err error) error {
	if p != nil && p.client != nil && p.client.credentialBearing.Load() {
		err = errCredentialProviderDiagnosticsSuppressed
	}
	return services.NewModuleExecutionFailure(summary, err)
}

func (r Runner) start(ctx context.Context, moduleID string) (*moduleProcess, error) {
	entrypoint, ok, err := r.moduleEntry(moduleID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("unknown module %q", moduleID)
	}
	return r.startEntry(ctx, entrypoint)
}

func (r Runner) startEntry(ctx context.Context, entrypoint ModuleEntry) (*moduleProcess, error) {
	entrypoint.ID = strings.TrimSpace(entrypoint.ID)
	entrypoint.Runtime = strings.TrimSpace(entrypoint.Runtime)
	if entrypoint.Runtime == "" {
		entrypoint.Runtime = modulecatalog.RuntimeJSONRPCStdio
	}
	if entrypoint.Runtime != modulecatalog.RuntimeJSONRPCStdio {
		return nil, fmt.Errorf("module %q uses unsupported runtime %q", entrypoint.ID, entrypoint.Runtime)
	}
	if entrypoint.usesCommand() {
		entrypoint.Command[0] = strings.TrimSpace(entrypoint.Command[0])
		if entrypoint.Command[0] == "" {
			return nil, fmt.Errorf("module %q command[0] is required", entrypoint.ID)
		}
	} else if entrypoint.ProjectDir == "" || entrypoint.Module == "" {
		return nil, fmt.Errorf("module %q missing project_dir or module", entrypoint.ID)
	}
	cmd, err := r.command(ctx, entrypoint)
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := newCapturedStderr()
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &moduleProcess{
		cmd:      cmd,
		client:   newClient(stdout, stdin),
		stderr:   stderr,
		waitDone: make(chan struct{}),
	}, nil
}

// command builds the OS command that launches a module process. Entries with an
// explicit "command" run an arbitrary executable that speaks the stdio JSON-RPC
// protocol (Go, Rust, or any other language); entries without one use the
// built-in Python interpreter path (python -m <module>).
func (r Runner) command(ctx context.Context, entry ModuleEntry) (*exec.Cmd, error) {
	if entry.usesCommand() {
		cmd := exec.CommandContext(ctx, entry.Command[0], entry.Command[1:]...)
		cmd.Env = os.Environ()
		if entry.ProjectDir != "" {
			cmd.Dir = entry.ProjectDir
		}
		return cmd, nil
	}

	python, err := r.pythonPath()
	if err != nil {
		return nil, err
	}
	sdkRoot, err := r.sdkRoot()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, python, "-m", entry.Module)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+strings.Join([]string{sdkRoot, entry.ProjectDir}, string(os.PathListSeparator)))
	cmd.Dir = entry.ProjectDir
	return cmd, nil
}

func (p *moduleProcess) startWait() {
	p.waitOnce.Do(func() {
		go func() {
			p.waitErr = p.cmd.Wait()
			close(p.waitDone)
		}()
	})
}

func (p *moduleProcess) wait() error {
	p.startWait()
	<-p.waitDone
	return p.waitErr
}

func (p *moduleProcess) waitContext(ctx context.Context) error {
	p.startWait()
	select {
	case <-p.waitDone:
		return p.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *moduleProcess) kill() error {
	if p.cmd.Process != nil {
		if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	return nil
}

func (p *moduleProcess) shutdownAndWait(ctx context.Context, timeout time.Duration) (error, error) {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	_, shutdownErr := p.client.call(shutdownCtx, rpcShutdownMethod, nil)
	waitErr := p.waitContext(shutdownCtx)
	if waitErr == nil || shutdownCtx.Err() == nil {
		return shutdownErr, waitErr
	}

	killErr := p.kill()
	return shutdownErr, errors.Join(waitErr, killErr, p.wait())
}

func (p *moduleProcess) killAndWait() {
	logPythonRPCError("kill module process", p.kill())
	logPythonRPCError("wait for killed module process", p.wait())
}

func (p *moduleProcess) markCredentialBearing() {
	if p == nil || p.client == nil {
		return
	}
	if p.stderr != nil {
		p.stderr.clearAndDiscard()
	}
	p.client.markCredentialBearing()
}

func (p *moduleProcess) stderrString() string {
	if p == nil || p.stderr == nil {
		return ""
	}
	if p.client != nil && p.client.credentialBearing.Load() {
		return ""
	}
	return p.stderr.StringAfter(stderrSettleTimeout)
}

type capturedStderr struct {
	mu      sync.Mutex
	data    []byte
	trimmed bool
	discard bool
	updated chan struct{}
}

func newCapturedStderr() *capturedStderr {
	return &capturedStderr{updated: make(chan struct{}, 1)}
}

func (s *capturedStderr) Write(p []byte) (int, error) {
	retained := false
	s.mu.Lock()
	if !s.discard {
		s.appendTail(p)
		retained = len(p) > 0
	}
	s.mu.Unlock()
	if retained {
		select {
		case s.updated <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

func (s *capturedStderr) clearAndDiscard() {
	if s == nil {
		return
	}
	s.mu.Lock()
	clearBytes(s.data)
	s.data = nil
	s.trimmed = false
	s.discard = true
	s.mu.Unlock()
	select {
	case <-s.updated:
	default:
	}
}

func (s *capturedStderr) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.trimmed {
		return string(s.data)
	}
	return stderrTruncationMarker + string(s.data)
}

func (s *capturedStderr) appendTail(p []byte) {
	const maximumTailBytes = maxCapturedStderrBytes - len(stderrTruncationMarker)
	if len(p) == 0 {
		return
	}
	if len(p) >= maximumTailBytes {
		s.data = append(s.data[:0], p[len(p)-maximumTailBytes:]...)
		s.trimmed = true
		return
	}
	if overflow := len(s.data) + len(p) - maximumTailBytes; overflow > 0 {
		copy(s.data, s.data[overflow:])
		s.data = s.data[:len(s.data)-overflow]
		s.trimmed = true
	}
	s.data = append(s.data, p...)
}

func (s *capturedStderr) StringAfter(wait time.Duration) string {
	if text := s.String(); strings.TrimSpace(text) != "" || wait <= 0 {
		return text
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-s.updated:
	case <-timer.C:
	}
	return s.String()
}

type StepProcessBroker struct {
	mu        sync.Mutex
	processes map[stepProcessKey]*moduleProcess
}

type stepProcessKey struct {
	runID    string
	moduleID string
}

func NewStepProcessBroker() *StepProcessBroker {
	return &StepProcessBroker{processes: map[stepProcessKey]*moduleProcess{}}
}

func (b *StepProcessBroker) process(ctx context.Context, runner Runner, runID, moduleID string) (*moduleProcess, error) {
	if b == nil || runID == "" {
		return runner.start(ctx, moduleID)
	}
	key := stepProcessKey{runID: runID, moduleID: moduleID}
	b.mu.Lock()
	if process, ok := b.processes[key]; ok {
		b.mu.Unlock()
		return process, nil
	}
	b.mu.Unlock()

	process, err := runner.start(context.Background(), moduleID)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	if existing, ok := b.processes[key]; ok {
		b.mu.Unlock()
		process.killAndWait()
		return existing, nil
	}
	b.processes[key] = process
	b.mu.Unlock()
	return process, nil
}

func (b *StepProcessBroker) release(process *moduleProcess) {
	if b == nil || process == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for key, tracked := range b.processes {
		if tracked == process {
			delete(b.processes, key)
		}
	}
}

func (b *StepProcessBroker) FinishRun(ctx context.Context, runID string) error {
	if b == nil || runID == "" {
		return nil
	}
	var processes []*moduleProcess
	b.mu.Lock()
	for key, process := range b.processes {
		if key.runID == runID {
			processes = append(processes, process)
			delete(b.processes, key)
		}
	}
	b.mu.Unlock()

	var firstErr error
	for _, process := range processes {
		shutdownErr, waitErr := process.shutdownAndWait(ctx, moduleShutdownTimeout)
		logPythonRPCError("shut down run module process", shutdownErr)
		if shutdownErr != nil && firstErr == nil {
			firstErr = shutdownErr
		}
		if waitErr != nil && firstErr == nil {
			firstErr = waitErr
		}
	}
	return firstErr
}

func (r Runner) pythonPath() (string, error) {
	if r.PythonPath != "" {
		return r.PythonPath, nil
	}
	if path, err := exec.LookPath("python3"); err == nil {
		return path, nil
	}
	return exec.LookPath("python")
}

func (r Runner) sdkRoot() (string, error) {
	if r.SDKRoot != "" {
		return r.SDKRoot, nil
	}
	if env := os.Getenv("HOVEL_PYTHON_SDK_ROOT"); env != "" {
		return env, nil
	}
	for _, candidate := range sdkRootCandidates() {
		if hasPythonSDK(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("could not locate sdk/python; set HOVEL_PYTHON_SDK_ROOT")
}

func (r Runner) configPath() string {
	if r.ConfigPath != "" {
		return preferOperatorModuleConfig(r.ConfigPath)
	}
	if env := strings.TrimSpace(os.Getenv(ModuleConfigEnv)); env != "" {
		return preferOperatorModuleConfig(env)
	}
	for _, candidate := range defaultModuleConfigCandidates() {
		path, err := resolveConfigPath(candidate)
		if err != nil || path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			preferred := preferOperatorModuleConfig(path)
			resolved, err := resolveConfigPath(preferred)
			if err == nil && isFullExampleModuleConfig(resolved) && !operatorModuleConfigReady(resolved) {
				continue
			}
			return preferred
		}
	}
	return ""
}

func preferOperatorModuleConfig(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return ""
	}
	resolved, err := resolveConfigPath(configPath)
	if err != nil || resolved == "" {
		return configPath
	}
	if filepath.Base(resolved) != "hovel-modules.json" {
		return configPath
	}
	pythonDir := filepath.Dir(resolved)
	if filepath.Base(pythonDir) != "python" {
		return configPath
	}
	examplesDir := filepath.Dir(pythonDir)
	if filepath.Base(examplesDir) != "examples" {
		return configPath
	}
	fullConfig := filepath.Join(examplesDir, "hovel-modules.json")
	if _, err := os.Stat(fullConfig); err != nil {
		return configPath
	}
	if !operatorModuleConfigReady(fullConfig) {
		return configPath
	}
	return fullConfig
}

func isFullExampleModuleConfig(configPath string) bool {
	configPath = filepath.Clean(strings.TrimSpace(configPath))
	if filepath.Base(configPath) != "hovel-modules.json" {
		return false
	}
	return filepath.Base(filepath.Dir(configPath)) == "examples"
}

func operatorModuleConfigReady(configPath string) bool {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var config ModuleConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return false
	}
	baseDir := filepath.Dir(configPath)
	for _, entry := range config.Modules {
		if len(entry.Command) == 0 {
			continue
		}
		command := strings.TrimSpace(entry.Command[0])
		if command == "" {
			return false
		}
		if !filepath.IsAbs(command) {
			command = filepath.Join(baseDir, command)
		}
		if _, err := os.Stat(command); err != nil {
			return false
		}
	}
	return true
}

func defaultModuleConfigCandidates() []string {
	var candidates []string
	add := func(path string) {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "." {
			return
		}
		for _, existing := range candidates {
			if existing == path {
				return
			}
		}
		candidates = append(candidates, path)
	}
	for _, env := range []string{"HOVEL_REPO_ROOT", "BUILD_WORKSPACE_DIRECTORY", "BUILD_WORKING_DIRECTORY"} {
		root := strings.TrimSpace(os.Getenv(env))
		if root == "" {
			continue
		}
		add(filepath.Join(root, "modules", "examples", "hovel-modules.json"))
		add(filepath.Join(root, "modules", "examples", "python", "hovel-modules.json"))
		add(filepath.Join(root, "examples", "hovel-modules.json"))
		add(filepath.Join(root, "examples", "python", "hovel-modules.json"))
	}
	add(filepath.Join("modules", "examples", "hovel-modules.json"))
	add(filepath.Join("modules", "examples", "python", "hovel-modules.json"))
	add(filepath.Join("examples", "hovel-modules.json"))
	add(filepath.Join("examples", "python", "hovel-modules.json"))
	return candidates
}

func (r Runner) moduleEntry(moduleID string) (ModuleEntry, bool, error) {
	entries, err := r.moduleEntries()
	if err != nil {
		return ModuleEntry{}, false, err
	}
	_, _, hasVersion := modulecatalog.SplitID(moduleID)
	moduleName := modulecatalog.ReferenceName(moduleID)
	for _, entry := range entries {
		if entry.ID == moduleID {
			return entry, true, nil
		}
	}
	if !hasVersion {
		for _, entry := range entries {
			if modulecatalog.ReferenceName(entry.ID) == moduleName {
				return entry, true, nil
			}
		}
	} else {
		for _, entry := range entries {
			_, _, entryHasVersion := modulecatalog.SplitID(entry.ID)
			if !entryHasVersion && modulecatalog.ReferenceName(entry.ID) == moduleName {
				return entry, true, nil
			}
		}
	}
	for _, entry := range entries {
		module, err := r.InspectEntry(context.Background(), entry)
		if err != nil {
			return ModuleEntry{}, false, err
		}
		if module.ID == moduleID {
			entry.ID = module.ID
			return entry, true, nil
		}
		if !hasVersion && modulecatalog.ReferenceName(module.ID) == moduleName {
			entry.ID = module.ID
			return entry, true, nil
		}
	}
	return ModuleEntry{}, false, nil
}

func (r Runner) moduleEntries() ([]ModuleEntry, error) {
	installed, err := r.installedModuleEntries()
	if err != nil {
		return nil, err
	}
	configured, err := r.configuredModuleEntries()
	if err != nil {
		return nil, err
	}
	path, err := resolveConfigPath(r.configPath())
	if err != nil {
		return nil, err
	}
	if path == "" {
		return append(installed, configured...), nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config ModuleConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(path)
	entries := make([]ModuleEntry, 0, len(config.Modules))
	for index, entry := range config.Modules {
		entry.ID = strings.TrimSpace(entry.ID)
		entry.Runtime = strings.TrimSpace(entry.Runtime)
		entry.ProjectDir = strings.TrimSpace(entry.ProjectDir)
		entry.Module = strings.TrimSpace(entry.Module)
		if entry.ID == "" {
			return nil, fmt.Errorf("module entry %d missing id", index+1)
		}
		if entry.Runtime == "" {
			entry.Runtime = modulecatalog.RuntimeJSONRPCStdio
		}
		if entry.Runtime != modulecatalog.RuntimeJSONRPCStdio {
			return nil, fmt.Errorf("module %q uses unsupported runtime %q", entry.ID, entry.Runtime)
		}
		if entry.ProjectDir != "" && !filepath.IsAbs(entry.ProjectDir) {
			entry.ProjectDir = filepath.Join(baseDir, entry.ProjectDir)
		}
		if entry.usesCommand() {
			entry.Command[0] = strings.TrimSpace(entry.Command[0])
			if entry.Command[0] == "" {
				return nil, fmt.Errorf("module %q command[0] is required", entry.ID)
			}
			// command[0] may be a path relative to the config file; resolve it
			// so the runner can launch the binary regardless of working dir.
			if program := entry.Command[0]; program != "" && !filepath.IsAbs(program) && strings.ContainsRune(program, os.PathSeparator) {
				entry.Command[0] = filepath.Join(baseDir, program)
			}
			entries = append(entries, entry)
			continue
		}
		if entry.ProjectDir == "" || entry.Module == "" {
			return nil, fmt.Errorf("module %q missing project_dir or module", entry.ID)
		}
		entries = append(entries, entry)
	}
	out := append(installed, configured...)
	return append(out, entries...), nil
}

func (r Runner) installedModuleEntries() ([]ModuleEntry, error) {
	workspacePath := workspacepath.ResolvePath(r.WorkspacePath)
	lock, err := modulepackage.LoadLock(filepath.Join(workspacePath, "module-lock.yaml"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	entries := make([]ModuleEntry, 0, len(lock.Modules))
	for _, record := range lock.Modules {
		pkg, err := modulepackage.LoadDir(record.Source)
		if err != nil {
			return nil, err
		}
		launch, err := pkg.LaunchEntry(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return nil, err
		}
		entries = append(entries, ModuleEntry{
			ID:         modulecatalog.CanonicalID(record.Name, record.Version),
			Runtime:    launch.Runtime,
			ProjectDir: launch.ProjectDir,
			Module:     launch.Module,
			Command:    append([]string(nil), launch.Command...),
		})
	}
	return entries, nil
}

func (r Runner) configuredModuleEntries() ([]ModuleEntry, error) {
	if strings.TrimSpace(r.WorkspacePath) == "" && strings.TrimSpace(r.HovelConfig) == "" {
		return nil, nil
	}
	config, _, err := hovelconfig.Load(hovelconfig.Options{
		Workspace:    r.WorkspacePath,
		ExplicitPath: r.HovelConfig,
	})
	if err != nil {
		return nil, err
	}
	var entries []ModuleEntry
	for _, root := range config.Modules.SearchPaths {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, modulepackage.ManifestName)); err == nil {
			entry, err := moduleEntryFromPackageRoot(root)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
			continue
		}
		children, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if !child.IsDir() {
				continue
			}
			childRoot := filepath.Join(root, child.Name())
			if _, err := os.Stat(filepath.Join(childRoot, modulepackage.ManifestName)); err != nil {
				continue
			}
			entry, err := moduleEntryFromPackageRoot(childRoot)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func moduleEntryFromPackageRoot(root string) (ModuleEntry, error) {
	pkg, err := modulepackage.LoadDir(root)
	if err != nil {
		return ModuleEntry{}, err
	}
	launch, err := pkg.LaunchEntry(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return ModuleEntry{}, err
	}
	return ModuleEntry{
		ID:         modulecatalog.CanonicalID(pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version),
		Runtime:    launch.Runtime,
		ProjectDir: launch.ProjectDir,
		Module:     launch.Module,
		Command:    append([]string(nil), launch.Command...),
	}, nil
}

func resolveConfigPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if filepath.IsAbs(path) {
		return path, nil
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	if candidate, ok := runfileManifestLookup(path); ok {
		return candidate, nil
	}
	for _, root := range runfileRoots() {
		candidate := filepath.Join(root, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return path, nil
}

func runfileRoots() []string {
	roots := workspaceRootsFromEnv()
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for i := 0; i < 8 && dir != "" && dir != string(filepath.Separator); i++ {
			roots = append(roots, dir)
			dir = filepath.Dir(dir)
		}
	}
	if exe, err := os.Executable(); err == nil {
		runfiles := exe + ".runfiles"
		roots = append(roots,
			runfiles,
			filepath.Join(runfiles, "hovel"),
			filepath.Join(runfiles, "_main"),
		)
	}
	if runfiles := os.Getenv("RUNFILES_DIR"); runfiles != "" {
		roots = append(roots,
			runfiles,
			filepath.Join(runfiles, "hovel"),
			filepath.Join(runfiles, "_main"),
		)
	}
	if testSrcDir := os.Getenv("TEST_SRCDIR"); testSrcDir != "" {
		roots = append(roots,
			testSrcDir,
			filepath.Join(testSrcDir, "hovel"),
			filepath.Join(testSrcDir, "_main"),
		)
		if workspace := os.Getenv("TEST_WORKSPACE"); workspace != "" {
			roots = append(roots, filepath.Join(testSrcDir, workspace))
		}
	}
	return roots
}

func sdkRootCandidates() []string {
	var candidates []string
	addClimbs := func(start string) {
		dir := start
		for i := 0; i < 8 && dir != "" && dir != string(filepath.Separator); i++ {
			candidates = append(candidates, filepath.Join(dir, "sdk", "python"))
			dir = filepath.Dir(dir)
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		addClimbs(cwd)
	}
	for _, root := range workspaceRootsFromEnv() {
		candidates = append(candidates, filepath.Join(root, "sdk", "python"))
		if filepath.Base(root) == "core" {
			candidates = append(candidates, filepath.Join(filepath.Dir(root), "sdk", "python"))
		}
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		addClimbs(exeDir)
		runfiles := exe + ".runfiles"
		candidates = append(candidates,
			filepath.Join(runfiles, "hovel", "sdk", "python"),
			filepath.Join(runfiles, "_main", "sdk", "python"),
			filepath.Join(runfiles, "sdk", "python"),
			filepath.Join(exeDir, "sdk", "python"),
		)
	}
	if runfiles := os.Getenv("RUNFILES_DIR"); runfiles != "" {
		candidates = append(candidates,
			filepath.Join(runfiles, "hovel", "sdk", "python"),
			filepath.Join(runfiles, "_main", "sdk", "python"),
			filepath.Join(runfiles, "sdk", "python"),
		)
	}
	if testSrcDir := os.Getenv("TEST_SRCDIR"); testSrcDir != "" {
		candidates = append(candidates,
			filepath.Join(testSrcDir, "hovel", "sdk", "python"),
			filepath.Join(testSrcDir, "_main", "sdk", "python"),
			filepath.Join(testSrcDir, "sdk", "python"),
		)
		if workspace := os.Getenv("TEST_WORKSPACE"); workspace != "" {
			candidates = append(candidates, filepath.Join(testSrcDir, workspace, "sdk", "python"))
		}
	}
	if sdkInit, ok := runfileManifestLookup("sdk/python/hovel_sdk/__init__.py"); ok {
		candidates = append(candidates, filepath.Dir(filepath.Dir(sdkInit)))
	}
	return candidates
}

func workspaceRootsFromEnv() []string {
	var roots []string
	for _, name := range []string{"HOVEL_REPO_ROOT", "BUILD_WORKSPACE_DIRECTORY", "BUILD_WORKING_DIRECTORY"} {
		root := strings.TrimSpace(os.Getenv(name))
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		if !slices.Contains(roots, root) {
			roots = append(roots, root)
		}
	}
	return roots
}

func runfileManifestLookup(path string) (string, bool) {
	manifest := os.Getenv("RUNFILES_MANIFEST_FILE")
	if manifest == "" {
		return "", false
	}
	file, err := os.Open(manifest)
	if err != nil {
		return "", false
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("hovel pythonrpc: close runfiles manifest: %v", err)
		}
	}()
	keys := []string{
		filepath.ToSlash(path),
		filepath.ToSlash(filepath.Join("_main", path)),
		filepath.ToSlash(filepath.Join("hovel", path)),
	}
	if workspace := os.Getenv("TEST_WORKSPACE"); workspace != "" {
		keys = append(keys, filepath.ToSlash(filepath.Join(workspace, path)))
	}
	wanted := map[string]struct{}{}
	for _, key := range keys {
		wanted[key] = struct{}{}
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if _, ok := wanted[key]; ok {
			return value, true
		}
	}
	return "", false
}

func hasPythonSDK(path string) bool {
	info, err := os.Stat(filepath.Join(path, "hovel_sdk", "__init__.py"))
	return err == nil && !info.IsDir()
}

type rpcClient struct {
	decoder *frameDecoder
	writer  io.WriteCloser

	credentialBearing atomic.Bool

	writeMu sync.Mutex

	mu      sync.Mutex
	nextID  int
	pending map[int]chan rpcMessage
	logs    []rpcLog
	onLog   func(rpcLog) error
	onEvent func(rpcSessionEvent) error
	readErr error
	done    chan struct{}
	once    sync.Once
}

func newClient(stdout io.Reader, stdin io.WriteCloser) *rpcClient {
	client := &rpcClient{
		decoder: newFrameDecoder(stdout),
		writer:  stdin,
		pending: map[int]chan rpcMessage{},
		done:    make(chan struct{}),
	}
	go client.readLoop()
	return client
}

func (c *rpcClient) markCredentialBearing() {
	if c == nil {
		return
	}
	c.credentialBearing.Store(true)
	c.mu.Lock()
	clearRPCLogs(c.logs)
	c.logs = nil
	c.onLog = nil
	c.onEvent = nil
	c.mu.Unlock()
}

func (c *rpcClient) call(ctx context.Context, method string, params any) (map[string]any, error) {
	message, err := c.callMessage(ctx, method, params)
	if err != nil {
		return nil, c.sanitizeDiagnosticError(err)
	}
	defer clearRPCMessage(&message)
	result, err := rpcResult(message)
	return result, c.sanitizeDiagnosticError(err)
}

func (c *rpcClient) callRaw(ctx context.Context, method string, params any) (json.RawMessage, error) {
	message, err := c.callMessage(ctx, method, params)
	if err != nil {
		return nil, c.sanitizeDiagnosticError(err)
	}
	result, err := rpcRawResult(&message)
	clearRPCMessage(&message)
	return result, c.sanitizeDiagnosticError(err)
}

func (c *rpcClient) sanitizeDiagnosticError(err error) error {
	if err == nil || !c.credentialBearing.Load() {
		return err
	}
	var callback callbackError
	if errors.As(err, &callback) {
		return err
	}
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, io.EOF):
		return io.EOF
	default:
		return errCredentialProviderDiagnosticsSuppressed
	}
}

func (c *rpcClient) callMessage(ctx context.Context, method string, params any) (rpcMessage, error) {
	if err := ctx.Err(); err != nil {
		return rpcMessage{}, err
	}

	c.mu.Lock()
	c.nextID++
	id := c.nextID
	responses := make(chan rpcMessage, 1)
	c.pending[id] = responses
	c.mu.Unlock()
	defer c.removePending(id)

	c.writeMu.Lock()
	if err := writeFrame(c.writer, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		c.writeMu.Unlock()
		return rpcMessage{}, err
	}
	c.writeMu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return rpcMessage{}, ctx.Err()
		case <-c.done:
			select {
			case message := <-responses:
				return message, nil
			default:
			}
			if err := ctx.Err(); err != nil {
				return rpcMessage{}, err
			}
			return rpcMessage{}, c.readError()
		case message := <-responses:
			return message, nil
		}
	}
}

func rpcResult(message rpcMessage) (map[string]any, error) {
	if message.Error != nil {
		return nil, errors.New(message.Error.Message)
	}
	if len(message.ResultRaw) == 0 {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal(message.ResultRaw, &result); err != nil || result == nil {
		return map[string]any{}, nil
	}
	return result, nil
}

func rpcRawResult(message *rpcMessage) (json.RawMessage, error) {
	if message == nil {
		return nil, errors.New("python rpc: result message is nil")
	}
	if message.Error != nil {
		return nil, errors.New(message.Error.Message)
	}
	if len(message.ResultRaw) == 0 {
		return json.RawMessage("null"), nil
	}
	result := message.ResultRaw
	message.ResultRaw = nil
	return result, nil
}

func (c *rpcClient) readLoop() {
	for {
		message, err := c.decoder.read()
		if err != nil {
			c.finish(err)
			return
		}
		if message.Method == "module/log" || message.Method == "module/session" {
			if err := c.handleNotification(message); err != nil {
				c.finish(err)
				return
			}
			continue
		}
		c.mu.Lock()
		responses := c.pending[message.ID]
		c.mu.Unlock()
		if responses == nil {
			clearRPCMessage(&message)
			continue
		}
		select {
		case responses <- message:
			message.ResultRaw = nil
		default:
			clearRPCMessage(&message)
		}
	}
}

func (c *rpcClient) handleNotification(message rpcMessage) error {
	switch message.Method {
	case "module/log":
		if message.Log.ReceivedAt.IsZero() {
			message.Log.ReceivedAt = time.Now().UTC()
		}
		c.mu.Lock()
		if c.credentialBearing.Load() {
			c.mu.Unlock()
			clearRPCMessage(&message)
			return nil
		}
		if len(c.logs) >= maxBufferedModuleLogs {
			c.mu.Unlock()
			return fmt.Errorf("module log notification count exceeds maximum %d", maxBufferedModuleLogs)
		}
		c.logs = append(c.logs, message.Log)
		onLog := c.onLog
		c.mu.Unlock()
		if onLog != nil && !c.credentialBearing.Load() {
			if err := onLog(message.Log); err != nil {
				return callbackError{err: err}
			}
		}
	case "module/session":
		c.mu.Lock()
		if c.credentialBearing.Load() {
			c.mu.Unlock()
			clearRPCMessage(&message)
			return nil
		}
		onEvent := c.onEvent
		c.mu.Unlock()
		if onEvent != nil && !c.credentialBearing.Load() {
			if err := onEvent(message.Session); err != nil {
				return callbackError{err: err}
			}
		}
	}
	return nil
}

func (c *rpcClient) removePending(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, id)
}

func (c *rpcClient) finish(err error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.readErr = err
		c.mu.Unlock()
		close(c.done)
	})
}

func (c *rpcClient) readError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return c.readErr
	}
	return io.EOF
}

func (c *rpcClient) setOnLog(fn func(rpcLog) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credentialBearing.Load() {
		c.onLog = nil
		return
	}
	c.onLog = fn
}

func (c *rpcClient) logsSnapshot() []rpcLog {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credentialBearing.Load() {
		return []rpcLog{}
	}
	return append([]rpcLog(nil), c.logs...)
}

func clearRPCLogs(logs []rpcLog) {
	for index := range logs {
		clearRPCLog(&logs[index])
	}
}

func clearRPCLog(log *rpcLog) {
	if log == nil {
		return
	}
	clear(log.Fields)
	*log = rpcLog{}
}

func clearRPCMessage(message *rpcMessage) {
	if message == nil {
		return
	}
	clearBytes(message.ResultRaw)
	clearRPCLog(&message.Log)
	clear(message.Session.Fields)
	clear(message.Session.Session.Capabilities)
	*message = rpcMessage{}
}

type rpcMessage struct {
	ID        int
	Method    string
	ResultRaw json.RawMessage
	Log       rpcLog
	Session   rpcSessionEvent
	Error     *rpcError
}

type rpcError struct {
	Message string `json:"message"`
}

type rpcLog struct {
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Logger     string         `json:"logger"`
	Fields     map[string]any `json:"fields"`
	Exception  string         `json:"exception"`
	ReceivedAt time.Time      `json:"-"`
}

type rpcSessionEvent struct {
	Event   string         `json:"event"`
	Session rpcSessionRef  `json:"session"`
	Fields  map[string]any `json:"fields"`
}

type rpcSessionRef struct {
	ID                 string `json:"id"`
	RunID              string `json:"runId"`
	ModuleID           string `json:"moduleId"`
	Target             string `json:"target"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	State              string `json:"state"`
	Transport          string `json:"transport"`
	InstalledPayloadID string `json:"installedPayloadId"`
	Capabilities       []any  `json:"capabilities"`
}

type frameDecoder struct {
	reader *framing.Reader
}

func newFrameDecoder(reader io.Reader) *frameDecoder {
	return &frameDecoder{reader: framing.NewReader(reader, maxFrameBytes)}
}

func (d *frameDecoder) read() (rpcMessage, error) {
	var raw struct {
		ID     *int            `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := d.reader.ReadJSON(&raw); err != nil {
		return rpcMessage{}, err
	}
	message := rpcMessage{Method: raw.Method, Error: raw.Error}
	if raw.ID != nil {
		message.ID = *raw.ID
	}
	if (raw.Method == "module/log" || raw.Method == "module/session") &&
		len(raw.Params) > maxModuleNotificationBytes {
		return rpcMessage{}, fmt.Errorf(
			"%s params size %d exceeds maximum %d",
			raw.Method,
			len(raw.Params),
			maxModuleNotificationBytes,
		)
	}
	if len(raw.Result) > 0 {
		message.ResultRaw = raw.Result
	}
	if raw.Method == "module/log" && len(raw.Params) > 0 {
		if err := json.Unmarshal(raw.Params, &message.Log); err != nil {
			return rpcMessage{}, err
		}
	}
	if raw.Method == "module/session" && len(raw.Params) > 0 {
		if err := json.Unmarshal(raw.Params, &message.Session); err != nil {
			return rpcMessage{}, err
		}
	}
	return message, nil
}

func writeFrame(writer io.Writer, message map[string]any) error {
	return framing.WriteJSON(writer, message)
}

func resultFromRPC(request run.Request, values map[string]any, logs []rpcLog) (run.Result, error) {
	findings, err := findingsFromRPC(values["findings"])
	if err != nil {
		return run.Result{}, err
	}
	artifacts, err := artifactsFromRPC(values["artifacts"])
	if err != nil {
		return run.Result{}, err
	}
	sessions, err := sessionsFromRPC(request, values["sessions"])
	if err != nil {
		return run.Result{}, err
	}
	installedPayloads, err := installedPayloadsFromRPC(values["installedPayloads"])
	if err != nil {
		return run.Result{}, err
	}
	agentHints, err := agentHintsFromRPC(values["agentHints"])
	if err != nil {
		return run.Result{}, err
	}
	args := run.ResultArgs{
		Summary:           stringValue(values["summary"]),
		Findings:          findings,
		Artifacts:         artifacts,
		Logs:              logsFromRPC(request, logs),
		Sessions:          sessions,
		InstalledPayloads: installedPayloads,
		AgentHints:        agentHints,
	}
	if stringValue(values["status"]) == string(run.StateFailed) {
		return run.Failed(request, args)
	}
	return run.Succeeded(request, args)
}

func logsFromRPC(request run.Request, logs []rpcLog) []run.LogEntry {
	out := make([]run.LogEntry, 0, len(logs))
	for _, log := range logs {
		fields := make(map[string]string, len(log.Fields)+1)
		for key, value := range log.Fields {
			fields[key] = fmt.Sprint(value)
		}
		if log.Exception != "" {
			fields["exception"] = log.Exception
		}
		out = append(out, run.LogEntry{
			Kind:     "event",
			Time:     log.ReceivedAt.Format(time.RFC3339Nano),
			Level:    log.Level,
			Source:   "module",
			Message:  log.Message,
			Logger:   log.Logger,
			RunID:    request.ID,
			Target:   request.Target,
			ModuleID: request.ModuleID,
			Fields:   fields,
		})
	}
	return out
}

func moduleFromRPC(info, schema map[string]any) (modulecatalog.Module, error) {
	name := strings.TrimSpace(stringValue(info["name"]))
	version := strings.TrimSpace(stringValue(info["version"]))
	if name == "" {
		return modulecatalog.Module{}, errors.New("module handshake missing name")
	}
	if version == "" {
		return modulecatalog.Module{}, errors.New("module handshake missing version")
	}
	moduleType, err := modulecatalog.NewModuleType(strings.TrimSpace(stringValue(info["moduleType"])))
	if err != nil {
		return modulecatalog.Module{}, err
	}
	chainConfig, err := requirementsFromRPC(schema["chainConfig"], "chainConfig")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	targetConfig, err := requirementsFromRPC(schema["targetConfig"], "targetConfig")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	tags, err := strictStringSlice(info["tags"], "handshake tags")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	display := strings.TrimSpace(stringValue(info["displayName"]))
	if display == "" {
		display = displayName(name)
	}
	module := modulecatalog.Module{
		ID:           modulecatalog.CanonicalID(name, version),
		Name:         display,
		Type:         moduleType,
		Version:      version,
		Summary:      stringValue(info["summary"]),
		Description:  stringValue(info["description"]),
		Tags:         tags,
		RuntimeKind:  modulecatalog.RuntimeJSONRPCStdio,
		Author:       "hovel",
		Enabled:      true,
		ChainConfig:  chainConfig,
		TargetConfig: targetConfig,
	}
	discovery, err := contextFromRPC(info["discoveryContext"], "discoveryContext")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	planning, err := contextFromRPC(schema["planningContext"], "planningContext")
	if err != nil {
		return modulecatalog.Module{}, err
	}
	module.Discovery = discovery
	module.Planning = planning
	return module, nil
}

func stepContractsFromRPC(value map[string]any) (modulecatalog.StepContractSet, error) {
	set := modulecatalog.StepContractSet{
		Version: strings.TrimSpace(stringValue(value["version"])),
	}
	rawSteps, present := value["steps"]
	if !present || rawSteps == nil {
		return set, nil
	}
	items, ok := rawSteps.([]any)
	if !ok {
		return set, errors.New("step contracts steps must be an array")
	}
	set.Steps = make([]modulecatalog.StepContract, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return set, fmt.Errorf("step contract %d must be an object", index+1)
		}
		requires, err := capabilityRequirementsFromRPC(object["requires"], fmt.Sprintf("step contract %d requires", index+1))
		if err != nil {
			return set, err
		}
		produces, err := capabilityRequirementsFromRPC(object["produces"], fmt.Sprintf("step contract %d produces", index+1))
		if err != nil {
			return set, err
		}
		materializes, err := prepareMaterializesFromRPC(object["prepare"], fmt.Sprintf("step contract %d prepare", index+1))
		if err != nil {
			return set, err
		}
		cleanup, err := cleanupContractFromRPC(object["cleanup"], fmt.Sprintf("step contract %d cleanup", index+1))
		if err != nil {
			return set, err
		}
		context, err := contextFromRPC(object["context"], fmt.Sprintf("step contract %d context", index+1))
		if err != nil {
			return set, err
		}
		set.Steps = append(set.Steps, modulecatalog.StepContract{
			ID:           strings.TrimSpace(stringValue(object["id"])),
			Kind:         strings.TrimSpace(stringValue(object["kind"])),
			ConfigSchema: anyMap(object["configSchema"]),
			Requires:     requires,
			Produces:     produces,
			Context:      context,
			Prepare: modulecatalog.StepPrepareContract{
				Materializes: materializes,
			},
			Cleanup: cleanup,
		})
	}
	return set, nil
}

func meshDescriptorFromRPC(value map[string]any) (mesh.Descriptor, error) {
	var descriptor mesh.Descriptor
	if len(value) == 0 {
		return descriptor, nil
	}
	if err := decodeRPCMap(value, &descriptor); err != nil {
		return mesh.Descriptor{}, err
	}
	return descriptor, nil
}

func credentialDeliveryDescriptorFromRPC(
	value map[string]any,
) (domainpki.CredentialDeliveryDescriptor, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return domainpki.CredentialDeliveryDescriptor{}, fmt.Errorf(
			"module credential delivery descriptor is invalid: %w",
			err,
		)
	}
	return credentialDeliveryDescriptorFromRawRPC(raw)
}

func credentialDeliveryDescriptorFromRawRPC(
	value json.RawMessage,
) (domainpki.CredentialDeliveryDescriptor, error) {
	descriptor, err := domainpki.DecodeCredentialDeliveryDescriptorJSON(value)
	if err != nil {
		return domainpki.CredentialDeliveryDescriptor{}, fmt.Errorf(
			"module credential delivery descriptor is invalid: %w",
			err,
		)
	}
	return descriptor.Clone(), nil
}

func reconcileCredentialDeliveryDescriptors(module *modulecatalog.Module) error {
	if module == nil {
		return errors.New("module credential delivery reconciliation requires a module")
	}
	nested := module.Mesh.CredentialDelivery
	standalone := module.CredentialDelivery
	if standalone == nil && nested == nil {
		return nil
	}
	if standalone == nil {
		descriptor := nested.Clone()
		module.CredentialDelivery = &descriptor
		return nil
	}
	if nested == nil {
		return nil
	}
	standaloneDigest, err := standalone.DigestSHA256()
	if err != nil {
		return fmt.Errorf("module standalone credential delivery descriptor is invalid: %w", err)
	}
	nestedDigest, err := nested.DigestSHA256()
	if err != nil {
		return fmt.Errorf("module mesh credential delivery descriptor is invalid: %w", err)
	}
	if standaloneDigest != nestedDigest {
		return errors.New("module standalone and mesh credential delivery descriptors do not match")
	}
	descriptor := standalone.Clone()
	module.Mesh.CredentialDelivery = &descriptor
	return nil
}

func contextFromRPC(value any, label string) (modulecatalog.Context, error) {
	if value == nil {
		return modulecatalog.Context{}, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return modulecatalog.Context{}, fmt.Errorf("%s must be an object", label)
	}
	data, err := json.Marshal(object)
	if err != nil {
		return modulecatalog.Context{}, err
	}
	var context modulecatalog.Context
	if err := json.Unmarshal(data, &context); err != nil {
		return modulecatalog.Context{}, fmt.Errorf("%s is invalid: %w", label, err)
	}
	return context, nil
}

func capabilityRequirementsFromRPC(value any, label string) ([]modulecatalog.CapabilityRequirement, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	requirements := make([]modulecatalog.CapabilityRequirement, 0, len(items))
	for index, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s item %d must be an object", label, index+1)
		}
		states, err := strictStringSlice(object["states"], fmt.Sprintf("%s item %d states", label, index+1))
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, modulecatalog.CapabilityRequirement{
			Type:          modulecatalog.CapabilityType(strings.TrimSpace(stringValue(object["type"]))),
			SchemaVersion: strings.TrimSpace(stringValue(object["schemaVersion"])),
			Attributes:    anyMap(object["attributes"]),
			States:        states,
		})
	}
	return requirements, nil
}

func prepareMaterializesFromRPC(value any, label string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	materializes, present := object["materializes"]
	if !present || materializes == nil {
		return nil, nil
	}
	items, ok := materializes.([]any)
	if !ok {
		return nil, fmt.Errorf("%s materializes must be an array", label)
	}
	out := make([]string, 0, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s materializes item %d must be a string", label, index+1)
		}
		out = append(out, strings.TrimSpace(text))
	}
	return out, nil
}

func cleanupContractFromRPC(value any, label string) (*modulecatalog.StepCleanupContract, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	return &modulecatalog.StepCleanupContract{StepID: strings.TrimSpace(stringValue(object["stepId"]))}, nil
}

func rpcArray(value any, label string) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	return items, nil
}

func rpcObjectItem(value any, label string, index int) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s item %d must be an object", label, index+1)
	}
	return object, nil
}

func strictStringSlice(value any, label string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", label)
	}
	out := make([]string, 0, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s item %d must be a string", label, index+1)
		}
		out = append(out, strings.TrimSpace(text))
	}
	return out, nil
}

func optionalAnyMap(value any, label string) (map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	out := make(map[string]any, len(object))
	for key, item := range object {
		out[key] = item
	}
	return out, nil
}

func anyMap(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(object))
	for key, item := range object {
		out[key] = item
	}
	return out
}

func requirementsFromRPC(value any, label string) ([]modulecatalog.Requirement, error) {
	items, err := rpcArray(value, label)
	if err != nil {
		return nil, err
	}
	requirements := make([]modulecatalog.Requirement, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, label, index)
		if err != nil {
			return nil, err
		}
		key, err := requiredStringValue(object["key"], fmt.Sprintf("%s item %d key", label, index+1))
		if err != nil {
			return nil, err
		}
		rawType, err := requiredStringValue(object["type"], fmt.Sprintf("%s item %d type", label, index+1))
		if err != nil {
			return nil, err
		}
		valueType := modulecatalog.ValueType(rawType)
		if !validRequirementType(valueType) {
			return nil, fmt.Errorf("%s item %d type %q is unsupported", label, index+1, rawType)
		}
		defaultValue, err := optionalStringValue(object["default"], fmt.Sprintf("%s item %d default", label, index+1))
		if err != nil {
			return nil, err
		}
		description, err := optionalStringValue(object["description"], fmt.Sprintf("%s item %d description", label, index+1))
		if err != nil {
			return nil, err
		}
		allowed, err := strictStringSlice(object["allowed"], fmt.Sprintf("%s item %d allowed", label, index+1))
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, modulecatalog.Requirement{
			Key:         key,
			Type:        valueType,
			Required:    boolValue(object["required"]),
			Default:     defaultValue,
			Description: description,
			Allowed:     allowed,
			Secret:      boolValue(object["secret"]),
		})
	}
	return requirements, nil
}

func requiredStringValue(value any, label string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s is required", label)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return text, nil
}

func optionalStringValue(value any, label string) (string, error) {
	if value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", label)
	}
	return text, nil
}

func validRequirementType(value modulecatalog.ValueType) bool {
	switch value {
	case modulecatalog.ValueString,
		modulecatalog.ValueSecret,
		modulecatalog.ValueBool,
		modulecatalog.ValueInt,
		modulecatalog.ValueFloat,
		modulecatalog.ValueEnum,
		modulecatalog.ValueDuration,
		modulecatalog.ValueURL,
		modulecatalog.ValueHost,
		modulecatalog.ValuePort,
		modulecatalog.ValueCIDR,
		modulecatalog.ValuePath,
		modulecatalog.ValueStringList,
		modulecatalog.ValueStringStringMap:
		return true
	default:
		return false
	}
}

func findingsFromRPC(value any) ([]run.Finding, error) {
	items, err := rpcArray(value, "findings")
	if err != nil {
		return nil, err
	}
	findings := make([]run.Finding, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "findings", index)
		if err != nil {
			return nil, err
		}
		findings = append(findings, run.Finding{
			Title:    stringValue(object["title"]),
			Severity: run.Severity(stringValue(object["severity"])),
			Detail:   stringValue(object["detail"]),
		})
	}
	return findings, nil
}

func artifactsFromRPC(value any) ([]run.Artifact, error) {
	items, err := rpcArray(value, "artifacts")
	if err != nil {
		return nil, err
	}
	artifacts := make([]run.Artifact, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "artifacts", index)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, run.Artifact{
			Name: stringValue(object["name"]),
			Kind: stringValue(object["kind"]),
			Data: stringValue(object["data"]),
			Path: stringValue(object["path"]),
		})
	}
	return artifacts, nil
}

type SessionBroker struct {
	mu           sync.Mutex
	sessions     map[string]*brokerSession
	nextOrder    uint64
	historyLimit int
}

func NewSessionBroker() *SessionBroker {
	return &SessionBroker{
		sessions:     map[string]*brokerSession{},
		historyLimit: defaultSessionHistoryBytes,
	}
}

func (b *SessionBroker) ListSessions(context.Context) ([]run.SessionRef, error) {
	if b == nil {
		return nil, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	ordered := make([]*brokerSession, 0, len(b.sessions))
	for _, session := range b.sessions {
		ordered = append(ordered, session)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].order == ordered[j].order {
			return ordered[i].ref.ID < ordered[j].ref.ID
		}
		return ordered[i].order < ordered[j].order
	})
	sessions := make([]run.SessionRef, 0, len(ordered))
	for _, session := range ordered {
		sessions = append(sessions, cloneSessionRef(session.ref))
	}
	return sessions, nil
}

func (b *SessionBroker) WriteSession(ctx context.Context, sessionID string, data []byte) error {
	session, err := b.lookup(sessionID)
	if err != nil {
		return err
	}
	_, err = session.process.client.call(ctx, "session/write", map[string]any{
		"sessionId": sessionID,
		"data":      base64.StdEncoding.EncodeToString(data),
	})
	return err
}

func (b *SessionBroker) ReadSession(ctx context.Context, sessionID string, timeout time.Duration) (run.SessionChunk, error) {
	session, err := b.lookup(sessionID)
	if err != nil {
		return run.SessionChunk{}, err
	}
	return session.read(ctx, sessionID, timeout)
}

func (b *SessionBroker) TailSession(ctx context.Context, sessionID string, options run.SessionTailOptions) (run.SessionChunk, error) {
	if err := ctx.Err(); err != nil {
		return run.SessionChunk{}, err
	}
	if options.MaxBytes < 0 {
		return run.SessionChunk{}, errors.New("tail byte count cannot be negative")
	}
	if options.MaxLines < 0 {
		return run.SessionChunk{}, errors.New("tail line count cannot be negative")
	}
	if options.MaxBytes > 0 && options.MaxLines > 0 {
		return run.SessionChunk{}, errors.New("tail byte and line limits are mutually exclusive")
	}
	session, err := b.lookup(sessionID)
	if err != nil {
		return run.SessionChunk{}, err
	}
	return session.tail(sessionID, options), nil
}

func (b *SessionBroker) CloseSession(ctx context.Context, sessionID string) error {
	session, err := b.lookup(sessionID)
	if err != nil {
		return err
	}
	session.closeMu.Lock()
	defer session.closeMu.Unlock()
	if !b.sessionIsTracked(sessionID, session) {
		return nil
	}
	_, callErr := session.process.client.call(ctx, "session/close", map[string]any{
		"sessionId": sessionID,
		"reason":    "operator requested close",
	})
	if callErr != nil {
		return callErr
	}
	processStillUsed, removed := b.removeSession(sessionID, session)
	if !removed {
		return nil
	}
	if !processStillUsed {
		shutdownErr, waitErr := session.process.shutdownAndWait(ctx, moduleShutdownTimeout)
		logPythonRPCError("shut down session module process", shutdownErr)
		callErr = errors.Join(callErr, shutdownErr, waitErr)
	}
	return callErr
}

func (b *SessionBroker) ListSessionCommands(ctx context.Context, sessionID string, request run.PayloadCommandListRequest) ([]run.PayloadCommand, error) {
	session, err := b.lookup(sessionID)
	if err != nil {
		return nil, err
	}
	values, err := session.process.client.call(ctx, "session.command.list", map[string]any{
		"sessionId": sessionID,
		"request":   request,
	})
	if err != nil {
		return nil, err
	}
	var decoded struct {
		Commands []run.PayloadCommand `json:"commands"`
	}
	if err := decodeRPCMap(values, &decoded); err != nil {
		return nil, services.NewModuleExecutionFailure("module returned invalid session command list", err)
	}
	return decoded.Commands, nil
}

func (b *SessionBroker) RunSessionCommand(ctx context.Context, sessionID string, request run.PayloadCommandRequest) (run.PayloadCommandResult, error) {
	session, err := b.lookup(sessionID)
	if err != nil {
		return run.PayloadCommandResult{}, err
	}
	values, err := session.process.client.call(ctx, "session.command.run", map[string]any{
		"sessionId": sessionID,
		"request":   request,
	})
	if err != nil {
		return run.PayloadCommandResult{}, err
	}
	var decoded run.PayloadCommandResult
	if err := decodeRPCMap(values, &decoded); err != nil {
		return run.PayloadCommandResult{}, services.NewModuleExecutionFailure("module returned invalid session command result", err)
	}
	return decoded, nil
}

func (b *SessionBroker) adopt(process *moduleProcess, sessions []run.SessionRef) error {
	if b == nil {
		return errors.New("session broker is not configured")
	}
	if process == nil {
		return errors.New("module process is required to adopt sessions")
	}
	normalized, err := normalizeSessionRefs(sessions)
	if err != nil {
		return err
	}

	b.mu.Lock()
	if b.sessions == nil {
		b.sessions = map[string]*brokerSession{}
	}
	for _, session := range normalized {
		if _, exists := b.sessions[session.ID]; exists {
			b.mu.Unlock()
			return fmt.Errorf("session %q is already tracked", session.ID)
		}
	}
	var adopted []*brokerSession
	for _, session := range normalized {
		order := b.nextOrder
		b.nextOrder++
		brokerSession := newBrokerSession(session, process, b.historyLimit)
		brokerSession.order = order
		b.sessions[session.ID] = brokerSession
		adopted = append(adopted, brokerSession)
	}
	b.mu.Unlock()
	for _, session := range adopted {
		go b.pumpSession(session.ref.ID, session)
	}
	return nil
}

func (b *SessionBroker) lookup(sessionID string) (*brokerSession, error) {
	if b == nil {
		return nil, errors.New("session broker is not configured")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	session, ok := b.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %s does not exist", sessionID)
	}
	return session, nil
}

func (b *SessionBroker) markClosed(sessionID string) {
	b.mu.Lock()
	session, ok := b.sessions[sessionID]
	if ok {
		session.ref.State = "closed"
	}
	b.mu.Unlock()
	if ok {
		session.closeLocal()
	}
}

func (b *SessionBroker) sessionIsTracked(sessionID string, expected *brokerSession) bool {
	if b == nil || expected == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessions[sessionID] == expected
}

func (b *SessionBroker) removeSession(sessionID string, expected *brokerSession) (bool, bool) {
	if b == nil || expected == nil {
		return false, false
	}
	b.mu.Lock()
	session, exists := b.sessions[sessionID]
	if !exists || session != expected {
		b.mu.Unlock()
		return false, false
	}
	delete(b.sessions, sessionID)
	processStillUsed := false
	for _, remaining := range b.sessions {
		if remaining.process == session.process {
			processStillUsed = true
			break
		}
	}
	b.mu.Unlock()
	session.closeLocal()
	return processStillUsed, true
}

func (b *SessionBroker) pumpSession(sessionID string, session *brokerSession) {
	for {
		if session.isClosed() {
			return
		}
		values, err := session.process.client.call(session.ctx, rpcSessionReadMethod, map[string]any{
			"sessionId": sessionID,
			"timeoutMs": sessionPumpReadTimeoutMilliseconds,
		})
		if err != nil {
			b.markClosed(sessionID)
			return
		}
		data, err := base64.StdEncoding.DecodeString(stringValue(values["data"]))
		if err != nil {
			b.markClosed(sessionID)
			return
		}
		session.appendData(data)
		if boolValue(values["closed"]) {
			b.markClosed(sessionID)
			return
		}
	}
}

func cloneSessionRef(session run.SessionRef) run.SessionRef {
	session.Capabilities = append([]string(nil), session.Capabilities...)
	return session
}

func normalizeSessionRefs(sessions []run.SessionRef) ([]run.SessionRef, error) {
	normalized := make([]run.SessionRef, 0, len(sessions))
	seen := make(map[string]struct{}, len(sessions))
	for index, session := range sessions {
		session = cloneSessionRef(session)
		session.ID = strings.TrimSpace(session.ID)
		if session.ID == "" {
			return nil, fmt.Errorf("session %d id is required", index+1)
		}
		if _, exists := seen[session.ID]; exists {
			return nil, fmt.Errorf("session %q is duplicated", session.ID)
		}
		seen[session.ID] = struct{}{}
		normalized = append(normalized, session)
	}
	return normalized, nil
}

func sessionsFromRPC(request run.Request, value any) ([]run.SessionRef, error) {
	items, err := rpcArray(value, "sessions")
	if err != nil {
		return nil, err
	}
	sessions := make([]run.SessionRef, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "sessions", index)
		if err != nil {
			return nil, err
		}
		capabilities, err := strictStringSlice(object["capabilities"], fmt.Sprintf("sessions item %d capabilities", index+1))
		if err != nil {
			return nil, err
		}
		session := run.SessionRef{
			ID:                 stringValue(object["id"]),
			RunID:              defaultString(stringValue(object["runId"]), request.ID),
			ModuleID:           defaultString(stringValue(object["moduleId"]), request.ModuleID),
			Target:             defaultString(stringValue(object["target"]), request.Target),
			Name:               stringValue(object["name"]),
			Kind:               defaultString(stringValue(object["kind"]), "shell"),
			State:              defaultString(stringValue(object["state"]), "active"),
			Transport:          defaultString(stringValue(object["transport"]), "stdio"),
			InstalledPayloadID: stringValue(object["installedPayloadId"]),
			Capabilities:       capabilities,
		}
		if session.ID == "" {
			return nil, fmt.Errorf("sessions item %d id is required", index+1)
		}
		sessions = append(sessions, session)
	}
	return normalizeSessionRefs(sessions)
}

func installedPayloadsFromRPC(value any) ([]run.InstalledPayloadDescriptor, error) {
	items, err := rpcArray(value, "installedPayloads")
	if err != nil {
		return nil, err
	}
	payloads := make([]run.InstalledPayloadDescriptor, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "installedPayloads", index)
		if err != nil {
			return nil, err
		}
		artifactIDs, err := strictStringSlice(object["artifactIds"], fmt.Sprintf("installedPayloads item %d artifactIds", index+1))
		if err != nil {
			return nil, err
		}
		reconnect, err := payloadProviderRecordFromRPC(object["reconnect"], fmt.Sprintf("installedPayloads item %d reconnect", index+1))
		if err != nil {
			return nil, err
		}
		cleanup, err := payloadProviderRecordFromRPC(object["cleanup"], fmt.Sprintf("installedPayloads item %d cleanup", index+1))
		if err != nil {
			return nil, err
		}
		metadata, err := stringMapFromRPC(object["metadata"], fmt.Sprintf("installedPayloads item %d metadata", index+1))
		if err != nil {
			return nil, err
		}
		payload := run.InstalledPayloadDescriptor{
			Provider:                 stringValue(object["provider"]),
			PayloadID:                stringValue(object["payloadId"]),
			PayloadVersion:           stringValue(object["payloadVersion"]),
			Target:                   stringValue(object["target"]),
			TargetID:                 stringValue(object["targetId"]),
			State:                    stringValue(object["state"]),
			Transport:                stringValue(object["transport"]),
			Endpoint:                 stringValue(object["endpoint"]),
			InstanceKey:              stringValue(object["instanceKey"]),
			StampID:                  stringValue(object["stampId"]),
			ArtifactIDs:              artifactIDs,
			SupportsReconnect:        boolValue(object["supportsReconnect"]),
			SupportsMultipleSessions: boolValue(object["supportsMultipleSessions"]),
			Reconnect:                reconnect,
			Cleanup:                  cleanup,
			Metadata:                 metadata,
		}
		if payload.Provider == "" {
			return nil, fmt.Errorf("installedPayloads item %d provider is required", index+1)
		}
		if payload.PayloadID == "" {
			return nil, fmt.Errorf("installedPayloads item %d payloadId is required", index+1)
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

func agentHintsFromRPC(value any) ([]run.AgentHint, error) {
	items, err := rpcArray(value, "agentHints")
	if err != nil {
		return nil, err
	}
	hints := make([]run.AgentHint, 0, len(items))
	for index, item := range items {
		object, err := rpcObjectItem(item, "agentHints", index)
		if err != nil {
			return nil, err
		}
		appliesTo, err := stringMapFromRPC(object["appliesTo"], fmt.Sprintf("agentHints item %d appliesTo", index+1))
		if err != nil {
			return nil, err
		}
		provenance, err := stringMapFromRPC(object["provenance"], fmt.Sprintf("agentHints item %d provenance", index+1))
		if err != nil {
			return nil, err
		}
		hint := run.AgentHint{
			Schema:     stringValue(object["schema"]),
			Phase:      stringValue(object["phase"]),
			Audience:   stringValue(object["audience"]),
			Risk:       stringValue(object["risk"]),
			AppliesTo:  appliesTo,
			Text:       stringValue(object["text"]),
			Provenance: provenance,
		}
		if hint.Schema == "" {
			hint.Schema = "hovel.agent_hint.v1"
		}
		hints = append(hints, hint)
	}
	return hints, nil
}

func payloadProviderRecordFromRPC(value any, label string) (*run.PayloadProviderRecord, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	descriptor, err := optionalAnyMap(object["descriptor"], label+" descriptor")
	if err != nil {
		return nil, err
	}
	return &run.PayloadProviderRecord{
		ProviderID:    stringValue(object["providerId"]),
		Schema:        stringValue(object["schema"]),
		SchemaVersion: stringValue(object["schemaVersion"]),
		Descriptor:    descriptor,
	}, nil
}

func stringMapFromRPC(value any, label string) (map[string]string, error) {
	if value == nil {
		return nil, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	out := make(map[string]string, len(object))
	for key, item := range object {
		out[key] = stringValue(item)
	}
	return out, nil
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func displayName(moduleID string) string {
	parts := strings.Split(moduleID, "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func withStderr(prefix string, err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w: %s", prefix, err, stderr)
}

func moduleFailure(summary, prefix string, err error, stderr string) error {
	var callback callbackError
	if errors.As(err, &callback) {
		return err
	}
	return services.NewModuleExecutionFailure(summary, withStderr(prefix, err, stderr))
}

type callbackError struct {
	err error
}

func (e callbackError) Error() string {
	return e.err.Error()
}

func (e callbackError) Unwrap() error {
	return e.err
}

func (r Runner) appendLog(ctx context.Context, request run.Request, log rpcLog) error {
	if r.Events == nil || r.IDs == nil || r.Clock == nil {
		return nil
	}
	id, err := event.NewID(r.IDs.NewID())
	if err != nil {
		return err
	}
	eventType, err := event.NewType("hovel.module.log")
	if err != nil {
		return err
	}
	level := normalizeModuleLogLevel(log.Level)
	fields := map[string]string{
		"level":   string(level),
		"message": log.Message,
		"logger":  log.Logger,
	}
	for key, value := range log.Fields {
		fields[key] = fmt.Sprint(value)
	}
	if log.Exception != "" {
		fields["exception"] = log.Exception
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Level:     level,
		Message:   log.Message,
		Timestamp: r.Clock.Now(),
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
	return r.Events.Append(ctx, evt)
}

func normalizeModuleLogLevel(level string) event.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return event.LevelDebug
	case "", "info":
		return event.LevelInfo
	case "warn", "warning":
		return event.LevelWarn
	case "error", "exception", "critical", "fatal":
		return event.LevelError
	default:
		return event.LevelInfo
	}
}

func (r Runner) appendSessionCreated(ctx context.Context, request run.Request, session run.SessionRef) error {
	if r.Events == nil || r.IDs == nil || r.Clock == nil {
		return nil
	}
	id, err := event.NewID(r.IDs.NewID())
	if err != nil {
		return err
	}
	eventType, err := event.NewType("hovel.session.created")
	if err != nil {
		return err
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Message:   "session opened",
		Timestamp: r.Clock.Now(),
		Refs: event.Refs{
			Operation: request.Operation,
			Chain:     request.Chain,
			RunID:     request.ID,
			ModuleID:  request.ModuleID,
			TargetID:  request.Target,
			SessionID: session.ID,
		},
		Fields: map[string]string{
			"sessionId": session.ID,
			"name":      session.Name,
			"kind":      session.Kind,
			"state":     session.State,
			"transport": session.Transport,
		},
	})
	if err != nil {
		return err
	}
	return r.Events.Append(ctx, evt)
}
