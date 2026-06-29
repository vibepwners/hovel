package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Vibe-Pwners/hovel/internal/app/hovelconfig"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/modulepackage"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorlog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/app/services"
	"github.com/Vibe-Pwners/hovel/internal/domain/daemon"
	"github.com/Vibe-Pwners/hovel/internal/domain/event"
	domainmodule "github.com/Vibe-Pwners/hovel/internal/domain/module"
	"github.com/Vibe-Pwners/hovel/internal/domain/run"
	workspacepath "github.com/Vibe-Pwners/hovel/internal/domain/workspace"
)

type WorkspaceInitializer interface {
	InitWorkspace(context.Context, services.InitWorkspaceRequest) (services.InitWorkspaceResult, error)
}

type DaemonStatusProvider interface {
	Status(context.Context, services.DaemonStatusRequest) (daemon.Status, error)
}

type PendingThrowCoordinator interface {
	CreatePendingThrow(context.Context, string, PendingThrowCreateRequest) (PendingThrowSnapshot, error)
	RequirePendingThrowReady(context.Context, string, string) (PendingThrowSnapshot, error)
	CancelPendingThrow(context.Context, string, string) error
}

type LaunchKeyPolicyManager interface {
	GetLaunchKeyPolicy(context.Context, string, string) (LaunchKeyPolicySnapshot, error)
	SetLaunchKeyPolicy(context.Context, string, LaunchKeyPolicySetRequest) (LaunchKeyPolicySnapshot, error)
}

type RunClientFactory interface {
	DialRunClient(socketPath string) (RunClient, error)
}

type RunClient interface {
	Close() error
	RunMockExploit(context.Context, RunMockExploitRequest) (RunMockExploitResponse, error)
	GeneratePayload(context.Context, string, GeneratePayloadRequest) (PayloadArtifactSet, error)
	ListPayloadCommands(context.Context, string, RunPayloadCommandListRequest) ([]PayloadCommand, error)
	RunPayloadCommand(context.Context, RunPayloadCommandRunRequest) (PayloadCommandResult, error)
	ListSessions(context.Context) ([]SessionRef, error)
	ReadSession(context.Context, string, time.Duration) (SessionChunk, error)
	TailSession(context.Context, string, SessionTailOptions) (SessionChunk, error)
	WriteSession(context.Context, string, []byte) error
	CloseSession(context.Context, string) error
	ListSessionCommands(context.Context, string, RunSessionCommandListRequest) ([]PayloadCommand, error)
	RunSessionCommand(context.Context, RunSessionCommandRunRequest) (PayloadCommandResult, error)
}

type RunLogPoller interface {
	PollOperationChainLogs(context.Context, string, string, uint64) (RunLogPollResult, error)
}

type RunLogPollResult struct {
	Last uint64
	Logs []RunPublishedLog
}

type RunPublishedLog struct {
	Seq       uint64
	Operation string
	Chain     string
	Entry     operatorlog.Entry
}

type PendingThrowCreateRequest struct {
	ID             string
	Operation      string
	Chain          string
	PlanHash       string
	AllowDangerous bool
	NowBypass      bool
}

type PendingThrowSnapshot struct {
	ID                  string
	Operation           string
	Chain               string
	PlanHash            string
	AllowDangerous      bool
	NowBypass           bool
	Ready               bool
	RequiredApproverIDs []string
	MissingApproverIDs  []string
}

type LaunchKeyPolicySetRequest struct {
	Operation        string
	Mode             string
	Quorum           int
	HeartbeatTimeout string
}

type LaunchKeyPolicySnapshot struct {
	Operation        string `json:"operation"`
	Mode             string `json:"mode"`
	Quorum           int    `json:"quorum,omitempty"`
	HeartbeatTimeout string `json:"heartbeatTimeout,omitempty"`
}

type CapabilityChainRunner interface {
	ExecuteCapabilityChain(context.Context, CapabilityChainRequest) (CapabilityChainResponse, error)
}

type ThrowPlanRecorder interface {
	RecordThrowPlan(context.Context, ThrowPlanRecord) error
}

type ThrowRecorder interface {
	RecordThrow(context.Context, ThrowRecord) error
}

type ThrowConfirmationRecorder interface {
	RecordThrowConfirmation(context.Context, ThrowConfirmationRecord) error
}

type ArtifactRecorder interface {
	MaterializeArtifact(context.Context, ArtifactMaterialization) (ArtifactRecord, error)
}

type ArtifactRepository interface {
	ListArtifacts(context.Context, string) ([]ArtifactRecord, error)
	GetArtifact(context.Context, string, string) (ArtifactRecord, error)
}

type EventRecorder interface {
	RecordEvent(context.Context, string, event.Event) error
}

type EventRepository interface {
	ListEvents(context.Context, string, event.Filter) ([]event.Event, error)
}

type ThrowConfirmationRepository interface {
	GetThrowConfirmation(context.Context, string, string) (ThrowConfirmationRecord, bool, error)
}

type ThrowPlanRepository interface {
	ListThrowPlans(context.Context, string) ([]ThrowPlanRecord, error)
	GetThrowPlan(context.Context, string, string) (ThrowPlanRecord, error)
}

type ChainFileStore interface {
	WriteChainFile(context.Context, string, ChainFile) error
	ReadChainFile(context.Context, string) (ChainFile, error)
}

type OperatorSession interface {
	CreateOperation(string) error
	UseOperation(string) error
	CreateChain(string) error
	UseChain(string) error
	RenameChain(string, string) error
	DeleteChain(string) error
	AddModule(string) (operatorsession.Step, error)
	AddStep(string, string) (operatorsession.Step, error)
	AddTarget(string) error
	ClearTargets()
	CreateTargetSet(string) error
	AddTargetToSet(string, string) error
	RemoveTargetFromSet(string, string) error
	SetChainConfig(string, string) error
	UnsetChainConfig(string) error
	SetTargetConfig(string, string, string) error
	UnsetTargetConfig(string, string) error
	AppendLog(...operatorlog.Entry) error
	AppendLogToChain(string, ...operatorlog.Entry) error
	ActiveLogs() []operatorlog.Entry
	Snapshot() operatorsession.State
}

type publishedFeedbackSession interface {
	RemoteFeedback() bool
}

type Runtime struct {
	Workspaces         WorkspaceInitializer
	Daemons            DaemonStatusProvider
	PendingThrows      PendingThrowCoordinator
	LaunchKeyPolicies  LaunchKeyPolicyManager
	Runs               RunClientFactory
	CapabilityChains   CapabilityChainRunner
	Plans              ThrowPlanRecorder
	Throws             ThrowRecorder
	Confirmations      ThrowConfirmationRecorder
	Artifacts          ArtifactRecorder
	ArtifactRecords    ArtifactRepository
	Events             EventRecorder
	EventRecords       EventRepository
	ThrowConfirmations ThrowConfirmationRepository
	ThrowPlans         ThrowPlanRepository
	ChainFiles         ChainFileStore
	Session            OperatorSession
	Modules            ModuleDatabase
	ModuleChecks       ModuleChecker
	ModuleInspector    ModuleInspector
	Payloads           PayloadRepository
	PayloadProviders   PayloadProviderService
}

type ModuleDatabase interface {
	List() []modulecatalog.Module
	ByType(modulecatalog.ModuleType) []modulecatalog.Module
	Search(string) []modulecatalog.Module
	Find(string) (modulecatalog.Module, bool)
	Validate(modulecatalog.ConfigView) modulecatalog.Validation
	ResolveStepAvailability([]modulecatalog.Capability) []modulecatalog.StepAvailability
}

type ModuleInspector interface {
	InspectPackage(context.Context, modulepackage.Package) (modulecatalog.Module, error)
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

type RunPayloadCommandListRequest = run.PayloadCommandListRequest
type RunSessionCommandListRequest = run.PayloadCommandListRequest
type GeneratePayloadRequest = run.GeneratePayloadRequest
type PayloadArtifactSet = run.PayloadArtifactSet
type PayloadArtifact = run.PayloadArtifact

type RunPayloadCommandRunRequest struct {
	Operation string
	Chain     string
	ModuleID  string
	Request   run.PayloadCommandRequest
}

type RunSessionCommandRunRequest struct {
	SessionID string
	Request   run.PayloadCommandRequest
}

type Finding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Artifact struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Data string `json:"data,omitempty"`
	Path string `json:"path,omitempty"`
}

type ArtifactRecord struct {
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	ThrowID   string `json:"throwId"`
	RunID     string `json:"runId"`
	ModuleID  string `json:"moduleId"`
	Target    string `json:"target"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int    `json:"size"`
	CreatedAt string `json:"createdAt"`
}

type ArtifactMaterialization struct {
	Workspace string
	ThrowID   string
	RunID     string
	ModuleID  string
	Target    string
	Artifact  Artifact
	CreatedAt time.Time
}

type SessionRef struct {
	ID                 string   `json:"id"`
	RunID              string   `json:"runId"`
	ModuleID           string   `json:"moduleId"`
	Target             string   `json:"target"`
	Name               string   `json:"name,omitempty"`
	Kind               string   `json:"kind"`
	State              string   `json:"state"`
	Transport          string   `json:"transport"`
	InstalledPayloadID string   `json:"installedPayloadId,omitempty"`
	Capabilities       []string `json:"capabilities"`
}

type SessionChunk struct {
	SessionID string `json:"sessionId"`
	Data      []byte `json:"data"`
	Closed    bool   `json:"closed"`
}

type SessionTailOptions struct {
	MaxBytes int
	MaxLines int
	Consume  bool
}

type LogEntry struct {
	ID             string            `json:"id,omitempty"`
	Time           string            `json:"time,omitempty"`
	Topic          string            `json:"topic,omitempty"`
	Kind           string            `json:"kind,omitempty"`
	Level          string            `json:"level"`
	Source         string            `json:"source,omitempty"`
	Message        string            `json:"message"`
	Logger         string            `json:"logger,omitempty"`
	ChainID        string            `json:"chainId,omitempty"`
	ChainName      string            `json:"chainName,omitempty"`
	RunID          string            `json:"runId,omitempty"`
	Target         string            `json:"target,omitempty"`
	ModuleID       string            `json:"moduleId,omitempty"`
	ElapsedSeconds *float64          `json:"elapsedSeconds,omitempty"`
	Fields         map[string]string `json:"fields,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
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

type CapabilityChainRequest struct {
	Operation    string
	Chain        string
	Target       string
	Steps        []CapabilityChainStepRef
	ChainConfig  map[string]string
	TargetConfig map[string]string
	ThrowID      string
	RunID        string
	ThrowStarted string
}

type CapabilityChainStepRef struct {
	ID       string `json:"id"`
	ModuleID string `json:"moduleId"`
	StepID   string `json:"stepId"`
}

type CapabilityChainResponse struct {
	RunID             string
	Target            string
	State             string
	Summary           string
	Capabilities      []CapabilityPayload
	Evidence          []CapabilityEvidence
	Logs              []LogEntry
	Sessions          []SessionRef
	InstalledPayloads []InstalledPayloadDescriptor
}

type CapabilityPayload struct {
	ID             string         `json:"id"`
	Type           string         `json:"type"`
	SchemaVersion  string         `json:"schemaVersion,omitempty"`
	State          string         `json:"state,omitempty"`
	ProducerStepID string         `json:"producerStepId,omitempty"`
	Attributes     map[string]any `json:"attributes,omitempty"`
	Extensions     map[string]any `json:"extensions,omitempty"`
}

type CapabilityEvidence struct {
	ID           string         `json:"id,omitempty"`
	Level        string         `json:"level,omitempty"`
	Kind         string         `json:"kind,omitempty"`
	SourceStepID string         `json:"sourceStepId,omitempty"`
	Message      string         `json:"message"`
	Details      map[string]any `json:"details,omitempty"`
}

type InitPayload struct {
	Created   bool `json:"created"`
	Workspace struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"workspace"`
}

type DaemonStatusPayload struct {
	State         string `json:"state"`
	WorkspacePath string `json:"workspacePath"`
	PID           int    `json:"pid,omitempty"`
	SocketPath    string `json:"socketPath,omitempty"`
	Health        string `json:"health,omitempty"`
}

type RunPayload struct {
	RunID             string                       `json:"runId"`
	ModuleID          string                       `json:"moduleId"`
	Target            string                       `json:"target"`
	State             string                       `json:"state"`
	Summary           string                       `json:"summary"`
	Findings          []Finding                    `json:"findings"`
	Artifacts         []Artifact                   `json:"artifacts"`
	Capabilities      []CapabilityPayload          `json:"capabilities,omitempty"`
	Evidence          []CapabilityEvidence         `json:"evidence,omitempty"`
	Logs              []LogEntry                   `json:"logs"`
	Sessions          []SessionRef                 `json:"sessions"`
	InstalledPayloads []InstalledPayloadDescriptor `json:"installedPayloads,omitempty"`
}

type ThrowPayload struct {
	Plan    ThrowPlanPayload `json:"plan"`
	ThrowID string           `json:"throwId,omitempty"`
	Chain   string           `json:"chain"`
	Targets []string         `json:"targets"`
	Results []RunPayload     `json:"results"`
}

type ThrowInspectPayload struct {
	Plan   ThrowPlanRecord `json:"plan"`
	Events []event.Event   `json:"events,omitempty"`
}

type ThrowPlanPayload struct {
	ID             string                   `json:"id"`
	ConfirmationID string                   `json:"confirmationId"`
	PlanHash       string                   `json:"planHash"`
	Chain          string                   `json:"chain"`
	Targets        []string                 `json:"targets"`
	Steps          []CapabilityChainStepRef `json:"steps,omitempty"`
	Review         string                   `json:"review"`
}

type ThrowPlanRecord struct {
	ID             string                       `json:"id"`
	ConfirmationID string                       `json:"confirmationId"`
	PlanHash       string                       `json:"planHash"`
	Workspace      string                       `json:"workspace"`
	Operation      string                       `json:"operation,omitempty"`
	Chain          string                       `json:"chain"`
	Targets        []string                     `json:"targets"`
	Modules        []string                     `json:"modules,omitempty"`
	Steps          []CapabilityChainStepRef     `json:"steps,omitempty"`
	ChainConfig    map[string]string            `json:"chainConfig,omitempty"`
	TargetConfigs  map[string]map[string]string `json:"targetConfigs,omitempty"`
	Review         string                       `json:"review"`
	Intent         string                       `json:"intent"`
}

type ThrowRecord struct {
	ID          string       `json:"id"`
	Workspace   string       `json:"workspace"`
	PlanID      string       `json:"planId"`
	PlanHash    string       `json:"planHash"`
	Chain       string       `json:"chain"`
	Targets     []string     `json:"targets"`
	State       string       `json:"state"`
	StartedAt   string       `json:"startedAt"`
	CompletedAt string       `json:"completedAt"`
	Runs        []RunSummary `json:"runs"`
}

type RunSummary struct {
	RunID     string `json:"runId"`
	ModuleID  string `json:"moduleId"`
	Target    string `json:"target"`
	State     string `json:"state"`
	Summary   string `json:"summary"`
	Artifacts int    `json:"artifacts"`
	Findings  int    `json:"findings"`
}

type ThrowConfirmationRecord struct {
	ID          string `json:"id"`
	Workspace   string `json:"workspace"`
	PlanID      string `json:"planId"`
	PlanHash    string `json:"planHash"`
	ClientID    string `json:"clientId"`
	Method      string `json:"method"`
	ConfirmedAt string `json:"confirmedAt"`
}

func (r ThrowPlanRecord) Payload() ThrowPlanPayload {
	return ThrowPlanPayload{
		ID:             r.ID,
		ConfirmationID: r.ConfirmationID,
		PlanHash:       r.PlanHash,
		Chain:          r.Chain,
		Targets:        append([]string(nil), r.Targets...),
		Steps:          cloneCapabilityChainStepRefs(r.Steps),
		Review:         r.Review,
	}
}

type ValidationPayload struct {
	Valid  bool                  `json:"valid"`
	Issues []modulecatalog.Issue `json:"issues"`
}

type ModuleInspectPayload struct {
	ID           string                      `json:"id"`
	Name         string                      `json:"name,omitempty"`
	Type         modulecatalog.ModuleType    `json:"type"`
	Version      string                      `json:"version,omitempty"`
	Summary      string                      `json:"summary,omitempty"`
	Description  string                      `json:"description,omitempty"`
	Tags         []string                    `json:"tags,omitempty"`
	RuntimeKind  string                      `json:"runtimeKind,omitempty"`
	Author       string                      `json:"author,omitempty"`
	Enabled      bool                        `json:"enabled"`
	ChainConfig  []modulecatalog.Requirement `json:"chainConfig,omitempty"`
	TargetConfig []modulecatalog.Requirement `json:"targetConfig,omitempty"`
	Discovery    *modulecatalog.Context      `json:"discoveryContext,omitempty"`
	Planning     *modulecatalog.Context      `json:"planningContext,omitempty"`
	Steps        []ModuleStepPayload         `json:"steps,omitempty"`
}

type ModuleStepPayload struct {
	ID       string                                `json:"id"`
	Kind     string                                `json:"kind"`
	Ready    bool                                  `json:"ready"`
	Requires []modulecatalog.CapabilityRequirement `json:"requires,omitempty"`
	Produces []modulecatalog.CapabilityRequirement `json:"produces,omitempty"`
	Context  *modulecatalog.Context                `json:"context,omitempty"`
	Missing  []modulecatalog.MissingCapability     `json:"missing,omitempty"`
}

type ModuleInstallPayload struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Reference string `json:"reference"`
	Source    string `json:"source"`
	Workspace string `json:"workspace"`
	Linked    bool   `json:"linked"`
}

type ModuleUninstallPayload struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Reference string `json:"reference"`
	Source    string `json:"source"`
	Workspace string `json:"workspace"`
	Linked    bool   `json:"linked"`
}

type ModuleBulkInstallPayload struct {
	Workspace string                 `json:"workspace"`
	Installed []ModuleInstallPayload `json:"installed"`
}

type ModuleInventoryPayload struct {
	Modules []ModuleInventoryRecord `json:"modules"`
}

type ModuleInventoryRecord struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Version     string                   `json:"version"`
	Type        modulecatalog.ModuleType `json:"type,omitempty"`
	Summary     string                   `json:"summary,omitempty"`
	Scope       string                   `json:"scope"`
	SourceKind  string                   `json:"sourceKind"`
	Source      string                   `json:"source"`
	SHA256      string                   `json:"sha256,omitempty"`
	Linked      bool                     `json:"linked,omitempty"`
	Installed   bool                     `json:"installed"`
	InstalledAt string                   `json:"installedAt,omitempty"`
}

type ChainFile struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ChainFileMetadata `json:"metadata"`
	Spec       ChainFileSpec     `json:"spec"`
}

type ChainFileMetadata struct {
	Name string `json:"name"`
}

type ChainFileSpec struct {
	Mode          string                       `json:"mode"`
	Steps         []ChainFileStep              `json:"steps"`
	Config        map[string]string            `json:"config,omitempty"`
	Targets       []ChainFileTarget            `json:"targets,omitempty"`
	TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
}

type ChainFileStep struct {
	ID   string `json:"id"`
	Uses string `json:"uses"`
	Step string `json:"step,omitempty"`
}

type ChainFileTarget struct {
	ID     string            `json:"id"`
	Config map[string]string `json:"config,omitempty"`
}

func HovelRegistry(runtime Runtime) Registry {
	return MustRegistry(withCommonOptions(
		Definition{
			Path:    []string{"control", "init"},
			Summary: "Initialize a local Hovel workspace.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("name", "n", "Workspace name"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: initHandler(runtime),
		},
		Definition{
			Path:    []string{"control", "daemon", "status"},
			Summary: "Inspect daemon status for a workspace.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: daemonStatusHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "create"},
			Aliases: [][]string{{"operation", "create"}},
			Summary: "Create and select an operation.",
			Positionals: []Positional{
				{Name: "operation", Help: "Operation name", Required: true},
			},
			Handler: operationCreateHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "use"},
			Aliases: [][]string{{"operation", "use"}},
			Summary: "Select the active operation.",
			Positionals: []Positional{
				{Name: "operation", Help: "Operation name", Required: true},
			},
			Handler: operationUseHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "list"},
			Aliases: [][]string{{"operation", "list"}},
			Summary: "List operations in the operator session.",
			Handler: operationListHandler(runtime),
		},
		Definition{
			Path:    []string{"op", "inspect"},
			Aliases: [][]string{{"operation", "inspect"}},
			Summary: "Inspect the active operation.",
			Handler: operationInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "create"},
			Aliases: [][]string{{"chains", "create"}},
			Summary: "Create a chain for the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain name", Required: true},
			},
			Handler: chainCreateHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "use"},
			Aliases: [][]string{{"chains", "use"}},
			Summary: "Select the active chain for the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain or module identifier", Required: true},
			},
			Handler: chainUseHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "rename"},
			Aliases: [][]string{{"chains", "rename"}},
			Summary: "Rename a chain and keep its targets and logs.",
			Positionals: []Positional{
				{Name: "chain", Help: "Current chain name", Required: true},
				{Name: "name", Help: "New chain name", Required: true},
			},
			Handler: chainRenameHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "add"},
			Aliases: [][]string{{"chains", "add"}},
			Summary: "Add a module to the active chain.",
			Positionals: []Positional{
				{Name: "module", Help: "Module ID", Required: true},
			},
			Handler: chainAddHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "validate"},
			Aliases: [][]string{{"chains", "validate"}},
			Summary: "Validate active chain configuration.",
			Options: []Option{
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: chainValidateHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "save"},
			Aliases: [][]string{{"chains", "save"}},
			Summary: "Save the active chain to a YAML file.",
			Positionals: []Positional{
				{Name: "file", Help: "Chain YAML file path", Required: true},
			},
			Options: []Option{
				boolOption("template", "", "Save a targetless reusable chain template"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: chainSaveHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "load"},
			Aliases: [][]string{{"chains", "load"}},
			Summary: "Load a chain from a YAML file.",
			Positionals: []Positional{
				{Name: "file", Help: "Chain YAML file path", Required: true},
			},
			Options: []Option{
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: chainLoadHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "set"},
			Aliases: [][]string{{"chains", "config", "set"}},
			Summary: "Set active chain configuration.",
			Positionals: []Positional{
				{Name: "key", Help: "Configuration key", Required: true},
				{Name: "value", Help: "Configuration value", Required: true},
			},
			Handler: chainConfigSetHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "unset"},
			Aliases: [][]string{{"chains", "config", "unset"}},
			Summary: "Unset active chain configuration.",
			Positionals: []Positional{
				{Name: "key", Help: "Configuration key", Required: true},
			},
			Handler: chainConfigUnsetHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "config", "list"},
			Aliases: [][]string{{"chains", "config", "list"}},
			Summary: "List active chain configuration.",
			Handler: chainConfigListHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "list"},
			Aliases: [][]string{{"chains", "list"}},
			Summary: "List chains in the operator session.",
			Handler: chainListHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "inspect"},
			Aliases: [][]string{{"chains", "inspect"}},
			Summary: "Inspect the active chain.",
			Handler: chainInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "delete"},
			Aliases: [][]string{{"chains", "delete"}},
			Summary: "Delete a chain from the operator session.",
			Positionals: []Positional{
				{Name: "chain", Help: "Chain name", Required: true},
			},
			Handler: chainDeleteHandler(runtime),
		},
		Definition{
			Path:    []string{"chain", "logs"},
			Aliases: [][]string{{"chains", "logs"}},
			Summary: "Show logs for the active chain.",
			Handler: chainLogsHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "add"},
			Aliases: [][]string{{"targets", "add"}},
			Summary: "Add a target to the operator session.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetsAddHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "clear"},
			Aliases: [][]string{{"targets", "clear"}},
			Summary: "Clear targets from the operator session.",
			Handler: targetsClearHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "config", "set"},
			Aliases: [][]string{{"targets", "config", "set"}},
			Summary: "Set operation target configuration.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
				{Name: "key", Help: "Configuration key", Required: true},
				{Name: "value", Help: "Configuration value", Required: true},
			},
			Handler: targetsConfigSetHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "config", "unset"},
			Aliases: [][]string{{"targets", "config", "unset"}},
			Summary: "Unset operation target configuration.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
				{Name: "key", Help: "Configuration key", Required: true},
			},
			Handler: targetsConfigUnsetHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "config", "list"},
			Aliases: [][]string{{"targets", "config", "list"}},
			Summary: "List operation target configuration.",
			Positionals: []Positional{
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetsConfigListHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "set", "create"},
			Aliases: [][]string{{"targets", "set", "create"}},
			Summary: "Create an operation target set.",
			Positionals: []Positional{
				{Name: "name", Help: "Target set name", Required: true},
			},
			Handler: targetSetCreateHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "set", "add"},
			Aliases: [][]string{{"targets", "set", "add"}},
			Summary: "Add an operation target to a target set.",
			Positionals: []Positional{
				{Name: "name", Help: "Target set name", Required: true},
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetSetAddHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "set", "remove"},
			Aliases: [][]string{{"targets", "set", "remove"}},
			Summary: "Remove an operation target from a target set.",
			Positionals: []Positional{
				{Name: "name", Help: "Target set name", Required: true},
				{Name: "target", Help: "Target identifier", Required: true},
			},
			Handler: targetSetRemoveHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "set", "list"},
			Aliases: [][]string{{"targets", "set", "list"}},
			Summary: "List operation target sets.",
			Handler: targetSetListHandler(runtime),
		},
		Definition{
			Path:    []string{"target", "set", "inspect"},
			Aliases: [][]string{{"targets", "set", "inspect"}},
			Summary: "Inspect an operation target set.",
			Positionals: []Positional{
				{Name: "name", Help: "Target set name", Required: true},
			},
			Handler: targetSetInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "installed"},
			Aliases: [][]string{{"modules", "installed"}, {"module", "list"}, {"modules", "list"}},
			Summary: "List modules installed in the selected module scope.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				stringOption("type", "t", "Module type filter"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesInstalledHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "available"},
			Aliases: [][]string{{"modules", "available"}, {"module", "search"}, {"modules", "search"}},
			Summary: "List locally available modules from installed records, package paths, caches, and local indexes.",
			Positionals: []Positional{
				{Name: "query", Help: "Search query", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				stringOption("type", "t", "Module type filter"),
				stringOption("index", "", "Additional local module index path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesAvailableHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "install"},
			Aliases: [][]string{{"modules", "install"}},
			Summary: "Install a trusted module package.",
			Positionals: []Positional{
				{Name: "source", Help: "Module .tgz package, package reference, or URL", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				stringOption("link", "", "Link a development package root instead of copying a .tgz"),
				stringOption("index", "", "Additional module index path for named installs"),
				stringOption("sha256", "", "Expected SHA-256 for downloaded or copied packages"),
				boolOption("no-scripts", "", "Skip trusted package install scripts"),
				boolOption("offline", "", "Disable network use during install"),
				boolOption("no-cache", "", "Do not store downloaded module packages"),
				boolOption("replace", "", "Replace an installed module with the same name and version"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesInstallHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "manual-install"},
			Aliases: [][]string{{"modules", "manual-install"}, {"module", "manualinstall"}, {"modules", "manualinstall"}},
			Summary: "Install a local stdio command as a development module.",
			Positionals: []Positional{
				{Name: "name", Help: "Module package name", Required: true},
			},
			Passthrough: Passthrough{Name: "command", Help: "Stdio command and arguments", Required: true},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				stringOption("type", "t", "Optional package type hint: survey, exploit, or payload_provider"),
				stringOption("version", "", "Module package version (default 0.0.0-manual)"),
				stringOption("summary", "", "Module package summary"),
				stringListOption("tag", "", "Module tag; repeat for multiple tags"),
				boolOption("replace", "", "Replace an installed manual module with the same name and version"),
				boolOption("no-check", "", "Skip stdio module validation before installing"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesManualInstallHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "bulk-install"},
			Aliases: [][]string{{"modules", "bulk-install"}},
			Summary: "Install trusted module packages from a bulk manifest.",
			Positionals: []Positional{
				{Name: "manifest", Help: "ModuleInstallSet YAML file or HTTPS URL", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				boolOption("no-scripts", "", "Skip trusted package install scripts"),
				boolOption("offline", "", "Disable network use during install"),
				boolOption("no-cache", "", "Do not store downloaded module packages"),
				boolOption("replace", "", "Replace installed modules with the same name and version"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesBulkInstallHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "uninstall"},
			Aliases: [][]string{{"modules", "uninstall"}},
			Summary: "Uninstall a trusted module package.",
			Positionals: []Positional{
				{Name: "module", Help: "Installed module reference", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				boolOption("no-scripts", "", "Skip trusted package uninstall scripts"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesUninstallHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "inspect"},
			Aliases: [][]string{{"modules", "inspect"}},
			Summary: "Inspect a module in the module database.",
			Positionals: []Positional{
				{Name: "module", Help: "Module reference", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"module", "check"},
			Aliases: [][]string{{"modules", "check"}},
			Summary: "Run a non-executing validation suite against a module.",
			Positionals: []Positional{
				{Name: "module", Help: "Module reference, package directory, or .tgz package", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("global", "", "Use the global module install scope"),
				boolOption("all", "", "Check every module in the module database"),
				boolOption("warnings-as-errors", "", "Return exit code 1 when warnings are present"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: modulesCheckHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "available"},
			Aliases: [][]string{{"payload", "available"}, {"payloads", "list"}, {"payload", "list"}},
			Summary: "List payloads available from configured providers.",
			Options: []Option{
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsAvailableHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "installed"},
			Aliases: [][]string{{"payload", "installed"}},
			Summary: "List installed payload records.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("state", "", "Payload state filter"),
				boolOption("all", "a", "Include removed payloads"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsInstalledHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "inspect"},
			Aliases: [][]string{{"payload", "inspect"}},
			Summary: "Inspect an installed payload record.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("events", "", "Include payload inventory events"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "connect"},
			Aliases: [][]string{{"payload", "connect"}},
			Summary: "Reconnect to an installed payload when the provider supports it.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsConnectHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "cleanup"},
			Aliases: [][]string{{"payload", "cleanup"}},
			Summary: "Ask the payload provider to clean up an installed payload.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("reason", "", "Cleanup reason"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsCleanupHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "mark-removed"},
			Aliases: [][]string{{"payload", "mark-removed"}},
			Summary: "Mark an installed payload record as removed without probing the target.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("reason", "", "Removal reason"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsMarkRemovedHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "refresh"},
			Aliases: [][]string{{"payload", "refresh"}},
			Summary: "Refresh an installed payload record through its provider.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsRefreshHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "register-squatter"},
			Aliases: [][]string{{"payload", "register-squatter"}},
			Summary: "Register a manually installed Squatter TCP-bind payload.",
			Positionals: []Positional{
				{Name: "target", Help: "Target host or label", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("host", "", "Reachable Squatter host"),
				stringOption("port", "", "Squatter TCP bind port"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsRegisterSquatterHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "commands"},
			Aliases: [][]string{{"payload", "commands"}, {"payloads", "capabilities"}, {"payload", "capabilities"}},
			Summary: "List provider-owned payload capabilities for an installed payload.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsCommandsHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "call"},
			Aliases: [][]string{{"payload", "call"}, {"payloads", "command"}, {"payload", "command"}},
			Summary: "Call a provider-owned payload capability outside an interactive session.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
				{Name: "capability", Help: "Provider capability or command name", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringListOption("arg", "a", "Capability argument; repeat for multiple args"),
				stringListOption("set", "s", "Request config override as key=value; repeat for multiple values"),
				stringOption("input-file", "", "Local file path to pass as provider input"),
				stringOption("input-data", "", "Inline provider input data"),
				stringOption("input-encoding", "", "Encoding for inline input data"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsCallHandler(runtime),
		},
		Definition{
			Path:    []string{"payloads", "getfile"},
			Aliases: [][]string{{"payload", "getfile"}},
			Summary: "Download a file through an installed payload command.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
				{Name: "remote", Help: "Remote path", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsRunCommandHandler(runtime, "getfile"),
		},
		Definition{
			Path:    []string{"payloads", "putfile"},
			Aliases: [][]string{{"payload", "putfile"}},
			Summary: "Upload a local file through an installed payload command.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
				{Name: "local", Help: "Local path", Required: true},
				{Name: "remote", Help: "Remote path", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsRunCommandHandler(runtime, "putfile"),
		},
		Definition{
			Path:    []string{"payloads", "cmd"},
			Aliases: [][]string{{"payload", "cmd"}},
			Summary: "Run one cmd.exe command through an installed payload command.",
			Positionals: []Positional{
				{Name: "payload", Help: "Payload handle or record ID", Required: true},
				{Name: "command", Help: "Command line", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: payloadsRunCommandHandler(runtime, "cmd"),
		},
		Definition{
			Path:    []string{"artifact", "list"},
			Aliases: [][]string{{"artifacts", "list"}},
			Summary: "List materialized artifacts.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: artifactsListHandler(runtime),
		},
		Definition{
			Path:    []string{"artifact", "inspect"},
			Aliases: [][]string{{"artifacts", "inspect"}},
			Summary: "Inspect a materialized artifact.",
			Positionals: []Positional{
				{Name: "artifact", Help: "Artifact ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: artifactsInspectHandler(runtime),
		},
		Definition{
			Path:           []string{"throw"},
			Aliases:        [][]string{{"run"}},
			Summary:        "Throw the selected chain or a configured chain file.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "file", Help: "Configured chain YAML file", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				stringOption("target-set", "", "Target set name"),
				boolOption("now", "", "Bypass typed confirmation prompt"),
				boolOption("allow-dangerous", "", "Permit modules tagged dangerous"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwHandler(runtime),
		},
		Definition{
			Path:    []string{"throw", "plan"},
			Summary: "Create or refresh a persisted throw plan without confirming or executing.",
			Positionals: []Positional{
				{Name: "file", Help: "Configured chain YAML file", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				stringOption("target-set", "", "Target set name"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwPlanHandler(runtime),
		},
		Definition{
			Path:    []string{"confirm"},
			Summary: "Pre-confirm the selected throw plan or chain file without executing it.",
			Positionals: []Positional{
				{Name: "file", Help: "Configured chain YAML file", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				stringOption("target-set", "", "Target set name"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: confirmHandler(runtime),
		},
		Definition{
			Path:    []string{"review"},
			Summary: "Review and confirm the selected throw plan or chain file without executing it.",
			Positionals: []Positional{
				{Name: "file", Help: "Configured chain YAML file", Required: false},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("chain", "c", "Chain name or module reference"),
				stringOption("target", "t", "Target identifier"),
				stringOption("target-set", "", "Target set name"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: reviewHandler(runtime),
		},
		Definition{
			Path:    []string{"throw", "list"},
			Aliases: [][]string{{"throws", "list"}},
			Summary: "List recorded throw plans.",
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwsListHandler(runtime),
		},
		Definition{
			Path:    []string{"throw", "inspect"},
			Aliases: [][]string{{"throws", "inspect"}},
			Summary: "Inspect a recorded throw plan.",
			Positionals: []Positional{
				{Name: "throw", Help: "Throw plan ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("events", "", "Include structured events for the reviewed plan"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: throwsInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"launch-key", "policy", "inspect"},
			Summary: "Inspect launch-key policy for an operation.",
			Options: []Option{
				stringOption("operation", "", "Operation name"),
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: launchKeyPolicyInspectHandler(runtime),
		},
		Definition{
			Path:    []string{"launch-key", "policy", "set"},
			Summary: "Set launch-key policy for an operation.",
			Positionals: []Positional{
				{Name: "mode", Help: "Policy mode: anyone, quorum, all_connected", Required: true},
			},
			Options: []Option{
				stringOption("operation", "", "Operation name"),
				stringOption("workspace", "w", "Workspace path"),
				stringOption("quorum", "", "Required approver count for quorum mode"),
				stringOption("heartbeat-timeout", "", "Live entity heartbeat timeout"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: launchKeyPolicySetHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "list"},
			Aliases:        [][]string{{"sessions"}},
			Summary:        "List post-exploitation sessions.",
			RequiresDaemon: true,
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionsListHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "connect"},
			Aliases:        [][]string{{"sessions", "connect"}},
			Summary:        "Connect interactively to an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("history-lines", "", "Print this many recent lines before attaching; default 20"),
				stringOption("history-bytes", "", "Print this many recent bytes before attaching"),
				boolOption("no-history", "", "Attach without printing recent session output"),
			},
			Handler: sessionConnectHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "tail"},
			Aliases:        [][]string{{"sessions", "tail"}},
			Summary:        "Print recent output from an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("bytes", "b", "Maximum recent bytes to print"),
				stringOption("lines", "n", "Maximum recent lines to print; default 20"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionTailHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "read"},
			Aliases:        [][]string{{"sessions", "read"}},
			Summary:        "Read buffered output from an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("tail", "t", "Continue reading until the session closes or the command is interrupted"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionReadHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "send"},
			Aliases:        [][]string{{"sessions", "send"}, {"session", "write"}, {"sessions", "write"}},
			Summary:        "Send data to an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
				{Name: "data", Help: "Data to send", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringOption("end", "e", "Terminator to append; supports escapes like \\n, \\r, \\0, and \\xNN"),
				boolOption("no-newline", "n", "Do not append the default newline terminator"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionSendHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "close"},
			Aliases:        [][]string{{"sessions", "close"}},
			Summary:        "Close an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionCloseHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "commands"},
			Aliases:        [][]string{{"sessions", "commands"}, {"session", "capabilities"}, {"sessions", "capabilities"}},
			Summary:        "List typed capabilities exposed by an active session.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionCommandsHandler(runtime),
		},
		Definition{
			Path:           []string{"session", "call"},
			Aliases:        [][]string{{"sessions", "call"}, {"session", "command"}, {"sessions", "command"}},
			Summary:        "Call a typed session capability without using the interactive byte stream.",
			RequiresDaemon: true,
			Positionals: []Positional{
				{Name: "session", Help: "Session ID", Required: true},
				{Name: "capability", Help: "Session capability or command name", Required: true},
			},
			Options: []Option{
				stringOption("workspace", "w", "Workspace path"),
				stringListOption("arg", "a", "Capability argument; repeat for multiple args"),
				stringListOption("set", "s", "Request config override as key=value; repeat for multiple values"),
				stringOption("input-file", "", "Local file path to pass as provider input"),
				stringOption("input-data", "", "Inline provider input data"),
				stringOption("input-encoding", "", "Encoding for inline input data"),
				boolOption("json", "j", "Emit JSON output"),
			},
			Handler: sessionCallHandler(runtime),
		},
	)...)
}

func stringOption(name, short, help string) Option {
	return Option{Name: name, Short: short, Help: help, Kind: OptionString}
}

func stringListOption(name, short, help string) Option {
	return Option{Name: name, Short: short, Help: help, Kind: OptionStringList}
}

func boolOption(name, short, help string) Option {
	return Option{Name: name, Short: short, Help: help, Kind: OptionBool}
}

func withCommonOptions(definitions ...Definition) []Definition {
	common := []Option{
		stringOption("config", "", "Config file path"),
		boolOption("no-color", "", "Disable styled terminal output"),
		boolOption("verbose", "v", "Emit verbose output"),
		boolOption("debug", "", "Emit debug output"),
	}
	out := make([]Definition, 0, len(definitions))
	for _, definition := range definitions {
		for _, option := range common {
			if !definitionHasOption(definition, option.Name) {
				definition.Options = append(definition.Options, option)
			}
		}
		out = append(out, definition)
	}
	return out
}

func definitionHasOption(definition Definition, name string) bool {
	for _, option := range definition.Options {
		if option.Name == name {
			return true
		}
	}
	return false
}

func initHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Workspaces == nil {
			return Result{}, fmt.Errorf("workspace service is not configured")
		}
		path := workspacepath.ResolvePath(invocation.Option("workspace"))
		name := invocation.Option("name")
		if name == "" {
			name = defaultWorkspaceName(path)
		}

		result, err := runtime.Workspaces.InitWorkspace(ctx, services.InitWorkspaceRequest{
			Name: name,
			Path: path,
		})
		if err != nil {
			return Result{}, err
		}

		payload := InitPayload{Created: result.Created}
		payload.Workspace.ID = result.Workspace.ID.String()
		payload.Workspace.Name = result.Workspace.Name.String()
		payload.Workspace.Path = result.Workspace.Path

		if result.Created {
			return Result{
				Human: fmt.Sprintf("Initialized workspace %s at %s", result.Workspace.Name, result.Workspace.Path),
				JSON:  payload,
			}, nil
		}
		return Result{
			Human: fmt.Sprintf("Workspace %s already initialized at %s", result.Workspace.Name, result.Workspace.Path),
			JSON:  payload,
		}, nil
	}
}

func daemonStatusHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Daemons == nil {
			return Result{}, fmt.Errorf("daemon service is not configured")
		}
		status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{
			WorkspacePath: workspacepath.ResolvePath(invocation.Option("workspace")),
		})
		if err != nil {
			return Result{}, err
		}
		payload := daemonStatusPayload(status)
		if status.State == daemon.StateNotRunning {
			return Result{
				Human: fmt.Sprintf("Daemon not running for workspace %s", status.WorkspacePath),
				JSON:  payload,
			}, nil
		}
		return Result{
			Human: fmt.Sprintf("Daemon running for workspace %s pid=%d health=%s", status.WorkspacePath, status.Identity.PID, status.Identity.Health),
			JSON:  payload,
		}, nil
	}
}

func operationCreateHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		operation := invocation.Positional("operation")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op create")
		}
		if err := runtime.Session.CreateOperation(operation); err != nil {
			return Result{}, err
		}
		if err := runtime.Session.UseOperation(operation); err != nil {
			return Result{}, err
		}
		return Result{Human: fmt.Sprintf("Operation selected: %s", operation)}, nil
	}
}

func operationUseHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		operation := invocation.Positional("operation")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op use")
		}
		if err := runtime.Session.UseOperation(operation); err != nil {
			return Result{}, err
		}
		return Result{Human: fmt.Sprintf("Operation selected: %s", operation)}, nil
	}
}

func operationListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op list")
		}
		state := runtime.Session.Snapshot()
		if len(state.Operations) == 0 {
			return Result{Human: "No operations"}, nil
		}
		var lines []string
		for _, operation := range state.Operations {
			prefix := " "
			if operation.Name == state.ActiveOperation {
				prefix = "*"
			}
			lines = append(lines, fmt.Sprintf("%s %s chains=%d", prefix, operation.Name, len(operation.Chains)))
		}
		return Result{Human: strings.Join(lines, "\n")}, nil
	}
}

func operationInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("op inspect")
		}
		state := runtime.Session.Snapshot()
		lines := []string{
			fmt.Sprintf("Operation %s chains=%d targets=%d target_sets=%d active_chain=%s", state.ActiveOperation, len(state.Chains), len(state.Targets), len(state.TargetSets), displayValue(state.ActiveChain, "none")),
		}
		for _, chain := range state.Chains {
			prefix := " "
			if chain.Name == state.ActiveChain {
				prefix = "*"
			}
			lines = append(lines, fmt.Sprintf("%s %s steps=%d topic=%s", prefix, chain.Name, len(chain.Steps), chain.LogTopic))
		}
		return Result{Human: strings.Join(lines, "\n")}, nil
	}
}

func chainCreateHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain create")
		}
		if err := runtime.Session.CreateChain(chain); err != nil {
			return Result{}, err
		}
		if err := runtime.Session.UseChain(chain); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain created and selected: %s", chain)}, nil
	}
}

func chainUseHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain use")
		}
		if err := runtime.Session.UseChain(chain); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain selected: %s", chain)}, nil
	}
}

func chainRenameHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		name := invocation.Positional("name")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain rename")
		}
		if err := runtime.Session.RenameChain(chain, name); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain renamed: %s -> %s", chain, name)}, nil
	}
}

func chainAddHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		db, err := moduleDBForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		moduleID := invocation.Positional("module")
		if isSquatterBindAlias(moduleID) {
			if runtime.Session == nil {
				return Result{}, operatorSessionRequiredError("chain add")
			}
			module, ok := findSquatterProviderModule(db)
			if !ok {
				return Result{}, fmt.Errorf("module squatter@v0.1.0 does not exist")
			}
			moduleID = module.ID
			step, err := runtime.Session.AddModule(moduleID)
			if err != nil {
				return Result{}, withActiveChainHelp(err)
			}
			if err := runtime.Session.SetChainConfig(squatterTypeConfigKey, squatterTypeTCPBind); err != nil {
				return Result{}, withActiveChainHelp(err)
			}
			if feedbackPublished(runtime.Session) {
				return Result{}, nil
			}
			return Result{Human: fmt.Sprintf("Module added: %s as %s (%s=%s)", moduleID, step.ID, squatterTypeConfigKey, squatterTypeTCPBind)}, nil
		}
		module, ok := db.Find(moduleID)
		if !ok {
			return Result{}, fmt.Errorf("module %s does not exist", moduleID)
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain add")
		}
		step, err := runtime.Session.AddModule(module.ID)
		if err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if isSquatterProviderModule(module) {
			if err := runtime.Session.SetChainConfig(squatterTypeConfigKey, squatterTypeTCPBind); err != nil {
				return Result{}, withActiveChainHelp(err)
			}
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		if isSquatterProviderModule(module) {
			return Result{Human: fmt.Sprintf("Module added: %s as %s (%s=%s)", module.ID, step.ID, squatterTypeConfigKey, squatterTypeTCPBind)}, nil
		}
		return Result{Human: fmt.Sprintf("Module added: %s as %s", module.ID, step.ID)}, nil
	}
}

const (
	squatterTypeConfigKey  = "squatter.type"
	squatterTypeTCPBind    = "tcp-bind"
	squatterTypeSMBPipe    = "smb-named-pipe"
	moduleIndexHTTPTimeout = 30 * time.Second
)

func isSquatterBindAlias(value string) bool {
	ref := strings.ToLower(strings.TrimSpace(value))
	switch ref {
	case "squatter.bind", "squatter-bind", "squatter/tcp-bind", "squatter.tcp_bind":
		return true
	}
	return false
}

func isSquatterProviderModule(module modulecatalog.Module) bool {
	return strings.EqualFold(module.Name, "squatter") && module.Type == modulecatalog.TypePayloadProvider
}

func isSquatterProviderModuleID(db ModuleDatabase, moduleID string) bool {
	module, ok := db.Find(moduleID)
	return ok && isSquatterProviderModule(module)
}

func squatterProviderModuleID(db ModuleDatabase) string {
	if module, ok := findSquatterProviderModule(db); ok {
		return module.ID
	}
	return "squatter@v0.1.0"
}

func findSquatterProviderModule(db ModuleDatabase) (modulecatalog.Module, bool) {
	if db != nil {
		if module, ok := db.Find("squatter@v0.1.0"); ok {
			if isSquatterProviderModule(module) {
				return module, true
			}
		}
		for _, module := range db.Search("squatter") {
			if isSquatterProviderModule(module) {
				return module, true
			}
		}
	}
	return modulecatalog.Module{}, false
}

func legacyExecutionModuleIDs(db ModuleDatabase, modules []string) []string {
	out := make([]string, 0, len(modules))
	for _, moduleID := range modules {
		if moduleID == "squatter.bind" {
			out = append(out, squatterProviderModuleID(db))
			continue
		}
		out = append(out, moduleID)
	}
	return out
}

func legacyExecutionModuleIDsForThrow(runtime Runtime, db ModuleDatabase, throw throwExecution) []string {
	modules := legacyExecutionModuleIDs(db, throw.Modules)
	if !shouldAutoConnectSquatterPayloads(runtime, db, throw) {
		return modules
	}
	filtered := make([]string, 0, len(modules))
	for _, moduleID := range modules {
		if isSquatterTCPBindModule(db, moduleID, throw.ChainConfig) {
			continue
		}
		filtered = append(filtered, moduleID)
	}
	if len(filtered) == 0 {
		return modules
	}
	return filtered
}

func hasSquatterBindModule(modules []string) bool {
	for _, moduleID := range modules {
		if moduleID == "squatter.bind" {
			return true
		}
	}
	return false
}

func isSquatterTCPBindModule(db ModuleDatabase, moduleID string, config map[string]string) bool {
	module, ok := db.Find(moduleID)
	if !ok || !isSquatterProviderModule(module) {
		return false
	}
	transport := strings.TrimSpace(config["payload.transport"])
	if transport != "" {
		return transport == squatterTypeTCPBind
	}
	mode := strings.TrimSpace(config[squatterTypeConfigKey])
	return mode == "" || mode == squatterTypeTCPBind
}

func shouldAutoConnectSquatterPayloads(runtime Runtime, db ModuleDatabase, throw throwExecution) bool {
	if runtime.Payloads == nil || runtime.PayloadProviders == nil {
		return false
	}
	hasBridge := false
	hasInstaller := false
	for _, moduleID := range throw.Modules {
		if moduleID == "squatter.bind" || isSquatterTCPBindModule(db, moduleID, throw.ChainConfig) {
			hasBridge = true
			continue
		}
		hasInstaller = true
	}
	return hasBridge && hasInstaller
}

func chainFileHasSquatterTCPBindModule(db ModuleDatabase, steps []ChainFileStep, config map[string]string) bool {
	for _, step := range steps {
		if strings.TrimSpace(step.Step) != "" {
			continue
		}
		moduleID := strings.TrimPrefix(strings.TrimSpace(step.Uses), "module:")
		if isSquatterTCPBindModule(db, moduleID, config) {
			return true
		}
	}
	return false
}

func chainValidateHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		db, err := moduleDBForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		logCommandError("append validation start log", runtime.Session.AppendLog(operatorlog.Info("validate", "validation started")))
		validation := ValidateState(db, state)
		payload := ValidationPayload{Valid: validation.Valid, Issues: validation.Issues}
		if validation.Valid {
			logCommandError("append validation success log", runtime.Session.AppendLog(operatorlog.Success("validate", "validation completed")))
			return Result{
				Human: fmt.Sprintf("Chain %s valid", state.ActiveChain),
				JSON:  payload,
			}, nil
		}
		var lines []string
		lines = append(lines, fmt.Sprintf("Chain %s invalid", state.ActiveChain))
		logEntries := []operatorlog.Entry{operatorlog.Finding("validate", "validation failed")}
		for _, issue := range validation.Issues {
			lines = append(lines, "[!] "+issue.Message)
			logEntries = append(logEntries, operatorlog.Finding("validate", issue.Message,
				operatorlog.Field{Name: "scope", Value: string(issue.Scope)},
				operatorlog.Field{Name: "module", Value: issue.ModuleID},
				operatorlog.Field{Name: "target", Value: issue.Target},
				operatorlog.Field{Name: "key", Value: issue.Key},
			))
		}
		logCommandError("append validation failure log", runtime.Session.AppendLog(logEntries...))
		return Result{
			Human: strings.Join(lines, "\n"),
			JSON:  payload,
		}, nil
	}
}

func chainSaveHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.ChainFiles == nil {
			return Result{}, fmt.Errorf("chain file store is not configured")
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		chainFile := chainFileFromState(state, invocation.Flag("template"))
		path := invocation.Positional("file")
		if strings.TrimSpace(path) == "" {
			return Result{}, fmt.Errorf("chain file path is required")
		}
		if err := runtime.ChainFiles.WriteChainFile(ctx, path, chainFile); err != nil {
			return Result{}, err
		}
		mode := chainFile.Spec.Mode
		return Result{
			Human: fmt.Sprintf("Chain %s saved as %s to %s", chainFile.Metadata.Name, mode, path),
			JSON:  chainFile,
		}, nil
	}
}

func chainLoadHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.ChainFiles == nil {
			return Result{}, fmt.Errorf("chain file store is not configured")
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain load")
		}
		path := invocation.Positional("file")
		if strings.TrimSpace(path) == "" {
			return Result{}, fmt.Errorf("chain file path is required")
		}
		chainFile, err := runtime.ChainFiles.ReadChainFile(ctx, path)
		if err != nil {
			return Result{}, err
		}
		if err := loadChainFile(runtime.Session, chainFile); err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Chain loaded: %s", chainFile.Metadata.Name),
			JSON:  chainFile,
		}, nil
	}
}

func chainConfigSetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		key := invocation.Positional("key")
		value := invocation.Positional("value")
		if err := runtime.Session.SetChainConfig(key, value); err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain config set: %s", key)}, nil
	}
}

func chainConfigUnsetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		key := invocation.Positional("key")
		if err := runtime.Session.UnsetChainConfig(key); err != nil {
			return Result{}, withActiveChainHelp(err)
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain config unset: %s", key)}, nil
	}
}

func chainConfigListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		db, err := moduleDBForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		requirements := requirementsByKey(db, state, modulecatalog.ScopeChain)
		if len(state.Config) == 0 && len(requirements) == 0 {
			return Result{Human: "No chain config set\n\nNext: config interactive"}, nil
		}
		return Result{Human: "Chain config\n" + availableConfigLines(state.Config, requirements)}, nil
	}
}

func chainListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain list")
		}
		state := runtime.Session.Snapshot()
		if len(state.Chains) == 0 {
			return Result{Human: "No chains"}, nil
		}
		var lines []string
		for _, chain := range state.Chains {
			prefix := " "
			if chain.Name == state.ActiveChain {
				prefix = "*"
			}
			lines = append(lines, fmt.Sprintf("%s %s steps=%d topic=%s", prefix, chain.Name, len(chain.Steps), chain.LogTopic))
		}
		return Result{Human: strings.Join(lines, "\n")}, nil
	}
}

func chainInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		state := runtime.Session.Snapshot()
		if state.ActiveChain == "" {
			return Result{}, activeChainRequiredError()
		}
		return Result{Human: chainInspect(state)}, nil
	}
}

func chainDeleteHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		chain := invocation.Positional("chain")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("chain delete")
		}
		if err := runtime.Session.DeleteChain(chain); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Chain deleted: %s", chain)}, nil
	}
}

func chainLogsHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, activeChainRequiredError()
		}
		state := runtime.Session.Snapshot()
		if state.ActiveChain == "" {
			return Result{}, activeChainRequiredError()
		}
		logs := runtime.Session.ActiveLogs()
		if len(logs) == 0 {
			return Result{Human: fmt.Sprintf("No logs for chain %s", state.ActiveChain)}, nil
		}
		return Result{Log: operatorlog.New("HOVEL//CHAIN", state.ActiveChain, logs)}, nil
	}
}

func targetsAddHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		target := invocation.Positional("target")
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target add")
		}
		if err := runtime.Session.AddTarget(target); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target added: %s", target)}, nil
	}
}

func targetsClearHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target clear")
		}
		runtime.Session.ClearTargets()
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: "Targets cleared"}, nil
	}
}

func targetsConfigSetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target config set")
		}
		target := invocation.Positional("target")
		key := invocation.Positional("key")
		value := invocation.Positional("value")
		if err := runtime.Session.SetTargetConfig(target, key, value); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target config set: %s %s", target, key)}, nil
	}
}

func targetsConfigUnsetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target config unset")
		}
		target := invocation.Positional("target")
		key := invocation.Positional("key")
		if err := runtime.Session.UnsetTargetConfig(target, key); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target config unset: %s %s", target, key)}, nil
	}
}

func targetsConfigListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		state, err := activeState(runtime)
		if err != nil {
			return Result{}, err
		}
		target := invocation.Positional("target")
		config, ok := state.TargetConfigs[target]
		db, err := moduleDBForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		requirements := requirementsByKey(db, state, modulecatalog.ScopeTarget)
		if (!ok || len(config) == 0) && len(requirements) == 0 {
			return Result{Human: fmt.Sprintf("No target config for %s\n\nNext: target config set %s <key> <value>", target, target)}, nil
		}
		return Result{Human: fmt.Sprintf("Target config %s\n%s", target, availableConfigLines(config, requirements))}, nil
	}
}

func targetSetCreateHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target set create")
		}
		name := invocation.Positional("name")
		if err := runtime.Session.CreateTargetSet(name); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target set created: %s", name)}, nil
	}
}

func targetSetAddHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target set add")
		}
		name := invocation.Positional("name")
		target := invocation.Positional("target")
		if err := runtime.Session.AddTargetToSet(name, target); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target set updated: %s added %s", name, target)}, nil
	}
}

func targetSetRemoveHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target set remove")
		}
		name := invocation.Positional("name")
		target := invocation.Positional("target")
		if err := runtime.Session.RemoveTargetFromSet(name, target); err != nil {
			return Result{}, err
		}
		if feedbackPublished(runtime.Session) {
			return Result{}, nil
		}
		return Result{Human: fmt.Sprintf("Target set updated: %s removed %s", name, target)}, nil
	}
}

func targetSetListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target set list")
		}
		state := runtime.Session.Snapshot()
		if len(state.TargetSets) == 0 {
			return Result{Human: "No target sets"}, nil
		}
		lines := make([]string, 0, len(state.TargetSets))
		for _, set := range state.TargetSets {
			lines = append(lines, fmt.Sprintf("%s targets=%d", set.Name, len(set.Targets)))
		}
		return Result{Human: strings.Join(lines, "\n")}, nil
	}
}

func targetSetInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if runtime.Session == nil {
			return Result{}, operatorSessionRequiredError("target set inspect")
		}
		name := invocation.Positional("name")
		state := runtime.Session.Snapshot()
		for _, set := range state.TargetSets {
			if set.Name != name {
				continue
			}
			lines := []string{fmt.Sprintf("Target set %s targets=%d", set.Name, len(set.Targets))}
			lines = append(lines, set.Targets...)
			return Result{Human: strings.Join(lines, "\n"), JSON: set}, nil
		}
		return Result{}, fmt.Errorf("target set does not exist")
	}
}

func modulesInstalledHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		records, err := installedModuleRecordsForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		records = filterModuleInventoryRecords(records, invocation.Positional("query"), modulecatalog.ModuleType(invocation.Option("type")))
		payload := ModuleInventoryPayload{Modules: records}
		if len(records) == 0 {
			return Result{Human: "No installed modules", JSON: payload}, nil
		}
		return Result{Human: moduleInventoryLines(records), JSON: payload}, nil
	}
}

func modulesInstallHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		workspacePath := workspaceFromInvocation(invocation)
		linkPath := strings.TrimSpace(invocation.Option("link"))
		source := strings.TrimSpace(invocation.Positional("source"))
		sha := invocation.Option("sha256")
		if linkPath == "" {
			var err error
			source, linkPath, sha, err = resolveInstallReference(workspacePath, source, sha, invocation)
			if err != nil {
				return Result{}, err
			}
		}
		result, linked, err := installModuleSource(ctx, runtime, workspacePath, source, linkPath, sha, invocation)
		if err != nil {
			return Result{}, err
		}
		payload := ModuleInstallPayload{
			Name:      result.Name,
			Version:   result.Version,
			Reference: modulecatalog.CanonicalID(result.Name, result.Version),
			Source:    result.Source,
			Workspace: workspacePath,
			Linked:    linked,
		}
		return Result{
			Human: fmt.Sprintf("Installed module %s from %s", payload.Reference, payload.Source),
			JSON:  payload,
		}, nil
	}
}

func modulesManualInstallHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		workspacePath := workspaceFromInvocation(invocation)
		name, version, err := manualInstallIdentity(invocation)
		if err != nil {
			return Result{}, err
		}
		command, err := normalizeManualInstallCommand(invocation.PassthroughArgs())
		if err != nil {
			return Result{}, err
		}
		options, err := moduleInstallOptions(ctx, runtime, workspacePath, invocation)
		if err != nil {
			return Result{}, err
		}
		if err := os.MkdirAll(workspacePath, 0o755); err != nil {
			return Result{}, err
		}
		tempRoot, err := os.MkdirTemp(workspacePath, ".manual-module-*")
		if err != nil {
			return Result{}, err
		}
		tempActive := true
		defer func() {
			if tempActive {
				removePathBestEffort(tempRoot)
			}
		}()
		typeHint := strings.TrimSpace(invocation.Option("type"))
		if typeHint != "" {
			if _, err := modulecatalog.NewModuleType(typeHint); err != nil {
				return Result{}, err
			}
		}
		manifest := modulepackage.Manifest{
			APIVersion: modulepackage.APIVersion,
			Kind:       modulepackage.Kind,
			Metadata: modulepackage.Metadata{
				Name:       name,
				Version:    version,
				ModuleType: typeHint,
				Summary:    invocation.Option("summary"),
				Tags:       trimmedList(invocation.OptionList("tag")),
			},
			Runtime: modulepackage.Runtime{Protocol: modulepackage.ProtocolJSONRPCStdio},
			Launch: []modulepackage.Launch{{
				Selector: modulepackage.Selector{},
				Command:  command,
			}},
		}
		if err := modulepackage.WriteManifest(tempRoot, manifest); err != nil {
			return Result{}, err
		}
		if !invocation.Flag("no-check") {
			if err := checkManualInstallModule(ctx, runtime, tempRoot, workspacePath, invocation.Option("config")); err != nil {
				return Result{}, err
			}
		}
		identity, err := manualInstallResolvedIdentity(ctx, runtime, tempRoot, name, version)
		if err != nil {
			return Result{}, err
		}
		if err := ensureManualInstallAvailable(workspacePath, identity.Name, identity.Version, invocation.Flag("replace")); err != nil {
			return Result{}, err
		}
		root := manualInstallRoot(workspacePath, identity.Name, identity.Version)
		if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
			return Result{}, err
		}
		backup, err := moveManualInstallRootAside(root, invocation.Flag("replace"))
		if err != nil {
			return Result{}, err
		}
		if err := os.Rename(tempRoot, root); err != nil {
			restoreManualInstallRoot(backup)
			return Result{}, err
		}
		tempActive = false
		options.SourceDir = root
		options.ResolveIdentity = func(modulepackage.Package) (modulepackage.InstallIdentity, error) {
			return identity, nil
		}
		result, err := modulepackage.InstallPreparedDir(options)
		if err != nil {
			removePathBestEffort(root)
			restoreManualInstallRoot(backup)
			return Result{}, err
		}
		removeManualInstallBackup(backup)
		payload := ModuleInstallPayload{
			Name:      result.Name,
			Version:   result.Version,
			Reference: modulecatalog.CanonicalID(result.Name, result.Version),
			Source:    result.Source,
			Workspace: workspacePath,
			Linked:    false,
		}
		return Result{
			Human: fmt.Sprintf("Installed manual module %s from %s", payload.Reference, strings.Join(command, " ")),
			JSON:  payload,
		}, nil
	}
}

func manualInstallIdentity(invocation Invocation) (string, string, error) {
	name := strings.TrimSpace(invocation.Positional("name"))
	if _, err := domainmodule.NewName(name); err != nil {
		return "", "", err
	}
	version := strings.TrimSpace(invocation.Option("version"))
	if version == "" {
		version = "0.0.0-manual"
	}
	if _, err := domainmodule.NewVersion(version); err != nil {
		return "", "", err
	}
	if err := requirePathSegment(version, "module version"); err != nil {
		return "", "", err
	}
	return name, version, nil
}

func requirePathSegment(value, label string) error {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("%s must be a single path segment", label)
	}
	return nil
}

func manualInstallResolvedIdentity(ctx context.Context, runtime Runtime, root, fallbackName, fallbackVersion string) (modulepackage.InstallIdentity, error) {
	identity := modulepackage.InstallIdentity{Name: fallbackName, Version: fallbackVersion}
	if runtime.ModuleInspector != nil {
		pkg, err := modulepackage.LoadDir(root)
		if err != nil {
			return modulepackage.InstallIdentity{}, err
		}
		module, err := runtime.ModuleInspector.InspectPackage(ctx, pkg)
		if err != nil {
			return modulepackage.InstallIdentity{}, err
		}
		identity = installIdentityFromModule(module)
	}
	if err := requirePathSegment(identity.Name, "module name"); err != nil {
		return modulepackage.InstallIdentity{}, err
	}
	if err := requirePathSegment(identity.Version, "module version"); err != nil {
		return modulepackage.InstallIdentity{}, err
	}
	return identity, nil
}

func installIdentityFromModule(module modulecatalog.Module) modulepackage.InstallIdentity {
	name, version, _ := modulecatalog.SplitID(module.ID)
	if name == "" {
		name = module.Name
	}
	if version == "" {
		version = module.Version
	}
	return modulepackage.InstallIdentity{Name: strings.TrimSpace(name), Version: strings.TrimSpace(version)}
}

func normalizeManualInstallCommand(command []string) ([]string, error) {
	out := append([]string(nil), command...)
	if len(out) == 0 {
		return nil, fmt.Errorf("command after -- is required")
	}
	first := strings.TrimSpace(out[0])
	if first == "" {
		return nil, fmt.Errorf("command after -- is required")
	}
	switch {
	case filepath.IsAbs(first):
		out[0] = filepath.Clean(first)
	case strings.ContainsAny(first, `/\`):
		abs, err := filepath.Abs(first)
		if err != nil {
			return nil, err
		}
		out[0] = abs
	default:
		path, err := exec.LookPath(first)
		if err != nil {
			return nil, fmt.Errorf("manual module command %q was not found on PATH", first)
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		out[0] = path
	}
	return out, nil
}

func ensureManualInstallAvailable(workspacePath, name, version string, replace bool) error {
	lock, err := modulepackage.LoadLock(filepath.Join(workspacePath, "module-lock.yaml"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		for _, record := range lock.Modules {
			if record.Name == name && record.Version == version {
				if replace {
					break
				}
				return fmt.Errorf("module %s is already installed; use --replace", modulecatalog.CanonicalID(name, version))
			}
		}
	}
	root := manualInstallRoot(workspacePath, name, version)
	if _, err := os.Stat(root); err == nil && !replace {
		return fmt.Errorf("module package directory %s already exists; use --replace", root)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func manualInstallRoot(workspacePath, name, version string) string {
	return filepath.Join(workspacePath, "modules", name, version)
}

type manualInstallBackup struct {
	parent string
	path   string
	root   string
}

func moveManualInstallRootAside(root string, replace bool) (manualInstallBackup, error) {
	if !replace {
		return manualInstallBackup{}, nil
	}
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return manualInstallBackup{}, nil
	} else if err != nil {
		return manualInstallBackup{}, err
	}
	parent, err := os.MkdirTemp(filepath.Dir(root), ".replace-*")
	if err != nil {
		return manualInstallBackup{}, err
	}
	backup := manualInstallBackup{
		parent: parent,
		path:   filepath.Join(parent, filepath.Base(root)),
		root:   root,
	}
	if err := os.Rename(root, backup.path); err != nil {
		removePathBestEffort(parent)
		return manualInstallBackup{}, err
	}
	return backup, nil
}

func restoreManualInstallRoot(backup manualInstallBackup) {
	if backup.path == "" {
		return
	}
	removePathBestEffort(backup.root)
	if err := os.Rename(backup.path, backup.root); err != nil {
		return
	}
	removePathBestEffort(backup.parent)
}

func removeManualInstallBackup(backup manualInstallBackup) {
	if backup.parent != "" {
		removePathBestEffort(backup.parent)
	}
}

func checkManualInstallModule(ctx context.Context, runtime Runtime, root, workspacePath, configPath string) error {
	if runtime.ModuleChecks == nil {
		return nil
	}
	report, err := runtime.ModuleChecks.CheckModule(ctx, ModuleCheckRequest{
		Reference: root,
		Workspace: workspacePath,
		Config:    configPath,
	})
	if err != nil {
		return err
	}
	report.Normalize()
	if report.Failures() == 0 {
		return nil
	}
	return fmt.Errorf("manual module validation failed\n\n%s", singleModuleCheckHuman(report))
}

func trimmedList(values []string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func removePathBestEffort(path string) {
	if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
}

func modulesBulkInstallHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		workspacePath := workspaceFromInvocation(invocation)
		manifestPath := invocation.Positional("manifest")
		baseOptions, err := moduleInstallOptions(ctx, runtime, workspacePath, invocation)
		if err != nil {
			return Result{}, err
		}
		set, err := loadBulkInstallSet(manifestPath, baseOptions)
		if err != nil {
			return Result{}, err
		}
		baseDir := bulkInstallBaseDir(manifestPath)
		payload := ModuleBulkInstallPayload{Workspace: workspacePath}
		for i, item := range set.Modules {
			source := resolveBulkInstallSource(baseDir, item.Source)
			if invocation.InstallProgress != nil {
				invocation.InstallProgress(modulepackage.InstallProgress{
					Stage:  modulepackage.InstallProgressSetEntry,
					Source: source,
					SHA256: item.SHA256,
					Index:  i + 1,
					Count:  len(set.Modules),
				})
			}
			result, linked, err := installModuleSource(ctx, runtime, workspacePath, source, "", item.SHA256, invocation)
			if err != nil {
				return Result{}, err
			}
			payload.Installed = append(payload.Installed, ModuleInstallPayload{
				Name:      result.Name,
				Version:   result.Version,
				Reference: modulecatalog.CanonicalID(result.Name, result.Version),
				Source:    result.Source,
				Workspace: workspacePath,
				Linked:    linked,
			})
		}
		return Result{
			Human: fmt.Sprintf("Installed %d modules", len(payload.Installed)),
			JSON:  payload,
		}, nil
	}
}

func modulesUninstallHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		workspacePath := workspaceFromInvocation(invocation)
		name, version, hasVersion := modulecatalog.SplitID(invocation.Positional("module"))
		if !hasVersion {
			version = ""
		}
		result, err := modulepackage.Uninstall(modulepackage.UninstallOptions{
			Workspace: workspacePath,
			Name:      name,
			Version:   version,
			NoScripts: invocation.Flag("no-scripts"),
		})
		if err != nil {
			return Result{}, err
		}
		payload := ModuleUninstallPayload{
			Name:      result.Name,
			Version:   result.Version,
			Reference: modulecatalog.CanonicalID(result.Name, result.Version),
			Source:    result.Source,
			Workspace: workspacePath,
			Linked:    result.Linked,
		}
		return Result{
			Human: fmt.Sprintf("Uninstalled module %s from %s", payload.Reference, payload.Source),
			JSON:  payload,
		}, nil
	}
}

func installModuleSource(ctx context.Context, runtime Runtime, workspacePath, source, linkPath, sha string, invocation Invocation) (modulepackage.InstallResult, bool, error) {
	base, err := moduleInstallOptions(ctx, runtime, workspacePath, invocation)
	if err != nil {
		return modulepackage.InstallResult{}, false, err
	}
	switch {
	case linkPath != "" && source != "":
		return modulepackage.InstallResult{}, false, fmt.Errorf("module install accepts either --link or source, not both")
	case linkPath == "" && source == "":
		return modulepackage.InstallResult{}, false, fmt.Errorf("module install requires --link or source")
	case linkPath != "":
		base.SourceDir = linkPath
		result, err := modulepackage.InstallLink(base)
		return result, true, err
	case strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://"):
		base.SourceURL = source
		base.SHA256 = sha
		result, err := modulepackage.InstallURL(base)
		return result, false, err
	default:
		base.SourceArchive = source
		base.SHA256 = sha
		result, err := modulepackage.InstallArchive(base)
		return result, false, err
	}
}

func moduleInstallOptions(ctx context.Context, runtime Runtime, workspacePath string, invocation Invocation) (modulepackage.InstallOptions, error) {
	config, _, err := hovelconfig.Load(hovelconfig.Options{
		Workspace:    workspacePath,
		ExplicitPath: invocation.Option("config"),
	})
	if err != nil {
		return modulepackage.InstallOptions{}, err
	}
	options := modulepackage.InstallOptions{
		Workspace:                    workspacePath,
		HostOS:                       goruntime.GOOS,
		HostArch:                     goruntime.GOARCH,
		NoScripts:                    invocation.Flag("no-scripts"),
		Offline:                      invocation.Flag("offline"),
		NoCache:                      invocation.Flag("no-cache") || !config.Cache.Enabled,
		Replace:                      invocation.Flag("replace"),
		PythonBuildStandaloneRelease: config.Runtime.Python.PythonBuildStandalone.Release,
		Progress:                     invocation.InstallProgress,
	}
	if runtime.ModuleInspector != nil {
		options.ResolveIdentity = func(pkg modulepackage.Package) (modulepackage.InstallIdentity, error) {
			module, err := runtime.ModuleInspector.InspectPackage(ctx, pkg)
			if err != nil {
				return modulepackage.InstallIdentity{}, err
			}
			return installIdentityFromModule(module), nil
		}
	}
	return options, nil
}

func resolveInstallReference(workspacePath, source, sha string, invocation Invocation) (string, string, string, error) {
	if source == "" || strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") || strings.EqualFold(filepath.Ext(source), ".tgz") {
		return source, "", sha, nil
	}
	config, _, err := hovelconfig.Load(hovelconfig.Options{
		Workspace:    workspacePath,
		ExplicitPath: invocation.Option("config"),
	})
	if err != nil {
		return "", "", "", err
	}
	if config.Cache.Enabled && !invocation.Flag("no-cache") {
		cachePath, err := modulepackage.DownloadCacheDir("")
		if err != nil {
			return "", "", "", err
		}
		candidate, ok, err := resolveModuleSourceCandidate(source, []string{cachePath}, true)
		if err != nil {
			return "", "", "", err
		}
		if ok {
			if sha == "" {
				sha = candidate.SHA256
			}
			if candidate.Linked {
				return "", candidate.Source, sha, nil
			}
			return candidate.Source, "", sha, nil
		}
	}
	candidate, ok, err := resolveModuleSourceCandidate(source, config.Modules.SearchPaths, false)
	if err != nil {
		return "", "", "", err
	}
	if ok {
		if sha == "" {
			sha = candidate.SHA256
		}
		if candidate.Linked {
			return "", candidate.Source, sha, nil
		}
		return candidate.Source, "", sha, nil
	}
	indexPaths := moduleInventoryIndexPaths(config, invocation)
	if len(indexPaths) == 0 {
		return "", "", "", fmt.Errorf("module reference %s was not found in local module packages, caches, or configured indexes", source)
	}
	entry, indexPath, err := resolveIndexEntry(source, indexPaths, invocation.Flag("offline"))
	if err != nil {
		return "", "", "", err
	}
	resolved := entry.URL
	if !strings.HasPrefix(resolved, "https://") && !strings.HasPrefix(resolved, "http://") && strings.HasPrefix(indexPath, "https://") {
		base, err := url.Parse(indexPath)
		if err != nil {
			return "", "", "", err
		}
		relative, err := url.Parse(resolved)
		if err != nil {
			return "", "", "", err
		}
		resolved = base.ResolveReference(relative).String()
	} else if !strings.HasPrefix(resolved, "https://") && !strings.HasPrefix(resolved, "http://") && !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(indexPath), resolved)
	}
	if sha == "" {
		sha = entry.SHA256
	}
	return resolved, "", sha, nil
}

type moduleInstallSourceCandidate struct {
	Name    string
	Version string
	Source  string
	SHA256  string
	Linked  bool
}

func resolveModuleSourceCandidate(reference string, paths []string, missingOK bool) (moduleInstallSourceCandidate, bool, error) {
	var found moduleInstallSourceCandidate
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			if missingOK && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return moduleInstallSourceCandidate{}, false, err
		}
		if !info.IsDir() {
			candidate, ok, err := moduleSourceCandidate(reference, path)
			if err != nil {
				return moduleInstallSourceCandidate{}, false, err
			}
			if ok && betterModuleSourceCandidate(candidate, found) {
				found = candidate
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(path, modulepackage.ManifestName)); err == nil {
			candidate, ok, err := moduleSourceCandidate(reference, path)
			if err != nil {
				return moduleInstallSourceCandidate{}, false, err
			}
			if ok && betterModuleSourceCandidate(candidate, found) {
				found = candidate
			}
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return moduleInstallSourceCandidate{}, false, err
		}
		for _, entry := range entries {
			candidate, ok, err := moduleSourceCandidate(reference, filepath.Join(path, entry.Name()))
			if err != nil {
				return moduleInstallSourceCandidate{}, false, err
			}
			if ok && betterModuleSourceCandidate(candidate, found) {
				found = candidate
			}
		}
	}
	return found, found.Name != "", nil
}

func moduleSourceCandidate(reference, path string) (moduleInstallSourceCandidate, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return moduleInstallSourceCandidate{}, false, err
	}
	if info.IsDir() {
		return modulePackageDirCandidate(reference, path)
	}
	return modulePackageArchiveCandidate(reference, path)
}

func modulePackageDirCandidate(reference, path string) (moduleInstallSourceCandidate, bool, error) {
	if _, err := os.Stat(filepath.Join(path, modulepackage.ManifestName)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return moduleInstallSourceCandidate{}, false, nil
		}
		return moduleInstallSourceCandidate{}, false, err
	}
	pkg, err := modulepackage.LoadDir(path)
	if err != nil {
		return moduleInstallSourceCandidate{}, false, err
	}
	candidate := moduleInstallSourceCandidate{
		Name:    pkg.Manifest.Metadata.Name,
		Version: pkg.Manifest.Metadata.Version,
		Source:  pkg.Root,
		Linked:  true,
	}
	if !moduleSourceCandidateMatches(reference, candidate) {
		return moduleInstallSourceCandidate{}, false, nil
	}
	return candidate, true, nil
}

func modulePackageArchiveCandidate(reference, path string) (moduleInstallSourceCandidate, bool, error) {
	if !strings.EqualFold(filepath.Ext(path), ".tgz") {
		return moduleInstallSourceCandidate{}, false, nil
	}
	manifest, err := modulepackage.LoadManifestArchive(path)
	if err != nil {
		return moduleInstallSourceCandidate{}, false, err
	}
	candidate := moduleInstallSourceCandidate{
		Name:    manifest.Metadata.Name,
		Version: manifest.Metadata.Version,
		Source:  path,
	}
	if !moduleSourceCandidateMatches(reference, candidate) {
		return moduleInstallSourceCandidate{}, false, nil
	}
	sum, err := modulepackage.FileSHA256(path)
	if err != nil {
		return moduleInstallSourceCandidate{}, false, err
	}
	candidate.SHA256 = sum
	return candidate, true, nil
}

func moduleSourceCandidateMatches(reference string, candidate moduleInstallSourceCandidate) bool {
	name, version, hasVersion := modulecatalog.SplitID(reference)
	if candidate.Name != name {
		return false
	}
	return !hasVersion || sameLooseVersion(candidate.Version, version)
}

func betterModuleSourceCandidate(candidate, current moduleInstallSourceCandidate) bool {
	if current.Name == "" {
		return true
	}
	if cmp := compareLooseSemver(candidate.Version, current.Version); cmp != 0 {
		return cmp > 0
	}
	return candidate.Source > current.Source
}

func resolveIndexEntry(reference string, indexPaths []string, offline bool) (modulepackage.IndexEntry, string, error) {
	name, version, hasVersion := modulecatalog.SplitID(reference)
	var found modulepackage.IndexEntry
	var foundIndex string
	for _, indexPath := range indexPaths {
		index, err := loadModuleIndex(indexPath, offline)
		if err != nil {
			return modulepackage.IndexEntry{}, "", err
		}
		for _, entry := range index.Modules {
			if entry.Name != name {
				continue
			}
			if hasVersion && !sameLooseVersion(entry.Version, version) {
				continue
			}
			if found.Name == "" || compareLooseSemver(entry.Version, found.Version) > 0 {
				found = entry
				foundIndex = indexPath
			}
		}
	}
	if found.Name == "" {
		return modulepackage.IndexEntry{}, "", fmt.Errorf("module reference %s not found in configured indexes", reference)
	}
	return found, foundIndex, nil
}

func loadModuleIndex(indexPath string, offline bool) (modulepackage.Index, error) {
	if strings.HasPrefix(indexPath, "https://") {
		cached, cacheErr := moduleIndexCachePath(indexPath)
		if offline {
			if cacheErr != nil {
				return modulepackage.Index{}, cacheErr
			}
			body, err := os.ReadFile(cached)
			if err != nil {
				return modulepackage.Index{}, fmt.Errorf("offline module install cannot load uncached URL index %s", indexPath)
			}
			return modulepackage.ParseIndex(body)
		}
		client := moduleIndexHTTPClient()
		resp, err := client.Get(indexPath)
		if err != nil {
			return modulepackage.Index{}, err
		}
		defer func() { logCommandError("close module index response body", resp.Body.Close()) }()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return modulepackage.Index{}, fmt.Errorf("download index %s failed: %s", indexPath, resp.Status)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return modulepackage.Index{}, err
		}
		if cacheErr == nil {
			if err := os.MkdirAll(filepath.Dir(cached), 0o755); err == nil {
				logCommandError("write cached module index", os.WriteFile(cached, body, 0o644))
			}
		}
		return modulepackage.ParseIndex(body)
	}
	if strings.HasPrefix(indexPath, "http://") {
		return modulepackage.Index{}, fmt.Errorf("module indexes require https: %s", indexPath)
	}
	return modulepackage.LoadIndex(indexPath)
}

func moduleIndexHTTPClient() *http.Client {
	client := *http.DefaultClient
	if client.Timeout == 0 {
		client.Timeout = moduleIndexHTTPTimeout
	}
	return &client
}

func moduleIndexCachePath(indexURL string) (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(indexURL))
	return filepath.Join(root, "hovel", "modules", "indexes", hex.EncodeToString(sum[:])+".yaml"), nil
}

func sameLooseVersion(left, right string) bool {
	return normalizeLooseVersion(left) == normalizeLooseVersion(right)
}

func normalizeLooseVersion(version string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
}

func compareLooseSemver(left, right string) int {
	leftParts := looseVersionParts(left)
	rightParts := looseVersionParts(right)
	for i := 0; i < len(leftParts) || i < len(rightParts); i++ {
		var l, r int
		if i < len(leftParts) {
			l = leftParts[i]
		}
		if i < len(rightParts) {
			r = rightParts[i]
		}
		if l != r {
			return l - r
		}
	}
	return strings.Compare(left, right)
}

func looseVersionParts(version string) []int {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	core := strings.SplitN(version, "-", 2)[0]
	fields := strings.Split(core, ".")
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		n, err := strconv.Atoi(field)
		logCommandError("parse version segment", err)
		parts = append(parts, n)
	}
	return parts
}

func resolveBulkInstallSource(baseDir, source string) string {
	if base, err := url.Parse(baseDir); err == nil && base.Scheme != "" && base.Host != "" {
		relative, err := url.Parse(source)
		if err != nil {
			return source
		}
		return base.ResolveReference(relative).String()
	}
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") || filepath.IsAbs(source) {
		return source
	}
	return filepath.Join(baseDir, source)
}

func loadBulkInstallSet(source string, opts modulepackage.InstallOptions) (modulepackage.InstallSet, error) {
	source = strings.TrimSpace(source)
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		return modulepackage.LoadInstallSetURL(source, opts)
	}
	return modulepackage.LoadInstallSet(source)
}

func bulkInstallBaseDir(source string) string {
	if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		dir := path.Dir(parsed.Path)
		if dir == "." {
			dir = ""
		}
		if dir != "" && dir != "/" {
			dir += "/"
		}
		parsed.Path = dir
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	return filepath.Dir(source)
}

func modulesInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		moduleID := invocation.Positional("module")
		db, err := moduleDBForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		module, ok := db.Find(moduleID)
		if !ok {
			return Result{}, fmt.Errorf("module %s does not exist", moduleID)
		}
		steps := moduleStepPayloads(module.ID, db.ResolveStepAvailability(nil))
		payload := moduleInspectPayload(module, steps)
		return Result{
			Human: moduleInspect(payload),
			JSON:  payload,
		}, nil
	}
}

func modulesAvailableHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		records, err := availableModuleRecordsForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		records = filterModuleInventoryRecords(records, invocation.Positional("query"), modulecatalog.ModuleType(invocation.Option("type")))
		payload := ModuleInventoryPayload{Modules: records}
		if len(records) == 0 {
			return Result{Human: "No available modules", JSON: payload}, nil
		}
		return Result{Human: moduleInventoryLines(records), JSON: payload}, nil
	}
}

func artifactsListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ArtifactRecords == nil {
			return Result{}, fmt.Errorf("artifact repository is not configured")
		}
		workspacePath := workspacepath.ResolvePath(invocation.Option("workspace"))
		artifacts, err := runtime.ArtifactRecords.ListArtifacts(ctx, workspacePath)
		if err != nil {
			return Result{}, err
		}
		if len(artifacts) == 0 {
			return Result{Human: "No artifacts", JSON: artifacts}, nil
		}
		lines := []string{"ID                                                                 THROW                     NAME                      KIND       SIZE PATH"}
		for _, artifact := range artifacts {
			lines = append(lines, fmt.Sprintf("%-66s %-25s %-25s %-10s %-4d %s", artifact.ID, artifact.ThrowID, artifact.Name, artifact.Kind, artifact.Size, artifact.Path))
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: artifacts}, nil
	}
}

func artifactsInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ArtifactRecords == nil {
			return Result{}, fmt.Errorf("artifact repository is not configured")
		}
		workspacePath := workspacepath.ResolvePath(invocation.Option("workspace"))
		artifact, err := runtime.ArtifactRecords.GetArtifact(ctx, workspacePath, invocation.Positional("artifact"))
		if err != nil {
			return Result{}, err
		}
		lines := []string{
			fmt.Sprintf("Artifact %s", artifact.ID),
			fmt.Sprintf("name       %s", artifact.Name),
			fmt.Sprintf("kind       %s", artifact.Kind),
			fmt.Sprintf("throw      %s", artifact.ThrowID),
			fmt.Sprintf("run        %s", artifact.RunID),
			fmt.Sprintf("module     %s", artifact.ModuleID),
			fmt.Sprintf("target     %s", artifact.Target),
			fmt.Sprintf("size       %d", artifact.Size),
			fmt.Sprintf("sha256     %s", artifact.SHA256),
			fmt.Sprintf("path       %s", artifact.Path),
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: artifact}, nil
	}
}

func throwHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.Daemons == nil {
			return Result{}, fmt.Errorf("daemon service is not configured")
		}
		db, err := moduleDBForInvocation(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		throw, err := throwInputsWithDB(ctx, runtime, invocation, db)
		if err != nil {
			return Result{}, err
		}
		if len(throw.Steps) == 0 && runtime.Runs == nil {
			return Result{}, fmt.Errorf("run client factory is not configured")
		}
		if len(throw.Steps) != 0 && runtime.CapabilityChains == nil {
			return Result{}, fmt.Errorf("capability chain runner is not configured")
		}
		if err := guardDangerousModulesWithDB(db, throw.Modules, invocation.Flag("allow-dangerous")); err != nil {
			return Result{}, err
		}
		status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{
			WorkspacePath: workspacepath.ResolvePath(invocation.Option("workspace")),
		})
		if err != nil {
			return Result{}, err
		}
		if status.State != daemon.StateRunning {
			return Result{}, fmt.Errorf("daemon is not running for workspace %s", status.WorkspacePath)
		}

		plan := newThrowPlanForExecution(status.WorkspacePath, throw)
		if runtime.Plans != nil {
			if err := runtime.Plans.RecordThrowPlan(ctx, plan); err != nil {
				return Result{}, err
			}
		}
		if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.planned", "throw planned", plan, "", "", event.LevelInfo, map[string]string{
			"planHash": plan.PlanHash,
			"review":   plan.Review,
		}); err != nil {
			return Result{}, err
		}
		if runtime.Confirmations != nil {
			method := "typed_yes"
			if invocation.Flag("now") {
				method = "now_bypass"
			}
			confirmed := false
			if method != "now_bypass" && runtime.ThrowConfirmations != nil {
				_, ok, err := runtime.ThrowConfirmations.GetThrowConfirmation(ctx, status.WorkspacePath, plan.PlanHash)
				if err != nil {
					return Result{}, err
				}
				confirmed = ok
			}
			if !confirmed {
				if method != "now_bypass" {
					if invocation.NonInteractive {
						return Result{}, fmt.Errorf("throw requires --now or a matching preconfirmation in non-interactive mode")
					}
					if invocation.Input == nil {
						return Result{}, fmt.Errorf("throw requires confirmation; run confirm first, type yes at the prompt, or pass --now")
					}
					prompt := throwConfirmationPrompt(plan, "throw")
					answer, err := invocation.Input.Confirm(ctx, prompt)
					if err != nil {
						return Result{}, err
					}
					if !answer.Confirmed(prompt) {
						return Result{}, fmt.Errorf("throw cancelled")
					}
				}
				confirmation := newThrowConfirmation(plan, confirmationClientID(runtime), method, time.Now().UTC())
				if err := runtime.Confirmations.RecordThrowConfirmation(ctx, confirmation); err != nil {
					return Result{}, err
				}
				if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.confirmed", "throw confirmed", plan, "", "", event.LevelInfo, map[string]string{
					"confirmationId": confirmation.ID,
					"method":         method,
				}); err != nil {
					return Result{}, err
				}
			}
		}
		pendingID := launchKeyPendingThrowID(plan, invocation.Flag("allow-dangerous"), invocation.Flag("now"))
		if err := requireLaunchKeyReady(ctx, runtime, status.Identity.SocketPath, PendingThrowCreateRequest{
			ID:             pendingID,
			Operation:      planOperation(plan),
			Chain:          plan.Chain,
			PlanHash:       plan.PlanHash,
			AllowDangerous: invocation.Flag("allow-dangerous"),
			NowBypass:      invocation.Flag("now"),
		}); err != nil {
			return Result{}, err
		}

		throwStarted := time.Now()
		var streamThrowLog func(...operatorlog.Entry)
		if invocation.StreamLog != nil {
			streamThrowLog = func(entries ...operatorlog.Entry) {
				for _, entry := range entries {
					invocation.StreamLog(entry)
				}
			}
		}
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			logCommandError("append throw header log", runtime.Session.AppendLogToChain(throw.Chain, throwHeader(throw.Chain)))
		}
		emitStreamLog(streamThrowLog, throwHeader(throw.Chain))
		var payload ThrowPayload
		payload.Plan = plan.Payload()
		payload.ThrowID = newThrowRecordID(plan, throwStarted)
		payload.Chain = throw.Chain
		payload.Targets = append([]string(nil), throw.Targets...)
		if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.started", "throw started", plan, payload.ThrowID, "", event.LevelInfo, nil); err != nil {
			return Result{}, err
		}
		planEntries := throwPlanEntries(payload, throwStarted)
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			logCommandError("append throw plan log", runtime.Session.AppendLogToChain(throw.Chain, planEntries...))
		}
		emitStreamLog(streamThrowLog, planEntries...)
		if len(throw.Steps) != 0 {
			if err := executeCapabilityThrow(ctx, runtime, status.WorkspacePath, plan, throw, &payload, throwStarted, streamThrowLog); err != nil {
				return Result{}, err
			}
		} else {
			client, err := runtime.Runs.DialRunClient(status.Identity.SocketPath)
			if err != nil {
				return Result{}, err
			}
			defer func() { logCommandError("close legacy throw daemon client", client.Close()) }()
			if err := executeLegacyThrow(ctx, runtime, client, status.WorkspacePath, db, plan, throw, &payload, throwStarted, streamThrowLog); err != nil {
				return Result{}, err
			}
		}
		completeEntries := throwCompleteEntries(payload, throwStarted)
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			logCommandError("append throw completion log", runtime.Session.AppendLogToChain(payload.Chain, completeEntries...))
			if runtime.Throws != nil {
				if err := runtime.Throws.RecordThrow(ctx, newThrowRecord(status.WorkspacePath, plan, payload, throwStarted, time.Now().UTC())); err != nil {
					return Result{}, err
				}
			}
			if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.completed", "throw completed", plan, payload.ThrowID, "", event.LevelInfo, map[string]string{
				"runs": fmt.Sprint(len(payload.Results)),
			}); err != nil {
				return Result{}, err
			}
			emitStreamLog(streamThrowLog, completeEntries...)
			return Result{JSON: payload}, nil
		}
		emitStreamLog(streamThrowLog, completeEntries...)
		log := throwLog(payload, throwStarted)
		if runtime.Session != nil {
			logCommandError("append throw log", runtime.Session.AppendLogToChain(payload.Chain, log.Entries()...))
		}
		if runtime.Throws != nil {
			if err := runtime.Throws.RecordThrow(ctx, newThrowRecord(status.WorkspacePath, plan, payload, throwStarted, time.Now().UTC())); err != nil {
				return Result{}, err
			}
		}
		if err := recordStructuredEvent(ctx, runtime, status.WorkspacePath, "hovel.throw.completed", "throw completed", plan, payload.ThrowID, "", event.LevelInfo, map[string]string{
			"runs": fmt.Sprint(len(payload.Results)),
		}); err != nil {
			return Result{}, err
		}
		result := Result{JSON: payload}
		if invocation.StreamLog == nil {
			result.Human = fmt.Sprintf("Throw completed chain %s against %d target(s)", payload.Chain, len(payload.Targets))
			result.Log = log
		}
		return result, nil
	}
}

func executeLegacyThrow(ctx context.Context, runtime Runtime, client RunClient, workspacePath string, db ModuleDatabase, plan ThrowPlanRecord, throw throwExecution, payload *ThrowPayload, throwStarted time.Time, streamLog func(...operatorlog.Entry)) error {
	modules := legacyExecutionModuleIDsForThrow(runtime, db, throw)
	autoConnectSquatter := shouldAutoConnectSquatterPayloads(runtime, db, throw)
	for _, target := range throw.Targets {
		for _, moduleID := range modules {
			runIndex := len(payload.Results) + 1
			startEntries := throwRunStartEntries(throw.Chain, target, moduleID, runIndex, len(throw.Targets)*len(modules), throwStarted)
			if runtime.Session != nil && feedbackPublished(runtime.Session) {
				logCommandError("append throw run start log", runtime.Session.AppendLogToChain(throw.Chain, startEntries...))
			}
			emitStreamLog(streamLog, startEntries...)
			stopRunLogs, streamedRunLogs := startRunLogStream(ctx, client, planOperation(plan), throw.Chain, streamLog)
			targetConfig, err := targetConfigForLegacyModule(ctx, client, db, throw, *payload, moduleID, target)
			if err != nil {
				stopRunLogs()
				return err
			}
			result, err := client.RunMockExploit(ctx, RunMockExploitRequest{
				Operation:    planOperation(plan),
				Chain:        throw.Chain,
				ModuleID:     moduleID,
				Target:       target,
				ChainConfig:  throw.ChainConfig,
				TargetConfig: targetConfig,
				ThrowStarted: throwStarted.Format(time.RFC3339Nano),
			})
			stopRunLogs()
			if err != nil {
				return err
			}
			if !streamedRunLogs {
				emitStreamLog(streamLog, throwModuleLogEntries(result, throwStarted, throw.Chain)...)
			}
			payload.Results = append(payload.Results, runPayload(result))
			if err := materializeRunArtifacts(ctx, runtime, workspacePath, plan, payload, moduleID, target, result.RunID); err != nil {
				return err
			}
			installedPayloads, err := recordInstalledPayloadsForRun(ctx, runtime, workspacePath, plan, payload, len(payload.Results)-1)
			if err != nil {
				return err
			}
			if autoConnectSquatter {
				if err := connectInstalledSquatterPayloadsForRun(ctx, runtime, workspacePath, plan, payload, len(payload.Results)-1, installedPayloads); err != nil {
					return err
				}
			}
			resultEntries := throwRunResultEntries(*payload, payload.Results[len(payload.Results)-1], runIndex, len(throw.Targets)*len(modules), throwStarted)
			if runtime.Session != nil && feedbackPublished(runtime.Session) {
				logCommandError("append throw run result log", runtime.Session.AppendLogToChain(throw.Chain, resultEntries...))
			}
			emitStreamLog(streamLog, resultEntries...)
		}
	}
	return nil
}

func targetConfigForLegacyModule(ctx context.Context, client RunClient, db ModuleDatabase, throw throwExecution, payload ThrowPayload, moduleID, target string) (map[string]string, error) {
	config := cloneStringMap(throw.TargetConfigs[target])
	if !shouldGenerateSquatterPayloadForModule(db, throw, moduleID, config) {
		return config, nil
	}
	providerID := squatterProviderModuleID(db)
	payloadConfig := squatterPayloadGenerationConfig(throw.ChainConfig, config, target)
	transport := strings.TrimSpace(payloadConfig["payload.transport"])
	if transport == "" {
		transport = squatterTypeTCPBind
	}
	generated, err := client.GeneratePayload(ctx, providerID, GeneratePayloadRequest{
		RunID:     payload.ThrowID + "-squatter-payload",
		Target:    firstConfiguredString(payloadConfig["target.host"], target),
		PayloadID: squatterPayloadIDForTransport(transport),
		Format:    "pe-exe",
		Config:    payloadConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("generate Squatter payload with %s: %w", providerID, err)
	}
	primary := generated.Primary
	if !strings.EqualFold(strings.TrimSpace(primary.Encoding), "base64") {
		return nil, fmt.Errorf("generate Squatter payload with %s: unsupported artifact encoding %q", providerID, primary.Encoding)
	}
	if strings.TrimSpace(primary.Bytes) == "" {
		return nil, fmt.Errorf("generate Squatter payload with %s: provider returned no payload bytes", providerID)
	}
	if config == nil {
		config = map[string]string{}
	}
	delete(config, "payload.local_path")
	config["payload.provider"] = "squatter"
	config["payload.id"] = squatterPayloadIDForTransport(transport)
	config["payload.format"] = firstConfiguredString(primary.Format, "pe-exe")
	config["payload.name"] = firstConfiguredString(primary.Name, "squatter.exe")
	config["payload.sha256"] = primary.SHA256
	config["payload.bytes_base64"] = primary.Bytes
	return config, nil
}

func shouldGenerateSquatterPayloadForModule(db ModuleDatabase, throw throwExecution, moduleID string, targetConfig map[string]string) bool {
	if strings.TrimSpace(targetConfig["payload.bytes_base64"]) != "" {
		return false
	}
	if !throwHasSquatterPayloadBridge(db, throw) {
		return false
	}
	if moduleID == "squatter.bind" || isSquatterProviderModuleID(db, moduleID) {
		return false
	}
	module, ok := db.Find(moduleID)
	if !ok || module.Type != modulecatalog.TypeExploit {
		return false
	}
	return isSquatterPayloadInstallerModule(module)
}

func throwHasSquatterPayloadBridge(db ModuleDatabase, throw throwExecution) bool {
	for _, moduleID := range throw.Modules {
		if moduleID == "squatter.bind" || isSquatterProviderModuleID(db, moduleID) {
			return true
		}
	}
	return false
}

func isSquatterPayloadInstallerModule(module modulecatalog.Module) bool {
	return modulecatalog.ReferenceName(module.ID) == "ms17-010-exploit"
}

func squatterPayloadGenerationConfig(chainConfig, targetConfig map[string]string, target string) map[string]string {
	config := cloneStringMap(chainConfig)
	if config == nil {
		config = map[string]string{}
	}
	for key, value := range targetConfig {
		config[key] = value
	}
	if strings.TrimSpace(config["target.host"]) == "" {
		config["target.host"] = target
	}
	if strings.TrimSpace(config["payload.transport"]) == "" {
		config["payload.transport"] = firstConfiguredString(config[squatterTypeConfigKey], squatterTypeTCPBind)
	}
	return config
}

func squatterPayloadIDForTransport(transport string) string {
	transport = strings.TrimSpace(transport)
	if transport == "" {
		transport = squatterTypeTCPBind
	}
	return "squatter/windows/x86/windows-7/" + transport + "/pe-exe"
}

func firstConfiguredString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func executeCapabilityThrow(ctx context.Context, runtime Runtime, workspacePath string, plan ThrowPlanRecord, throw throwExecution, payload *ThrowPayload, throwStarted time.Time, streamLog func(...operatorlog.Entry)) error {
	for _, target := range throw.Targets {
		runIndex := len(payload.Results) + 1
		runID := fmt.Sprintf("%s-capability-%d", payload.ThrowID, runIndex)
		startEntries := throwRunStartEntries(throw.Chain, target, "capability-chain", runIndex, len(throw.Targets), throwStarted)
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			logCommandError("append capability throw start log", runtime.Session.AppendLogToChain(throw.Chain, startEntries...))
		}
		emitStreamLog(streamLog, startEntries...)
		result, err := runtime.CapabilityChains.ExecuteCapabilityChain(ctx, CapabilityChainRequest{
			Operation:    planOperation(plan),
			Chain:        throw.Chain,
			Target:       target,
			Steps:        cloneCapabilityChainStepRefs(throw.Steps),
			ChainConfig:  cloneStringMap(throw.ChainConfig),
			TargetConfig: cloneStringMap(throw.TargetConfigs[target]),
			ThrowID:      payload.ThrowID,
			RunID:        runID,
			ThrowStarted: throwStarted.Format(time.RFC3339Nano),
		})
		if err != nil {
			return err
		}
		payload.Results = append(payload.Results, capabilityChainRunPayload(target, runID, result))
		if err := materializeRunArtifacts(ctx, runtime, workspacePath, plan, payload, "capability-chain", target, payload.Results[len(payload.Results)-1].RunID); err != nil {
			return err
		}
		if _, err := recordInstalledPayloadsForRun(ctx, runtime, workspacePath, plan, payload, len(payload.Results)-1); err != nil {
			return err
		}
		resultEntries := throwRunResultEntries(*payload, payload.Results[len(payload.Results)-1], runIndex, len(throw.Targets), throwStarted)
		if runtime.Session != nil && feedbackPublished(runtime.Session) {
			logCommandError("append capability throw result log", runtime.Session.AppendLogToChain(throw.Chain, resultEntries...))
		}
		emitStreamLog(streamLog, resultEntries...)
	}
	return nil
}

func emitStreamLog(streamLog func(...operatorlog.Entry), entries ...operatorlog.Entry) {
	if streamLog == nil {
		return
	}
	streamLog(entries...)
}

func startRunLogStream(ctx context.Context, client RunClient, operation, chain string, streamLog func(...operatorlog.Entry)) (func(), bool) {
	if streamLog == nil {
		return func() {}, false
	}
	poller, ok := client.(RunLogPoller)
	if !ok {
		return func() {}, false
	}
	initial, err := poller.PollOperationChainLogs(ctx, operation, chain, 0)
	if err != nil {
		return func() {}, false
	}
	cursor := initial.Last
	pollCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				cursor = pollRunLogs(pollCtx, poller, operation, chain, cursor, streamLog)
			}
		}
	}()
	stop := func() {
		cancel()
		<-done
		cursor = pollRunLogs(ctx, poller, operation, chain, cursor, streamLog)
	}
	return stop, true
}

func pollRunLogs(ctx context.Context, poller RunLogPoller, operation, chain string, cursor uint64, streamLog func(...operatorlog.Entry)) uint64 {
	result, err := poller.PollOperationChainLogs(ctx, operation, chain, cursor)
	if err != nil {
		return cursor
	}
	for _, log := range result.Logs {
		emitStreamLog(streamLog, log.Entry)
	}
	return result.Last
}

func materializeRunArtifacts(ctx context.Context, runtime Runtime, workspacePath string, plan ThrowPlanRecord, payload *ThrowPayload, moduleID, target, runID string) error {
	if runtime.Artifacts == nil {
		return nil
	}
	resultIndex := len(payload.Results) - 1
	for artifactIndex, artifact := range payload.Results[resultIndex].Artifacts {
		record, err := runtime.Artifacts.MaterializeArtifact(ctx, ArtifactMaterialization{
			Workspace: workspacePath,
			ThrowID:   payload.ThrowID,
			RunID:     runID,
			ModuleID:  moduleID,
			Target:    target,
			Artifact:  artifact,
			CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		if err := recordStructuredEvent(ctx, runtime, workspacePath, "hovel.artifact.recorded", "artifact recorded", plan, payload.ThrowID, runID, event.LevelInfo, map[string]string{
			"artifactId": record.ID,
			"name":       record.Name,
			"kind":       record.Kind,
			"path":       record.Path,
			"sha256":     record.SHA256,
		}); err != nil {
			return err
		}
		payload.Results[resultIndex].Artifacts[artifactIndex].Data = ""
		payload.Results[resultIndex].Artifacts[artifactIndex].Name = record.Name
	}
	return nil
}

func recordInstalledPayloadsForRun(ctx context.Context, runtime Runtime, workspacePath string, plan ThrowPlanRecord, payload *ThrowPayload, resultIndex int) ([]InstalledPayloadRecord, error) {
	if runtime.Payloads == nil || resultIndex < 0 || resultIndex >= len(payload.Results) {
		return nil, nil
	}
	result := payload.Results[resultIndex]
	records := make([]InstalledPayloadRecord, 0, len(result.InstalledPayloads))
	for descriptorIndex, descriptor := range result.InstalledPayloads {
		record := installedPayloadRecordFromDescriptor(workspacePath, plan, payload.ThrowID, result, descriptor)
		recorded, err := runtime.Payloads.RecordInstalledPayload(ctx, record)
		if err != nil {
			return nil, err
		}
		records = append(records, recorded)
		payload.Results[resultIndex].InstalledPayloads[descriptorIndex].State = recorded.State
		if err := recordStructuredEvent(ctx, runtime, workspacePath, "hovel.payload.installed", "installed payload recorded", plan, payload.ThrowID, result.RunID, event.LevelInfo, map[string]string{
			"payloadHandle": recorded.Handle,
			"payloadId":     recorded.PayloadID,
			"provider":      recorded.Provider,
			"state":         recorded.State,
			"target":        recorded.Target,
			"transport":     recorded.Transport,
		}); err != nil {
			return nil, err
		}
	}
	return records, nil
}

func connectInstalledSquatterPayloadsForRun(ctx context.Context, runtime Runtime, workspacePath string, plan ThrowPlanRecord, payload *ThrowPayload, resultIndex int, records []InstalledPayloadRecord) error {
	if runtime.Payloads == nil || runtime.PayloadProviders == nil || resultIndex < 0 || resultIndex >= len(payload.Results) {
		return nil
	}
	for descriptorIndex, record := range records {
		if !autoConnectableSquatterPayload(record) {
			continue
		}
		session, err := runtime.PayloadProviders.ConnectInstalledPayload(ctx, record)
		if err != nil {
			if _, updateErr := runtime.Payloads.UpdateInstalledPayloadState(ctx, workspacePath, record.Handle, PayloadStateUnreachable, err.Error()); updateErr != nil {
				return fmt.Errorf("connect installed payload %s: %w; additionally failed to mark payload unreachable: %v", payloadRecordRef(record), err, updateErr)
			}
			return fmt.Errorf("connect installed payload %s: %w", payloadRecordRef(record), err)
		}
		if session.InstalledPayloadID == "" {
			session.InstalledPayloadID = record.Handle
		}
		connected, err := runtime.Payloads.UpdateInstalledPayloadState(ctx, workspacePath, record.Handle, PayloadStateConnected, "session connected")
		if err != nil {
			return err
		}
		payload.Results[resultIndex].Sessions = append(payload.Results[resultIndex].Sessions, session)
		if descriptorIndex < len(payload.Results[resultIndex].InstalledPayloads) {
			payload.Results[resultIndex].InstalledPayloads[descriptorIndex].State = connected.State
		}
		if err := recordStructuredEvent(ctx, runtime, workspacePath, "hovel.payload.connected", "installed payload connected", plan, payload.ThrowID, payload.Results[resultIndex].RunID, event.LevelInfo, map[string]string{
			"payloadHandle": connected.Handle,
			"payloadId":     connected.PayloadID,
			"provider":      connected.Provider,
			"session":       session.ID,
			"target":        connected.Target,
			"transport":     connected.Transport,
		}); err != nil {
			return err
		}
	}
	return nil
}

func autoConnectableSquatterPayload(record InstalledPayloadRecord) bool {
	return strings.EqualFold(record.Provider, "squatter") && record.SupportsReconnect && record.Reconnect != nil
}

func payloadRecordRef(record InstalledPayloadRecord) string {
	for _, value := range []string{record.Handle, record.PayloadID, record.InstanceKey} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "unknown"
}

func installedPayloadRecordFromDescriptor(workspacePath string, plan ThrowPlanRecord, throwID string, result RunPayload, descriptor InstalledPayloadDescriptor) InstalledPayloadRecord {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	state := descriptor.State
	if state == "" {
		state = PayloadStateInstalled
	}
	target := descriptor.Target
	if target == "" {
		target = result.Target
	}
	targetID := descriptor.TargetID
	if targetID == "" {
		targetID = result.Target
	}
	return InstalledPayloadRecord{
		Workspace:                workspacePath,
		Provider:                 descriptor.Provider,
		PayloadID:                descriptor.PayloadID,
		PayloadVersion:           descriptor.PayloadVersion,
		Target:                   target,
		TargetID:                 targetID,
		State:                    state,
		Transport:                descriptor.Transport,
		Endpoint:                 descriptor.Endpoint,
		InstanceKey:              descriptor.InstanceKey,
		StampID:                  descriptor.StampID,
		ArtifactIDs:              append([]string(nil), descriptor.ArtifactIDs...),
		SupportsReconnect:        descriptor.SupportsReconnect,
		SupportsMultipleSessions: descriptor.SupportsMultipleSessions,
		Reconnect:                clonePayloadProviderRecord(descriptor.Reconnect),
		Cleanup:                  clonePayloadProviderRecord(descriptor.Cleanup),
		Operation:                planOperation(plan),
		Chain:                    plan.Chain,
		ThrowID:                  throwID,
		RunID:                    result.RunID,
		CreatedAt:                now,
		UpdatedAt:                now,
		LastSeenAt:               now,
		Metadata:                 cloneStringMap(descriptor.Metadata),
	}
}

func confirmHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		plan, err := recordThrowPlan(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		if invocation.NonInteractive {
			return Result{}, fmt.Errorf("confirm requires an interactive typed yes confirmation")
		}
		if invocation.Input == nil {
			return Result{}, fmt.Errorf("confirm requires confirmation; type yes at the prompt")
		}
		prompt := throwConfirmationPrompt(plan, "confirm")
		answer, err := invocation.Input.Confirm(ctx, prompt)
		if err != nil {
			return Result{}, err
		}
		if !answer.Confirmed(prompt) {
			return Result{}, fmt.Errorf("confirm cancelled")
		}
		confirmation, err := recordThrowConfirmation(ctx, runtime, plan, "preconfirmed")
		if err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Confirmed throw plan %s for chain %s against %d target(s)", plan.ID, plan.Chain, len(plan.Targets)),
			JSON:  confirmation,
		}, nil
	}
}

func reviewHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		plan, err := recordThrowPlan(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		if invocation.NonInteractive {
			return Result{}, fmt.Errorf("review requires an interactive typed yes confirmation")
		}
		if invocation.Input == nil {
			return Result{}, fmt.Errorf("review requires confirmation; type yes at the prompt")
		}
		prompt := throwConfirmationPrompt(plan, "confirm review")
		answer, err := invocation.Input.Confirm(ctx, prompt)
		if err != nil {
			return Result{}, err
		}
		if !answer.Confirmed(prompt) {
			return Result{}, fmt.Errorf("review cancelled")
		}
		confirmation, err := recordThrowConfirmation(ctx, runtime, plan, "reviewed_yes")
		if err != nil {
			return Result{}, err
		}
		return Result{
			JSON: confirmation,
			Log: operatorlog.New("HOVEL//REVIEW", plan.Chain, []operatorlog.Entry{
				operatorlog.Success("review", "confirmed",
					operatorlog.Field{Name: "plan", Value: plan.ID},
					operatorlog.Field{Name: "targets", Value: fmt.Sprint(len(plan.Targets))},
					operatorlog.Field{Name: "planHash", Value: plan.PlanHash},
				),
			}),
		}, nil
	}
}

func throwConfirmationPrompt(plan ThrowPlanRecord, action string) ConfirmationPrompt {
	return ConfirmationPrompt{
		Title:           "THROW REVIEW",
		Action:          action,
		RequiredLiteral: "yes",
		Plan:            plan,
		Fields: []ConfirmationField{
			{Label: "operation", Value: planOperation(plan)},
			{Label: "chain", Value: plan.Chain},
			{Label: "targets", Value: strings.Join(plan.Targets, ", ")},
			{Label: "modules", Value: formatReviewList(plan.Modules)},
			{Label: "chain config", Value: formatReviewConfig(plan.ChainConfig)},
			{Label: "target config", Value: formatReviewTargetConfigs(plan.Targets, plan.TargetConfigs)},
			{Label: "plan hash", Value: shortPlanHash(plan.PlanHash), Muted: true},
		},
	}
}

func shortPlanHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) <= 10 {
		return hash
	}
	return hash[:10]
}

func formatReviewList(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}

func formatReviewConfig(config map[string]string) string {
	if len(config) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", key, config[key]))
	}
	return strings.Join(lines, "\n")
}

func formatReviewTargetConfigs(targets []string, configs map[string]map[string]string) string {
	if len(configs) == 0 {
		return "(none)"
	}
	orderedTargets := append([]string(nil), targets...)
	seen := make(map[string]bool, len(orderedTargets))
	for _, target := range orderedTargets {
		seen[target] = true
	}
	for target := range configs {
		if !seen[target] {
			orderedTargets = append(orderedTargets, target)
		}
	}
	lines := make([]string, 0)
	for _, target := range orderedTargets {
		config := configs[target]
		if len(config) == 0 {
			continue
		}
		lines = append(lines, target)
		for _, line := range strings.Split(formatReviewConfig(config), "\n") {
			lines = append(lines, "  "+line)
		}
	}
	if len(lines) == 0 {
		return "(none)"
	}
	return strings.Join(lines, "\n")
}

func recordThrowPlan(ctx context.Context, runtime Runtime, invocation Invocation) (ThrowPlanRecord, error) {
	if runtime.Plans == nil {
		return ThrowPlanRecord{}, fmt.Errorf("throw plan recorder is not configured")
	}
	throw, err := throwInputs(ctx, runtime, invocation)
	if err != nil {
		return ThrowPlanRecord{}, err
	}
	workspacePath := workspacepath.ResolvePath(invocation.Option("workspace"))
	plan := newThrowPlanForExecution(workspacePath, throw)
	if err := runtime.Plans.RecordThrowPlan(ctx, plan); err != nil {
		return ThrowPlanRecord{}, err
	}
	return plan, nil
}

func recordThrowConfirmation(ctx context.Context, runtime Runtime, plan ThrowPlanRecord, method string) (ThrowConfirmationRecord, error) {
	if runtime.Confirmations == nil {
		return ThrowConfirmationRecord{}, fmt.Errorf("throw confirmation recorder is not configured")
	}
	confirmation := newThrowConfirmation(plan, confirmationClientID(runtime), method, time.Now().UTC())
	if err := runtime.Confirmations.RecordThrowConfirmation(ctx, confirmation); err != nil {
		return ThrowConfirmationRecord{}, err
	}
	return confirmation, nil
}

func throwPlanHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		plan, err := recordThrowPlan(ctx, runtime, invocation)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Human: fmt.Sprintf("Planned throw %s for chain %s against %d target(s)", plan.ID, plan.Chain, len(plan.Targets)),
			JSON:  plan.Payload(),
		}, nil
	}
}

func throwsListHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ThrowPlans == nil {
			return Result{}, fmt.Errorf("throw plan repository is not configured")
		}
		workspacePath := workspacepath.ResolvePath(invocation.Option("workspace"))
		plans, err := runtime.ThrowPlans.ListThrowPlans(ctx, workspacePath)
		if err != nil {
			return Result{}, err
		}
		if len(plans) == 0 {
			return Result{Human: "No throws", JSON: plans}, nil
		}
		lines := []string{"ID                         CHAIN                     TARGETS REVIEW"}
		for _, plan := range plans {
			lines = append(lines, fmt.Sprintf("%-26s %-25s %-7d %s", plan.ID, plan.Chain, len(plan.Targets), plan.Review))
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: plans}, nil
	}
}

func throwsInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.ThrowPlans == nil {
			return Result{}, fmt.Errorf("throw plan repository is not configured")
		}
		workspacePath := workspacepath.ResolvePath(invocation.Option("workspace"))
		plan, err := runtime.ThrowPlans.GetThrowPlan(ctx, workspacePath, invocation.Positional("throw"))
		if err != nil {
			return Result{}, err
		}
		lines := []string{
			fmt.Sprintf("Throw %s", plan.ID),
			fmt.Sprintf("chain          %s", plan.Chain),
			fmt.Sprintf("targets        %s", strings.Join(plan.Targets, ", ")),
			fmt.Sprintf("confirmation   %s", plan.ConfirmationID),
			fmt.Sprintf("review         %s", plan.Review),
			fmt.Sprintf("intent         %s", plan.Intent),
		}
		payload := ThrowInspectPayload{Plan: plan}
		if invocation.Flag("events") {
			if runtime.EventRecords == nil {
				return Result{}, fmt.Errorf("event repository is not configured")
			}
			events, err := runtime.EventRecords.ListEvents(ctx, workspacePath, event.Filter{PlanHash: plan.PlanHash})
			if err != nil {
				return Result{}, err
			}
			payload.Events = events
			lines = append(lines, "")
			lines = append(lines, eventLines(events)...)
		}
		if invocation.Flag("events") {
			return Result{Human: strings.Join(lines, "\n"), JSON: payload}, nil
		}
		return Result{Human: strings.Join(lines, "\n"), JSON: plan}, nil
	}
}

func launchKeyPolicyInspectHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.LaunchKeyPolicies == nil {
			return Result{}, fmt.Errorf("launch-key policy manager is not configured")
		}
		if runtime.Daemons == nil {
			return Result{}, fmt.Errorf("daemon service is not configured")
		}
		status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{
			WorkspacePath: workspacepath.ResolvePath(invocation.Option("workspace")),
		})
		if err != nil {
			return Result{}, err
		}
		operation := strings.TrimSpace(invocation.Option("operation"))
		if operation == "" && runtime.Session != nil {
			operation = runtime.Session.Snapshot().ActiveOperation
		}
		snapshot, err := runtime.LaunchKeyPolicies.GetLaunchKeyPolicy(ctx, status.Identity.SocketPath, operation)
		if err != nil {
			return Result{}, err
		}
		return Result{Human: launchKeyPolicyHuman(snapshot), JSON: snapshot}, nil
	}
}

func launchKeyPolicySetHandler(runtime Runtime) Handler {
	return func(ctx context.Context, invocation Invocation) (Result, error) {
		if runtime.LaunchKeyPolicies == nil {
			return Result{}, fmt.Errorf("launch-key policy manager is not configured")
		}
		if runtime.Daemons == nil {
			return Result{}, fmt.Errorf("daemon service is not configured")
		}
		status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{
			WorkspacePath: workspacepath.ResolvePath(invocation.Option("workspace")),
		})
		if err != nil {
			return Result{}, err
		}
		quorum := 0
		if raw := strings.TrimSpace(invocation.Option("quorum")); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 {
				return Result{}, fmt.Errorf("launch-key quorum must be at least 1")
			}
			quorum = parsed
		}
		operation := strings.TrimSpace(invocation.Option("operation"))
		if operation == "" && runtime.Session != nil {
			operation = runtime.Session.Snapshot().ActiveOperation
		}
		snapshot, err := runtime.LaunchKeyPolicies.SetLaunchKeyPolicy(ctx, status.Identity.SocketPath, LaunchKeyPolicySetRequest{
			Operation:        operation,
			Mode:             invocation.Positional("mode"),
			Quorum:           quorum,
			HeartbeatTimeout: invocation.Option("heartbeat-timeout"),
		})
		if err != nil {
			return Result{}, err
		}
		return Result{Human: launchKeyPolicyHuman(snapshot), JSON: snapshot}, nil
	}
}

func launchKeyPolicyHuman(snapshot LaunchKeyPolicySnapshot) string {
	lines := []string{
		fmt.Sprintf("Launch-key policy %s", snapshot.Operation),
		fmt.Sprintf("mode              %s", snapshot.Mode),
	}
	if snapshot.Quorum > 0 {
		lines = append(lines, fmt.Sprintf("quorum           %d", snapshot.Quorum))
	}
	if snapshot.HeartbeatTimeout != "" {
		lines = append(lines, fmt.Sprintf("heartbeat        %s", snapshot.HeartbeatTimeout))
	}
	return strings.Join(lines, "\n")
}

func eventLines(events []event.Event) []string {
	if len(events) == 0 {
		return []string{"No events"}
	}
	lines := []string{"EVENTS", "TIME                           LEVEL TYPE                         MESSAGE"}
	for _, evt := range events {
		lines = append(lines, fmt.Sprintf("%-30s %-5s %-28s %s", evt.Timestamp.Format(time.RFC3339Nano), evt.Level, evt.Type, evt.Message))
	}
	return lines
}

func recordStructuredEvent(ctx context.Context, runtime Runtime, workspacePath, typ, message string, plan ThrowPlanRecord, throwID, runID string, level event.Level, fields map[string]string) error {
	if runtime.Events == nil {
		return nil
	}
	id, err := event.NewID(eventID(typ))
	if err != nil {
		return err
	}
	eventType, err := event.NewType(typ)
	if err != nil {
		return err
	}
	if fields == nil {
		fields = map[string]string{}
	}
	if plan.PlanHash != "" {
		fields["planHash"] = plan.PlanHash
	}
	topic := ""
	if plan.Chain != "" {
		topic = "operation/" + planOperation(plan) + "/chain/" + plan.Chain + "/logs"
	}
	evt, err := event.New(event.Args{
		ID:        id,
		Type:      eventType,
		Level:     level,
		Message:   message,
		Timestamp: time.Now().UTC(),
		Topic:     topic,
		Refs: event.Refs{
			WorkspaceID: workspacePath,
			Operation:   planOperation(plan),
			Chain:       plan.Chain,
			ThrowID:     throwID,
			RunID:       runID,
		},
		Fields: fields,
	})
	if err != nil {
		return err
	}
	return runtime.Events.RecordEvent(ctx, workspacePath, evt)
}

func eventID(typ string) string {
	safeType := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			return r
		default:
			return '-'
		}
	}, typ)
	safeType = strings.Trim(safeType, "-")
	if safeType == "" {
		safeType = "event"
	}
	return fmt.Sprintf("event-%s-%d", safeType, time.Now().UnixNano())
}

func dialDaemonRunClient(ctx context.Context, runtime Runtime, workspacePath string) (RunClient, func(), error) {
	if runtime.Daemons == nil {
		return nil, nil, fmt.Errorf("daemon service is not configured")
	}
	if runtime.Runs == nil {
		return nil, nil, fmt.Errorf("run client factory is not configured")
	}
	status, err := runtime.Daemons.Status(ctx, services.DaemonStatusRequest{WorkspacePath: workspacepath.ResolvePath(workspacePath)})
	if err != nil {
		return nil, nil, err
	}
	if status.State != daemon.StateRunning {
		return nil, nil, fmt.Errorf("daemon is not running for workspace %s", status.WorkspacePath)
	}
	client, err := runtime.Runs.DialRunClient(status.Identity.SocketPath)
	if err != nil {
		return nil, nil, err
	}
	return client, func() { logCommandError("close daemon run client", client.Close()) }, nil
}

func newThrowPlanForExecution(workspacePath string, throw throwExecution) ThrowPlanRecord {
	hash := planHashForExecution(throw)
	return ThrowPlanRecord{
		ID:             "plan-" + stableIDComponent(hash),
		ConfirmationID: "confirmation-" + stableIDComponent(hash),
		PlanHash:       hash,
		Workspace:      workspacePath,
		Operation:      throw.Operation,
		Chain:          throw.Chain,
		Targets:        append([]string(nil), throw.Targets...),
		Modules:        append([]string(nil), throw.Modules...),
		Steps:          cloneCapabilityChainStepRefs(throw.Steps),
		ChainConfig:    cloneStringMap(throw.ChainConfig),
		TargetConfigs:  cloneTargetConfigs(throw.TargetConfigs),
		Review:         "operator-confirmed",
		Intent:         fmt.Sprintf("throw chain %s against %d target(s)", throw.Chain, len(throw.Targets)),
	}
}

func newThrowConfirmation(plan ThrowPlanRecord, clientID, method string, confirmedAt time.Time) ThrowConfirmationRecord {
	if clientID == "" {
		clientID = "command"
	}
	if method == "" {
		method = "typed_yes"
	}
	return ThrowConfirmationRecord{
		ID:          plan.ConfirmationID,
		Workspace:   plan.Workspace,
		PlanID:      plan.ID,
		PlanHash:    plan.PlanHash,
		ClientID:    clientID,
		Method:      method,
		ConfirmedAt: confirmedAt.UTC().Format(time.RFC3339Nano),
	}
}

func newThrowRecordID(plan ThrowPlanRecord, startedAt time.Time) string {
	started := startedAt.UTC()
	if started.IsZero() {
		started = time.Now().UTC()
	}
	return "throw-" + strings.TrimPrefix(plan.ID, "plan-") + "-" + strconv.FormatInt(started.UnixNano(), 36)
}

func newThrowRecord(workspacePath string, plan ThrowPlanRecord, payload ThrowPayload, startedAt, completedAt time.Time) ThrowRecord {
	record := ThrowRecord{
		ID:          payload.ThrowID,
		Workspace:   workspacePath,
		PlanID:      plan.ID,
		PlanHash:    plan.PlanHash,
		Chain:       payload.Chain,
		Targets:     append([]string(nil), payload.Targets...),
		State:       "succeeded",
		StartedAt:   startedAt.UTC().Format(time.RFC3339Nano),
		CompletedAt: completedAt.UTC().Format(time.RFC3339Nano),
	}
	for _, result := range payload.Results {
		if result.State != "succeeded" {
			record.State = result.State
		}
		record.Runs = append(record.Runs, RunSummary{
			RunID:     result.RunID,
			ModuleID:  result.ModuleID,
			Target:    result.Target,
			State:     result.State,
			Summary:   result.Summary,
			Artifacts: len(result.Artifacts),
			Findings:  len(result.Findings),
		})
	}
	return record
}

func planOperation(plan ThrowPlanRecord) string {
	if plan.Operation != "" {
		return plan.Operation
	}
	return operatorsession.DefaultOperation
}

func confirmationClientID(runtime Runtime) string {
	if runtime.Session != nil && feedbackPublished(runtime.Session) {
		return "cli"
	}
	return "command"
}

func planHashForExecution(throw throwExecution) string {
	operation := strings.TrimSpace(throw.Operation)
	if operation == "" {
		operation = operatorsession.DefaultOperation
	}
	review := struct {
		Operation     string                       `json:"operation"`
		Chain         string                       `json:"chain"`
		Targets       []string                     `json:"targets"`
		Modules       []string                     `json:"modules"`
		Steps         []CapabilityChainStepRef     `json:"steps,omitempty"`
		ChainConfig   map[string]string            `json:"chainConfig,omitempty"`
		TargetConfigs map[string]map[string]string `json:"targetConfigs,omitempty"`
	}{
		Operation:     operation,
		Chain:         throw.Chain,
		Targets:       append([]string(nil), throw.Targets...),
		Modules:       append([]string(nil), throw.Modules...),
		Steps:         cloneCapabilityChainStepRefs(throw.Steps),
		ChainConfig:   cloneStringMap(throw.ChainConfig),
		TargetConfigs: cloneTargetConfigs(throw.TargetConfigs),
	}
	data, err := json.Marshal(review)
	if err != nil {
		return planHashLegacy(throw.Chain, throw.Targets)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func planHashLegacy(chain string, targets []string) string {
	var b strings.Builder
	b.WriteString("chain:")
	b.WriteString(chain)
	b.WriteString("\ntargets:")
	for _, target := range targets {
		b.WriteString("\n")
		b.WriteString(target)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func stableIDComponent(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 16 {
		return value[:16]
	}
	if value != "" {
		return value
	}
	return "record"
}

func launchKeyPendingThrowID(plan ThrowPlanRecord, allowDangerous, nowBypass bool) string {
	fingerprint := struct {
		PlanHash       string `json:"planHash"`
		AllowDangerous bool   `json:"allowDangerous"`
		NowBypass      bool   `json:"nowBypass"`
	}{
		PlanHash:       plan.PlanHash,
		AllowDangerous: allowDangerous,
		NowBypass:      nowBypass,
	}
	data, err := json.Marshal(fingerprint)
	if err != nil {
		return "pending-" + stableIDComponent(plan.PlanHash)
	}
	sum := sha256.Sum256(data)
	return "pending-" + hex.EncodeToString(sum[:16])
}

func requireLaunchKeyReady(ctx context.Context, runtime Runtime, socketPath string, req PendingThrowCreateRequest) error {
	if runtime.PendingThrows == nil {
		return nil
	}
	if _, err := runtime.PendingThrows.CreatePendingThrow(ctx, socketPath, req); err != nil && !isPendingThrowExistsError(err, req.ID) {
		return err
	}
	if _, err := runtime.PendingThrows.RequirePendingThrowReady(ctx, socketPath, req.ID); err != nil {
		return fmt.Errorf("launch-key pending throw %s is not ready: %w", req.ID, err)
	}
	if err := runtime.PendingThrows.CancelPendingThrow(ctx, socketPath, req.ID); err != nil {
		return fmt.Errorf("consume launch-key pending throw %s: %w", req.ID, err)
	}
	return nil
}

func isPendingThrowExistsError(err error, id string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "pending throw "+id+" already exists")
}

type throwExecution struct {
	Operation      string
	Chain          string
	Targets        []string
	Modules        []string
	Steps          []CapabilityChainStepRef
	ChainConfig    map[string]string
	TargetConfigs  map[string]map[string]string
	SkippedTargets []SkippedTarget
}

type SkippedTarget struct {
	Target string
	Reason string
}

type throwStepRef = CapabilityChainStepRef

// guardDangerousModules refuses to throw a chain that contains a module tagged
// dangerous unless the operator explicitly opted in with --allow-dangerous. The
// check runs before any plan, confirmation, or daemon work so a refused throw
// leaves no records behind. Unknown module IDs are treated as not-dangerous here;
// they fail later with a clearer "module does not exist" error.
func guardDangerousModules(runtime Runtime, modules []string, allow bool) error {
	return guardDangerousModulesWithDB(moduleDB(runtime), modules, allow)
}

func guardDangerousModulesWithDB(db ModuleDatabase, modules []string, allow bool) error {
	if allow {
		return nil
	}
	var blocked []string
	for _, moduleID := range modules {
		if moduleID == "squatter.bind" {
			blocked = append(blocked, moduleID)
			continue
		}
		module, ok := db.Find(moduleID)
		if ok && module.Dangerous() {
			blocked = append(blocked, module.ID)
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	return fmt.Errorf("refusing to throw dangerous module(s) %s without --allow-dangerous", strings.Join(blocked, ", "))
}

func throwInputs(ctx context.Context, runtime Runtime, invocation Invocation) (throwExecution, error) {
	return throwInputsWithDB(ctx, runtime, invocation, moduleDB(runtime))
}

func throwInputsWithDB(ctx context.Context, runtime Runtime, invocation Invocation, db ModuleDatabase) (throwExecution, error) {
	if file := invocation.Positional("file"); strings.TrimSpace(file) != "" {
		return throwInputsFromChainFileWithDB(ctx, runtime, invocation, file, db)
	}
	operation := operatorsession.DefaultOperation
	chain := invocation.Option("chain")
	explicitTarget := invocation.Option("target")
	targetSet := invocation.Option("target-set")
	if explicitTarget != "" && targetSet != "" {
		return throwExecution{}, fmt.Errorf("--target and --target-set cannot be used together")
	}
	var targets []string
	if explicitTarget != "" {
		targets = append(targets, explicitTarget)
	}
	chainConfig := map[string]string{}
	targetConfigs := map[string]map[string]string{}
	var modules []string
	var steps []CapabilityChainStepRef
	validateTargetCompatibility := false
	if runtime.Session != nil {
		state := runtime.Session.Snapshot()
		if state.ActiveOperation != "" {
			operation = state.ActiveOperation
		}
		if chain == "" {
			chain = state.Chain
		}
		selected, ok := selectedChainState(state, chain)
		if !ok {
			return throwExecution{}, fmt.Errorf("chain %s does not exist", chain)
		}
		hasSquatterBind := false
		for _, step := range selected.Steps {
			if step.StepID == "squatter.bind" {
				hasSquatterBind = true
				modules = append(modules, "squatter.bind")
				continue
			}
			modules = append(modules, step.ModuleID)
			if step.StepID != "" {
				steps = append(steps, CapabilityChainStepRef{ID: step.ID, ModuleID: step.ModuleID, StepID: step.StepID})
			}
		}
		chainConfig = cloneStringMap(selected.Config)
		for _, step := range selected.Steps {
			if step.StepID == "" && isSquatterTCPBindModule(db, step.ModuleID, chainConfig) {
				hasSquatterBind = true
				break
			}
		}
		targetConfigs = cloneTargetConfigs(state.TargetConfigs)
		if explicitTarget != "" && hasString(state.Targets, explicitTarget) {
			validateTargetCompatibility = true
		}
		if len(targets) == 0 {
			if targetSet != "" {
				set, ok := targetSetByName(state.TargetSets, targetSet)
				if !ok {
					return throwExecution{}, fmt.Errorf("target set %s does not exist", targetSet)
				}
				targets = append(targets, set.Targets...)
				validateTargetCompatibility = true
			} else {
				targets = append(targets, state.Targets...)
			}
		}
		if hasSquatterBind {
			targetConfigs = applySquatterBindTargetConfig(targets, targetConfigs, chainConfig)
		}
	} else if targetSet != "" {
		return throwExecution{}, fmt.Errorf("--target-set requires an operator session")
	}
	if strings.TrimSpace(chain) == "" {
		return throwExecution{}, fmt.Errorf("chain is required; set one with chain use <chain> or pass --chain")
	}
	if len(targets) == 0 {
		return throwExecution{}, fmt.Errorf("target is required; add one with target add <target> or pass --target")
	}
	if len(modules) == 0 {
		if runtime.Session != nil {
			return throwExecution{}, fmt.Errorf("chain %s has no modules; add one with chain add <module>", chain)
		}
		moduleRef := chain
		if module, ok := db.Find(chain); ok {
			moduleRef = module.ID
		}
		modules = append(modules, moduleRef)
	}
	targetConfigs = targetConfigsForTargets(targets, targetConfigs)
	var skipped []SkippedTarget
	if validateTargetCompatibility {
		var err error
		targets, targetConfigs, skipped, err = compatibleThrowTargets(db, validationSteps(modules, steps), chainConfig, targetConfigs, targets, explicitTarget != "")
		if err != nil {
			return throwExecution{}, err
		}
	}
	return throwExecution{
		Operation:      operation,
		Chain:          chain,
		Targets:        targets,
		Modules:        modules,
		Steps:          steps,
		ChainConfig:    chainConfig,
		TargetConfigs:  targetConfigs,
		SkippedTargets: skipped,
	}, nil
}

func validationSteps(modules []string, steps []CapabilityChainStepRef) []CapabilityChainStepRef {
	if len(steps) != 0 {
		return steps
	}
	out := make([]CapabilityChainStepRef, 0, len(modules))
	for i, moduleID := range modules {
		out = append(out, CapabilityChainStepRef{
			ID:       fmt.Sprintf("step-%d", i+1),
			ModuleID: moduleID,
		})
	}
	return out
}

func applySquatterBindTargetConfig(targets []string, configs map[string]map[string]string, chainConfig map[string]string) map[string]map[string]string {
	if configs == nil {
		configs = map[string]map[string]string{}
	}
	chainBindPort := strings.TrimSpace(chainConfig["squatter.bind_port"])
	chainPayloadBindPort := strings.TrimSpace(chainConfig["payload.bind_port"])
	remotePath := strings.TrimSpace(chainConfig["squatter.remote_path"])
	for _, target := range targets {
		config := cloneStringMap(configs[target])
		if config == nil {
			config = map[string]string{}
		}
		switch strings.TrimSpace(config["target.port"]) {
		case "139", "445":
		default:
			config["target.port"] = "445"
		}
		config["payload.transport"] = squatterTypeTCPBind
		if remotePath != "" {
			config["payload.remote_path"] = remotePath
		}
		switch targetBindPort := strings.TrimSpace(config["payload.bind_port"]); {
		case chainBindPort != "":
			config["payload.bind_port"] = chainBindPort
		case targetBindPort != "":
			config["payload.bind_port"] = targetBindPort
		case chainPayloadBindPort != "":
			config["payload.bind_port"] = chainPayloadBindPort
		default:
			config["payload.bind_port"] = "9101"
		}
		configs[target] = config
	}
	return configs
}

func throwInputsFromChainFile(ctx context.Context, runtime Runtime, invocation Invocation, path string) (throwExecution, error) {
	return throwInputsFromChainFileWithDB(ctx, runtime, invocation, path, moduleDB(runtime))
}

func throwInputsFromChainFileWithDB(ctx context.Context, runtime Runtime, invocation Invocation, path string, db ModuleDatabase) (throwExecution, error) {
	if runtime.ChainFiles == nil {
		return throwExecution{}, fmt.Errorf("chain file store is not configured")
	}
	operation := operatorsession.DefaultOperation
	if runtime.Session != nil {
		if state := runtime.Session.Snapshot(); state.ActiveOperation != "" {
			operation = state.ActiveOperation
		}
	}
	file, err := runtime.ChainFiles.ReadChainFile(ctx, path)
	if err != nil {
		return throwExecution{}, err
	}
	if err := validateChainFileForThrow(file); err != nil {
		return throwExecution{}, err
	}
	targets := make([]string, 0, len(file.Spec.Targets))
	targetConfigs := cloneTargetConfigs(file.Spec.TargetConfigs)
	for _, target := range file.Spec.Targets {
		targets = append(targets, target.ID)
		if len(target.Config) != 0 {
			if targetConfigs == nil {
				targetConfigs = map[string]map[string]string{}
			}
			targetConfigs[target.ID] = cloneStringMap(target.Config)
		}
	}
	if target := invocation.Option("target"); target != "" {
		targets = []string{target}
	}
	targetConfigs = targetConfigsForTargets(targets, targetConfigs)
	modules := make([]string, 0, len(file.Spec.Steps))
	steps := make([]throwStepRef, 0, len(file.Spec.Steps))
	for _, step := range file.Spec.Steps {
		if !strings.HasPrefix(strings.TrimSpace(step.Uses), "module:") {
			return throwExecution{}, fmt.Errorf("chain file step %s uses unsupported runtime %q", step.ID, step.Uses)
		}
		moduleID := strings.TrimPrefix(strings.TrimSpace(step.Uses), "module:")
		if moduleID == "" {
			return throwExecution{}, fmt.Errorf("chain file step %s module reference is required", step.ID)
		}
		stepID := strings.TrimSpace(step.Step)
		if stepID == "squatter.bind" {
			modules = append(modules, "squatter.bind")
			continue
		} else {
			modules = append(modules, moduleID)
		}
		if stepID != "" {
			steps = append(steps, throwStepRef{
				ID:       step.ID,
				ModuleID: moduleID,
				StepID:   stepID,
			})
		}
	}
	if len(targets) == 0 {
		return throwExecution{}, fmt.Errorf("target is required; configured chain files must include targets or pass --target")
	}
	if hasSquatterBindModule(modules) || chainFileHasSquatterTCPBindModule(db, file.Spec.Steps, file.Spec.Config) {
		targetConfigs = applySquatterBindTargetConfig(targets, targetConfigs, file.Spec.Config)
	}
	return throwExecution{
		Operation:     operation,
		Chain:         file.Metadata.Name,
		Targets:       targets,
		Modules:       modules,
		Steps:         steps,
		ChainConfig:   cloneStringMap(file.Spec.Config),
		TargetConfigs: targetConfigs,
	}, nil
}

func targetConfigsForTargets(targets []string, configs map[string]map[string]string) map[string]map[string]string {
	if len(targets) == 0 || len(configs) == 0 {
		return nil
	}
	scoped := make(map[string]map[string]string, len(targets))
	for _, target := range targets {
		config := configs[target]
		if len(config) == 0 {
			continue
		}
		scoped[target] = cloneStringMap(config)
	}
	if len(scoped) == 0 {
		return nil
	}
	return scoped
}

func compatibleThrowTargets(db ModuleDatabase, steps []CapabilityChainStepRef, chainConfig map[string]string, targetConfigs map[string]map[string]string, targets []string, strict bool) ([]string, map[string]map[string]string, []SkippedTarget, error) {
	var kept []string
	var skipped []SkippedTarget
	for _, target := range targets {
		view := modulecatalog.ConfigView{
			Steps:         validationStepRefs(steps),
			Targets:       []string{target},
			ChainConfig:   cloneStringMap(chainConfig),
			TargetConfigs: targetConfigsForTargets([]string{target}, targetConfigs),
		}
		validation := db.Validate(view)
		if validation.Valid {
			kept = append(kept, target)
			continue
		}
		targetIssues := targetIssuesFor(validation.Issues, target)
		if len(targetIssues) == 0 {
			kept = append(kept, target)
			continue
		}
		if strict {
			return nil, nil, nil, fmt.Errorf("target %s incompatible: %s", target, issueMessages(targetIssues))
		}
		skipped = append(skipped, SkippedTarget{Target: target, Reason: issueMessages(targetIssues)})
	}
	if len(kept) == 0 {
		if len(skipped) != 0 {
			return nil, nil, nil, fmt.Errorf("no compatible targets: %s", skippedTargetMessages(skipped))
		}
		return nil, nil, nil, fmt.Errorf("target is required; add one with target add <target> or pass --target")
	}
	return kept, targetConfigsForTargets(kept, targetConfigs), skipped, nil
}

func validationStepRefs(steps []CapabilityChainStepRef) []modulecatalog.StepRef {
	refs := make([]modulecatalog.StepRef, 0, len(steps))
	for _, step := range steps {
		refs = append(refs, modulecatalog.StepRef{ID: step.ID, ModuleID: step.ModuleID})
	}
	return refs
}

func targetIssuesFor(issues []modulecatalog.Issue, target string) []modulecatalog.Issue {
	var out []modulecatalog.Issue
	for _, issue := range issues {
		if issue.Scope == modulecatalog.ScopeTarget && issue.Target == target {
			out = append(out, issue)
		}
	}
	return out
}

func issueMessages(issues []modulecatalog.Issue) string {
	if len(issues) == 0 {
		return "unknown incompatibility"
	}
	messages := make([]string, 0, len(issues))
	for _, issue := range issues {
		messages = append(messages, issue.Message)
	}
	return strings.Join(messages, "; ")
}

func skippedTargetMessages(skipped []SkippedTarget) string {
	messages := make([]string, 0, len(skipped))
	for _, target := range skipped {
		messages = append(messages, fmt.Sprintf("%s (%s)", target.Target, target.Reason))
	}
	return strings.Join(messages, "; ")
}

func targetSetByName(sets []operatorsession.TargetSet, name string) (operatorsession.TargetSet, bool) {
	for _, set := range sets {
		if set.Name == name {
			return set, true
		}
	}
	return operatorsession.TargetSet{}, false
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validateChainFileForThrow(file ChainFile) error {
	if err := validateChainFileShape(file); err != nil {
		return err
	}
	if file.Spec.Mode != "configured" {
		return fmt.Errorf("chain file mode must be configured for throw")
	}
	if len(file.Spec.Targets) == 0 {
		return fmt.Errorf("chain file must include targets for throw")
	}
	capabilitySteps := 0
	bridgeSteps := 0
	for _, step := range file.Spec.Steps {
		stepID := strings.TrimSpace(step.Step)
		if stepID == "squatter.bind" {
			bridgeSteps++
			continue
		}
		if stepID != "" {
			capabilitySteps++
		}
	}
	if capabilitySteps != 0 && capabilitySteps+bridgeSteps != len(file.Spec.Steps) {
		return fmt.Errorf("chain file capability-step execution: all steps must declare step")
	}
	return nil
}

func validateChainFileShape(file ChainFile) error {
	if strings.TrimSpace(file.APIVersion) == "" {
		return fmt.Errorf("chain file apiVersion is required")
	}
	if file.Kind != "Chain" {
		return fmt.Errorf("chain file kind must be Chain")
	}
	if strings.TrimSpace(file.Metadata.Name) == "" {
		return fmt.Errorf("chain file metadata.name is required")
	}
	if file.Spec.Mode != "" && file.Spec.Mode != "template" && file.Spec.Mode != "configured" {
		return fmt.Errorf("chain file mode must be template or configured")
	}
	if len(file.Spec.Steps) == 0 {
		return fmt.Errorf("chain file must include at least one step")
	}
	for _, step := range file.Spec.Steps {
		if strings.TrimSpace(step.ID) == "" {
			return fmt.Errorf("chain file step id is required")
		}
		if strings.TrimSpace(step.Uses) == "" {
			return fmt.Errorf("chain file step %s module reference is required", step.ID)
		}
		if !strings.HasPrefix(step.Uses, "module:") && !strings.HasPrefix(step.Uses, "service:") && !strings.HasPrefix(step.Uses, "provider:") {
			return fmt.Errorf("chain file step %s uses must start with module:, service:, or provider", step.ID)
		}
	}
	return nil
}

func selectedChainState(state operatorsession.State, chain string) (operatorsession.Chain, bool) {
	if chain == "" || chain == state.ActiveChain {
		return operatorsession.Chain{
			Name:     state.Chain,
			Steps:    append([]operatorsession.Step(nil), state.Steps...),
			Config:   cloneStringMap(state.Config),
			LogTopic: state.LogTopic,
		}, true
	}
	for _, candidate := range state.Chains {
		if candidate.Name == chain {
			return candidate, true
		}
	}
	return operatorsession.Chain{}, false
}

func chainFileFromState(state operatorsession.State, template bool) ChainFile {
	mode := "configured"
	if template {
		mode = "template"
	}
	file := ChainFile{
		APIVersion: "hovel.dev/v1alpha1",
		Kind:       "Chain",
		Metadata:   ChainFileMetadata{Name: state.ActiveChain},
		Spec: ChainFileSpec{
			Mode:  mode,
			Steps: chainFileSteps(state.Steps),
		},
	}
	if !template {
		file.Spec.Config = cloneStringMap(state.Config)
		for _, target := range state.Targets {
			file.Spec.Targets = append(file.Spec.Targets, ChainFileTarget{
				ID:     target,
				Config: cloneStringMap(state.TargetConfigs[target]),
			})
		}
		file.Spec.TargetConfigs = cloneTargetConfigs(state.TargetConfigs)
	}
	return file
}

func chainFileSteps(steps []operatorsession.Step) []ChainFileStep {
	out := make([]ChainFileStep, 0, len(steps))
	for _, step := range steps {
		fileStep := ChainFileStep{
			ID:   step.ID,
			Uses: "module:" + step.ModuleID,
			Step: step.StepID,
		}
		out = append(out, fileStep)
	}
	return out
}

func loadChainFile(session OperatorSession, file ChainFile) error {
	if err := validateChainFileShape(file); err != nil {
		return err
	}
	name := strings.TrimSpace(file.Metadata.Name)
	if err := session.DeleteChain(name); err != nil && !strings.Contains(err.Error(), "does not exist") {
		return err
	}
	if err := session.CreateChain(name); err != nil {
		return err
	}
	if err := session.UseChain(name); err != nil {
		return err
	}
	for _, step := range file.Spec.Steps {
		moduleID := strings.TrimPrefix(strings.TrimSpace(step.Uses), "module:")
		if moduleID == "" {
			return fmt.Errorf("chain file step %s module reference is required", step.ID)
		}
		if strings.TrimSpace(step.Step) != "" {
			if _, err := session.AddStep(moduleID, strings.TrimSpace(step.Step)); err != nil {
				return err
			}
			continue
		}
		if _, err := session.AddModule(moduleID); err != nil {
			return err
		}
	}
	for key, value := range file.Spec.Config {
		if err := session.SetChainConfig(key, value); err != nil {
			return err
		}
	}
	for _, target := range file.Spec.Targets {
		if strings.TrimSpace(target.ID) == "" {
			return fmt.Errorf("chain file target id is required")
		}
		if err := session.AddTarget(target.ID); err != nil {
			return err
		}
		targetConfig := target.Config
		if len(targetConfig) == 0 {
			targetConfig = file.Spec.TargetConfigs[target.ID]
		}
		for key, value := range targetConfig {
			if err := session.SetTargetConfig(target.ID, key, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func activeState(runtime Runtime) (operatorsession.State, error) {
	if runtime.Session == nil {
		return operatorsession.State{}, activeChainRequiredError()
	}
	state := runtime.Session.Snapshot()
	if state.ActiveChain == "" {
		return operatorsession.State{}, activeChainRequiredError()
	}
	return state, nil
}

func feedbackPublished(session OperatorSession) bool {
	publisher, ok := session.(publishedFeedbackSession)
	return ok && publisher.RemoteFeedback()
}

func activeChainRequiredError() error {
	return fmt.Errorf("active chain is required\n\nStart with:\n  chain create <name>\n  chain use <name>")
}

func operatorSessionRequiredError(command string) error {
	return fmt.Errorf("%s needs an operator session\n\nUse the interactive shell:\n  hovel shell\n\nOr keep using one-shot commands that do not depend on selected chain state, such as:\n  hovel module installed\n  hovel module available\n  hovel throw --chain <chain> --target <target>", command)
}

func withActiveChainHelp(err error) error {
	if err != nil && strings.Contains(err.Error(), "active chain is required") {
		return activeChainRequiredError()
	}
	return err
}

func displayValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func installedModuleRecordsForInvocation(ctx context.Context, runtime Runtime, invocation Invocation) ([]ModuleInventoryRecord, error) {
	workspacePath := workspaceFromInvocation(invocation)
	scope := "workspace"
	if invocation.Flag("global") {
		scope = "global"
	}
	return installedModuleRecords(ctx, runtime, workspacePath, scope)
}

func installedModuleRecords(ctx context.Context, runtime Runtime, workspacePath, scope string) ([]ModuleInventoryRecord, error) {
	lock, err := modulepackage.LoadLock(filepath.Join(workspacePath, "module-lock.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	records := make([]ModuleInventoryRecord, 0, len(lock.Modules))
	for _, lockRecord := range lock.Modules {
		pkg, err := modulepackage.LoadDir(lockRecord.Source)
		if err != nil {
			return nil, fmt.Errorf("load installed module %s@%s: %w", lockRecord.Name, lockRecord.Version, err)
		}
		module, err := moduleFromPackage(ctx, runtime, pkg)
		if err != nil {
			return nil, fmt.Errorf("inspect installed module %s@%s: %w", lockRecord.Name, lockRecord.Version, err)
		}
		record := moduleInventoryRecordFromModule(module, scope, "installed", lockRecord.Source)
		record.SHA256 = lockRecord.SHA256
		record.Linked = lockRecord.Linked
		record.Installed = true
		record.InstalledAt = lockRecord.InstalledAt
		records = append(records, record)
	}
	sortModuleInventoryRecords(records)
	return records, nil
}

func availableModuleRecordsForInvocation(ctx context.Context, runtime Runtime, invocation Invocation) ([]ModuleInventoryRecord, error) {
	workspacePath := workspaceFromInvocation(invocation)
	config, _, err := hovelconfig.Load(hovelconfig.Options{
		Workspace:    workspacePath,
		ExplicitPath: invocation.Option("config"),
	})
	if err != nil {
		return nil, err
	}

	var records []ModuleInventoryRecord
	for _, module := range moduleDB(runtime).List() {
		records = append(records, moduleInventoryRecordFromModule(module, "runtime", "catalog", "configured catalog"))
	}
	installed, err := installedModuleRecordsForInvocation(ctx, runtime, invocation)
	if err != nil {
		return nil, err
	}
	records = append(records, installed...)
	searchRecords, err := moduleInventoryRecordsFromSearchPaths(ctx, runtime, config.Modules.SearchPaths, "local", "search-path")
	if err != nil {
		return nil, err
	}
	records = append(records, searchRecords...)
	if config.Cache.Enabled {
		cachePath, err := modulepackage.DownloadCacheDir("")
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(cachePath); err == nil {
			cacheRecords, err := moduleInventoryRecordsFromSearchPaths(ctx, runtime, []string{cachePath}, "cache", "cache")
			if err != nil {
				return nil, err
			}
			records = append(records, cacheRecords...)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	indexRecords, err := moduleInventoryRecordsFromIndexes(moduleInventoryIndexPaths(config, invocation), config.Cache.Enabled)
	if err != nil {
		return nil, err
	}
	records = append(records, indexRecords...)
	records = dedupeModuleInventoryRecords(records)
	sortModuleInventoryRecords(records)
	return records, nil
}

func moduleInventoryIndexPaths(config hovelconfig.Config, invocation Invocation) []string {
	paths := defaultLocalModuleIndexPaths()
	paths = append(paths, config.Modules.Indexes...)
	if explicit := strings.TrimSpace(invocation.Option("index")); explicit != "" {
		paths = append(paths, explicit)
	}
	return dedupeStrings(paths)
}

func defaultLocalModuleIndexPaths() []string {
	var paths []string
	addRoot := func(root string) {
		root = strings.TrimSpace(root)
		if root == "" {
			return
		}
		if abs, err := filepath.Abs(root); err == nil {
			root = abs
		}
		path := filepath.Join(root, "dist", "modules", "module-index.yaml")
		if _, err := os.Stat(path); err != nil {
			return
		}
		paths = append(paths, path)
	}

	if configPath := strings.TrimSpace(os.Getenv("HOVEL_MODULE_CONFIG")); configPath != "" {
		if resolved, err := filepath.Abs(configPath); err == nil {
			configPath = resolved
		}
		dir := filepath.Dir(configPath)
		switch filepath.Base(dir) {
		case "examples":
			addRoot(filepath.Dir(dir))
		case "python":
			if filepath.Base(filepath.Dir(dir)) == "examples" {
				addRoot(filepath.Dir(filepath.Dir(dir)))
			}
		}
	}
	if root := strings.TrimSpace(os.Getenv("HOVEL_REPO_ROOT")); root != "" {
		addRoot(root)
	}
	if root := strings.TrimSpace(os.Getenv("BUILD_WORKSPACE_DIRECTORY")); root != "" {
		addRoot(root)
	}
	return dedupeStrings(paths)
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func moduleInventoryRecordsFromSearchPaths(ctx context.Context, runtime Runtime, paths []string, scope, sourceKind string) ([]ModuleInventoryRecord, error) {
	var records []ModuleInventoryRecord
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			record, ok, err := moduleInventoryRecordFromPackageFile(path, scope, sourceKind)
			if err != nil {
				return nil, err
			}
			if ok {
				records = append(records, record)
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(path, modulepackage.ManifestName)); err == nil {
			pkg, err := modulepackage.LoadDir(path)
			if err != nil {
				return nil, err
			}
			module, err := moduleFromPackage(ctx, runtime, pkg)
			if err != nil {
				return nil, err
			}
			records = append(records, moduleInventoryRecordFromModule(module, scope, sourceKind, pkg.Root))
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			child := filepath.Join(path, entry.Name())
			if entry.IsDir() {
				if _, err := os.Stat(filepath.Join(child, modulepackage.ManifestName)); err != nil {
					continue
				}
				pkg, err := modulepackage.LoadDir(child)
				if err != nil {
					return nil, err
				}
				module, err := moduleFromPackage(ctx, runtime, pkg)
				if err != nil {
					return nil, err
				}
				records = append(records, moduleInventoryRecordFromModule(module, scope, sourceKind, pkg.Root))
				continue
			}
			record, ok, err := moduleInventoryRecordFromPackageFile(child, scope, sourceKind)
			if err != nil {
				return nil, err
			}
			if ok {
				records = append(records, record)
			}
		}
	}
	return records, nil
}

func moduleInventoryRecordsFromIndexes(indexPaths []string, cacheEnabled bool) ([]ModuleInventoryRecord, error) {
	var records []ModuleInventoryRecord
	for _, indexPath := range indexPaths {
		indexPath = strings.TrimSpace(indexPath)
		if indexPath == "" {
			continue
		}
		index, err := loadLocalModuleIndex(indexPath)
		if err != nil {
			return nil, err
		}
		for _, entry := range index.Modules {
			archive, sourceKind, ok, err := archiveForIndexEntry(indexPath, entry, cacheEnabled)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			record, ok, err := moduleInventoryRecordFromPackageFile(archive, "local", sourceKind)
			if err != nil {
				return nil, err
			}
			if ok {
				records = append(records, record)
			}
		}
	}
	return records, nil
}

func loadLocalModuleIndex(indexPath string) (modulepackage.Index, error) {
	if strings.HasPrefix(indexPath, "https://") {
		index, err := loadModuleIndex(indexPath, true)
		if err != nil {
			return modulepackage.Index{}, nil
		}
		return index, nil
	}
	if strings.HasPrefix(indexPath, "http://") {
		return modulepackage.Index{}, nil
	}
	return modulepackage.LoadIndex(indexPath)
}

func archiveForIndexEntry(indexPath string, entry modulepackage.IndexEntry, cacheEnabled bool) (string, string, bool, error) {
	source := strings.TrimSpace(entry.URL)
	if source == "" {
		return "", "", false, nil
	}
	if !strings.HasPrefix(source, "https://") && !strings.HasPrefix(source, "http://") {
		if !filepath.IsAbs(source) {
			source = filepath.Join(filepath.Dir(indexPath), source)
		}
		if _, err := os.Stat(source); err == nil {
			return source, "index", true, nil
		} else if !os.IsNotExist(err) {
			return "", "", false, err
		}
	}
	if !cacheEnabled || strings.TrimSpace(entry.SHA256) == "" {
		return "", "", false, nil
	}
	cachePath, err := modulepackage.DownloadCacheDir("")
	if err != nil {
		return "", "", false, err
	}
	archive := filepath.Join(cachePath, strings.ToLower(strings.TrimSpace(entry.SHA256))+".tgz")
	if _, err := os.Stat(archive); err == nil {
		return archive, "cache", true, nil
	} else if !os.IsNotExist(err) {
		return "", "", false, err
	}
	return "", "", false, nil
}

func moduleInventoryRecordFromPackageFile(path, scope, sourceKind string) (ModuleInventoryRecord, bool, error) {
	if !strings.EqualFold(filepath.Ext(path), ".tgz") {
		return ModuleInventoryRecord{}, false, nil
	}
	manifest, err := modulepackage.LoadManifestArchive(path)
	if err != nil {
		return ModuleInventoryRecord{}, false, err
	}
	record := moduleInventoryRecordFromManifest(manifest, scope, sourceKind, path)
	if sum, err := modulepackage.FileSHA256(path); err == nil {
		record.SHA256 = sum
	}
	return record, true, nil
}

func moduleInventoryRecordFromModule(module modulecatalog.Module, scope, sourceKind, source string) ModuleInventoryRecord {
	name, version, _ := modulecatalog.SplitID(module.ID)
	if name == "" {
		name = module.Name
	}
	if version == "" {
		version = module.Version
	}
	return ModuleInventoryRecord{
		ID:         module.ID,
		Name:       name,
		Version:    version,
		Type:       module.Type,
		Summary:    module.Summary,
		Scope:      scope,
		SourceKind: sourceKind,
		Source:     source,
	}
}

func moduleInventoryRecordFromManifest(manifest modulepackage.Manifest, scope, sourceKind, source string) ModuleInventoryRecord {
	return ModuleInventoryRecord{
		ID:         modulecatalog.CanonicalID(manifest.Metadata.Name, manifest.Metadata.Version),
		Name:       manifest.Metadata.Name,
		Version:    manifest.Metadata.Version,
		Type:       modulecatalog.ModuleType(manifest.Metadata.ModuleType),
		Summary:    manifest.Metadata.Summary,
		Scope:      scope,
		SourceKind: sourceKind,
		Source:     source,
	}
}

func filterModuleInventoryRecords(records []ModuleInventoryRecord, query string, moduleType modulecatalog.ModuleType) []ModuleInventoryRecord {
	query = strings.ToLower(strings.TrimSpace(query))
	filtered := make([]ModuleInventoryRecord, 0, len(records))
	for _, record := range records {
		if moduleType != "" && record.Type != moduleType {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(record.ID + " " + record.Name + " " + record.Summary + " " + record.SourceKind + " " + record.Source)
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func dedupeModuleInventoryRecords(records []ModuleInventoryRecord) []ModuleInventoryRecord {
	byID := map[string]ModuleInventoryRecord{}
	for _, record := range records {
		key := moduleInventoryRecordKey(record)
		if key == "" {
			continue
		}
		if existing, ok := byID[key]; ok && moduleInventoryRecordRank(existing) >= moduleInventoryRecordRank(record) {
			continue
		}
		byID[key] = record
	}
	out := make([]ModuleInventoryRecord, 0, len(byID))
	for _, record := range byID {
		out = append(out, record)
	}
	return out
}

func moduleInventoryRecordKey(record ModuleInventoryRecord) string {
	name := strings.TrimSpace(record.Name)
	version := normalizeLooseVersion(record.Version)
	if name != "" {
		if version != "" {
			return name + "@" + version
		}
		return name
	}
	id := strings.TrimSpace(record.ID)
	if id == "" {
		return ""
	}
	name, version, hasVersion := modulecatalog.SplitID(id)
	if !hasVersion {
		return id
	}
	return name + "@" + normalizeLooseVersion(version)
}

func moduleInventoryRecordRank(record ModuleInventoryRecord) int {
	if record.Installed {
		if record.Scope == "workspace" {
			return 100
		}
		return 90
	}
	switch record.SourceKind {
	case "search-path":
		return 80
	case "cache":
		return 70
	case "index":
		return 60
	case "catalog":
		return 10
	default:
		return 10
	}
}

func sortModuleInventoryRecords(records []ModuleInventoryRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].ID != records[j].ID {
			return records[i].ID < records[j].ID
		}
		if records[i].Scope != records[j].Scope {
			return records[i].Scope < records[j].Scope
		}
		return records[i].Source < records[j].Source
	})
}

func moduleDB(runtime Runtime) ModuleDatabase {
	if runtime.Modules != nil {
		return runtime.Modules
	}
	return modulecatalog.BuiltIns()
}

func moduleDBForInvocation(ctx context.Context, runtime Runtime, invocation Invocation) (ModuleDatabase, error) {
	base := moduleDB(runtime)
	workspacePath := workspaceFromInvocation(invocation)
	config, _, err := hovelconfig.Load(hovelconfig.Options{
		Workspace:    workspacePath,
		ExplicitPath: invocation.Option("config"),
	})
	if err != nil {
		return nil, err
	}
	searchPaths := append([]string(nil), config.Modules.SearchPaths...)
	configured, err := modulesFromSearchPaths(ctx, runtime, searchPaths)
	if err != nil {
		return nil, err
	}
	installed, err := installedPackageModules(ctx, runtime, workspacePath)
	if err != nil {
		return nil, err
	}
	if len(configured) == 0 && len(installed) == 0 {
		return base, nil
	}
	modules := base.List()
	modules = append(modules, configured...)
	modules = append(modules, installed...)
	catalog := modulecatalog.New(modules...)
	return catalog, nil
}

func modulesFromSearchPaths(ctx context.Context, runtime Runtime, paths []string) ([]modulecatalog.Module, error) {
	var modules []modulecatalog.Module
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(path, modulepackage.ManifestName)); err == nil {
			pkg, err := modulepackage.LoadDir(path)
			if err != nil {
				return nil, err
			}
			module, err := moduleFromPackage(ctx, runtime, pkg)
			if err != nil {
				return nil, err
			}
			modules = append(modules, module)
			continue
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			child := filepath.Join(path, entry.Name())
			if entry.IsDir() {
				if _, err := os.Stat(filepath.Join(child, modulepackage.ManifestName)); err != nil {
					continue
				}
				pkg, err := modulepackage.LoadDir(child)
				if err != nil {
					return nil, err
				}
				module, err := moduleFromPackage(ctx, runtime, pkg)
				if err != nil {
					return nil, err
				}
				modules = append(modules, module)
				continue
			}
		}
	}
	return modules, nil
}

func installedPackageModules(ctx context.Context, runtime Runtime, workspacePath string) ([]modulecatalog.Module, error) {
	lock, err := modulepackage.LoadLock(filepath.Join(workspacePath, "module-lock.yaml"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	modules := make([]modulecatalog.Module, 0, len(lock.Modules))
	for _, record := range lock.Modules {
		pkg, err := modulepackage.LoadDir(record.Source)
		if err != nil {
			return nil, fmt.Errorf("load installed module %s@%s: %w", record.Name, record.Version, err)
		}
		module, err := moduleFromPackage(ctx, runtime, pkg)
		if err != nil {
			return nil, fmt.Errorf("inspect installed module %s@%s: %w", record.Name, record.Version, err)
		}
		modules = append(modules, module)
	}
	return modules, nil
}

func moduleFromPackage(ctx context.Context, runtime Runtime, pkg modulepackage.Package) (modulecatalog.Module, error) {
	if runtime.ModuleInspector != nil {
		return runtime.ModuleInspector.InspectPackage(ctx, pkg)
	}
	return moduleFromManifest(pkg.Manifest), nil
}

func moduleFromManifest(manifest modulepackage.Manifest) modulecatalog.Module {
	return modulecatalog.Module{
		ID:          modulecatalog.CanonicalID(manifest.Metadata.Name, manifest.Metadata.Version),
		Name:        manifest.Metadata.Name,
		Type:        modulecatalog.ModuleType(manifest.Metadata.ModuleType),
		Version:     manifest.Metadata.Version,
		Summary:     manifest.Metadata.Summary,
		Tags:        append([]string(nil), manifest.Metadata.Tags...),
		RuntimeKind: manifest.Runtime.Protocol,
		Author:      manifest.Metadata.Author,
		Enabled:     true,
	}
}

func workspaceFromInvocation(invocation Invocation) string {
	if invocation.Flag("global") {
		return globalModuleWorkspace()
	}
	return workspacepath.ResolvePath(invocation.Option("workspace"))
}

func globalModuleWorkspace() string {
	if dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dataHome != "" {
		return filepath.Join(dataHome, "hovel", "modules")
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		return filepath.Join(home, ".local", "share", "hovel", "modules")
	}
	return filepath.Join(".hovel-global")
}

func ValidateState(db ModuleDatabase, state operatorsession.State) modulecatalog.Validation {
	var issues []modulecatalog.Issue
	if len(state.Steps) == 0 {
		issues = append(issues, modulecatalog.Issue{Scope: modulecatalog.ScopeChain, Message: "chain has no modules"})
	}
	if len(state.Targets) == 0 {
		issues = append(issues, modulecatalog.Issue{Scope: modulecatalog.ScopeTarget, Message: "chain has no targets"})
	}

	normalSteps := make([]modulecatalog.StepRef, 0, len(state.Steps))
	for _, step := range state.Steps {
		ref := modulecatalog.StepRef{ID: step.ID, ModuleID: step.ModuleID}
		if step.StepID == "squatter.bind" || (step.StepID == "" && isSquatterTCPBindModule(db, step.ModuleID, state.Config)) {
			if step.StepID == "squatter.bind" {
				ref.ModuleID = "squatter.bind"
			}
			issues = append(issues, validateCommandRequirements(modulecatalog.ScopeChain, ref, "", squatterBindRequirements(modulecatalog.ScopeChain), state.Config)...)
			continue
		}
		normalSteps = append(normalSteps, ref)
	}
	if len(normalSteps) != 0 {
		validation := db.Validate(modulecatalog.ConfigView{
			Steps:         normalSteps,
			Targets:       append([]string(nil), state.Targets...),
			ChainConfig:   cloneStringMap(state.Config),
			TargetConfigs: cloneTargetConfigs(state.TargetConfigs),
		})
		for _, issue := range validation.Issues {
			if issue.Scope == modulecatalog.ScopeTarget && issue.Message == "chain has no targets" {
				continue
			}
			issues = append(issues, issue)
		}
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Scope != issues[j].Scope {
			return issues[i].Scope < issues[j].Scope
		}
		if issues[i].Target != issues[j].Target {
			return issues[i].Target < issues[j].Target
		}
		if issues[i].StepID != issues[j].StepID {
			return issues[i].StepID < issues[j].StepID
		}
		return issues[i].Key < issues[j].Key
	})
	return modulecatalog.Validation{Valid: len(issues) == 0, Issues: issues}
}

func validateCommandRequirements(scope modulecatalog.Scope, step modulecatalog.StepRef, target string, requirements []modulecatalog.Requirement, values map[string]string) []modulecatalog.Issue {
	var issues []modulecatalog.Issue
	for _, requirement := range requirements {
		value := values[requirement.Key]
		if value == "" {
			if requirement.Required {
				issues = append(issues, modulecatalog.Issue{
					Scope:    scope,
					StepID:   step.ID,
					ModuleID: step.ModuleID,
					Target:   target,
					Key:      requirement.Key,
					Message:  fmt.Sprintf("missing %s config %s", scope, requirement.Key),
				})
			}
			continue
		}
		if err := modulecatalog.ValidateValue(requirement, value); err != nil {
			issues = append(issues, modulecatalog.Issue{
				Scope:    scope,
				StepID:   step.ID,
				ModuleID: step.ModuleID,
				Target:   target,
				Key:      requirement.Key,
				Message:  fmt.Sprintf("invalid %s config %s: %v", scope, requirement.Key, err),
			})
		}
	}
	return issues
}

func requirementsByKey(db ModuleDatabase, state operatorsession.State, scope modulecatalog.Scope) map[string]modulecatalog.Requirement {
	requirements := map[string]modulecatalog.Requirement{}
	for _, step := range state.Steps {
		if step.StepID == "squatter.bind" || (step.StepID == "" && isSquatterTCPBindModule(db, step.ModuleID, state.Config)) {
			for _, requirement := range squatterBindRequirements(scope) {
				requirements[requirement.Key] = requirement
			}
			continue
		}
		module, ok := db.Find(step.ModuleID)
		if !ok {
			continue
		}
		var scoped []modulecatalog.Requirement
		if scope == modulecatalog.ScopeTarget {
			scoped = module.TargetConfig
		} else {
			scoped = module.ChainConfig
		}
		for _, requirement := range scoped {
			requirements[requirement.Key] = requirement
		}
	}
	return requirements
}

func squatterBindRequirements(scope modulecatalog.Scope) []modulecatalog.Requirement {
	if scope == modulecatalog.ScopeTarget {
		return nil
	}
	return []modulecatalog.Requirement{
		{
			Key:         squatterTypeConfigKey,
			Type:        modulecatalog.ValueEnum,
			Required:    false,
			Default:     squatterTypeTCPBind,
			Allowed:     []string{squatterTypeTCPBind},
			Description: "Squatter install/session mode.",
		},
		{
			Key:         "squatter.bind_port",
			Type:        modulecatalog.ValuePort,
			Required:    false,
			Default:     "9101",
			Description: "TCP bind port opened by the Squatter agent on the target.",
		},
		{
			Key:         "squatter.remote_path",
			Type:        modulecatalog.ValueString,
			Required:    false,
			Description: "Optional fixed target path used when the MS17-010 exploit installs the Squatter agent; unset auto-generates a fresh path.",
		},
	}
}

func availableConfigLines(config map[string]string, requirements map[string]modulecatalog.Requirement) string {
	seen := map[string]bool{}
	var lines []string
	for _, key := range sortedRequirementKeys(requirements) {
		requirement := requirements[key]
		seen[key] = true
		status := "optional"
		if requirement.Required {
			status = "required"
		}
		value := config[key]
		if value == "" && requirement.Default != "" {
			status = "default"
			value = requirement.Default
		} else if value != "" {
			status = "set"
		}
		typeName := string(requirement.Type)
		if typeName == "" {
			typeName = "string"
		}
		display := ""
		if value != "" {
			display = modulecatalog.DisplayValue(requirement, value)
		}
		lines = append(lines, fmt.Sprintf("  %-28s %-18s %-8s %s", key, typeName, status, display))
	}
	for _, key := range sortedConfigKeys(config) {
		if seen[key] {
			continue
		}
		lines = append(lines, fmt.Sprintf("  %-28s %-18s %-8s %s", key, "string", "set", config[key]))
	}
	if len(lines) == 0 {
		return "  none"
	}
	return strings.Join(lines, "\n")
}

func sortedRequirementKeys(values map[string]modulecatalog.Requirement) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedConfigKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func moduleInventoryLines(records []ModuleInventoryRecord) string {
	lines := []string{
		"ID                         TYPE              SCOPE      SOURCE       SUMMARY",
		"--                         ----              -----      ------       -------",
	}
	for _, record := range records {
		source := record.SourceKind
		if record.Installed {
			source = "installed"
		}
		lines = append(lines, fmt.Sprintf("%-26s %-17s %-10s %-12s %s", record.ID, record.Type, record.Scope, source, record.Summary))
	}
	return strings.Join(lines, "\n")
}

func moduleInspect(payload ModuleInspectPayload) string {
	lines := []string{
		fmt.Sprintf("%s %s", payload.ID, payload.Type),
		"",
		payload.Summary,
	}
	if payload.Description != "" {
		lines = append(lines, payload.Description)
	}
	lines = append(lines,
		"",
		fmt.Sprintf("version      %s", payload.Version),
		fmt.Sprintf("runtime      %s", payload.RuntimeKind),
		fmt.Sprintf("author       %s", payload.Author),
		fmt.Sprintf("enabled      %t", payload.Enabled),
	)
	if len(payload.Tags) > 0 {
		lines = append(lines, "tags         "+strings.Join(payload.Tags, ", "))
	}
	if payload.Discovery != nil {
		lines = append(lines, "", "discovery context")
		lines = append(lines, contextLines(*payload.Discovery)...)
	}
	if payload.Planning != nil {
		lines = append(lines, "", "planning context")
		lines = append(lines, contextLines(*payload.Planning)...)
	}
	if len(payload.ChainConfig) > 0 {
		lines = append(lines, "", "chain config")
		for _, requirement := range payload.ChainConfig {
			lines = append(lines, requirementLine(requirement))
		}
	}
	if len(payload.TargetConfig) > 0 {
		lines = append(lines, "", "target config")
		for _, requirement := range payload.TargetConfig {
			lines = append(lines, requirementLine(requirement))
		}
	}
	if len(payload.Steps) > 0 {
		lines = append(lines, "", "steps")
		for _, step := range payload.Steps {
			state := "ready"
			if !step.Ready {
				state = "blocked"
			}
			line := fmt.Sprintf("  %-28s %-20s %s", step.ID, step.Kind, state)
			if len(step.Missing) > 0 {
				line += " missing " + missingCapabilitySummary(step.Missing[0])
				if len(step.Missing) > 1 {
					line += fmt.Sprintf(" (+%d more)", len(step.Missing)-1)
				}
			}
			lines = append(lines, line)
			if step.Context != nil && step.Context.Summary != "" {
				lines = append(lines, "    context "+step.Context.Summary)
			}
		}
	}
	lines = append(lines, "", "Next: chain add "+payload.ID)
	return strings.Join(lines, "\n")
}

func contextLines(context modulecatalog.Context) []string {
	var lines []string
	if context.Summary != "" {
		lines = append(lines, "  summary      "+context.Summary)
	}
	if len(context.Keywords) > 0 {
		lines = append(lines, "  keywords     "+strings.Join(context.Keywords, ", "))
	}
	if len(context.Capabilities) > 0 {
		lines = append(lines, "  capabilities "+strings.Join(context.Capabilities, ", "))
	}
	if context.Risk.Level != "" {
		detail := context.Risk.Level
		if len(context.Risk.Reasons) > 0 {
			detail += " (" + strings.Join(context.Risk.Reasons, ", ") + ")"
		}
		lines = append(lines, "  risk         "+detail)
	}
	if context.Cleanup != "" {
		lines = append(lines, "  cleanup      "+context.Cleanup)
	}
	return lines
}

func moduleInspectPayload(module modulecatalog.Module, steps []ModuleStepPayload) ModuleInspectPayload {
	payload := ModuleInspectPayload{
		ID:           module.ID,
		Name:         module.Name,
		Type:         module.Type,
		Version:      module.Version,
		Summary:      module.Summary,
		Description:  module.Description,
		Tags:         append([]string(nil), module.Tags...),
		RuntimeKind:  module.RuntimeKind,
		Author:       module.Author,
		Enabled:      module.Enabled,
		ChainConfig:  append([]modulecatalog.Requirement(nil), module.ChainConfig...),
		TargetConfig: append([]modulecatalog.Requirement(nil), module.TargetConfig...),
		Steps:        steps,
	}
	if contextPresent(module.Discovery) {
		discovery := module.Discovery
		payload.Discovery = &discovery
	}
	if contextPresent(module.Planning) {
		planning := module.Planning
		payload.Planning = &planning
	}
	return payload
}

func moduleStepPayloads(moduleID string, availability []modulecatalog.StepAvailability) []ModuleStepPayload {
	steps := []ModuleStepPayload{}
	for _, item := range availability {
		if item.ModuleID != moduleID {
			continue
		}
		payload := ModuleStepPayload{
			ID:       item.Step.ID,
			Kind:     item.Step.Kind,
			Ready:    item.Resolution.Ready,
			Requires: append([]modulecatalog.CapabilityRequirement(nil), item.Step.Requires...),
			Produces: append([]modulecatalog.CapabilityRequirement(nil), item.Step.Produces...),
			Missing:  append([]modulecatalog.MissingCapability(nil), item.Resolution.Missing...),
		}
		if contextPresent(item.Step.Context) {
			context := item.Step.Context
			payload.Context = &context
		}
		steps = append(steps, payload)
	}
	return steps
}

func ModuleStepPayloadsForMCP(moduleID string, availability []modulecatalog.StepAvailability) []ModuleStepPayload {
	return moduleStepPayloads(moduleID, availability)
}

func contextPresent(context modulecatalog.Context) bool {
	return context.Summary != "" ||
		len(context.Keywords) > 0 ||
		len(context.Platforms) > 0 ||
		len(context.Targets) > 0 ||
		len(context.Capabilities) > 0 ||
		len(context.Preconditions) > 0 ||
		len(context.SideEffects) > 0 ||
		context.Cleanup != "" ||
		context.Risk.Level != "" ||
		len(context.Risk.Reasons) > 0 ||
		len(context.Examples) > 0 ||
		len(context.AgentHints) > 0
}

func missingCapabilitySummary(missing modulecatalog.MissingCapability) string {
	parts := []string{string(missing.Type)}
	keys := make([]string, 0, len(missing.Attributes))
	for key := range missing.Attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, missing.Attributes[key]))
	}
	if len(missing.States) > 0 {
		parts = append(parts, "state="+strings.Join(missing.States, "|"))
	}
	return strings.Join(parts, " ")
}

func requirementLine(requirement modulecatalog.Requirement) string {
	required := "optional"
	if requirement.Required {
		required = "required"
	}
	typeName := string(requirement.Type)
	if typeName == "" {
		typeName = "string"
	}
	line := fmt.Sprintf("  %-28s %-18s %s", requirement.Key, typeName, required)
	if len(requirement.Allowed) > 0 {
		line += " [" + strings.Join(requirement.Allowed, ", ") + "]"
	}
	if requirement.Description != "" {
		line += "  " + requirement.Description
	}
	return line
}

func chainInspect(state operatorsession.State) string {
	lines := []string{
		fmt.Sprintf("Chain %s steps=%d config=%d topic=%s", state.ActiveChain, len(state.Steps), len(state.Config), state.LogTopic),
		"",
		"steps",
	}
	if len(state.Steps) == 0 {
		lines = append(lines, "  none")
	} else {
		for _, step := range state.Steps {
			label := step.ModuleID
			if step.StepID != "" {
				label = step.StepID
			}
			lines = append(lines, fmt.Sprintf("  %-10s %s", step.ID, label))
		}
	}
	lines = append(lines, "", "targets")
	if len(state.Targets) == 0 {
		lines = append(lines, "  none")
	} else {
		for _, target := range state.Targets {
			lines = append(lines, "  "+target)
		}
	}
	lines = append(lines, "", "Next: add <module>, target add <target>, config interactive, validate, throw")
	return strings.Join(lines, "\n")
}

func cloneStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneTargetConfigs(values map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(values))
	for target, config := range values {
		out[target] = cloneStringMap(config)
	}
	return out
}

func cloneCapabilityChainStepRefs(values []CapabilityChainStepRef) []CapabilityChainStepRef {
	if len(values) == 0 {
		return nil
	}
	return append([]CapabilityChainStepRef(nil), values...)
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func daemonStatusPayload(status daemon.Status) DaemonStatusPayload {
	payload := DaemonStatusPayload{
		State:         string(status.State),
		WorkspacePath: status.WorkspacePath,
	}
	if status.State == daemon.StateRunning {
		payload.PID = status.Identity.PID
		payload.SocketPath = status.Identity.SocketPath
		payload.Health = string(status.Identity.Health)
	}
	return payload
}

func runPayload(result RunMockExploitResponse) RunPayload {
	return RunPayload{
		RunID:             result.RunID,
		ModuleID:          result.ModuleID,
		Target:            result.Target,
		State:             result.State,
		Summary:           result.Summary,
		Findings:          result.Findings,
		Artifacts:         result.Artifacts,
		Logs:              result.Logs,
		Sessions:          result.Sessions,
		InstalledPayloads: cloneInstalledPayloadDescriptors(result.InstalledPayloads),
	}
}

func capabilityChainRunPayload(target, runID string, result CapabilityChainResponse) RunPayload {
	if result.RunID != "" {
		runID = result.RunID
	}
	if result.Target != "" {
		target = result.Target
	}
	return RunPayload{
		RunID:             runID,
		ModuleID:          "capability-chain",
		Target:            target,
		State:             result.State,
		Summary:           result.Summary,
		Capabilities:      cloneCapabilityPayloads(result.Capabilities),
		Evidence:          cloneCapabilityEvidence(result.Evidence),
		Logs:              append([]LogEntry(nil), result.Logs...),
		Sessions:          append([]SessionRef(nil), result.Sessions...),
		InstalledPayloads: cloneInstalledPayloadDescriptors(result.InstalledPayloads),
	}
}

func cloneCapabilityPayloads(values []CapabilityPayload) []CapabilityPayload {
	if len(values) == 0 {
		return nil
	}
	out := make([]CapabilityPayload, 0, len(values))
	for _, value := range values {
		value.Attributes = cloneAnyMap(value.Attributes)
		value.Extensions = cloneAnyMap(value.Extensions)
		out = append(out, value)
	}
	return out
}

func cloneCapabilityEvidence(values []CapabilityEvidence) []CapabilityEvidence {
	if len(values) == 0 {
		return nil
	}
	out := make([]CapabilityEvidence, 0, len(values))
	for _, value := range values {
		value.Details = cloneAnyMap(value.Details)
		out = append(out, value)
	}
	return out
}

func throwHeader(chain string) operatorlog.Entry {
	return operatorlog.Entry{
		Kind:      operatorlog.KindHeader,
		Level:     operatorlog.LevelInfo,
		Message:   "HOVEL//THROW",
		ChainName: chain,
	}
}

func throwPlanEntries(payload ThrowPayload, started time.Time) []operatorlog.Entry {
	return []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("0/5 review plan",
			operatorlog.Field{Name: "plan", Value: payload.Plan.ID},
			operatorlog.Field{Name: "confirmation", Value: payload.Plan.ConfirmationID},
			operatorlog.Field{Name: "review", Value: payload.Plan.Review},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Stage("1/5 prepare chain",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Info("chain", "chain staged",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
	}
}

func throwRunStartEntries(chain, target, moduleID string, runIndex, runCount int, started time.Time) []operatorlog.Entry {
	at := time.Now()
	targetStep := fmt.Sprintf("%d/%d", runIndex, runCount)
	return []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("2/5 engage target",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "address", Value: target},
		).WithTarget(target), at, started, chain),
		elapsedAt(operatorlog.Info("throw", "target engaged",
			operatorlog.Field{Name: "run", Value: "pending"},
			operatorlog.Field{Name: "target", Value: target},
		).WithTarget(target), at, started, chain),
		elapsedAt(operatorlog.Stage("3/5 execute module",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "module", Value: moduleID},
		).WithTarget(target).WithModule(moduleID), at, started, chain),
	}
}

func throwRunResultEntries(payload ThrowPayload, result RunPayload, runIndex, runCount int, started time.Time) []operatorlog.Entry {
	at := lastLogTime(result.Logs, time.Now())
	targetStep := fmt.Sprintf("%d/%d", runIndex, runCount)
	entries := []operatorlog.Entry{
		elapsedAt(operatorlog.Info("module", result.Summary).
			WithTarget(result.Target).
			WithRun(result.RunID).
			WithModule(result.ModuleID), at, started, payload.Chain),
		elapsedAt(operatorlog.Stage("4/5 record result",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "run", Value: result.RunID},
		).WithTarget(result.Target).WithRun(result.RunID), at, started, payload.Chain),
	}
	for _, finding := range result.Findings {
		entries = append(entries, elapsedAt(operatorlog.Finding("finding", finding.Title,
			operatorlog.Field{Name: "severity", Value: finding.Severity},
			operatorlog.Field{Name: "detail", Value: finding.Detail},
		).WithTarget(result.Target).WithRun(result.RunID), at, started, payload.Chain))
	}
	for _, artifact := range result.Artifacts {
		entries = append(entries, elapsedAt(operatorlog.Artifact("artifact", artifact.Name,
			operatorlog.Field{Name: "kind", Value: artifact.Kind},
		).WithTarget(result.Target).WithRun(result.RunID), at, started, payload.Chain))
	}
	for _, session := range result.Sessions {
		entries = append(entries, elapsedAt(operatorlog.Info("session", "session opened",
			operatorlog.Field{Name: "session", Value: session.ID},
			operatorlog.Field{Name: "kind", Value: session.Kind},
			operatorlog.Field{Name: "state", Value: session.State},
		).WithTarget(result.Target).WithRun(result.RunID), at, started, payload.Chain))
	}
	return entries
}

func throwModuleLogEntries(result RunMockExploitResponse, started time.Time, chain string) []operatorlog.Entry {
	entries := make([]operatorlog.Entry, 0, len(result.Logs))
	for _, log := range result.Logs {
		at, err := time.Parse(time.RFC3339Nano, log.Time)
		if err != nil || at.IsZero() {
			at = time.Now()
		}
		entries = append(entries, elapsedAt(operatorlog.Info("module", log.Message, logFields(log)...).
			WithTarget(result.Target).
			WithRun(result.RunID).
			WithModule(result.ModuleID), at, started, chain))
	}
	return entries
}

func throwCompleteEntries(payload ThrowPayload, started time.Time) []operatorlog.Entry {
	at := time.Now()
	return []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("5/5 complete throw",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), at, started, payload.Chain),
		elapsedAt(operatorlog.Success("throw", "completed",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), at, started, payload.Chain),
	}
}

func throwLog(payload ThrowPayload, started time.Time) operatorlog.Log {
	elapsed := func(entry operatorlog.Entry) operatorlog.Entry {
		return elapsedAt(entry, time.Now(), started, payload.Chain)
	}
	elapsedAtLogTime := func(entry operatorlog.Entry, log LogEntry) operatorlog.Entry {
		at, err := time.Parse(time.RFC3339Nano, log.Time)
		if err != nil || at.IsZero() {
			at = time.Now()
		}
		return elapsedAt(entry, at, started, payload.Chain)
	}
	entries := []operatorlog.Entry{
		elapsedAt(operatorlog.Stage("0/5 review plan",
			operatorlog.Field{Name: "plan", Value: payload.Plan.ID},
			operatorlog.Field{Name: "confirmation", Value: payload.Plan.ConfirmationID},
			operatorlog.Field{Name: "review", Value: payload.Plan.Review},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Stage("1/5 prepare chain",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
		elapsedAt(operatorlog.Info("chain", "chain staged",
			operatorlog.Field{Name: "chain", Value: payload.Chain},
			operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
		), started, started, payload.Chain),
	}
	for index, result := range payload.Results {
		targetStep := fmt.Sprintf("%d/%d", index+1, len(payload.Results))
		resultStarted := firstLogTime(result.Logs, started)
		resultFinished := lastLogTime(result.Logs, time.Now())
		entries = append(entries, elapsedAt(operatorlog.Stage("2/5 engage target",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "address", Value: result.Target},
		).WithTarget(result.Target).WithRun(result.RunID), resultStarted, started, payload.Chain))
		entries = append(entries, elapsedAt(operatorlog.Info("throw", "target engaged",
			operatorlog.Field{Name: "run", Value: result.RunID},
			operatorlog.Field{Name: "target", Value: result.Target},
		).WithTarget(result.Target).WithRun(result.RunID), resultStarted, started, payload.Chain))
		entries = append(entries, elapsedAt(operatorlog.Stage("3/5 execute module",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "module", Value: result.ModuleID},
		).WithTarget(result.Target).WithRun(result.RunID).WithModule(result.ModuleID), resultStarted, started, payload.Chain))
		for _, log := range result.Logs {
			entries = append(entries, elapsedAtLogTime(operatorlog.Info("module", log.Message, logFields(log)...).
				WithTarget(result.Target).
				WithRun(result.RunID).
				WithModule(result.ModuleID), log))
		}
		if result.Summary != "" {
			entries = append(entries, elapsedAt(operatorlog.Info("module", result.Summary).
				WithTarget(result.Target).
				WithRun(result.RunID).
				WithModule(result.ModuleID), resultFinished, started, payload.Chain))
		}
		entries = append(entries, elapsedAt(operatorlog.Stage("4/5 record result",
			operatorlog.Field{Name: "target", Value: targetStep},
			operatorlog.Field{Name: "run", Value: result.RunID},
		).WithTarget(result.Target).WithRun(result.RunID), resultFinished, started, payload.Chain))
		for _, finding := range result.Findings {
			entries = append(entries, elapsedAt(operatorlog.Finding("finding", finding.Title,
				operatorlog.Field{Name: "severity", Value: finding.Severity},
				operatorlog.Field{Name: "detail", Value: finding.Detail},
			).WithTarget(result.Target).WithRun(result.RunID), resultFinished, started, payload.Chain))
		}
		for _, artifact := range result.Artifacts {
			entries = append(entries, elapsedAt(operatorlog.Artifact("artifact", artifact.Name,
				operatorlog.Field{Name: "kind", Value: artifact.Kind},
			).WithTarget(result.Target).WithRun(result.RunID), resultFinished, started, payload.Chain))
		}
		for _, session := range result.Sessions {
			entries = append(entries, elapsedAt(operatorlog.Info("session", "session opened",
				operatorlog.Field{Name: "session", Value: session.ID},
				operatorlog.Field{Name: "kind", Value: session.Kind},
				operatorlog.Field{Name: "state", Value: session.State},
			).WithTarget(result.Target).WithRun(result.RunID), resultFinished, started, payload.Chain))
		}
	}
	entries = append(entries, elapsed(operatorlog.Stage("5/5 complete throw",
		operatorlog.Field{Name: "chain", Value: payload.Chain},
		operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
	)))
	entries = append(entries, elapsed(operatorlog.Success("throw", "completed",
		operatorlog.Field{Name: "chain", Value: payload.Chain},
		operatorlog.Field{Name: "targets", Value: fmt.Sprintf("%d", len(payload.Targets))},
	)))

	return operatorlog.New(
		"HOVEL//THROW",
		payload.Chain,
		entries,
	)
}

func elapsedAt(entry operatorlog.Entry, at, started time.Time, chain string) operatorlog.Entry {
	if at.Before(started) {
		at = started
	}
	return entry.
		WithElapsed(at.Sub(started).Seconds()).
		WithChain(chain).
		WithTopic("operation/" + operatorsession.DefaultOperation + "/chain/" + chain + "/logs")
}

func firstLogTime(logs []LogEntry, fallback time.Time) time.Time {
	for _, log := range logs {
		if at, err := time.Parse(time.RFC3339Nano, log.Time); err == nil && !at.IsZero() {
			return at
		}
	}
	return fallback
}

func lastLogTime(logs []LogEntry, fallback time.Time) time.Time {
	for i := len(logs) - 1; i >= 0; i-- {
		if at, err := time.Parse(time.RFC3339Nano, logs[i].Time); err == nil && !at.IsZero() {
			return at
		}
	}
	return fallback
}

func logFields(log LogEntry) []operatorlog.Field {
	fields := make([]operatorlog.Field, 0, len(log.Fields)+2)
	if log.Level != "" {
		fields = append(fields, operatorlog.Field{Name: "level", Value: log.Level})
	}
	if log.Logger != "" {
		fields = append(fields, operatorlog.Field{Name: "logger", Value: log.Logger})
	}
	keys := make([]string, 0, len(log.Fields))
	for key := range log.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fields = append(fields, operatorlog.Field{Name: key, Value: log.Fields[key]})
	}
	return fields
}

func defaultWorkspaceName(path string) string {
	base := filepath.Base(filepath.Clean(path))
	base = strings.TrimLeft(base, ".")
	var b strings.Builder
	for _, r := range base {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}
