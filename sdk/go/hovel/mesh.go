package hovel

import (
	"errors"
	"strings"
)

const defaultMeshRunID = "mesh"

var errMeshSessionUnavailable = errors.New("hovel: session support is not available in this mesh runtime")

// MeshDescriber is the common Mesh discovery surface. A module that supports
// any Mesh operation should implement this method and advertise only the
// capabilities and task kinds it actually supports.
type MeshDescriber interface {
	Module
	DescribeMesh(MeshDescribeRequest) (MeshDescriptor, error)
}

// MeshTopologyProvider is implemented by modules that can report current Mesh
// nodes, links, or routes.
type MeshTopologyProvider interface {
	Module
	MeshTopology(MeshTopologyRequest) (MeshTopology, error)
}

// MeshBeaconProvider is implemented by modules that can report Mesh beacons.
type MeshBeaconProvider interface {
	Module
	ListMeshBeacons(MeshBeaconRequest) ([]MeshBeacon, error)
}

// MeshTaskProvider is implemented by modules that can run provider-owned Mesh
// tasks such as survey, command, upload_execute, or load.
type MeshTaskProvider interface {
	Module
	RunMeshTask(*MeshContext, MeshTaskRequest) (MeshTaskResult, error)
}

// MeshStreamProvider is implemented by modules that can open a Mesh-backed
// routed flow as a normal Hovel session.
type MeshStreamProvider interface {
	Module
	OpenMeshStream(*MeshContext, MeshStreamRequest) (SessionRef, error)
}

// MeshProvider is the convenience interface for modules that implement every
// Mesh surface. Simple Mesh providers do not need to satisfy this interface;
// they can implement MeshDescriber plus only the optional operation interfaces
// they support.
type MeshProvider interface {
	MeshDescriber
	MeshTopologyProvider
	MeshBeaconProvider
	MeshTaskProvider
	MeshStreamProvider
}

// MeshTaskKind names common mesh task operations. Providers may define
// additional task kinds; these constants keep common node-operation vocabulary
// stable across SDKs.
type MeshTaskKind string

const (
	MeshTaskSurvey        MeshTaskKind = "survey"
	MeshTaskUpload        MeshTaskKind = "upload"
	MeshTaskExecute       MeshTaskKind = "execute"
	MeshTaskUploadExecute MeshTaskKind = "upload_execute"
	MeshTaskCommand       MeshTaskKind = "command"
	MeshTaskLoad          MeshTaskKind = "load"
	MeshTaskStream        MeshTaskKind = "stream"
)

// MeshTargetScope describes what a task kind can address. A provider can use
// MeshTargetDestination to advertise tasks that operate on hosts reachable from
// a node, which is the SDK contract needed for pivoted exploit delivery.
type MeshTargetScope string

const (
	MeshTargetNode        MeshTargetScope = "node"
	MeshTargetRoute       MeshTargetScope = "route"
	MeshTargetDestination MeshTargetScope = "destination"
)

// MeshTaskStatus describes the terminal outcome of provider-owned Mesh work.
// Providers may use additional status values when their contract requires it.
type MeshTaskStatus string

const (
	MeshTaskStatusSucceeded MeshTaskStatus = "succeeded"
	MeshTaskStatusFailed    MeshTaskStatus = "failed"
)

// MeshNode is an operator-addressable participant in a mesh.
type MeshNode struct {
	ID           string         `json:"id"`
	ParentID     string         `json:"parentId,omitempty"`
	Name         string         `json:"name,omitempty"`
	Kind         string         `json:"kind,omitempty"`
	State        string         `json:"state,omitempty"`
	Address      string         `json:"address,omitempty"`
	Platform     string         `json:"platform,omitempty"`
	OS           string         `json:"os,omitempty"`
	Arch         string         `json:"arch,omitempty"`
	Labels       map[string]any `json:"labels,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	LastSeen     string         `json:"lastSeen,omitempty"`
}

// MeshLink is a communication edge between two mesh nodes.
type MeshLink struct {
	ID         string         `json:"id"`
	Source     string         `json:"source"`
	Target     string         `json:"target"`
	Kind       string         `json:"kind,omitempty"`
	State      string         `json:"state,omitempty"`
	Transport  string         `json:"transport,omitempty"`
	Cost       int            `json:"cost,omitempty"`
	LatencyMS  int            `json:"latencyMs,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// MeshRoute is an ordered path across mesh nodes and links.
type MeshRoute struct {
	ID         string         `json:"id,omitempty"`
	Nodes      []string       `json:"nodes"`
	Links      []string       `json:"links,omitempty"`
	Cost       int            `json:"cost,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// MeshTopology is a live or declared view of the provider-owned mesh.
type MeshTopology struct {
	Root       string         `json:"root,omitempty"`
	Nodes      []MeshNode     `json:"nodes,omitempty"`
	Links      []MeshLink     `json:"links,omitempty"`
	Routes     []MeshRoute    `json:"routes,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// MeshTaskSpec describes one task kind a provider can perform.
type MeshTaskSpec struct {
	Kind         MeshTaskKind      `json:"kind"`
	Summary      string            `json:"summary,omitempty"`
	ConfigSchema map[string]any    `json:"configSchema,omitempty"`
	ReadOnly     bool              `json:"readOnly,omitempty"`
	Destructive  bool              `json:"destructive,omitempty"`
	OpensStream  bool              `json:"opensStream,omitempty"`
	TargetScopes []MeshTargetScope `json:"targetScopes,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
}

// MeshTrigger declares a condition that can cause mesh work or state
// changes. The provider owns the trigger expression language.
type MeshTrigger struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	Kind       string         `json:"kind,omitempty"`
	NodeID     string         `json:"nodeId,omitempty"`
	State      string         `json:"state,omitempty"`
	Expression string         `json:"expression,omitempty"`
	Schedule   string         `json:"schedule,omitempty"`
	ActionKind MeshTaskKind   `json:"actionKind,omitempty"`
	Config     map[string]any `json:"config,omitempty"`
	LastFired  string         `json:"lastFired,omitempty"`
}

// MeshBeacon is a node liveness or work/status signal.
type MeshBeacon struct {
	ID              string         `json:"id"`
	NodeID          string         `json:"nodeId"`
	Time            string         `json:"time,omitempty"`
	State           string         `json:"state,omitempty"`
	Transport       string         `json:"transport,omitempty"`
	RemoteAddr      string         `json:"remoteAddr,omitempty"`
	IntervalSeconds int            `json:"intervalSeconds,omitempty"`
	Fields          map[string]any `json:"fields,omitempty"`
}

// MeshDescriptor reports a provider's mesh capabilities without requiring
// target contact. Dynamic details belong in MeshTopology or ListMeshBeacons.
type MeshDescriptor struct {
	Name         string         `json:"name,omitempty"`
	Version      string         `json:"version,omitempty"`
	Summary      string         `json:"summary,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Topology     *MeshTopology  `json:"topology,omitempty"`
	Tasks        []MeshTaskSpec `json:"tasks,omitempty"`
	Triggers     []MeshTrigger  `json:"triggers,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
}

type MeshDescribeRequest struct {
	Agent *AgentContext `json:"agentContext,omitempty"`
}

type MeshTopologyRequest struct {
	Root          string        `json:"root,omitempty"`
	IncludeRoutes bool          `json:"includeRoutes,omitempty"`
	Agent         *AgentContext `json:"agentContext,omitempty"`
}

type MeshBeaconRequest struct {
	NodeID string        `json:"nodeId,omitempty"`
	Since  string        `json:"since,omitempty"`
	Limit  int           `json:"limit,omitempty"`
	Agent  *AgentContext `json:"agentContext,omitempty"`
}

// MeshTaskRequest asks a provider to perform a node, route, or destination operation.
type MeshTaskRequest struct {
	RunID           string         `json:"runId,omitempty"`
	TaskID          string         `json:"taskId,omitempty"`
	Kind            MeshTaskKind   `json:"kind"`
	NodeID          string         `json:"nodeId,omitempty"`
	Target          string         `json:"target,omitempty"`
	Route           *MeshRoute     `json:"route,omitempty"`
	DestinationHost string         `json:"destinationHost,omitempty"`
	DestinationPort int            `json:"destinationPort,omitempty"`
	Protocol        string         `json:"protocol,omitempty"`
	Config          map[string]any `json:"config,omitempty"`
	Args            []string       `json:"args,omitempty"`
	InputData       string         `json:"inputData,omitempty"`
	InputEncoding   string         `json:"inputEncoding,omitempty"`
	Agent           *AgentContext  `json:"agentContext,omitempty"`
}

// MeshTaskResult is the result of a mesh task. Sessions opened through the
// MeshContext are attached automatically, but providers may also return
// externally brokered SessionRef values explicitly.
type MeshTaskResult struct {
	TaskID          string         `json:"taskId,omitempty"`
	Status          MeshTaskStatus `json:"status,omitempty"`
	Summary         string         `json:"summary,omitempty"`
	NodeID          string         `json:"nodeId,omitempty"`
	Route           *MeshRoute     `json:"route,omitempty"`
	DestinationHost string         `json:"destinationHost,omitempty"`
	DestinationPort int            `json:"destinationPort,omitempty"`
	Protocol        string         `json:"protocol,omitempty"`
	Outputs         map[string]any `json:"outputs,omitempty"`
	Findings        []Finding      `json:"findings,omitempty"`
	Artifacts       []Artifact     `json:"artifacts,omitempty"`
	Sessions        []SessionRef   `json:"sessions,omitempty"`
	Beacons         []MeshBeacon   `json:"beacons,omitempty"`
	Events          []MeshEvent    `json:"events,omitempty"`
	AgentHints      []AgentHint    `json:"agentHints,omitempty"`
}

// SucceededMeshTask builds a successful mesh task result.
func SucceededMeshTask(summary string) MeshTaskResult {
	return MeshTaskResult{
		Status:  MeshTaskStatusSucceeded,
		Summary: summary,
	}
}

// MeshEvent is provider-authored audit or progress evidence for mesh work.
type MeshEvent struct {
	ID      string         `json:"id,omitempty"`
	Kind    string         `json:"kind"`
	NodeID  string         `json:"nodeId,omitempty"`
	Level   string         `json:"level,omitempty"`
	Message string         `json:"message,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// MeshStreamRequest asks a provider to open a routed flow to an endpoint
// reachable through a node or route. Protocol is provider-defined; Hovel can
// bridge TCP and UDP SessionRefs to daemon-owned local listeners so tools only
// connect to a loopback socket.
type MeshStreamRequest struct {
	RunID           string         `json:"runId,omitempty"`
	ModuleID        string         `json:"moduleId,omitempty"`
	Target          string         `json:"target,omitempty"`
	NodeID          string         `json:"nodeId,omitempty"`
	Route           *MeshRoute     `json:"route,omitempty"`
	DestinationHost string         `json:"destinationHost,omitempty"`
	DestinationPort int            `json:"destinationPort,omitempty"`
	Protocol        string         `json:"protocol,omitempty"`
	Config          map[string]any `json:"config,omitempty"`
	Agent           *AgentContext  `json:"agentContext,omitempty"`
}

// MeshContext carries execution helpers for task and stream methods.
type MeshContext struct {
	RunID    string
	ModuleID string
	Target   string
	NodeID   string
	Agent    *AgentContext
	Log      *Logger

	sessions *sessionRegistry
}

// OpenSession registers a provider-owned session opened while serving a mesh
// task or stream. Use this for interactive shells, routed protocol flows, and
// provider-backed command channels that must outlive the RPC response.
func (c *MeshContext) OpenSession(session Session, opts ...SessionOption) (SessionRef, error) {
	if c.sessions == nil {
		return SessionRef{}, errMeshSessionUnavailable
	}
	return c.sessions.open(session, opts...)
}

func meshModuleID(info Info) string {
	name := strings.TrimSpace(info.Name)
	version := strings.TrimSpace(info.Version)
	if version == "" {
		return name
	}
	return name + "@" + version
}
