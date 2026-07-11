package mesh

import "github.com/Vibe-Pwners/hovel/internal/domain/run"

// TaskKind names common node-mesh operations. Providers may expose
// additional task kinds, but these constants keep core task vocabulary stable.
type TaskKind string

const (
	TaskSurvey        TaskKind = "survey"
	TaskUpload        TaskKind = "upload"
	TaskExecute       TaskKind = "execute"
	TaskUploadExecute TaskKind = "upload_execute"
	TaskCommand       TaskKind = "command"
	TaskLoad          TaskKind = "load"
	TaskStream        TaskKind = "stream"
)

// TargetScope describes what a task kind can address. Destination-scoped
// tasks operate on systems reachable through a node or route rather than only
// on the mesh node itself.
type TargetScope string

const (
	TargetNode        TargetScope = "node"
	TargetRoute       TargetScope = "route"
	TargetDestination TargetScope = "destination"
)

// TaskStatus describes the terminal outcome of provider-owned Mesh work.
// Providers may return additional statuses when their contract requires it.
type TaskStatus string

const (
	TaskStatusSucceeded TaskStatus = "succeeded"
	TaskStatusFailed    TaskStatus = "failed"
)

// ListenerDeployment describes whether a listening post shares the provider
// deployment or runs as a separate data-plane service.
type ListenerDeployment string

const (
	ListenerDeploymentEmbedded ListenerDeployment = "embedded"
	ListenerDeploymentSeparate ListenerDeployment = "separate"
)

// ListenerManagement identifies who owns listening-post lifecycle.
type ListenerManagement string

const (
	ListenerManagementProvider ListenerManagement = "provider"
	ListenerManagementExternal ListenerManagement = "external"
)

// ListenerState describes provider-reported listening-post lifecycle state.
// Providers may return additional states when their contract requires it.
type ListenerState string

const (
	ListenerStateStarting ListenerState = "starting"
	ListenerStateActive   ListenerState = "active"
	ListenerStateStopping ListenerState = "stopping"
	ListenerStateStopped  ListenerState = "stopped"
	ListenerStateFailed   ListenerState = "failed"
)

// Listener is a provider-reported listening post. Provider configuration and
// credentials are intentionally absent from this read model.
type Listener struct {
	ID           string             `json:"id"`
	Name         string             `json:"name,omitempty"`
	Kind         string             `json:"kind,omitempty"`
	State        ListenerState      `json:"state,omitempty"`
	Deployment   ListenerDeployment `json:"deployment,omitempty"`
	Management   ListenerManagement `json:"management,omitempty"`
	NodeID       string             `json:"nodeId,omitempty"`
	Addresses    []string           `json:"addresses,omitempty"`
	Protocols    []string           `json:"protocols,omitempty"`
	Capabilities []string           `json:"capabilities,omitempty"`
	Labels       map[string]any     `json:"labels,omitempty"`
	Attributes   map[string]any     `json:"attributes,omitempty"`
	UpdatedAt    string             `json:"updatedAt,omitempty"`
}

// ListenerListRequest filters dynamic listening-post state.
type ListenerListRequest struct {
	ListenerID string            `json:"listenerId,omitempty"`
	State      ListenerState     `json:"state,omitempty"`
	Agent      *run.AgentContext `json:"agentContext,omitempty"`
}

// ListenerStartRequest asks a provider to idempotently start or attach a
// listening post. Config is write-only and must not be echoed in Listener.
type ListenerStartRequest struct {
	ListenerID string             `json:"listenerId"`
	Name       string             `json:"name,omitempty"`
	Kind       string             `json:"kind,omitempty"`
	Deployment ListenerDeployment `json:"deployment,omitempty"`
	Management ListenerManagement `json:"management,omitempty"`
	Config     map[string]any     `json:"config,omitempty"`
	Agent      *run.AgentContext  `json:"agentContext,omitempty"`
}

// ListenerStopRequest asks a provider to idempotently stop or detach a
// listening post.
type ListenerStopRequest struct {
	ListenerID string            `json:"listenerId"`
	Agent      *run.AgentContext `json:"agentContext,omitempty"`
}

// Node is an operator-addressable participant in a provider-owned mesh.
type Node struct {
	ID           string         `json:"id"`
	ParentID     string         `json:"parentId,omitempty"`
	ListenerID   string         `json:"listenerId,omitempty"`
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

// Link is a communication edge between two mesh nodes.
type Link struct {
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

// Route is an ordered path across mesh nodes and links.
type Route struct {
	ID         string         `json:"id,omitempty"`
	Nodes      []string       `json:"nodes"`
	Links      []string       `json:"links,omitempty"`
	Cost       int            `json:"cost,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Topology is a live or declared view of a provider-owned node mesh.
type Topology struct {
	Root       string         `json:"root,omitempty"`
	Nodes      []Node         `json:"nodes,omitempty"`
	Links      []Link         `json:"links,omitempty"`
	Routes     []Route        `json:"routes,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// TaskSpec describes one mesh task kind a provider can perform.
type TaskSpec struct {
	Kind         TaskKind       `json:"kind"`
	Summary      string         `json:"summary,omitempty"`
	ConfigSchema map[string]any `json:"configSchema,omitempty"`
	ReadOnly     bool           `json:"readOnly,omitempty"`
	Destructive  bool           `json:"destructive,omitempty"`
	OpensStream  bool           `json:"opensStream,omitempty"`
	TargetScopes []TargetScope  `json:"targetScopes,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
}

// ListenerSpec advertises one listening-post kind and its supported
// deployment and management modes without contacting a live listener.
type ListenerSpec struct {
	Kind            string               `json:"kind"`
	Summary         string               `json:"summary,omitempty"`
	Deployments     []ListenerDeployment `json:"deployments,omitempty"`
	ManagementModes []ListenerManagement `json:"managementModes,omitempty"`
	Protocols       []string             `json:"protocols,omitempty"`
	ConfigSchema    map[string]any       `json:"configSchema,omitempty"`
	Capabilities    []string             `json:"capabilities,omitempty"`
}

// Trigger declares a provider-owned condition that can fire mesh work.
type Trigger struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	Kind       string         `json:"kind,omitempty"`
	NodeID     string         `json:"nodeId,omitempty"`
	ListenerID string         `json:"listenerId,omitempty"`
	State      string         `json:"state,omitempty"`
	Expression string         `json:"expression,omitempty"`
	Schedule   string         `json:"schedule,omitempty"`
	ActionKind TaskKind       `json:"actionKind,omitempty"`
	Config     map[string]any `json:"config,omitempty"`
	LastFired  string         `json:"lastFired,omitempty"`
}

// Beacon is a node liveness, rendezvous, or work/status signal.
type Beacon struct {
	ID              string         `json:"id"`
	NodeID          string         `json:"nodeId"`
	ListenerID      string         `json:"listenerId,omitempty"`
	Time            string         `json:"time,omitempty"`
	State           string         `json:"state,omitempty"`
	Transport       string         `json:"transport,omitempty"`
	RemoteAddr      string         `json:"remoteAddr,omitempty"`
	IntervalSeconds int            `json:"intervalSeconds,omitempty"`
	Fields          map[string]any `json:"fields,omitempty"`
}

// Descriptor reports a provider's mesh capabilities without requiring
// target contact. Dynamic details belong in Topology or ListBeacons.
type Descriptor struct {
	Name          string         `json:"name,omitempty"`
	Version       string         `json:"version,omitempty"`
	Summary       string         `json:"summary,omitempty"`
	Capabilities  []string       `json:"capabilities,omitempty"`
	Topology      *Topology      `json:"topology,omitempty"`
	Tasks         []TaskSpec     `json:"tasks,omitempty"`
	ListenerTypes []ListenerSpec `json:"listenerTypes,omitempty"`
	Triggers      []Trigger      `json:"triggers,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

// DescribeRequest asks a provider to describe its mesh surface.
type DescribeRequest struct {
	Agent *run.AgentContext `json:"agentContext,omitempty"`
}

// TopologyRequest asks for provider-owned topology, optionally with routes.
type TopologyRequest struct {
	Root          string            `json:"root,omitempty"`
	ListenerID    string            `json:"listenerId,omitempty"`
	IncludeRoutes bool              `json:"includeRoutes,omitempty"`
	Agent         *run.AgentContext `json:"agentContext,omitempty"`
}

// BeaconRequest asks for recent beacons, optionally filtered by node.
type BeaconRequest struct {
	NodeID     string            `json:"nodeId,omitempty"`
	ListenerID string            `json:"listenerId,omitempty"`
	Since      string            `json:"since,omitempty"`
	Limit      int               `json:"limit,omitempty"`
	Agent      *run.AgentContext `json:"agentContext,omitempty"`
}

// TaskRequest asks a provider to perform a node, route, or destination operation.
type TaskRequest struct {
	RunID           string            `json:"runId,omitempty"`
	TaskID          string            `json:"taskId,omitempty"`
	Kind            TaskKind          `json:"kind"`
	NodeID          string            `json:"nodeId,omitempty"`
	ListenerID      string            `json:"listenerId,omitempty"`
	Target          string            `json:"target,omitempty"`
	Route           *Route            `json:"route,omitempty"`
	DestinationHost string            `json:"destinationHost,omitempty"`
	DestinationPort int               `json:"destinationPort,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	Config          map[string]any    `json:"config,omitempty"`
	Args            []string          `json:"args,omitempty"`
	InputData       string            `json:"inputData,omitempty"`
	InputEncoding   string            `json:"inputEncoding,omitempty"`
	Agent           *run.AgentContext `json:"agentContext,omitempty"`
}

// TaskResult is the outcome of a provider-owned mesh task.
type TaskResult struct {
	TaskID          string           `json:"taskId,omitempty"`
	Status          TaskStatus       `json:"status"`
	Summary         string           `json:"summary,omitempty"`
	NodeID          string           `json:"nodeId,omitempty"`
	ListenerID      string           `json:"listenerId,omitempty"`
	Route           *Route           `json:"route,omitempty"`
	DestinationHost string           `json:"destinationHost,omitempty"`
	DestinationPort int              `json:"destinationPort,omitempty"`
	Protocol        string           `json:"protocol,omitempty"`
	Outputs         map[string]any   `json:"outputs,omitempty"`
	Findings        []run.Finding    `json:"findings,omitempty"`
	Artifacts       []run.Artifact   `json:"artifacts,omitempty"`
	Sessions        []run.SessionRef `json:"sessions,omitempty"`
	Beacons         []Beacon         `json:"beacons,omitempty"`
	Events          []Event          `json:"events,omitempty"`
	AgentHints      []run.AgentHint  `json:"agentHints,omitempty"`
}

// Event is provider-authored audit or progress evidence for mesh work.
type Event struct {
	ID         string         `json:"id,omitempty"`
	Kind       string         `json:"kind"`
	NodeID     string         `json:"nodeId,omitempty"`
	ListenerID string         `json:"listenerId,omitempty"`
	Level      string         `json:"level,omitempty"`
	Message    string         `json:"message,omitempty"`
	Fields     map[string]any `json:"fields,omitempty"`
}

// StreamRequest asks a provider to open a routed flow through a node or route.
// Protocol is provider-defined; daemon local socket bridges currently map TCP
// streams and capability-marked UDP datagrams onto the returned session.
type StreamRequest struct {
	RunID           string            `json:"runId,omitempty"`
	ModuleID        string            `json:"moduleId,omitempty"`
	Target          string            `json:"target,omitempty"`
	NodeID          string            `json:"nodeId,omitempty"`
	ListenerID      string            `json:"listenerId,omitempty"`
	Route           *Route            `json:"route,omitempty"`
	DestinationHost string            `json:"destinationHost,omitempty"`
	DestinationPort int               `json:"destinationPort,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	Config          map[string]any    `json:"config,omitempty"`
	Agent           *run.AgentContext `json:"agentContext,omitempty"`
}
