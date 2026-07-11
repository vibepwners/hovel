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

// Node is an operator-addressable participant in a provider-owned mesh.
type Node struct {
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
	Kind         string         `json:"kind"`
	Summary      string         `json:"summary,omitempty"`
	ConfigSchema map[string]any `json:"configSchema,omitempty"`
	ReadOnly     bool           `json:"readOnly,omitempty"`
	Destructive  bool           `json:"destructive,omitempty"`
	OpensStream  bool           `json:"opensStream,omitempty"`
	TargetScopes []string       `json:"targetScopes,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
}

// Trigger declares a provider-owned condition that can fire mesh work.
type Trigger struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	Kind       string         `json:"kind,omitempty"`
	NodeID     string         `json:"nodeId,omitempty"`
	State      string         `json:"state,omitempty"`
	Expression string         `json:"expression,omitempty"`
	Schedule   string         `json:"schedule,omitempty"`
	ActionKind string         `json:"actionKind,omitempty"`
	Config     map[string]any `json:"config,omitempty"`
	LastFired  string         `json:"lastFired,omitempty"`
}

// Beacon is a node liveness, rendezvous, or work/status signal.
type Beacon struct {
	ID              string         `json:"id"`
	NodeID          string         `json:"nodeId"`
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
	Name         string         `json:"name,omitempty"`
	Version      string         `json:"version,omitempty"`
	Summary      string         `json:"summary,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Topology     *Topology      `json:"topology,omitempty"`
	Tasks        []TaskSpec     `json:"tasks,omitempty"`
	Triggers     []Trigger      `json:"triggers,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
}

// DescribeRequest asks a provider to describe its mesh surface.
type DescribeRequest struct {
	Agent *run.AgentContext `json:"agentContext,omitempty"`
}

// TopologyRequest asks for provider-owned topology, optionally with routes.
type TopologyRequest struct {
	Root          string            `json:"root,omitempty"`
	IncludeRoutes bool              `json:"includeRoutes,omitempty"`
	Agent         *run.AgentContext `json:"agentContext,omitempty"`
}

// BeaconRequest asks for recent beacons, optionally filtered by node.
type BeaconRequest struct {
	NodeID string            `json:"nodeId,omitempty"`
	Since  string            `json:"since,omitempty"`
	Limit  int               `json:"limit,omitempty"`
	Agent  *run.AgentContext `json:"agentContext,omitempty"`
}

// TaskRequest asks a provider to perform a node, route, or destination operation.
type TaskRequest struct {
	RunID           string            `json:"runId,omitempty"`
	TaskID          string            `json:"taskId,omitempty"`
	Kind            string            `json:"kind"`
	NodeID          string            `json:"nodeId,omitempty"`
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
	Status          string           `json:"status"`
	Summary         string           `json:"summary,omitempty"`
	NodeID          string           `json:"nodeId,omitempty"`
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
	ID      string         `json:"id,omitempty"`
	Kind    string         `json:"kind"`
	NodeID  string         `json:"nodeId,omitempty"`
	Level   string         `json:"level,omitempty"`
	Message string         `json:"message,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// StreamRequest asks a provider to open a routed flow through a node or route.
// Protocol is provider-defined; daemon local socket bridges currently map TCP
// streams and capability-marked UDP datagrams onto the returned session.
type StreamRequest struct {
	RunID           string            `json:"runId,omitempty"`
	ModuleID        string            `json:"moduleId,omitempty"`
	Target          string            `json:"target,omitempty"`
	NodeID          string            `json:"nodeId,omitempty"`
	Route           *Route            `json:"route,omitempty"`
	DestinationHost string            `json:"destinationHost,omitempty"`
	DestinationPort int               `json:"destinationPort,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	Config          map[string]any    `json:"config,omitempty"`
	Agent           *run.AgentContext `json:"agentContext,omitempty"`
}
