package hovel

// PayloadProvider is implemented by modules that generate payload artifacts for
// delivery by exploit modules. It extends the normal Module lifecycle with
// provider-specific JSON-RPC methods.
type PayloadProvider interface {
	Module
	ListPayloads(PayloadQuery) ([]PayloadInfo, error)
	ResolvePayload(PayloadQuery) (PayloadInfo, error)
	PrepareListener(PrepareListenerRequest) (ListenerRef, error)
	GeneratePayload(GeneratePayloadRequest) (PayloadArtifactSet, error)
	ConnectSession(ConnectSessionRequest) (SessionRef, error)
	CleanupPayload(CleanupPayloadRequest) (CleanupResult, error)
	ReadPayloadChunk(ReadPayloadChunkRequest) (PayloadChunk, error)
}

// PayloadCommandProvider is an optional extension for provider-owned commands
// against an installed payload. Hovel brokers the call; the provider owns the
// transport and payload wire protocol.
type PayloadCommandProvider interface {
	ListPayloadCommands(PayloadCommandListRequest) ([]PayloadCommand, error)
	RunPayloadCommand(PayloadCommandRequest) (PayloadCommandResult, error)
}

// PayloadQuery describes the payload variant requested by Hovel during
// planning or execution.
type PayloadQuery struct {
	Target       string            `json:"target,omitempty"`
	Platform     string            `json:"platform,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	Format       string            `json:"format,omitempty"`
	Transport    string            `json:"transport,omitempty"`
	Config       map[string]string `json:"config,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
}

type PayloadInfo struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	Platform     string           `json:"platform"`
	Arch         string           `json:"arch"`
	MinOS        string           `json:"minOS,omitempty"`
	TestedOS     []string         `json:"testedOS,omitempty"`
	Formats      []string         `json:"formats"`
	Capabilities []string         `json:"capabilities"`
	Transport    PayloadTransport `json:"transport"`
	Session      PayloadSession   `json:"session"`
}

type PayloadTransport struct {
	Kind      string `json:"kind"`
	Encrypted bool   `json:"encrypted"`
}

type PayloadSession struct {
	Kind                     string `json:"kind"`
	Acquisition              string `json:"acquisition"`
	RequiresPreThrowListener bool   `json:"requiresPreThrowListener"`
	RequiresPostThrowConnect bool   `json:"requiresPostThrowConnect"`
	Owner                    string `json:"owner"`
}

type PrepareListenerRequest struct {
	RunID     string            `json:"runId,omitempty"`
	Target    string            `json:"target"`
	PayloadID string            `json:"payloadId"`
	Config    map[string]string `json:"config,omitempty"`
	Agent     *AgentContext     `json:"agentContext,omitempty"`
}

type GeneratePayloadRequest struct {
	RunID     string            `json:"runId,omitempty"`
	Target    string            `json:"target"`
	PayloadID string            `json:"payloadId"`
	Format    string            `json:"format"`
	Config    map[string]string `json:"config,omitempty"`
	Listener  *ListenerRef      `json:"listener,omitempty"`
	Agent     *AgentContext     `json:"agentContext,omitempty"`
}

type PayloadArtifactSet struct {
	Primary   PayloadArtifact   `json:"primary"`
	Artifacts []PayloadArtifact `json:"artifacts"`
}

type PayloadArtifact struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Format   string `json:"format"`
	Encoding string `json:"encoding"`
	Bytes    string `json:"bytes,omitempty"`
	Handle   string `json:"handle,omitempty"`
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// InstalledPayloadDescriptor is the explicit provider-owned record Hovel stores
// when a payload has been installed on a target. The provider owns the opaque
// reconnect and cleanup blobs; Hovel stores and returns them without probing the
// target or interpreting provider internals.
type InstalledPayloadDescriptor struct {
	Provider                 string                 `json:"provider"`
	PayloadID                string                 `json:"payloadId"`
	PayloadVersion           string                 `json:"payloadVersion,omitempty"`
	Target                   string                 `json:"target"`
	TargetID                 string                 `json:"targetId,omitempty"`
	State                    string                 `json:"state,omitempty"`
	Transport                string                 `json:"transport,omitempty"`
	Endpoint                 string                 `json:"endpoint,omitempty"`
	InstanceKey              string                 `json:"instanceKey,omitempty"`
	StampID                  string                 `json:"stampId,omitempty"`
	ArtifactIDs              []string               `json:"artifactIds,omitempty"`
	SupportsReconnect        bool                   `json:"supportsReconnect,omitempty"`
	SupportsMultipleSessions bool                   `json:"supportsMultipleSessions,omitempty"`
	Reconnect                *PayloadProviderRecord `json:"reconnect,omitempty"`
	Cleanup                  *PayloadProviderRecord `json:"cleanup,omitempty"`
	Metadata                 map[string]string      `json:"metadata,omitempty"`
}

// PayloadProviderRecord is an opaque JSON payload owned by the provider that
// produced it. Hovel persists the record so future explicit payload operations
// can call back into that provider.
type PayloadProviderRecord struct {
	ProviderID    string         `json:"providerId,omitempty"`
	Schema        string         `json:"schema,omitempty"`
	SchemaVersion string         `json:"schemaVersion,omitempty"`
	Descriptor    map[string]any `json:"descriptor,omitempty"`
}

type ConnectSessionRequest struct {
	RunID              string                 `json:"runId,omitempty"`
	Target             string                 `json:"target"`
	PayloadID          string                 `json:"payloadId"`
	InstalledPayloadID string                 `json:"installedPayloadId,omitempty"`
	Config             map[string]string      `json:"config,omitempty"`
	Reconnect          *PayloadProviderRecord `json:"reconnect,omitempty"`
	Agent              *AgentContext          `json:"agentContext,omitempty"`
}

type CleanupPayloadRequest struct {
	RunID              string                 `json:"runId,omitempty"`
	Target             string                 `json:"target,omitempty"`
	PayloadID          string                 `json:"payloadId,omitempty"`
	InstalledPayloadID string                 `json:"installedPayloadId,omitempty"`
	Reason             string                 `json:"reason,omitempty"`
	Cleanup            *PayloadProviderRecord `json:"cleanup,omitempty"`
	Agent              *AgentContext          `json:"agentContext,omitempty"`
}

type CleanupResult struct {
	Status string `json:"status"`
}

type ReadPayloadChunkRequest struct {
	Handle string `json:"handle"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

type PayloadChunk struct {
	Handle   string `json:"handle"`
	Offset   int64  `json:"offset"`
	Data     string `json:"data"`
	EOF      bool   `json:"eof"`
	Encoding string `json:"encoding"`
}

type PayloadCommandListRequest struct {
	InstalledPayloadID string                 `json:"installedPayloadId,omitempty"`
	Target             string                 `json:"target,omitempty"`
	PayloadID          string                 `json:"payloadId,omitempty"`
	Config             map[string]string      `json:"config,omitempty"`
	Reconnect          *PayloadProviderRecord `json:"reconnect,omitempty"`
	Agent              *AgentContext          `json:"agentContext,omitempty"`
}

type PayloadCommand struct {
	Name         string                   `json:"name"`
	Summary      string                   `json:"summary,omitempty"`
	Usage        string                   `json:"usage,omitempty"`
	ReadOnly     bool                     `json:"readOnly,omitempty"`
	Destructive  bool                     `json:"destructive,omitempty"`
	Capabilities []string                 `json:"capabilities,omitempty"`
	Arguments    []PayloadCommandArgument `json:"arguments,omitempty"`
}

type PayloadCommandArgument struct {
	Name     string `json:"name"`
	Help     string `json:"help,omitempty"`
	Required bool   `json:"required,omitempty"`
}

type PayloadCommandRequest struct {
	InstalledPayloadID string                 `json:"installedPayloadId,omitempty"`
	Target             string                 `json:"target,omitempty"`
	PayloadID          string                 `json:"payloadId,omitempty"`
	Command            string                 `json:"command"`
	Args               []string               `json:"args,omitempty"`
	InputPath          string                 `json:"inputPath,omitempty"`
	InputData          string                 `json:"inputData,omitempty"`
	InputEncoding      string                 `json:"inputEncoding,omitempty"`
	Config             map[string]string      `json:"config,omitempty"`
	Reconnect          *PayloadProviderRecord `json:"reconnect,omitempty"`
	Agent              *AgentContext          `json:"agentContext,omitempty"`
}

type PayloadCommandResult struct {
	Command   string            `json:"command"`
	Summary   string            `json:"summary,omitempty"`
	Stdout    string            `json:"stdout,omitempty"`
	Stderr    string            `json:"stderr,omitempty"`
	Artifacts []Artifact        `json:"artifacts,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}
