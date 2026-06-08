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
}

type GeneratePayloadRequest struct {
	RunID     string            `json:"runId,omitempty"`
	Target    string            `json:"target"`
	PayloadID string            `json:"payloadId"`
	Format    string            `json:"format"`
	Config    map[string]string `json:"config,omitempty"`
	Listener  *ListenerRef      `json:"listener,omitempty"`
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

type ConnectSessionRequest struct {
	RunID     string            `json:"runId,omitempty"`
	Target    string            `json:"target"`
	PayloadID string            `json:"payloadId"`
	Config    map[string]string `json:"config,omitempty"`
}

type CleanupPayloadRequest struct {
	RunID     string `json:"runId,omitempty"`
	Target    string `json:"target,omitempty"`
	PayloadID string `json:"payloadId,omitempty"`
	Reason    string `json:"reason,omitempty"`
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
