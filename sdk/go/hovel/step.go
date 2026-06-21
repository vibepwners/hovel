package hovel

// CapabilityType names a core chain capability schema.
type CapabilityType string

const (
	CapabilityRemoteExecution CapabilityType = "RemoteExecutionCapability"
	CapabilityCredential      CapabilityType = "CredentialCapability"
	CapabilityPayloadArtifact CapabilityType = "PayloadArtifact"
	CapabilityPayloadInstance CapabilityType = "PayloadInstance"
	CapabilityTransport       CapabilityType = "TransportEndpoint"
	CapabilitySessionRef      CapabilityType = "SessionRef"
	CapabilityCleanupHandle   CapabilityType = "CleanupHandle"
)

// StepProvider is implemented by modules that expose typed chain-step
// contracts. The daemon uses these methods for planning, preparation,
// confirmed execution, and cleanup.
type StepProvider interface {
	Module
	DescribeSteps() (StepContractSet, error)
	PrepareStep(StepPrepareRequest) (StepPrepareResult, error)
	ExecuteStep(StepExecuteRequest) (StepExecuteResult, error)
	CleanupStep(StepCleanupRequest) (StepCleanupResult, error)
}

// StepContractSet is the live contract snapshot returned by a module.
type StepContractSet struct {
	Version string         `json:"version,omitempty"`
	Steps   []StepContract `json:"steps"`
}

// StepContract describes one callable chain step owned by a module.
type StepContract struct {
	ID           string                  `json:"id"`
	Kind         string                  `json:"kind"`
	ConfigSchema map[string]any          `json:"configSchema,omitempty"`
	Requires     []CapabilityRequirement `json:"requires,omitempty"`
	Produces     []CapabilityRequirement `json:"produces,omitempty"`
	Prepare      StepPrepareContract     `json:"prepare,omitempty"`
	Cleanup      *StepCleanupContract    `json:"cleanup,omitempty"`
}

type StepPrepareContract struct {
	Materializes []string `json:"materializes,omitempty"`
}

type StepCleanupContract struct {
	StepID string `json:"stepId,omitempty"`
}

// CapabilityRequirement describes the type, attributes, and states a step
// requires or produces.
type CapabilityRequirement struct {
	Type          CapabilityType `json:"type"`
	SchemaVersion string         `json:"schemaVersion,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
	States        []string       `json:"states,omitempty"`
}

// Capability is typed durable chain state.
type Capability struct {
	ID             string         `json:"id"`
	Type           CapabilityType `json:"type"`
	SchemaVersion  string         `json:"schemaVersion"`
	State          string         `json:"state"`
	ProducerStepID string         `json:"producerStepId,omitempty"`
	Attributes     map[string]any `json:"attributes,omitempty"`
	Extensions     map[string]any `json:"extensions,omitempty"`
}

type PreparedValue struct {
	Value    any  `json:"value"`
	Editable bool `json:"editable"`
}

type OperatorSummary struct {
	Warnings            []string `json:"warnings,omitempty"`
	TargetSideArtifacts []string `json:"targetSideArtifacts,omitempty"`
}

type StepPrepareRequest struct {
	PreparedPlanID         string                   `json:"preparedPlanId,omitempty"`
	StepID                 string                   `json:"stepId"`
	Config                 map[string]any           `json:"config,omitempty"`
	Inputs                 []CapabilityRef          `json:"inputs,omitempty"`
	ExistingPreparedValues map[string]PreparedValue `json:"existingPreparedValues,omitempty"`
	Agent                  *AgentContext            `json:"agentContext,omitempty"`
}

type StepPrepareResult struct {
	PlannedOutputs  []Capability             `json:"plannedOutputs,omitempty"`
	PreparedValues  map[string]PreparedValue `json:"preparedValues,omitempty"`
	OperatorSummary OperatorSummary          `json:"operatorSummary,omitempty"`
	Evidence        []Evidence               `json:"evidence,omitempty"`
	AgentHints      []AgentHint              `json:"agentHints,omitempty"`
}

type StepExecuteRequest struct {
	RunID                   string          `json:"runId,omitempty"`
	StepID                  string          `json:"stepId"`
	ConfirmedPreparedValues map[string]any  `json:"confirmedPreparedValues,omitempty"`
	Inputs                  []CapabilityRef `json:"inputs,omitempty"`
	RunMetadata             map[string]any  `json:"runMetadata,omitempty"`
	Agent                   *AgentContext   `json:"agentContext,omitempty"`
}

type StepExecuteResult struct {
	Status            string                       `json:"status"`
	Capabilities      []Capability                 `json:"capabilities,omitempty"`
	StateTransitions  []CapabilityTransition       `json:"stateTransitions,omitempty"`
	Evidence          []Evidence                   `json:"evidence,omitempty"`
	Sessions          []SessionRef                 `json:"sessions,omitempty"`
	InstalledPayloads []InstalledPayloadDescriptor `json:"installedPayloads,omitempty"`
	AgentHints        []AgentHint                  `json:"agentHints,omitempty"`
}

type StepCleanupRequest struct {
	RunID           string        `json:"runId,omitempty"`
	StepID          string        `json:"stepId"`
	CleanupHandleID string        `json:"cleanupHandleId"`
	Mode            string        `json:"mode,omitempty"`
	Agent           *AgentContext `json:"agentContext,omitempty"`
}

type StepCleanupResult struct {
	Status           string                 `json:"status"`
	StateTransitions []CapabilityTransition `json:"stateTransitions,omitempty"`
	Evidence         []Evidence             `json:"evidence,omitempty"`
	AgentHints       []AgentHint            `json:"agentHints,omitempty"`
}

type CapabilityRef struct {
	CapabilityID string         `json:"capabilityId"`
	Type         CapabilityType `json:"type"`
}

type CapabilityTransition struct {
	CapabilityID string `json:"capabilityId"`
	From         string `json:"from,omitempty"`
	To           string `json:"to"`
	Reason       string `json:"reason,omitempty"`
}

type Evidence struct {
	ID           string         `json:"id"`
	Level        string         `json:"level"`
	Kind         string         `json:"kind"`
	SourceStepID string         `json:"sourceStepId,omitempty"`
	Message      string         `json:"message"`
	Details      map[string]any `json:"details,omitempty"`
}
