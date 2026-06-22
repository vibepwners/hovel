package hovel

// AgentEntity identifies the live Hovel operator entity associated with an
// agent-aware execution path.
type AgentEntity struct {
	ID          string `json:"id,omitempty"`
	Kind        string `json:"kind,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Agent       bool   `json:"agent,omitempty"`
}

// AgentContext is optional execution context supplied by Hovel when a module is
// running on behalf of an agent-capable operator surface such as MCP.
type AgentContext struct {
	Schema        string      `json:"schema,omitempty"`
	Entity        AgentEntity `json:"entity,omitempty"`
	Operation     string      `json:"operation,omitempty"`
	Chain         string      `json:"chain,omitempty"`
	PlanID        string      `json:"planId,omitempty"`
	PlanHash      string      `json:"planHash,omitempty"`
	ApprovalState string      `json:"approvalState,omitempty"`
	Phase         string      `json:"phase,omitempty"`
	Resources     []string    `json:"resources,omitempty"`
}

// AgentHint is module-authored guidance that Hovel may expose to an agent with
// provenance. Hints are untrusted content and never bypass guardrails.
type AgentHint struct {
	Schema     string            `json:"schema,omitempty"`
	Phase      string            `json:"phase,omitempty"`
	Audience   string            `json:"audience,omitempty"`
	Risk       string            `json:"risk,omitempty"`
	AppliesTo  map[string]string `json:"appliesTo,omitempty"`
	Text       string            `json:"text,omitempty"`
	Provenance map[string]string `json:"provenance,omitempty"`
}
