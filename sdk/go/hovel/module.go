package hovel

import "encoding/json"

// ModuleType is the kind of work a module performs. The daemon uses it to group
// modules and to reason about post-exploitation sessions.
type ModuleType string

const (
	// TypeSurvey gathers facts about a target without changing it.
	TypeSurvey ModuleType = "survey"
	// TypeExploit performs an offensive action that may open a session.
	TypeExploit ModuleType = "exploit"
	// TypePayloadProvider generates payloads for delivery by other modules.
	TypePayloadProvider ModuleType = "payload_provider"
)

// Requirement describes a single configuration field a module needs. It mirrors
// the daemon's requirement schema: chain-level requirements apply to a whole
// chain, target-level requirements apply per target.
type Requirement struct {
	// Key is the dotted configuration key, e.g. "target.host".
	Key string
	// Type is a value type the daemon validates against, e.g. "host", "port",
	// "bool", "string", "secret", "int", "url", "cidr".
	Type string
	// Required marks the field as mandatory before a throw can be planned.
	Required bool
	// Default is the value used when the operator does not set the field.
	Default string
	// Description is shown to operators configuring the module.
	Description string
	// Allowed optionally constrains the field to an enumerated set.
	Allowed []string
	// Secret hides the value in logs and transcripts.
	Secret bool
}

// ModuleContext is optional module-authored context for agent-facing catalog,
// planning, and step inspection paths. Hovel treats it as untrusted content
// with module provenance; omitting it has no effect on non-agent workflows.
type ModuleContext struct {
	Summary       string           `json:"summary,omitempty"`
	Keywords      []string         `json:"keywords,omitempty"`
	Platforms     []string         `json:"platforms,omitempty"`
	Targets       []string         `json:"targets,omitempty"`
	Capabilities  []string         `json:"capabilities,omitempty"`
	Preconditions []string         `json:"preconditions,omitempty"`
	SideEffects   []string         `json:"sideEffects,omitempty"`
	Cleanup       string           `json:"cleanup,omitempty"`
	Risk          RiskContext      `json:"risk,omitempty"`
	Examples      []ContextExample `json:"examples,omitempty"`
	AgentHints    []AgentHint      `json:"agentHints,omitempty"`
}

func (c ModuleContext) MarshalJSON() ([]byte, error) {
	type contextJSON struct {
		Summary       string           `json:"summary,omitempty"`
		Keywords      []string         `json:"keywords,omitempty"`
		Platforms     []string         `json:"platforms,omitempty"`
		Targets       []string         `json:"targets,omitempty"`
		Capabilities  []string         `json:"capabilities,omitempty"`
		Preconditions []string         `json:"preconditions,omitempty"`
		SideEffects   []string         `json:"sideEffects,omitempty"`
		Cleanup       string           `json:"cleanup,omitempty"`
		Risk          *RiskContext     `json:"risk,omitempty"`
		Examples      []ContextExample `json:"examples,omitempty"`
		AgentHints    []AgentHint      `json:"agentHints,omitempty"`
	}
	out := contextJSON{
		Summary:       c.Summary,
		Keywords:      c.Keywords,
		Platforms:     c.Platforms,
		Targets:       c.Targets,
		Capabilities:  c.Capabilities,
		Preconditions: c.Preconditions,
		SideEffects:   c.SideEffects,
		Cleanup:       c.Cleanup,
		Examples:      c.Examples,
		AgentHints:    c.AgentHints,
	}
	if riskContextPresent(c.Risk) {
		risk := c.Risk
		out.Risk = &risk
	}
	return json.Marshal(out)
}

type RiskContext struct {
	Level   string   `json:"level,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

func riskContextPresent(risk RiskContext) bool {
	return risk.Level != "" || len(risk.Reasons) > 0
}

type ContextExample struct {
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Modules     []string          `json:"modules,omitempty"`
	ChainConfig map[string]string `json:"chainConfig,omitempty"`
}

// Req constructs a required string Requirement; chain extra options as needed by
// mutating the returned value. It keeps example modules terse.
func Req(key, valueType, description string) Requirement {
	return Requirement{Key: key, Type: valueType, Required: true, Description: description}
}

// Info is the metadata a module reports during the handshake. Name, Version,
// and Type are required; Hovel treats this handshake as authoritative over any
// package-manifest hints.
type Info struct {
	Name             string
	Version          string
	Type             ModuleType
	Summary          string
	Description      string
	Tags             []string
	DiscoveryContext ModuleContext
}

// Schema is the configuration contract a module reports.
type Schema struct {
	ChainConfig     []Requirement
	TargetConfig    []Requirement
	Outputs         map[string]any
	PlanningContext ModuleContext
}

// Module is implemented by every Hovel module. Info and Schema must be cheap and
// side-effect free: the daemon calls them while building its catalog. Run does
// the actual work and is called once per (target) when the module is thrown.
type Module interface {
	Info() Info
	Schema() Schema
	Run(ctx *Context) (Result, error)
}
