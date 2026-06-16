package hovel

import "encoding/json"

// Finding is a single observation a module reports. Severity is a free-form
// label such as "info", "low", "medium", "high", or "critical".
type Finding struct {
	Title    string
	Severity string
	Detail   string
}

// Artifact is a blob a module produces — either inline data or a path on disk.
type Artifact struct {
	Name string
	Kind string
	Data string
	Path string
}

// InlineArtifact stores data directly in the artifact (kind is a MIME type).
func InlineArtifact(name, kind, data string) Artifact {
	return Artifact{Name: name, Kind: kind, Data: data}
}

// TextArtifact is an inline text/plain artifact.
func TextArtifact(name, data string) Artifact {
	return InlineArtifact(name, "text/plain", data)
}

// JSONArtifact marshals v to an inline application/json artifact.
func JSONArtifact(name string, v any) Artifact {
	data, err := json.Marshal(v)
	if err != nil {
		data = []byte("null")
	}
	return InlineArtifact(name, "application/json", string(data))
}

// FileArtifact references a file on disk by path instead of inlining its bytes.
func FileArtifact(name, kind, path string) Artifact {
	return Artifact{Name: name, Kind: kind, Path: path}
}

// Result is what a module returns from Run. Build it with [Ok] or [Failed].
type Result struct {
	Status            string
	Summary           string
	Findings          []Finding
	Artifacts         []Artifact
	Outputs           map[string]any
	Sessions          []SessionRef
	InstalledPayloads []InstalledPayloadDescriptor
}

// ResultOption customizes a Result built by [Ok] or [Failed].
type ResultOption func(*Result)

// WithSummary sets the human-readable summary line.
func WithSummary(summary string) ResultOption {
	return func(r *Result) { r.Summary = summary }
}

// WithFindings appends findings to the result.
func WithFindings(findings ...Finding) ResultOption {
	return func(r *Result) { r.Findings = append(r.Findings, findings...) }
}

// WithArtifacts appends artifacts to the result.
func WithArtifacts(artifacts ...Artifact) ResultOption {
	return func(r *Result) { r.Artifacts = append(r.Artifacts, artifacts...) }
}

// WithInstalledPayloads appends explicit installed-payload descriptors to the
// module result. Hovel persists these records only when a module returns them.
func WithInstalledPayloads(payloads ...InstalledPayloadDescriptor) ResultOption {
	return func(r *Result) { r.InstalledPayloads = append(r.InstalledPayloads, payloads...) }
}

// Ok builds a succeeded result carrying the given outputs.
func Ok(outputs map[string]any, opts ...ResultOption) Result {
	result := Result{Status: "succeeded", Summary: "module completed", Outputs: outputs}
	for _, opt := range opts {
		opt(&result)
	}
	return result
}

// Failed builds a failed result with the given summary.
func Failed(summary string, opts ...ResultOption) Result {
	result := Result{Status: "failed", Summary: summary}
	for _, opt := range opts {
		opt(&result)
	}
	return result
}

// wire conversions ----------------------------------------------------------

func (f Finding) toRPC() map[string]any {
	return map[string]any{"title": f.Title, "severity": severityOrInfo(f.Severity), "detail": f.Detail}
}

func severityOrInfo(severity string) string {
	if severity == "" {
		return "info"
	}
	return severity
}

func (a Artifact) toRPC() map[string]any {
	out := map[string]any{"name": a.Name, "kind": a.Kind}
	if a.Data != "" {
		out["data"] = a.Data
	}
	if a.Path != "" {
		out["path"] = a.Path
	}
	return out
}

func (r Result) toRPC(sessions []SessionRef) map[string]any {
	findings := make([]map[string]any, 0, len(r.Findings))
	for _, finding := range r.Findings {
		findings = append(findings, finding.toRPC())
	}
	artifacts := make([]map[string]any, 0, len(r.Artifacts))
	for _, artifact := range r.Artifacts {
		artifacts = append(artifacts, artifact.toRPC())
	}
	seen := map[string]bool{}
	refs := make([]map[string]any, 0, len(r.Sessions)+len(sessions))
	for _, session := range append(append([]SessionRef{}, r.Sessions...), sessions...) {
		if seen[session.ID] {
			continue
		}
		seen[session.ID] = true
		refs = append(refs, session.toRPC())
	}
	outputs := r.Outputs
	if outputs == nil {
		outputs = map[string]any{}
	}
	status := r.Status
	if status == "" {
		status = "succeeded"
	}
	return map[string]any{
		"status":            status,
		"summary":           r.Summary,
		"findings":          findings,
		"artifacts":         artifacts,
		"outputs":           outputs,
		"sessions":          refs,
		"installedPayloads": r.InstalledPayloads,
	}
}
