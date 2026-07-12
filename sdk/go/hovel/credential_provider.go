package hovel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// CredentialProviderExecutionSchemaV1 versions the secret-bearing provider
// invocation surface independently from credential-delivery discovery.
const CredentialProviderExecutionSchemaV1 = "hovel.pki.provider-execution/v1"

const (
	redactedCredentialBytes  = "<credential bytes redacted>"
	redactedCredentialSecret = "<credential secret redacted>"
)

var (
	// ErrCredentialMaterialVariant reports an invalid credential material union.
	ErrCredentialMaterialVariant = errors.New("credential material requires exactly one valid bytes or reference variant")
	// ErrCredentialArtifactVariant reports an invalid credential artifact union.
	ErrCredentialArtifactVariant = errors.New("credential artifact requires exactly one valid data or path variant")
	// ErrCredentialStampOutputVariant reports an invalid stamp output union.
	ErrCredentialStampOutputVariant = errors.New("credential stamp output requires exactly one artifact or deployment variant")
)

// CredentialBytes carries secret-aware binary material. JSON encodes this
// named byte slice as standard padded base64, while String and GoString avoid
// exposing the contents in ordinary diagnostics.
type CredentialBytes []byte

func (CredentialBytes) String() string { return redactedCredentialBytes }

func (CredentialBytes) GoString() string { return redactedCredentialBytes }

// Bytes returns a defensive copy for provider consumption.
func (b CredentialBytes) Bytes() []byte { return append([]byte(nil), b...) }

// MarshalJSON emits canonical padded RFC 4648 base64.
func (b CredentialBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

// UnmarshalJSON rejects whitespace, noncanonical padding, and non-zero pad
// bits instead of accepting encoding/base64's permissive forms.
func (b *CredentialBytes) UnmarshalJSON(data []byte) error {
	if b == nil {
		return errors.New("credential bytes destination is nil")
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("decode credential bytes string: %w", err)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return errors.New("credential bytes must be canonical padded base64")
	}
	*b = append((*b)[:0], decoded...)
	return nil
}

// CredentialSecretReference is an opaque provider-scoped capability whose
// ordinary string formatting is redacted.
type CredentialSecretReference string

func (CredentialSecretReference) String() string { return redactedCredentialSecret }

func (CredentialSecretReference) GoString() string { return redactedCredentialSecret }

// CredentialProtectedPath is an invocation-scoped path whose ordinary string
// formatting is redacted because names and layout may disclose secrets.
type CredentialProtectedPath string

func (CredentialProtectedPath) String() string { return redactedCredentialSecret }

func (CredentialProtectedPath) GoString() string { return redactedCredentialSecret }

// CredentialOperationScope correlates a provider invocation with daemon
// bookkeeping without exposing unrelated run or workspace configuration.
type CredentialOperationScope struct {
	OperationID string `json:"operationId,omitempty"`
	RunID       string `json:"runId,omitempty"`
	ChainID     string `json:"chainId,omitempty"`
	ThrowID     string `json:"throwId,omitempty"`
	Target      string `json:"target,omitempty"`
	ListenerID  string `json:"listenerId,omitempty"`
	NodeID      string `json:"nodeId,omitempty"`
}

// CredentialProviderTarget binds an invocation to the exact module and
// versioned credential-delivery descriptor selected by Hovel.
type CredentialProviderTarget struct {
	ModuleID         string `json:"moduleId"`
	ProviderID       string `json:"providerId"`
	ProviderVersion  string `json:"providerVersion"`
	DescriptorSHA256 string `json:"descriptorSha256"`
}

// CredentialScopedReference identifies a non-exportable or externally owned
// credential capability. Reference is provider-scoped, not a general signing
// oracle.
type CredentialScopedReference struct {
	ProviderID   string                    `json:"providerId"`
	Reference    CredentialSecretReference `json:"reference"`
	Capabilities []string                  `json:"capabilities,omitempty"`
}

type credentialMaterialValueKind uint8

const (
	credentialMaterialValueUnset credentialMaterialValueKind = iota
	credentialMaterialValueBytes
	credentialMaterialValueReference
)

// CredentialMaterialValue is a sealed credential bytes-or-reference union.
// Construct values with NewCredentialMaterialBytes or
// NewCredentialMaterialReference.
type CredentialMaterialValue struct {
	kind      credentialMaterialValueKind
	data      CredentialBytes
	reference CredentialScopedReference
}

// NewCredentialMaterialBytes constructs a non-empty byte material variant.
func NewCredentialMaterialBytes(data []byte) (CredentialMaterialValue, error) {
	if len(data) == 0 {
		return CredentialMaterialValue{}, fmt.Errorf("%w: bytes must not be empty", ErrCredentialMaterialVariant)
	}
	return CredentialMaterialValue{
		kind: credentialMaterialValueBytes,
		data: append(CredentialBytes(nil), data...),
	}, nil
}

// NewCredentialMaterialReference constructs a provider-scoped reference
// variant and defensively copies its capabilities.
func NewCredentialMaterialReference(reference CredentialScopedReference) (CredentialMaterialValue, error) {
	if strings.TrimSpace(reference.ProviderID) == "" || strings.TrimSpace(string(reference.Reference)) == "" {
		return CredentialMaterialValue{}, fmt.Errorf(
			"%w: provider ID and reference must not be empty",
			ErrCredentialMaterialVariant,
		)
	}
	reference.Capabilities = append([]string(nil), reference.Capabilities...)
	return CredentialMaterialValue{kind: credentialMaterialValueReference, reference: reference}, nil
}

// Bytes returns a defensive copy and reports whether this is the bytes variant.
func (v CredentialMaterialValue) Bytes() ([]byte, bool) {
	if v.kind != credentialMaterialValueBytes {
		return nil, false
	}
	return v.data.Bytes(), true
}

// Reference returns a defensive copy and reports whether this is the reference
// variant.
func (v CredentialMaterialValue) Reference() (CredentialScopedReference, bool) {
	if v.kind != credentialMaterialValueReference {
		return CredentialScopedReference{}, false
	}
	reference := v.reference
	reference.Capabilities = append([]string(nil), reference.Capabilities...)
	return reference, true
}

func (CredentialMaterialValue) String() string { return redactedCredentialSecret }

func (CredentialMaterialValue) GoString() string { return redactedCredentialSecret }

// ResolvedCredentialMaterial is a tagged secret-bearing input. Public and
// private-byte forms carry a bytes Value; private-reference forms carry a
// reference Value.
// Providers must not return, log, or retain either value unless their
// advertised lifecycle explicitly requires retention.
type ResolvedCredentialMaterial struct {
	Projection CredentialProjection `json:"projection"`
	Encoding   string               `json:"encoding"`
	SHA256     string               `json:"sha256"`
	form       CredentialMaterialForm
	value      CredentialMaterialValue
}

func (ResolvedCredentialMaterial) String() string { return redactedCredentialSecret }

func (ResolvedCredentialMaterial) GoString() string { return redactedCredentialSecret }

// NewResolvedCredentialMaterial binds a material form to its only valid value
// variant. The returned value cannot be mutated into a form/value mismatch.
func NewResolvedCredentialMaterial(
	projection CredentialProjection,
	form CredentialMaterialForm,
	encoding string,
	sha256 string,
	value CredentialMaterialValue,
) (ResolvedCredentialMaterial, error) {
	valid := false
	switch form {
	case CredentialMaterialPublic, CredentialMaterialPrivateBytes:
		valid = value.kind == credentialMaterialValueBytes && len(value.data) > 0
	case CredentialMaterialPrivateReference:
		valid = value.kind == credentialMaterialValueReference
	}
	if !valid {
		return ResolvedCredentialMaterial{}, fmt.Errorf(
			"%w: form %q does not match its value", ErrCredentialMaterialVariant, form,
		)
	}
	material := ResolvedCredentialMaterial{
		Projection: projection,
		Encoding:   encoding,
		SHA256:     sha256,
		form:       form,
		value:      value,
	}
	return material.clone(), nil
}

// Form reports whether the material is public bytes, private bytes, or a
// provider-scoped private reference.
func (m ResolvedCredentialMaterial) Form() CredentialMaterialForm { return m.form }

// Bytes returns a defensive copy for byte-backed material.
func (m ResolvedCredentialMaterial) Bytes() ([]byte, bool) { return m.value.Bytes() }

// Reference returns a defensive copy for reference-backed material.
func (m ResolvedCredentialMaterial) Reference() (CredentialScopedReference, bool) {
	return m.value.Reference()
}

func (m ResolvedCredentialMaterial) clone() ResolvedCredentialMaterial {
	result := m
	if data, ok := m.value.Bytes(); ok {
		result.value, _ = NewCredentialMaterialBytes(data)
	} else if reference, ok := m.value.Reference(); ok {
		result.value, _ = NewCredentialMaterialReference(reference)
	}
	return result
}

type resolvedCredentialMaterialWire struct {
	Projection CredentialProjection   `json:"projection"`
	Form       CredentialMaterialForm `json:"form"`
	Encoding   string                 `json:"encoding"`
	SHA256     string                 `json:"sha256"`
	Data       json.RawMessage        `json:"data"`
	Reference  json.RawMessage        `json:"reference"`
}

// MarshalJSON preserves the canonical data/reference wire union.
func (m ResolvedCredentialMaterial) MarshalJSON() ([]byte, error) {
	type materialWire struct {
		Projection CredentialProjection       `json:"projection"`
		Form       CredentialMaterialForm     `json:"form"`
		Encoding   string                     `json:"encoding"`
		SHA256     string                     `json:"sha256"`
		Data       CredentialBytes            `json:"data,omitempty"`
		Reference  *CredentialScopedReference `json:"reference,omitempty"`
	}
	wire := materialWire{
		Projection: m.Projection,
		Form:       m.form,
		Encoding:   m.Encoding,
		SHA256:     m.SHA256,
	}
	switch m.form {
	case CredentialMaterialPublic, CredentialMaterialPrivateBytes:
		if m.value.kind != credentialMaterialValueBytes || len(m.value.data) == 0 {
			return nil, fmt.Errorf("%w: form %q requires bytes", ErrCredentialMaterialVariant, m.form)
		}
		wire.Data = append(CredentialBytes(nil), m.value.data...)
	case CredentialMaterialPrivateReference:
		if m.value.kind != credentialMaterialValueReference {
			return nil, fmt.Errorf("%w: form %q requires a reference", ErrCredentialMaterialVariant, m.form)
		}
		reference, err := NewCredentialMaterialReference(m.value.reference)
		if err != nil {
			return nil, err
		}
		value, _ := reference.Reference()
		wire.Reference = &value
	default:
		return nil, fmt.Errorf("%w: unknown form %q", ErrCredentialMaterialVariant, m.form)
	}
	return json.Marshal(wire)
}

// UnmarshalJSON rejects ambiguous, absent, and form-mismatched variants.
func (m *ResolvedCredentialMaterial) UnmarshalJSON(data []byte) error {
	var wire resolvedCredentialMaterialWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	hasData := wire.Data != nil
	hasReference := wire.Reference != nil
	if hasData == hasReference {
		return ErrCredentialMaterialVariant
	}
	var value CredentialMaterialValue
	var err error
	if hasData {
		var material CredentialBytes
		if err := json.Unmarshal(wire.Data, &material); err != nil {
			return fmt.Errorf("decode credential data: %w", err)
		}
		value, err = NewCredentialMaterialBytes(material)
	} else {
		var reference CredentialScopedReference
		if err := json.Unmarshal(wire.Reference, &reference); err != nil {
			return fmt.Errorf("decode credential reference: %w", err)
		}
		value, err = NewCredentialMaterialReference(reference)
	}
	if err != nil {
		return err
	}
	result, err := NewResolvedCredentialMaterial(
		wire.Projection, wire.Form, wire.Encoding, wire.SHA256, value,
	)
	if err != nil {
		return err
	}
	*m = result.clone()
	return nil
}

// CredentialRuntimeRequest delivers one resolved material projection directly
// to a provider runtime. RequestID is the idempotency and receipt correlation
// key for this invocation.
type CredentialRuntimeRequest struct {
	SchemaVersion string                     `json:"schemaVersion"`
	Provider      CredentialProviderTarget   `json:"provider"`
	RequestID     string                     `json:"requestId"`
	AssignmentID  string                     `json:"assignmentId"`
	SlotName      string                     `json:"slotName"`
	Credential    ResolvedCredentialMetadata `json:"credential"`
	Material      ResolvedCredentialMaterial `json:"material"`
	Scope         CredentialOperationScope   `json:"scope"`
}

// CredentialFile is one owner-protected, invocation-scoped file. The path is
// valid only for the provider call unless the provider copies it into storage
// it owns and reports that action in its receipt.
type CredentialFile struct {
	Projection CredentialProjection    `json:"projection"`
	Form       CredentialMaterialForm  `json:"form"`
	MediaType  string                  `json:"mediaType"`
	Path       CredentialProtectedPath `json:"path"`
	SHA256     string                  `json:"sha256"`
	Size       uint64                  `json:"size"`
}

// CredentialFilesRequest delivers a bounded set of protected files to a
// provider that advertises the files capability.
type CredentialFilesRequest struct {
	SchemaVersion string                     `json:"schemaVersion"`
	Provider      CredentialProviderTarget   `json:"provider"`
	RequestID     string                     `json:"requestId"`
	AssignmentID  string                     `json:"assignmentId"`
	SlotName      string                     `json:"slotName"`
	Credential    ResolvedCredentialMetadata `json:"credential"`
	Files         []CredentialFile           `json:"files"`
	Scope         CredentialOperationScope   `json:"scope"`
}

// CredentialDeliveryReceipt is non-secret evidence that a provider accepted
// a runtime or file delivery. ProviderReference is opaque but stable enough for
// provider-side reconciliation; ReceiptSHA256 binds any provider-owned receipt
// without returning its contents.
type CredentialDeliveryReceipt struct {
	RequestID         string `json:"requestId"`
	ProviderReference string `json:"providerReference,omitempty"`
	ReceiptSHA256     string `json:"receiptSha256,omitempty"`
}

// CredentialEncodingRequest asks the named provider schema to transform one
// resolved projection. MaximumEncodedBytes is a hard output bound.
type CredentialEncodingRequest struct {
	SchemaVersion       string                     `json:"schemaVersion"`
	Provider            CredentialProviderTarget   `json:"provider"`
	RequestID           string                     `json:"requestId"`
	ProviderID          string                     `json:"providerId"`
	ProviderSchema      string                     `json:"providerSchema"`
	OutputForm          CredentialMaterialForm     `json:"outputForm"`
	MaximumEncodedBytes uint64                     `json:"maximumEncodedBytes"`
	Source              ResolvedCredentialMaterial `json:"source"`
	Scope               CredentialOperationScope   `json:"scope"`
}

// CredentialEncodingResult returns only the requested encoded bytes and their
// digest. Hovel checks the advertised schema, form, bound, and digest before
// using the result in another provider call.
type CredentialEncodingResult struct {
	RequestID string                 `json:"requestId"`
	Form      CredentialMaterialForm `json:"form"`
	Encoding  string                 `json:"encoding"`
	SHA256    string                 `json:"sha256"`
	Data      CredentialBytes        `json:"data"`
}

type credentialArtifactContentKind uint8

const (
	credentialArtifactContentUnset credentialArtifactContentKind = iota
	credentialArtifactContentData
	credentialArtifactContentPath
)

// CredentialArtifactContent is a sealed artifact data-or-protected-path union.
// Construct values with NewCredentialArtifactData or
// NewCredentialArtifactPath.
type CredentialArtifactContent struct {
	kind credentialArtifactContentKind
	data CredentialBytes
	path CredentialProtectedPath
}

// NewCredentialArtifactData constructs a non-empty in-memory artifact variant.
func NewCredentialArtifactData(data []byte) (CredentialArtifactContent, error) {
	if len(data) == 0 {
		return CredentialArtifactContent{}, fmt.Errorf("%w: data must not be empty", ErrCredentialArtifactVariant)
	}
	return CredentialArtifactContent{
		kind: credentialArtifactContentData,
		data: append(CredentialBytes(nil), data...),
	}, nil
}

// NewCredentialArtifactPath constructs a non-empty protected-path artifact
// variant.
func NewCredentialArtifactPath(path string) (CredentialArtifactContent, error) {
	if strings.TrimSpace(path) == "" {
		return CredentialArtifactContent{}, fmt.Errorf("%w: path must not be empty", ErrCredentialArtifactVariant)
	}
	return CredentialArtifactContent{
		kind: credentialArtifactContentPath,
		path: CredentialProtectedPath(path),
	}, nil
}

// Data returns a defensive copy and reports whether this is the data variant.
func (c CredentialArtifactContent) Data() ([]byte, bool) {
	if c.kind != credentialArtifactContentData {
		return nil, false
	}
	return c.data.Bytes(), true
}

// Path returns the redacting path value and reports whether this is the path
// variant.
func (c CredentialArtifactContent) Path() (CredentialProtectedPath, bool) {
	if c.kind != credentialArtifactContentPath {
		return "", false
	}
	return c.path, true
}

func (c CredentialArtifactContent) clone() CredentialArtifactContent {
	result := c
	result.data = append(CredentialBytes(nil), c.data...)
	return result
}

func (CredentialArtifactContent) String() string { return redactedCredentialSecret }

func (CredentialArtifactContent) GoString() string { return redactedCredentialSecret }

type credentialArtifactWire struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name,omitempty"`
	SHA256   string          `json:"sha256,omitempty"`
	Encoding string          `json:"encoding"`
	Data     json.RawMessage `json:"data"`
	Path     json.RawMessage `json:"path"`
}

func credentialArtifactContentFromWire(wire credentialArtifactWire) (CredentialArtifactContent, error) {
	hasData := wire.Data != nil
	hasPath := wire.Path != nil
	if hasData == hasPath {
		return CredentialArtifactContent{}, ErrCredentialArtifactVariant
	}
	if hasData {
		var data CredentialBytes
		if err := json.Unmarshal(wire.Data, &data); err != nil {
			return CredentialArtifactContent{}, fmt.Errorf("decode credential artifact data: %w", err)
		}
		return NewCredentialArtifactData(data)
	}
	var path string
	if err := json.Unmarshal(wire.Path, &path); err != nil {
		return CredentialArtifactContent{}, fmt.Errorf("decode credential artifact path: %w", err)
	}
	return NewCredentialArtifactPath(path)
}

func marshalCredentialArtifact(wire credentialArtifactWire, content CredentialArtifactContent) ([]byte, error) {
	type artifactWire struct {
		ID       string                  `json:"id,omitempty"`
		Name     string                  `json:"name,omitempty"`
		SHA256   string                  `json:"sha256,omitempty"`
		Encoding string                  `json:"encoding"`
		Data     CredentialBytes         `json:"data,omitempty"`
		Path     CredentialProtectedPath `json:"path,omitempty"`
	}
	result := artifactWire{ID: wire.ID, Name: wire.Name, SHA256: wire.SHA256, Encoding: wire.Encoding}
	switch content.kind {
	case credentialArtifactContentData:
		if len(content.data) == 0 {
			return nil, ErrCredentialArtifactVariant
		}
		result.Data = append(CredentialBytes(nil), content.data...)
	case credentialArtifactContentPath:
		if strings.TrimSpace(string(content.path)) == "" {
			return nil, ErrCredentialArtifactVariant
		}
		result.Path = content.path
	default:
		return nil, ErrCredentialArtifactVariant
	}
	return json.Marshal(result)
}

// CredentialArtifactInput is the exact artifact covered by a persisted stamp
// plan. Content is exactly one data or protected-path variant; Hovel verifies
// ID and SHA256 before invocation.
type CredentialArtifactInput struct {
	ID       string                    `json:"id"`
	SHA256   string                    `json:"sha256"`
	Encoding string                    `json:"encoding"`
	Content  CredentialArtifactContent `json:"-"`
}

// MarshalJSON preserves the canonical data/path wire union.
func (a CredentialArtifactInput) MarshalJSON() ([]byte, error) {
	return marshalCredentialArtifact(credentialArtifactWire{
		ID: a.ID, SHA256: a.SHA256, Encoding: a.Encoding,
	}, a.Content)
}

// UnmarshalJSON rejects ambiguous and absent data/path variants.
func (a *CredentialArtifactInput) UnmarshalJSON(data []byte) error {
	var wire credentialArtifactWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	content, err := credentialArtifactContentFromWire(wire)
	if err != nil {
		return err
	}
	*a = CredentialArtifactInput{ID: wire.ID, SHA256: wire.SHA256, Encoding: wire.Encoding, Content: content}
	return nil
}

// CredentialArtifactOutput is a provider-produced stamped artifact. Content
// is exactly one data or protected-path variant. Hovel ingests and hashes it
// before recording stamp success.
type CredentialArtifactOutput struct {
	Name     string                    `json:"name"`
	Encoding string                    `json:"encoding"`
	Content  CredentialArtifactContent `json:"-"`
}

// MarshalJSON preserves the canonical data/path wire union.
func (a CredentialArtifactOutput) MarshalJSON() ([]byte, error) {
	return marshalCredentialArtifact(credentialArtifactWire{Name: a.Name, Encoding: a.Encoding}, a.Content)
}

// UnmarshalJSON rejects ambiguous and absent data/path variants.
func (a *CredentialArtifactOutput) UnmarshalJSON(data []byte) error {
	var wire credentialArtifactWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	content, err := credentialArtifactContentFromWire(wire)
	if err != nil {
		return err
	}
	*a = CredentialArtifactOutput{Name: wire.Name, Encoding: wire.Encoding, Content: content}
	return nil
}

// CredentialDeploymentOutput is provider-owned deployment evidence. Receipt
// is write-only to Hovel; public bookkeeping stores only its SHA-256 digest.
type CredentialDeploymentOutput struct {
	Reference string          `json:"reference"`
	Receipt   CredentialBytes `json:"receipt"`
}

type credentialStampOutputKind uint8

const (
	credentialStampOutputUnset credentialStampOutputKind = iota
	credentialStampOutputArtifact
	credentialStampOutputDeployment
)

// CredentialStampOutput is a sealed union containing exactly one artifact or
// deployment result. Construct values with NewCredentialStampArtifactOutput or
// NewCredentialStampDeploymentOutput.
type CredentialStampOutput struct {
	kind       credentialStampOutputKind
	artifact   CredentialArtifactOutput
	deployment CredentialDeploymentOutput
}

// NewCredentialStampArtifactOutput constructs and validates an artifact stamp result.
func NewCredentialStampArtifactOutput(
	artifact CredentialArtifactOutput,
) (CredentialStampOutput, error) {
	if strings.TrimSpace(artifact.Name) == "" || strings.TrimSpace(artifact.Encoding) == "" {
		return CredentialStampOutput{}, fmt.Errorf(
			"%w: artifact name and encoding must not be empty",
			ErrCredentialStampOutputVariant,
		)
	}
	if _, err := marshalCredentialArtifact(
		credentialArtifactWire{Name: artifact.Name, Encoding: artifact.Encoding}, artifact.Content,
	); err != nil {
		return CredentialStampOutput{}, fmt.Errorf("%w: %v", ErrCredentialStampOutputVariant, err)
	}
	artifact.Content = artifact.Content.clone()
	return CredentialStampOutput{kind: credentialStampOutputArtifact, artifact: artifact}, nil
}

// NewCredentialStampDeploymentOutput constructs and validates a deployment stamp result.
func NewCredentialStampDeploymentOutput(
	deployment CredentialDeploymentOutput,
) (CredentialStampOutput, error) {
	if strings.TrimSpace(deployment.Reference) == "" || len(deployment.Receipt) == 0 {
		return CredentialStampOutput{}, fmt.Errorf(
			"%w: deployment reference and receipt must not be empty",
			ErrCredentialStampOutputVariant,
		)
	}
	deployment.Receipt = append(CredentialBytes(nil), deployment.Receipt...)
	return CredentialStampOutput{kind: credentialStampOutputDeployment, deployment: deployment}, nil
}

// Artifact returns the artifact and reports whether this is the artifact variant.
func (o CredentialStampOutput) Artifact() (CredentialArtifactOutput, bool) {
	artifact := o.artifact
	artifact.Content = artifact.Content.clone()
	return artifact, o.kind == credentialStampOutputArtifact
}

// Deployment returns the deployment and reports whether this is the deployment variant.
func (o CredentialStampOutput) Deployment() (CredentialDeploymentOutput, bool) {
	deployment := o.deployment
	deployment.Receipt = append(CredentialBytes(nil), deployment.Receipt...)
	return deployment, o.kind == credentialStampOutputDeployment
}

// MarshalJSON preserves the canonical artifact/deployment wire union.
func (o CredentialStampOutput) MarshalJSON() ([]byte, error) {
	switch o.kind {
	case credentialStampOutputArtifact:
		return json.Marshal(struct {
			Artifact CredentialArtifactOutput `json:"artifact"`
		}{Artifact: o.artifact})
	case credentialStampOutputDeployment:
		return json.Marshal(struct {
			Deployment CredentialDeploymentOutput `json:"deployment"`
		}{Deployment: o.deployment})
	default:
		return nil, ErrCredentialStampOutputVariant
	}
}

// UnmarshalJSON rejects ambiguous and absent artifact/deployment variants.
func (o *CredentialStampOutput) UnmarshalJSON(data []byte) error {
	var wire struct {
		Artifact   json.RawMessage `json:"artifact"`
		Deployment json.RawMessage `json:"deployment"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	hasArtifact := wire.Artifact != nil
	hasDeployment := wire.Deployment != nil
	if hasArtifact == hasDeployment {
		return ErrCredentialStampOutputVariant
	}
	if hasArtifact {
		var artifact CredentialArtifactOutput
		if err := json.Unmarshal(wire.Artifact, &artifact); err != nil {
			return err
		}
		validated, err := NewCredentialStampArtifactOutput(artifact)
		if err != nil {
			return err
		}
		*o = validated
		return nil
	}
	var deployment CredentialDeploymentOutput
	if err := json.Unmarshal(wire.Deployment, &deployment); err != nil {
		return err
	}
	validated, err := NewCredentialStampDeploymentOutput(deployment)
	if err != nil {
		return err
	}
	*o = validated
	return nil
}

type CredentialStampedMaterialDigest struct {
	Projection CredentialProjection `json:"projection"`
	Reference  string               `json:"reference"`
	SHA256     string               `json:"sha256"`
}

type CredentialStampTargetResolution string

const (
	CredentialStampTargetUnchanged  CredentialStampTargetResolution = "unchanged"
	CredentialStampTargetTranslated CredentialStampTargetResolution = "translated"
)

// CredentialStampExecutionRequest combines the immutable descriptor-validated
// request with the exact input artifact and short-lived resolved material.
type CredentialStampExecutionRequest struct {
	SchemaVersion   string                            `json:"schemaVersion"`
	Provider        CredentialProviderTarget          `json:"provider"`
	StampID         string                            `json:"stampId"`
	Request         CredentialStampRequest            `json:"request"`
	Input           CredentialArtifactInput           `json:"input"`
	Material        ResolvedCredentialMaterial        `json:"resolvedMaterial"`
	ExpectedDigests []CredentialStampedMaterialDigest `json:"expectedDigests"`
	Scope           CredentialOperationScope          `json:"scope"`
}

// CredentialStampExecutionResult reports provider evidence, not final daemon
// bookkeeping. Hovel independently verifies and ingests Output before creating
// the durable credential-stamp result.
type CredentialStampExecutionResult struct {
	StampID          string                            `json:"stampId"`
	Output           CredentialStampOutput             `json:"output"`
	TargetResolution CredentialStampTargetResolution   `json:"targetResolution"`
	ResolvedTarget   CredentialStampTarget             `json:"resolvedTarget"`
	BytesWritten     CredentialCanonicalUint64         `json:"bytesWritten"`
	MaterialDigests  []CredentialStampedMaterialDigest `json:"materialDigests"`
}

// CredentialRuntimeProvider is implemented only by providers that consume
// resolved credential material directly at operation start.
type CredentialRuntimeProvider interface {
	Module
	LoadRuntimeCredential(CredentialRuntimeRequest) (CredentialDeliveryReceipt, error)
}

// CredentialFilesProvider is implemented only by providers that consume
// invocation-scoped protected files.
type CredentialFilesProvider interface {
	Module
	LoadCredentialFiles(CredentialFilesRequest) (CredentialDeliveryReceipt, error)
}

// CredentialEncodingProvider is implemented only by providers that advertise
// a provider-encoding schema.
type CredentialEncodingProvider interface {
	Module
	EncodeCredentialMaterial(CredentialEncodingRequest) (CredentialEncodingResult, error)
}

// CredentialStampProvider is implemented only by providers that advertise a
// standard or advanced stamping capability.
type CredentialStampProvider interface {
	Module
	StampCredential(CredentialStampExecutionRequest) (CredentialStampExecutionResult, error)
}

func credentialProviderMethodUnavailable(module Module, method string) error {
	return fmt.Errorf("module %q does not implement %s", module.Info().Name, method)
}
