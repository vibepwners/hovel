package hovel

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

const (
	// CredentialProviderExecutionSchemaV1 versions the secret-bearing provider
	// invocation surface independently from credential-delivery discovery.
	CredentialProviderExecutionSchemaV1 = "hovel.pki.provider-execution/v1"
	// CredentialEncodingRaw identifies bytes stored without another encoding layer.
	CredentialEncodingRaw = "raw"
	// CredentialEncodingJSON identifies a serialized JSON credential projection.
	CredentialEncodingJSON = "json"
)

const (
	redactedCredentialBytes  = "<credential bytes redacted>"
	redactedCredentialSecret = "<credential secret redacted>"
)

func formatRedacted(state fmt.State, marker string) {
	_, _ = state.Write([]byte(marker))
}

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

// Format redacts the bytes for fmt value-formatting verbs, including verbs
// that do not use String or GoString.
func (CredentialBytes) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedCredentialBytes)
}

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

type credentialSecretText struct {
	value *string
}

func newCredentialSecretText(value string) credentialSecretText {
	return credentialSecretText{value: &value}
}

func (s credentialSecretText) reveal() string {
	if s.value == nil {
		return ""
	}
	return *s.value
}

// CredentialSecretReference is an opaque provider-scoped capability whose
// ordinary string formatting is redacted. Its pointer-boxed representation
// also prevents unsupported fmt verbs from embedding the secret in errors.
type CredentialSecretReference struct {
	secret credentialSecretText
}

// NewCredentialSecretReference wraps an opaque provider-scoped reference.
func NewCredentialSecretReference(value string) CredentialSecretReference {
	return CredentialSecretReference{secret: newCredentialSecretText(value)}
}

// Reveal returns the reference for an explicit provider protocol boundary.
func (r CredentialSecretReference) Reveal() string { return r.secret.reveal() }

func (CredentialSecretReference) String() string { return redactedCredentialSecret }

func (CredentialSecretReference) GoString() string { return redactedCredentialSecret }

func (CredentialSecretReference) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedCredentialSecret)
}

func (r CredentialSecretReference) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Reveal())
}

func (r *CredentialSecretReference) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("credential secret reference destination is nil")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode credential secret reference: %w", err)
	}
	*r = NewCredentialSecretReference(value)
	return nil
}

func (r CredentialSecretReference) Validate() error {
	return validateCredentialCanonicalText(
		r.Reveal(),
		"credential secret reference",
		maximumCredentialIDBytes,
	)
}

// CredentialProtectedPath is an invocation-scoped path whose ordinary string
// formatting is redacted because names and layout may disclose secrets. Its
// pointer-boxed representation also remains secret-safe under unsupported fmt
// verbs.
type CredentialProtectedPath struct {
	secret credentialSecretText
}

// NewCredentialProtectedPath wraps an invocation-scoped protected path.
func NewCredentialProtectedPath(value string) CredentialProtectedPath {
	return CredentialProtectedPath{secret: newCredentialSecretText(value)}
}

// Reveal returns the path for an explicit provider protocol boundary.
func (p CredentialProtectedPath) Reveal() string { return p.secret.reveal() }

func (CredentialProtectedPath) String() string { return redactedCredentialSecret }

func (CredentialProtectedPath) GoString() string { return redactedCredentialSecret }

func (CredentialProtectedPath) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedCredentialSecret)
}

func (p CredentialProtectedPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Reveal())
}

func (p *CredentialProtectedPath) UnmarshalJSON(data []byte) error {
	if p == nil {
		return errors.New("credential protected path destination is nil")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode credential protected path: %w", err)
	}
	*p = NewCredentialProtectedPath(value)
	return nil
}

func (p CredentialProtectedPath) Validate() error {
	return validateCredentialCanonicalText(
		p.Reveal(),
		"credential protected path",
		maximumCredentialPathBytes,
	)
}

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

func (s CredentialOperationScope) Validate() error {
	values := []struct {
		name  string
		value string
	}{
		{name: "operation id", value: s.OperationID},
		{name: "run id", value: s.RunID},
		{name: "chain id", value: s.ChainID},
		{name: "throw id", value: s.ThrowID},
		{name: "target", value: s.Target},
		{name: "listener id", value: s.ListenerID},
		{name: "node id", value: s.NodeID},
	}
	for _, value := range values {
		if value.value == "" {
			continue
		}
		if err := validateCredentialCanonicalText(
			value.value,
			"credential operation "+value.name,
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
	}
	return nil
}

// CredentialProviderTarget binds an invocation to the exact module and
// versioned credential-delivery descriptor selected by Hovel.
type CredentialProviderTarget struct {
	ModuleID         string `json:"moduleId"`
	ProviderID       string `json:"providerId"`
	ProviderVersion  string `json:"providerVersion"`
	DescriptorSHA256 string `json:"descriptorSha256"`
}

func (t CredentialProviderTarget) Validate() error {
	values := []struct {
		name  string
		value string
	}{
		{name: "module id", value: t.ModuleID},
		{name: "provider id", value: t.ProviderID},
		{name: "provider version", value: t.ProviderVersion},
	}
	for _, value := range values {
		if err := validateCredentialCanonicalText(
			value.value,
			"credential provider "+value.name,
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
	}
	return validateCredentialSHA256(t.DescriptorSHA256, "credential provider descriptor")
}

// CredentialScopedReference identifies a non-exportable or externally owned
// credential capability. Reference is provider-scoped, not a general signing
// oracle.
type CredentialScopedReference struct {
	ProviderID   string                    `json:"providerId"`
	Reference    CredentialSecretReference `json:"reference"`
	Capabilities []string                  `json:"capabilities,omitempty"`
}

func (r CredentialScopedReference) Validate() error {
	if err := validateCredentialCanonicalText(
		r.ProviderID,
		"credential reference provider id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := r.Reference.Validate(); err != nil {
		return err
	}
	if len(r.Capabilities) > maximumCredentialReferenceCapabilities {
		return errors.New("credential reference capabilities exceed limits")
	}
	seen := make(map[string]struct{}, len(r.Capabilities))
	for _, capability := range r.Capabilities {
		if err := validateCredentialCanonicalText(
			capability,
			"credential reference capability",
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
		if _, duplicate := seen[capability]; duplicate {
			return errors.New("credential reference capabilities contain a duplicate")
		}
		seen[capability] = struct{}{}
	}
	return nil
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
	if len(data) == 0 || len(data) > maximumCredentialBinaryBytes {
		return CredentialMaterialValue{}, fmt.Errorf(
			"%w: bytes must be non-empty and bounded",
			ErrCredentialMaterialVariant,
		)
	}
	return CredentialMaterialValue{
		kind: credentialMaterialValueBytes,
		data: append(CredentialBytes(nil), data...),
	}, nil
}

// NewCredentialMaterialReference constructs a provider-scoped reference
// variant and defensively copies its capabilities.
func NewCredentialMaterialReference(reference CredentialScopedReference) (CredentialMaterialValue, error) {
	if err := reference.Validate(); err != nil {
		return CredentialMaterialValue{}, fmt.Errorf(
			"%w: %v",
			ErrCredentialMaterialVariant,
			err,
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

func (CredentialMaterialValue) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedCredentialSecret)
}

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

func (ResolvedCredentialMaterial) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedCredentialSecret)
}

func (m ResolvedCredentialMaterial) Validate() error {
	if err := validateCredentialProjectionForm(m.Projection, m.form); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		m.Encoding,
		"credential material encoding",
		maximumCredentialEncodingBytes,
	); err != nil {
		return err
	}
	if err := validateCredentialSHA256(m.SHA256, "credential material"); err != nil {
		return err
	}
	if m.form == CredentialMaterialPrivateReference {
		if m.value.kind != credentialMaterialValueReference || len(m.value.data) != 0 {
			return ErrCredentialMaterialVariant
		}
		return m.value.reference.Validate()
	}
	if m.value.kind != credentialMaterialValueBytes ||
		len(m.value.data) == 0 || len(m.value.data) > maximumCredentialBinaryBytes ||
		!credentialScopedReferenceIsZero(m.value.reference) {
		return ErrCredentialMaterialVariant
	}
	return validateCredentialDigest(m.value.data, m.SHA256, "credential material")
}

func credentialScopedReferenceIsZero(reference CredentialScopedReference) bool {
	return reference.ProviderID == "" && reference.Reference.Reveal() == "" &&
		len(reference.Capabilities) == 0
}

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
	if err := material.Validate(); err != nil {
		return ResolvedCredentialMaterial{}, err
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
	if err := m.Validate(); err != nil {
		return nil, err
	}
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
	if m == nil {
		return errors.New("resolved credential material destination is nil")
	}
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

func (r CredentialRuntimeRequest) Validate() error {
	if err := validateCredentialExecutionEnvelope(r.SchemaVersion, r.RequestID); err != nil {
		return err
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := validateCredentialDeliveryInputs(
		r.AssignmentID,
		r.SlotName,
		r.Credential,
		r.Scope,
	); err != nil {
		return err
	}
	return r.Material.Validate()
}

// CredentialFile is one owner-protected, invocation-scoped file. The path is
// valid only for the provider call unless the provider copies it into storage
// it owns and reports that action in its receipt.
type CredentialFile struct {
	Projection CredentialProjection    `json:"projection"`
	Form       CredentialMaterialForm  `json:"form"`
	Encoding   string                  `json:"encoding"`
	MediaType  string                  `json:"mediaType"`
	Path       CredentialProtectedPath `json:"path"`
	SHA256     string                  `json:"sha256"`
	Size       uint64                  `json:"size"`
}

func (f CredentialFile) Validate() error {
	if err := validateCredentialProjectionForm(f.Projection, f.Form); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		f.Encoding,
		"credential file encoding",
		maximumCredentialEncodingBytes,
	); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		f.MediaType,
		"credential file media type",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := f.Path.Validate(); err != nil {
		return err
	}
	if err := validateCredentialSHA256(f.SHA256, "credential file"); err != nil {
		return err
	}
	if f.Size == 0 || f.Size > maximumCredentialBinaryBytes {
		return errors.New("credential file size is invalid")
	}
	return nil
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

func (r CredentialFilesRequest) Validate() error {
	if err := validateCredentialExecutionEnvelope(r.SchemaVersion, r.RequestID); err != nil {
		return err
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := validateCredentialDeliveryInputs(
		r.AssignmentID,
		r.SlotName,
		r.Credential,
		r.Scope,
	); err != nil {
		return err
	}
	if len(r.Files) == 0 || len(r.Files) > maximumCredentialExecutionFiles {
		return errors.New("credential files request is empty or exceeds limits")
	}
	seen := make(map[string]struct{}, len(r.Files))
	for _, file := range r.Files {
		if err := file.Validate(); err != nil {
			return err
		}
		path := file.Path.Reveal()
		if _, duplicate := seen[path]; duplicate {
			return errors.New("credential files request contains a duplicate path")
		}
		seen[path] = struct{}{}
	}
	return nil
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

func (r CredentialDeliveryReceipt) Validate() error {
	if err := validateCredentialCanonicalText(
		r.RequestID,
		"credential delivery receipt request id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if r.ProviderReference != "" {
		if err := validateCredentialCanonicalText(
			r.ProviderReference,
			"credential provider reference",
			maximumCredentialIDBytes,
		); err != nil {
			return err
		}
	}
	if r.ReceiptSHA256 != "" {
		return validateCredentialSHA256(r.ReceiptSHA256, "credential delivery receipt")
	}
	return nil
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

func (r CredentialEncodingRequest) Validate() error {
	if err := validateCredentialExecutionEnvelope(r.SchemaVersion, r.RequestID); err != nil {
		return err
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		r.ProviderID,
		"credential encoding provider id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if r.ProviderID != r.Provider.ProviderID {
		return errors.New("credential encoding provider does not match its invocation target")
	}
	if err := validateCredentialCanonicalText(
		r.ProviderSchema,
		"credential provider schema",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := r.OutputForm.Validate(); err != nil {
		return err
	}
	if r.MaximumEncodedBytes == 0 || r.MaximumEncodedBytes > maximumCredentialBinaryBytes {
		return errors.New("credential encoding output bound is invalid")
	}
	if err := r.Source.Validate(); err != nil {
		return err
	}
	return r.Scope.Validate()
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

func (r CredentialEncodingResult) Validate() error {
	if err := validateCredentialCanonicalText(
		r.RequestID,
		"credential encoding result request id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := r.Form.Validate(); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		r.Encoding,
		"credential encoding",
		maximumCredentialEncodingBytes,
	); err != nil {
		return err
	}
	if len(r.Data) == 0 || len(r.Data) > maximumCredentialBinaryBytes {
		return errors.New("encoded credential data is empty or exceeds limits")
	}
	return validateCredentialDigest(r.Data, r.SHA256, "encoded credential")
}

func (r CredentialEncodingResult) ValidateFor(request CredentialEncodingRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.RequestID != request.RequestID || r.Form != request.OutputForm ||
		uint64(len(r.Data)) > request.MaximumEncodedBytes {
		return errors.New("credential encoding result does not match its request")
	}
	return nil
}

func validateCredentialExecutionEnvelope(schemaVersion, requestID string) error {
	if schemaVersion != CredentialProviderExecutionSchemaV1 {
		return fmt.Errorf("unsupported credential provider execution schema %q", schemaVersion)
	}
	return validateCredentialCanonicalText(
		requestID,
		"credential provider request id",
		maximumCredentialIDBytes,
	)
}

func validateCredentialDeliveryInputs(
	assignmentID string,
	slotName string,
	credential ResolvedCredentialMetadata,
	scope CredentialOperationScope,
) error {
	if err := validateCredentialCanonicalText(
		assignmentID,
		"credential assignment id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		slotName,
		"credential slot name",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := credential.Validate(); err != nil {
		return err
	}
	return scope.Validate()
}

func validateCredentialDigest(data []byte, value, label string) error {
	if err := validateCredentialSHA256(value, label); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != value {
		return fmt.Errorf("%s sha256 does not match its bytes", label)
	}
	return nil
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
	if len(data) == 0 || len(data) > maximumCredentialBinaryBytes {
		return CredentialArtifactContent{}, fmt.Errorf(
			"%w: data must be non-empty and bounded",
			ErrCredentialArtifactVariant,
		)
	}
	return CredentialArtifactContent{
		kind: credentialArtifactContentData,
		data: append(CredentialBytes(nil), data...),
	}, nil
}

// NewCredentialArtifactPath constructs a non-empty protected-path artifact
// variant.
func NewCredentialArtifactPath(path string) (CredentialArtifactContent, error) {
	protected := NewCredentialProtectedPath(path)
	if err := protected.Validate(); err != nil {
		return CredentialArtifactContent{}, fmt.Errorf("%w: %v", ErrCredentialArtifactVariant, err)
	}
	return CredentialArtifactContent{
		kind: credentialArtifactContentPath,
		path: protected,
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
		return CredentialProtectedPath{}, false
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

func (CredentialArtifactContent) Format(state fmt.State, _ rune) {
	formatRedacted(state, redactedCredentialSecret)
}

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
		ID       string                   `json:"id,omitempty"`
		Name     string                   `json:"name,omitempty"`
		SHA256   string                   `json:"sha256,omitempty"`
		Encoding string                   `json:"encoding"`
		Data     CredentialBytes          `json:"data,omitempty"`
		Path     *CredentialProtectedPath `json:"path,omitempty"`
	}
	result := artifactWire{ID: wire.ID, Name: wire.Name, SHA256: wire.SHA256, Encoding: wire.Encoding}
	switch content.kind {
	case credentialArtifactContentData:
		if len(content.data) == 0 {
			return nil, ErrCredentialArtifactVariant
		}
		result.Data = append(CredentialBytes(nil), content.data...)
	case credentialArtifactContentPath:
		if len(content.data) != 0 {
			return nil, ErrCredentialArtifactVariant
		}
		if err := content.path.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCredentialArtifactVariant, err)
		}
		path := content.path
		result.Path = &path
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

func (a CredentialArtifactInput) Validate() error {
	if err := validateCredentialCanonicalText(
		a.ID,
		"credential stamp input id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := validateCredentialSHA256(a.SHA256, "credential stamp input"); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		a.Encoding,
		"credential artifact encoding",
		maximumCredentialEncodingBytes,
	); err != nil {
		return err
	}
	switch a.Content.kind {
	case credentialArtifactContentData:
		if len(a.Content.data) == 0 || len(a.Content.data) > maximumCredentialBinaryBytes ||
			a.Content.path.Reveal() != "" {
			return ErrCredentialArtifactVariant
		}
		return validateCredentialDigest(a.Content.data, a.SHA256, "credential stamp input")
	case credentialArtifactContentPath:
		if len(a.Content.data) != 0 {
			return ErrCredentialArtifactVariant
		}
		return a.Content.path.Validate()
	default:
		return ErrCredentialArtifactVariant
	}
}

// MarshalJSON preserves the canonical data/path wire union.
func (a CredentialArtifactInput) MarshalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return marshalCredentialArtifact(credentialArtifactWire{
		ID: a.ID, SHA256: a.SHA256, Encoding: a.Encoding,
	}, a.Content)
}

// UnmarshalJSON rejects ambiguous and absent data/path variants.
func (a *CredentialArtifactInput) UnmarshalJSON(data []byte) error {
	if a == nil {
		return errors.New("credential artifact input destination is nil")
	}
	var wire credentialArtifactWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	content, err := credentialArtifactContentFromWire(wire)
	if err != nil {
		return err
	}
	result := CredentialArtifactInput{
		ID: wire.ID, SHA256: wire.SHA256, Encoding: wire.Encoding, Content: content,
	}
	if err := result.Validate(); err != nil {
		return err
	}
	*a = result
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

func (a CredentialArtifactOutput) Validate() error {
	if err := validateCredentialCanonicalText(
		a.Name,
		"credential artifact output name",
		maximumCredentialNameBytes,
	); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		a.Encoding,
		"credential artifact encoding",
		maximumCredentialEncodingBytes,
	); err != nil {
		return err
	}
	switch a.Content.kind {
	case credentialArtifactContentData:
		if len(a.Content.data) == 0 || len(a.Content.data) > maximumCredentialBinaryBytes ||
			a.Content.path.Reveal() != "" {
			return ErrCredentialArtifactVariant
		}
	case credentialArtifactContentPath:
		if len(a.Content.data) != 0 {
			return ErrCredentialArtifactVariant
		}
		return a.Content.path.Validate()
	default:
		return ErrCredentialArtifactVariant
	}
	return nil
}

// MarshalJSON preserves the canonical data/path wire union.
func (a CredentialArtifactOutput) MarshalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return marshalCredentialArtifact(credentialArtifactWire{Name: a.Name, Encoding: a.Encoding}, a.Content)
}

// UnmarshalJSON rejects ambiguous and absent data/path variants.
func (a *CredentialArtifactOutput) UnmarshalJSON(data []byte) error {
	if a == nil {
		return errors.New("credential artifact output destination is nil")
	}
	var wire credentialArtifactWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	content, err := credentialArtifactContentFromWire(wire)
	if err != nil {
		return err
	}
	result := CredentialArtifactOutput{Name: wire.Name, Encoding: wire.Encoding, Content: content}
	if err := result.Validate(); err != nil {
		return err
	}
	*a = result
	return nil
}

// CredentialDeploymentOutput is provider-owned deployment evidence. Receipt
// is write-only to Hovel; public bookkeeping stores only its SHA-256 digest.
type CredentialDeploymentOutput struct {
	Reference string          `json:"reference"`
	Receipt   CredentialBytes `json:"receipt"`
}

func (o CredentialDeploymentOutput) Validate() error {
	if err := validateCredentialCanonicalText(
		o.Reference,
		"credential deployment reference",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if len(o.Receipt) == 0 || len(o.Receipt) > maximumCredentialReceiptBytes {
		return errors.New("credential deployment receipt is empty or exceeds limits")
	}
	return nil
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
	if err := artifact.Validate(); err != nil {
		return CredentialStampOutput{}, fmt.Errorf("%w: %v", ErrCredentialStampOutputVariant, err)
	}
	artifact.Content = artifact.Content.clone()
	return CredentialStampOutput{kind: credentialStampOutputArtifact, artifact: artifact}, nil
}

// NewCredentialStampDeploymentOutput constructs and validates a deployment stamp result.
func NewCredentialStampDeploymentOutput(
	deployment CredentialDeploymentOutput,
) (CredentialStampOutput, error) {
	if err := deployment.Validate(); err != nil {
		return CredentialStampOutput{}, fmt.Errorf("%w: %v", ErrCredentialStampOutputVariant, err)
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

func (o CredentialStampOutput) Validate() error {
	switch o.kind {
	case credentialStampOutputArtifact:
		if len(o.deployment.Receipt) != 0 || o.deployment.Reference != "" {
			return ErrCredentialStampOutputVariant
		}
		return o.artifact.Validate()
	case credentialStampOutputDeployment:
		if o.artifact.Name != "" || o.artifact.Encoding != "" ||
			o.artifact.Content.kind != credentialArtifactContentUnset {
			return ErrCredentialStampOutputVariant
		}
		return o.deployment.Validate()
	default:
		return ErrCredentialStampOutputVariant
	}
}

// MarshalJSON preserves the canonical artifact/deployment wire union.
func (o CredentialStampOutput) MarshalJSON() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
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
	if o == nil {
		return errors.New("credential stamp output destination is nil")
	}
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

func (d CredentialStampedMaterialDigest) Validate() error {
	if err := d.Projection.Validate(); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		d.Reference,
		"credential stamped material reference",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	return validateCredentialSHA256(d.SHA256, "credential stamped material")
}

type CredentialStampTargetResolution string

const (
	CredentialStampTargetUnchanged  CredentialStampTargetResolution = "unchanged"
	CredentialStampTargetTranslated CredentialStampTargetResolution = "translated"
)

func (r CredentialStampTargetResolution) Validate() error {
	switch r {
	case CredentialStampTargetUnchanged, CredentialStampTargetTranslated:
		return nil
	default:
		return fmt.Errorf("unsupported credential stamp target resolution %q", r)
	}
}

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

func (r CredentialStampExecutionRequest) Validate() error {
	if r.SchemaVersion != CredentialProviderExecutionSchemaV1 {
		return fmt.Errorf("unsupported credential provider execution schema %q", r.SchemaVersion)
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := validateCredentialCanonicalText(
		r.StampID,
		"credential stamp id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := r.Request.Validate(); err != nil {
		return err
	}
	if err := r.Input.Validate(); err != nil {
		return err
	}
	if err := r.Material.Validate(); err != nil {
		return err
	}
	materialForm, err := r.Request.Material.Form()
	if err != nil {
		return err
	}
	if r.Material.Projection != r.Request.Material.Projection ||
		r.Material.Form() != materialForm {
		return errors.New("resolved credential material does not match the stamp request")
	}
	if err := validateCredentialStampedMaterialDigests(r.ExpectedDigests); err != nil {
		return err
	}
	return r.Scope.Validate()
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

func (r CredentialStampExecutionResult) Validate() error {
	if err := validateCredentialCanonicalText(
		r.StampID,
		"credential stamp result id",
		maximumCredentialIDBytes,
	); err != nil {
		return err
	}
	if err := r.Output.Validate(); err != nil {
		return err
	}
	if err := r.TargetResolution.Validate(); err != nil {
		return err
	}
	if err := r.ResolvedTarget.Validate(); err != nil {
		return err
	}
	bytesWritten, err := r.BytesWritten.Uint64()
	if err != nil || bytesWritten == 0 || bytesWritten > maximumCredentialBinaryBytes {
		return errors.New("credential stamp result bytes written is invalid")
	}
	return validateCredentialStampedMaterialDigests(r.MaterialDigests)
}

func (r CredentialStampExecutionResult) ValidateFor(
	request CredentialStampExecutionRequest,
) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.StampID != request.StampID {
		return errors.New("credential stamp result id does not match its request")
	}
	bytesWritten, _ := r.BytesWritten.Uint64()
	if bytesWritten != request.Request.EncodedBytes {
		return errors.New("credential stamp result byte count does not match its request")
	}
	if r.TargetResolution == CredentialStampTargetUnchanged &&
		!reflect.DeepEqual(r.ResolvedTarget, request.Request.Target) {
		return errors.New("unchanged credential stamp target does not match its request")
	}
	if !credentialStampedMaterialDigestsEqual(
		r.MaterialDigests,
		request.ExpectedDigests,
	) {
		return errors.New("credential stamp result material digests do not match its request")
	}
	return nil
}

func validateCredentialStampedMaterialDigests(
	digests []CredentialStampedMaterialDigest,
) error {
	if len(digests) == 0 || len(digests) > maximumCredentialStampDigests {
		return errors.New("credential stamped material digests are empty or exceed limits")
	}
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if err := digest.Validate(); err != nil {
			return err
		}
		key := string(digest.Projection) + "\x00" + digest.Reference
		if _, duplicate := seen[key]; duplicate {
			return errors.New("credential stamped material digests contain a duplicate")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func credentialStampedMaterialDigestsEqual(
	left []CredentialStampedMaterialDigest,
	right []CredentialStampedMaterialDigest,
) bool {
	if len(left) != len(right) {
		return false
	}
	want := make(map[string]string, len(right))
	for _, digest := range right {
		want[string(digest.Projection)+"\x00"+digest.Reference] = digest.SHA256
	}
	for _, digest := range left {
		key := string(digest.Projection) + "\x00" + digest.Reference
		if want[key] != digest.SHA256 {
			return false
		}
	}
	return true
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
