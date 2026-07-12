package pki

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

const (
	CredentialProviderExecutionSchemaV1  = "hovel.pki.provider-execution/v1"
	MaximumCredentialExecutionJSON       = 64 << 20
	MaximumCredentialExecutionFiles      = 64
	MaximumCredentialReferenceCaps       = 64
	MaximumCredentialOperationDeliveries = 64
	MaximumCredentialSelections          = 64
	MaximumCredentialPathBytes           = 4096
	MaximumCredentialEncodingBytes       = 256
	MaximumCredentialReceiptBytes        = 1 << 20
	redactedCredentialSecret             = "<credential secret redacted>"
	credentialConsumerPathSeparator      = "/"
)

// CredentialBytes carries ephemeral secret-aware binary material. JSON uses
// the encoding/json base64 representation for byte slices; ordinary string
// formatting never exposes the contents.
type CredentialBytes []byte

func (CredentialBytes) String() string   { return redactedCredentialSecret }
func (CredentialBytes) GoString() string { return redactedCredentialSecret }

func (b CredentialBytes) Clone() CredentialBytes {
	return append(CredentialBytes(nil), b...)
}

// CredentialSecretReference is an opaque provider-scoped capability. It is
// secret-aware because possession may authorize use of non-exportable key
// material.
type CredentialSecretReference string

func (CredentialSecretReference) String() string   { return redactedCredentialSecret }
func (CredentialSecretReference) GoString() string { return redactedCredentialSecret }

func (r CredentialSecretReference) Validate() error {
	return validateCanonicalContractText(string(r), "credential secret reference", MaxIDLength)
}

// CredentialProtectedPath is an invocation-scoped owner-protected path. It is
// redacted from ordinary diagnostics because paths can disclose secret names
// and workspace layout.
type CredentialProtectedPath string

func (CredentialProtectedPath) String() string   { return redactedCredentialSecret }
func (CredentialProtectedPath) GoString() string { return redactedCredentialSecret }

func (p CredentialProtectedPath) Validate() error {
	return validateCanonicalContractText(string(p), "credential protected path", MaximumCredentialPathBytes)
}

// CredentialOperationScope correlates an ephemeral provider invocation with
// daemon-owned operations without coupling PKI to other domain packages.
type CredentialOperationScope struct {
	OperationID OperationID `json:"operationId,omitempty"`
	RunID       string      `json:"runId,omitempty"`
	ChainID     string      `json:"chainId,omitempty"`
	ThrowID     string      `json:"throwId,omitempty"`
	Target      string      `json:"target,omitempty"`
	ListenerID  string      `json:"listenerId,omitempty"`
	NodeID      string      `json:"nodeId,omitempty"`
}

// CredentialConsumerBinding identifies one assignment subject that may supply
// a credential to an operation. It is internal orchestration state rather than
// a wire-level request: callers select assignment IDs, while the daemon derives
// allowed consumers from the Mesh operation being invoked.
type CredentialConsumerBinding struct {
	Type ConsumerType
	ID   ConsumerID
}

// NewMeshProviderConsumer binds credentials owned by the selected canonical
// Mesh provider name. Provider names do not include an installed-version
// suffix.
func NewMeshProviderConsumer(providerName string) (CredentialConsumerBinding, error) {
	if _, err := NewConsumerID(providerName); err != nil {
		return CredentialConsumerBinding{}, err
	}
	return newCredentialConsumerBinding(ConsumerMeshProvider, providerName)
}

// NewMeshListenerConsumer binds credentials owned by one listener of the
// selected Mesh module.
func NewMeshListenerConsumer(providerName, listenerID string) (CredentialConsumerBinding, error) {
	if _, err := NewConsumerID(providerName); err != nil {
		return CredentialConsumerBinding{}, err
	}
	if _, err := NewConsumerID(listenerID); err != nil {
		return CredentialConsumerBinding{}, err
	}
	return newCredentialConsumerBinding(
		ConsumerMeshListener,
		providerName+credentialConsumerPathSeparator+listenerID,
	)
}

// NewMeshNodeConsumer binds credentials owned by one node of the selected Mesh
// module.
func NewMeshNodeConsumer(providerName, nodeID string) (CredentialConsumerBinding, error) {
	if _, err := NewConsumerID(providerName); err != nil {
		return CredentialConsumerBinding{}, err
	}
	if _, err := NewConsumerID(nodeID); err != nil {
		return CredentialConsumerBinding{}, err
	}
	return newCredentialConsumerBinding(
		ConsumerMeshNode,
		providerName+credentialConsumerPathSeparator+nodeID,
	)
}

func newCredentialConsumerBinding(
	consumerType ConsumerType,
	consumerID string,
) (CredentialConsumerBinding, error) {
	binding := CredentialConsumerBinding{Type: consumerType, ID: ConsumerID(consumerID)}
	if err := binding.Validate(); err != nil {
		return CredentialConsumerBinding{}, err
	}
	return binding, nil
}

func (b CredentialConsumerBinding) Validate() error {
	if err := b.Type.Validate(); err != nil {
		return err
	}
	return b.ID.Validate()
}

func (b CredentialConsumerBinding) Matches(assignment Assignment) bool {
	return b.Type == assignment.ConsumerType && b.ID == assignment.ConsumerID
}

// CredentialProviderTarget binds a secret-bearing invocation to the exact
// module and versioned credential-delivery descriptor selected by Hovel.
type CredentialProviderTarget struct {
	ModuleID         string             `json:"moduleId"`
	ProviderID       DeliveryProviderID `json:"providerId"`
	ProviderVersion  string             `json:"providerVersion"`
	DescriptorSHA256 string             `json:"descriptorSha256"`
}

func (t CredentialProviderTarget) Validate() error {
	if err := validateCanonicalContractText(t.ModuleID, "credential provider module id", MaxIDLength); err != nil {
		return err
	}
	if err := t.ProviderID.Validate(); err != nil {
		return err
	}
	if err := validateCanonicalContractText(t.ProviderVersion, "credential provider version", MaxIDLength); err != nil {
		return err
	}
	return validateCanonicalSHA256(t.DescriptorSHA256, "credential provider descriptor")
}

func (s CredentialOperationScope) Validate() error {
	if s.OperationID != "" {
		if err := s.OperationID.Validate(); err != nil {
			return err
		}
	}
	values := []struct {
		name  string
		value string
	}{
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
		if err := validateCanonicalContractText(value.value, value.name, MaxIDLength); err != nil {
			return err
		}
	}
	return nil
}

// CredentialScopedReference identifies a non-exportable or externally owned
// credential capability. The reference remains scoped to ProviderID.
type CredentialScopedReference struct {
	ProviderID   DeliveryProviderID        `json:"providerId"`
	Reference    CredentialSecretReference `json:"reference"`
	Capabilities []string                  `json:"capabilities,omitempty"`
}

func (r CredentialScopedReference) Clone() CredentialScopedReference {
	result := r
	result.Capabilities = append([]string(nil), r.Capabilities...)
	return result
}

func (r CredentialScopedReference) Validate() error {
	if err := r.ProviderID.Validate(); err != nil {
		return err
	}
	if err := r.Reference.Validate(); err != nil {
		return err
	}
	if len(r.Capabilities) > MaximumCredentialReferenceCaps || hasDuplicateStrings(r.Capabilities) {
		return errors.New("pki: credential scoped reference capabilities are invalid")
	}
	for _, capability := range r.Capabilities {
		if err := validateCanonicalContractText(capability, "credential reference capability", MaxIDLength); err != nil {
			return err
		}
	}
	return nil
}

// ResolvedCredentialMaterial is a tagged ephemeral provider input. Data is
// active for public/private-byte forms; Reference is active only for a
// private-reference form.
type ResolvedCredentialMaterial struct {
	Projection CredentialProjection       `json:"projection"`
	Form       CredentialMaterialForm     `json:"form"`
	Encoding   string                     `json:"encoding"`
	SHA256     string                     `json:"sha256"`
	Data       CredentialBytes            `json:"data,omitempty"`
	Reference  *CredentialScopedReference `json:"reference,omitempty"`
}

func (m ResolvedCredentialMaterial) Clone() ResolvedCredentialMaterial {
	result := m
	result.Data = m.Data.Clone()
	if m.Reference != nil {
		value := m.Reference.Clone()
		result.Reference = &value
	}
	return result
}

func (m ResolvedCredentialMaterial) Validate() error {
	if err := m.Projection.Validate(); err != nil {
		return err
	}
	if err := m.Form.Validate(); err != nil {
		return err
	}
	if err := validateResolvedProjectionForm(m.Projection, m.Form); err != nil {
		return err
	}
	if err := validateCanonicalContractText(m.Encoding, "credential material encoding", MaximumCredentialEncodingBytes); err != nil {
		return err
	}
	if err := validateCanonicalSHA256(m.SHA256, "credential material"); err != nil {
		return err
	}
	if m.Form == CredentialMaterialPrivateReference {
		if len(m.Data) != 0 || m.Reference == nil {
			return errors.New("pki: private-reference material requires exactly one scoped reference")
		}
		return m.Reference.Validate()
	}
	if len(m.Data) == 0 || len(m.Data) > MaximumBundleBinaryBytes || m.Reference != nil {
		return errors.New("pki: byte material requires bounded data and no scoped reference")
	}
	return validateCredentialDigest(m.Data, m.SHA256, "credential material")
}

func validateResolvedProjectionForm(projection CredentialProjection, form CredentialMaterialForm) error {
	switch projection {
	case CredentialProjectionCertificateDER, CredentialProjectionPublicKeySPKI,
		CredentialProjectionChainDER, CredentialProjectionTrustDER, CredentialProjectionCRLDER:
		if form != CredentialMaterialPublic {
			return errors.New("pki: public credential projection requires public material")
		}
	case CredentialProjectionPrivateKeyPKCS8:
		if form != CredentialMaterialPrivateBytes {
			return errors.New("pki: private-key projection requires private bytes")
		}
	case CredentialProjectionSignerReference:
		if form != CredentialMaterialPrivateReference {
			return errors.New("pki: signer projection requires a private reference")
		}
	case CredentialProjectionBundle, CredentialProjectionProviderEncoding,
		CredentialProjectionLiteralReference:
		return nil
	default:
		return fmt.Errorf("pki: unsupported resolved credential projection %q", projection)
	}
	return nil
}

// CredentialMaterialSelection identifies one typed, unresolved view of
// credential material. It deliberately carries no resolved bytes, references,
// paths, or provider details.
type CredentialMaterialSelection struct {
	Projection CredentialProjection   `json:"projection"`
	Form       CredentialMaterialForm `json:"form"`
}

func (s *CredentialMaterialSelection) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("pki: credential material selection destination is nil")
	}
	type wire CredentialMaterialSelection
	var value wire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionJSON, &value, "credential material selection",
	); err != nil {
		return err
	}
	validated := CredentialMaterialSelection(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*s = validated.Clone()
	return nil
}

func (s CredentialMaterialSelection) Clone() CredentialMaterialSelection {
	return s
}

func (s CredentialMaterialSelection) Validate() error {
	if err := s.Projection.Validate(); err != nil {
		return err
	}
	if err := s.Form.Validate(); err != nil {
		return err
	}
	return validateResolvedProjectionForm(s.Projection, s.Form)
}

// CredentialSelection is the non-secret external contract used to select one
// assignment slot and one unresolved material view for a Mesh operation.
type CredentialSelection struct {
	RequestID    CredentialExecutionRequestID `json:"requestId"`
	AssignmentID AssignmentID                 `json:"assignmentId"`
	SlotName     CredentialSlotName           `json:"slotName"`
	Capability   DeliveryCapability           `json:"capability"`
	Material     CredentialMaterialSelection  `json:"material"`
}

func (s *CredentialSelection) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("pki: credential selection destination is nil")
	}
	type wire CredentialSelection
	var value wire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionJSON, &value, "credential selection",
	); err != nil {
		return err
	}
	validated := CredentialSelection(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*s = validated.Clone()
	return nil
}

func (s CredentialSelection) Clone() CredentialSelection {
	result := s
	result.Material = s.Material.Clone()
	return result
}

func (s CredentialSelection) Validate() error {
	if err := s.RequestID.Validate(); err != nil {
		return err
	}
	if err := s.AssignmentID.Validate(); err != nil {
		return err
	}
	if err := s.SlotName.Validate(); err != nil {
		return err
	}
	if err := s.Capability.Validate(); err != nil {
		return err
	}
	if s.Capability != DeliveryCapabilityRuntime {
		return fmt.Errorf("pki: unsupported credential selection capability %q", s.Capability)
	}
	if err := s.Material.Validate(); err != nil {
		return err
	}
	switch s.Material.Projection {
	case CredentialProjectionCertificateDER, CredentialProjectionPublicKeySPKI,
		CredentialProjectionPrivateKeyPKCS8:
		return nil
	case CredentialProjectionBundle, CredentialProjectionChainDER,
		CredentialProjectionTrustDER, CredentialProjectionCRLDER,
		CredentialProjectionSignerReference, CredentialProjectionProviderEncoding,
		CredentialProjectionLiteralReference:
		return fmt.Errorf(
			"pki: unsupported runtime credential selection projection %q",
			s.Material.Projection,
		)
	default:
		return fmt.Errorf(
			"pki: unsupported credential selection projection %q",
			s.Material.Projection,
		)
	}
}

type CredentialSelections []CredentialSelection

func (selections *CredentialSelections) UnmarshalJSON(data []byte) error {
	if selections == nil {
		return errors.New("pki: credential selections destination is nil")
	}
	if len(data) == 0 || len(data) > MaximumCredentialExecutionJSON {
		return errors.New("pki: credential selections json has an invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value []CredentialSelection
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("pki: decode credential selections: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("pki: credential selections contains trailing json data")
	}
	if value == nil {
		return errors.New("pki: credential selections value must be a JSON array")
	}
	validated := CredentialSelections(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*selections = validated.Clone()
	return nil
}

func (selections CredentialSelections) Clone() CredentialSelections {
	result := make(CredentialSelections, len(selections))
	for index := range selections {
		result[index] = selections[index].Clone()
	}
	return result
}

func (selections CredentialSelections) Validate() error {
	if len(selections) > MaximumCredentialSelections {
		return fmt.Errorf("pki: credential selections exceed %d entries", MaximumCredentialSelections)
	}
	requestIDs := make(map[CredentialExecutionRequestID]struct{}, len(selections))
	type assignmentSlot struct {
		assignmentID AssignmentID
		slotName     CredentialSlotName
	}
	assignmentSlots := make(map[assignmentSlot]struct{}, len(selections))
	for _, selection := range selections {
		if err := selection.Validate(); err != nil {
			return err
		}
		if _, duplicate := requestIDs[selection.RequestID]; duplicate {
			return errors.New("pki: credential selections contain a duplicate request id")
		}
		requestIDs[selection.RequestID] = struct{}{}
		key := assignmentSlot{assignmentID: selection.AssignmentID, slotName: selection.SlotName}
		if _, duplicate := assignmentSlots[key]; duplicate {
			return errors.New("pki: credential selections contain a duplicate assignment and slot")
		}
		assignmentSlots[key] = struct{}{}
	}
	return nil
}

type CredentialRuntimeRequest struct {
	SchemaVersion string                       `json:"schemaVersion"`
	Provider      CredentialProviderTarget     `json:"provider"`
	RequestID     CredentialExecutionRequestID `json:"requestId"`
	AssignmentID  AssignmentID                 `json:"assignmentId"`
	SlotName      CredentialSlotName           `json:"slotName"`
	Credential    ResolvedCredentialMetadata   `json:"credential"`
	Material      ResolvedCredentialMaterial   `json:"material"`
	Scope         CredentialOperationScope     `json:"scope"`
}

func (r *CredentialRuntimeRequest) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential runtime request destination is nil")
	}
	type wire CredentialRuntimeRequest
	var value wire
	if err := strictDecodeJSONObject(data, MaximumCredentialExecutionJSON, &value, "credential runtime request"); err != nil {
		return err
	}
	validated := CredentialRuntimeRequest(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*r = validated.Clone()
	return nil
}

func (r CredentialRuntimeRequest) Clone() CredentialRuntimeRequest {
	result := r
	result.Material = r.Material.Clone()
	return result
}

func (r CredentialRuntimeRequest) Validate() error {
	if err := validateExecutionEnvelope(r.SchemaVersion, r.RequestID); err != nil {
		return err
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := validateCredentialDeliveryInputs(r.AssignmentID, r.SlotName, r.Credential, r.Scope); err != nil {
		return err
	}
	return r.Material.Validate()
}

// ValidateRuntimeRequest verifies a resolved runtime delivery against the
// provider's advertised capability and slot contract. The check happens after
// daemon-side assignment resolution and again before the provider is called.
func (d CredentialDeliveryDescriptor) ValidateRuntimeRequest(
	request CredentialRuntimeRequest,
) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if !slices.Contains(d.Capabilities, DeliveryCapabilityRuntime) {
		return errors.New("pki: provider does not advertise runtime credential delivery")
	}
	slot, ok := d.credentialSlot(request.SlotName)
	if !ok {
		return fmt.Errorf("pki: provider does not advertise credential slot %q", request.SlotName)
	}
	if !slices.Contains(slot.AcceptedProjections, request.Material.Projection) {
		return fmt.Errorf(
			"pki: credential slot %q does not accept projection %q",
			request.SlotName,
			request.Material.Projection,
		)
	}
	if !slices.Contains(slot.AcceptedMaterialForms, request.Material.Form) {
		return fmt.Errorf(
			"pki: credential slot %q does not accept material form %q",
			request.SlotName,
			request.Material.Form,
		)
	}
	if slot.PrivateMaterial == PrivateMaterialForbidden && request.Material.Form.IsPrivate() {
		return fmt.Errorf("pki: credential slot %q forbids private material", request.SlotName)
	}
	if slot.PrivateMaterial == PrivateMaterialRequired && !request.Material.Form.IsPrivate() {
		return fmt.Errorf("pki: credential slot %q requires private material", request.SlotName)
	}
	if len(request.Material.Data) > 0 && uint64(len(request.Material.Data)) > slot.MaximumEncodedBytes {
		return fmt.Errorf("pki: credential material exceeds slot %q encoded-size limit", request.SlotName)
	}
	metadata := request.Credential
	if !slices.Contains(slot.AcceptedBundleVersions, metadata.BundleVersion) ||
		!slices.Contains(slot.AcceptedProfiles, metadata.ProfileID) ||
		!slices.Contains(slot.AcceptedCompatibilityTargets, metadata.CompatibilityTargetID) ||
		slot.Purpose != metadata.Purpose || slot.ConsumerType != metadata.ConsumerType {
		return errors.New("pki: resolved credential metadata is incompatible with its slot")
	}
	return nil
}

type CredentialFile struct {
	Projection CredentialProjection    `json:"projection"`
	Form       CredentialMaterialForm  `json:"form"`
	MediaType  string                  `json:"mediaType"`
	Path       CredentialProtectedPath `json:"path"`
	SHA256     string                  `json:"sha256"`
	Size       uint64                  `json:"size"`
}

func (f CredentialFile) Validate() error {
	if err := f.Projection.Validate(); err != nil {
		return err
	}
	if err := f.Form.Validate(); err != nil {
		return err
	}
	if err := validateResolvedProjectionForm(f.Projection, f.Form); err != nil {
		return err
	}
	if err := validateCanonicalContractText(f.MediaType, "credential file media type", MaxIDLength); err != nil {
		return err
	}
	if err := f.Path.Validate(); err != nil {
		return err
	}
	if err := validateCanonicalSHA256(f.SHA256, "credential file"); err != nil {
		return err
	}
	if f.Size == 0 || f.Size > MaximumBundleBinaryBytes {
		return errors.New("pki: credential file size is invalid")
	}
	return nil
}

type CredentialFilesRequest struct {
	SchemaVersion string                       `json:"schemaVersion"`
	Provider      CredentialProviderTarget     `json:"provider"`
	RequestID     CredentialExecutionRequestID `json:"requestId"`
	AssignmentID  AssignmentID                 `json:"assignmentId"`
	SlotName      CredentialSlotName           `json:"slotName"`
	Credential    ResolvedCredentialMetadata   `json:"credential"`
	Files         []CredentialFile             `json:"files"`
	Scope         CredentialOperationScope     `json:"scope"`
}

func (r *CredentialFilesRequest) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential files request destination is nil")
	}
	type wire CredentialFilesRequest
	var value wire
	if err := strictDecodeJSONObject(data, MaximumCredentialExecutionJSON, &value, "credential files request"); err != nil {
		return err
	}
	validated := CredentialFilesRequest(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*r = validated.Clone()
	return nil
}

func (r CredentialFilesRequest) Clone() CredentialFilesRequest {
	result := r
	result.Files = append([]CredentialFile(nil), r.Files...)
	return result
}

func (r CredentialFilesRequest) Validate() error {
	if err := validateExecutionEnvelope(r.SchemaVersion, r.RequestID); err != nil {
		return err
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := validateCredentialDeliveryInputs(r.AssignmentID, r.SlotName, r.Credential, r.Scope); err != nil {
		return err
	}
	if len(r.Files) == 0 || len(r.Files) > MaximumCredentialExecutionFiles {
		return errors.New("pki: credential files request is empty or exceeds limits")
	}
	seen := make(map[CredentialProtectedPath]struct{}, len(r.Files))
	for _, file := range r.Files {
		if err := file.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[file.Path]; duplicate {
			return errors.New("pki: credential files request contains a duplicate path")
		}
		seen[file.Path] = struct{}{}
	}
	return nil
}

// CredentialOperationDelivery is a strict tagged union for credential hooks
// that must execute in the same consumer process as the operation that uses
// them. Encoding and stamping are intentionally excluded because they produce
// transferable material or artifacts before the consumer operation starts.
type CredentialOperationDelivery struct {
	Capability DeliveryCapability        `json:"capability"`
	Runtime    *CredentialRuntimeRequest `json:"runtime,omitempty"`
	Files      *CredentialFilesRequest   `json:"files,omitempty"`
}

func (d *CredentialOperationDelivery) UnmarshalJSON(data []byte) error {
	if d == nil {
		return errors.New("pki: credential operation delivery destination is nil")
	}
	type wire CredentialOperationDelivery
	var value wire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialExecutionJSON, &value, "credential operation delivery",
	); err != nil {
		return err
	}
	validated := CredentialOperationDelivery(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*d = validated.Clone()
	return nil
}

func (d CredentialOperationDelivery) Clone() CredentialOperationDelivery {
	result := d
	if d.Runtime != nil {
		value := d.Runtime.Clone()
		result.Runtime = &value
	}
	if d.Files != nil {
		value := d.Files.Clone()
		result.Files = &value
	}
	return result
}

func (d CredentialOperationDelivery) Validate() error {
	switch d.Capability {
	case DeliveryCapabilityRuntime:
		if d.Runtime == nil || d.Files != nil {
			return errors.New("pki: runtime operation delivery requires exactly its runtime variant")
		}
		return d.Runtime.Validate()
	case DeliveryCapabilityFiles:
		if d.Runtime != nil || d.Files == nil {
			return errors.New("pki: files operation delivery requires exactly its files variant")
		}
		return d.Files.Validate()
	default:
		return fmt.Errorf("pki: unsupported operation delivery capability %q", d.Capability)
	}
}

func (d CredentialOperationDelivery) ProviderTarget() CredentialProviderTarget {
	if d.Runtime != nil {
		return d.Runtime.Provider
	}
	if d.Files != nil {
		return d.Files.Provider
	}
	return CredentialProviderTarget{}
}

func (d CredentialOperationDelivery) RequestID() CredentialExecutionRequestID {
	if d.Runtime != nil {
		return d.Runtime.RequestID
	}
	if d.Files != nil {
		return d.Files.RequestID
	}
	return ""
}

func (d CredentialOperationDelivery) SlotName() CredentialSlotName {
	if d.Runtime != nil {
		return d.Runtime.SlotName
	}
	if d.Files != nil {
		return d.Files.SlotName
	}
	return ""
}

type CredentialOperationDeliveries []CredentialOperationDelivery

func (deliveries CredentialOperationDeliveries) Clone() CredentialOperationDeliveries {
	result := make(CredentialOperationDeliveries, len(deliveries))
	for index := range deliveries {
		result[index] = deliveries[index].Clone()
	}
	return result
}

// Clear removes ephemeral bytes, references, and protected paths from every
// delivery in place. Callers should invoke it as soon as the consuming provider
// operation finishes.
func (deliveries CredentialOperationDeliveries) Clear() {
	for index := range deliveries {
		if deliveries[index].Runtime != nil {
			clear(deliveries[index].Runtime.Material.Data)
			if deliveries[index].Runtime.Material.Reference != nil {
				*deliveries[index].Runtime.Material.Reference = CredentialScopedReference{}
			}
		}
		if deliveries[index].Files != nil {
			for fileIndex := range deliveries[index].Files.Files {
				deliveries[index].Files.Files[fileIndex].Path = ""
			}
		}
		deliveries[index] = CredentialOperationDelivery{}
	}
	clear(deliveries)
}

func (deliveries CredentialOperationDeliveries) ValidateForModule(moduleID string) error {
	if err := validateCanonicalContractText(moduleID, "credential consumer module id", MaxIDLength); err != nil {
		return err
	}
	if len(deliveries) > MaximumCredentialOperationDeliveries {
		return fmt.Errorf(
			"pki: credential operation exceeds %d deliveries",
			MaximumCredentialOperationDeliveries,
		)
	}
	requestIDs := make(map[CredentialExecutionRequestID]struct{}, len(deliveries))
	slots := make(map[CredentialSlotName]struct{}, len(deliveries))
	for _, delivery := range deliveries {
		if err := delivery.Validate(); err != nil {
			return err
		}
		if delivery.ProviderTarget().ModuleID != moduleID {
			return errors.New("pki: operation delivery target does not match its consumer module")
		}
		requestID := delivery.RequestID()
		if _, duplicate := requestIDs[requestID]; duplicate {
			return errors.New("pki: credential operation contains a duplicate request id")
		}
		requestIDs[requestID] = struct{}{}
		slot := delivery.SlotName()
		if _, duplicate := slots[slot]; duplicate {
			return errors.New("pki: credential operation contains a duplicate slot")
		}
		slots[slot] = struct{}{}
	}
	return nil
}

type CredentialDeliveryReceipt struct {
	RequestID         CredentialExecutionRequestID `json:"requestId"`
	ProviderReference string                       `json:"providerReference,omitempty"`
	ReceiptSHA256     string                       `json:"receiptSha256,omitempty"`
}

func (r *CredentialDeliveryReceipt) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential delivery receipt destination is nil")
	}
	type wire CredentialDeliveryReceipt
	var value wire
	if err := strictDecodeJSONObject(data, MaximumCredentialExecutionJSON, &value, "credential delivery receipt"); err != nil {
		return err
	}
	validated := CredentialDeliveryReceipt(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*r = validated
	return nil
}

func (r CredentialDeliveryReceipt) Validate() error {
	if err := r.RequestID.Validate(); err != nil {
		return err
	}
	if r.ProviderReference != "" {
		if err := validateCanonicalContractText(r.ProviderReference, "credential provider reference", MaxIDLength); err != nil {
			return err
		}
	}
	if r.ReceiptSHA256 != "" {
		return validateCanonicalSHA256(r.ReceiptSHA256, "credential delivery receipt")
	}
	return nil
}

type CredentialEncodingRequest struct {
	SchemaVersion       string                       `json:"schemaVersion"`
	Provider            CredentialProviderTarget     `json:"provider"`
	RequestID           CredentialExecutionRequestID `json:"requestId"`
	ProviderID          DeliveryProviderID           `json:"providerId"`
	ProviderSchema      string                       `json:"providerSchema"`
	OutputForm          CredentialMaterialForm       `json:"outputForm"`
	MaximumEncodedBytes uint64                       `json:"maximumEncodedBytes"`
	Source              ResolvedCredentialMaterial   `json:"source"`
	Scope               CredentialOperationScope     `json:"scope"`
}

func (r *CredentialEncodingRequest) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential encoding request destination is nil")
	}
	type wire CredentialEncodingRequest
	var value wire
	if err := strictDecodeJSONObject(data, MaximumCredentialExecutionJSON, &value, "credential encoding request"); err != nil {
		return err
	}
	validated := CredentialEncodingRequest(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*r = validated.Clone()
	return nil
}

func (r CredentialEncodingRequest) Clone() CredentialEncodingRequest {
	result := r
	result.Source = r.Source.Clone()
	return result
}

func (r CredentialEncodingRequest) Validate() error {
	if err := validateExecutionEnvelope(r.SchemaVersion, r.RequestID); err != nil {
		return err
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := r.ProviderID.Validate(); err != nil {
		return err
	}
	if r.ProviderID != r.Provider.ProviderID {
		return errors.New("pki: credential encoding schema provider does not match its invocation target")
	}
	if err := validateCanonicalContractText(r.ProviderSchema, "credential provider schema", MaxIDLength); err != nil {
		return err
	}
	if err := r.OutputForm.Validate(); err != nil {
		return err
	}
	if r.MaximumEncodedBytes == 0 || r.MaximumEncodedBytes > MaximumBundleBinaryBytes {
		return errors.New("pki: credential encoding output bound is invalid")
	}
	if err := r.Source.Validate(); err != nil {
		return err
	}
	return r.Scope.Validate()
}

type CredentialEncodingResult struct {
	RequestID CredentialExecutionRequestID `json:"requestId"`
	Form      CredentialMaterialForm       `json:"form"`
	Encoding  string                       `json:"encoding"`
	SHA256    string                       `json:"sha256"`
	Data      CredentialBytes              `json:"data"`
}

func (r *CredentialEncodingResult) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential encoding result destination is nil")
	}
	type wire CredentialEncodingResult
	var value wire
	if err := strictDecodeJSONObject(data, MaximumCredentialExecutionJSON, &value, "credential encoding result"); err != nil {
		return err
	}
	validated := CredentialEncodingResult(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*r = validated.Clone()
	return nil
}

func (r CredentialEncodingResult) Clone() CredentialEncodingResult {
	result := r
	result.Data = r.Data.Clone()
	return result
}

func (r CredentialEncodingResult) Validate() error {
	if err := r.RequestID.Validate(); err != nil {
		return err
	}
	if err := r.Form.Validate(); err != nil {
		return err
	}
	if err := validateCanonicalContractText(r.Encoding, "credential encoding", MaximumCredentialEncodingBytes); err != nil {
		return err
	}
	if len(r.Data) == 0 || len(r.Data) > MaximumBundleBinaryBytes {
		return errors.New("pki: encoded credential data is empty or exceeds limits")
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
	if r.RequestID != request.RequestID || r.Form != request.OutputForm || uint64(len(r.Data)) > request.MaximumEncodedBytes {
		return errors.New("pki: credential encoding result does not match its request")
	}
	return nil
}

type CredentialArtifactInput struct {
	ID       StampReferenceID        `json:"id"`
	SHA256   string                  `json:"sha256"`
	Encoding string                  `json:"encoding"`
	Data     CredentialBytes         `json:"data,omitempty"`
	Path     CredentialProtectedPath `json:"path,omitempty"`
}

func (a CredentialArtifactInput) Clone() CredentialArtifactInput {
	result := a
	result.Data = a.Data.Clone()
	return result
}

func (a CredentialArtifactInput) Validate() error {
	if err := a.ID.Validate(); err != nil {
		return err
	}
	if err := validateCanonicalSHA256(a.SHA256, "credential stamp input"); err != nil {
		return err
	}
	if err := validateCanonicalContractText(a.Encoding, "credential artifact encoding", MaximumCredentialEncodingBytes); err != nil {
		return err
	}
	if (len(a.Data) == 0) == (a.Path == "") {
		return errors.New("pki: credential artifact input requires exactly one data or path variant")
	}
	if len(a.Data) > 0 {
		if len(a.Data) > MaximumBundleBinaryBytes {
			return errors.New("pki: credential artifact input exceeds limits")
		}
		return validateCredentialDigest(a.Data, a.SHA256, "credential stamp input")
	}
	return a.Path.Validate()
}

type CredentialArtifactOutput struct {
	Name     string                  `json:"name"`
	Encoding string                  `json:"encoding"`
	Data     CredentialBytes         `json:"data,omitempty"`
	Path     CredentialProtectedPath `json:"path,omitempty"`
}

func (a CredentialArtifactOutput) Clone() CredentialArtifactOutput {
	result := a
	result.Data = a.Data.Clone()
	return result
}

func (a CredentialArtifactOutput) Validate() error {
	if err := validateCanonicalContractText(a.Name, "credential artifact output name", MaxNameLength); err != nil {
		return err
	}
	if err := validateCanonicalContractText(a.Encoding, "credential artifact encoding", MaximumCredentialEncodingBytes); err != nil {
		return err
	}
	if (len(a.Data) == 0) == (a.Path == "") {
		return errors.New("pki: credential artifact output requires exactly one data or path variant")
	}
	if len(a.Data) > MaximumBundleBinaryBytes {
		return errors.New("pki: credential artifact output exceeds limits")
	}
	if a.Path != "" {
		return a.Path.Validate()
	}
	return nil
}

type CredentialDeploymentOutput struct {
	Reference StampReferenceID `json:"reference"`
	Receipt   CredentialBytes  `json:"receipt"`
}

func (o CredentialDeploymentOutput) Clone() CredentialDeploymentOutput {
	result := o
	result.Receipt = o.Receipt.Clone()
	return result
}

func (o CredentialDeploymentOutput) Validate() error {
	if err := o.Reference.Validate(); err != nil {
		return err
	}
	if len(o.Receipt) == 0 || len(o.Receipt) > MaximumCredentialReceiptBytes {
		return errors.New("pki: credential deployment receipt is empty or exceeds limits")
	}
	return nil
}

type CredentialStampOutput struct {
	Artifact   *CredentialArtifactOutput   `json:"artifact,omitempty"`
	Deployment *CredentialDeploymentOutput `json:"deployment,omitempty"`
}

func (o CredentialStampOutput) Clone() CredentialStampOutput {
	result := o
	if o.Artifact != nil {
		value := o.Artifact.Clone()
		result.Artifact = &value
	}
	if o.Deployment != nil {
		value := o.Deployment.Clone()
		result.Deployment = &value
	}
	return result
}

func (o CredentialStampOutput) Validate() error {
	if (o.Artifact == nil) == (o.Deployment == nil) {
		return errors.New("pki: credential stamp output requires exactly one tagged variant")
	}
	if o.Artifact != nil {
		return o.Artifact.Validate()
	}
	return o.Deployment.Validate()
}

type CredentialStampExecutionRequest struct {
	SchemaVersion   string                     `json:"schemaVersion"`
	Provider        CredentialProviderTarget   `json:"provider"`
	StampID         StampID                    `json:"stampId"`
	Request         CredentialStampRequest     `json:"request"`
	Input           CredentialArtifactInput    `json:"input"`
	Material        ResolvedCredentialMaterial `json:"resolvedMaterial"`
	ExpectedDigests []StampedMaterialDigest    `json:"expectedDigests"`
	Scope           CredentialOperationScope   `json:"scope"`
}

func (r *CredentialStampExecutionRequest) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential stamp execution request destination is nil")
	}
	type wire CredentialStampExecutionRequest
	var value wire
	if err := strictDecodeJSONObject(data, MaximumCredentialExecutionJSON, &value, "credential stamp execution request"); err != nil {
		return err
	}
	validated := CredentialStampExecutionRequest(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*r = validated.Clone()
	return nil
}

func (r CredentialStampExecutionRequest) Clone() CredentialStampExecutionRequest {
	result := r
	result.Request = r.Request.Clone()
	result.Input = r.Input.Clone()
	result.Material = r.Material.Clone()
	result.ExpectedDigests = append([]StampedMaterialDigest(nil), r.ExpectedDigests...)
	return result
}

func (r CredentialStampExecutionRequest) Validate() error {
	if err := validateSchemaVersion(r.SchemaVersion, CredentialProviderExecutionSchemaV1); err != nil {
		return err
	}
	if err := r.Provider.Validate(); err != nil {
		return err
	}
	if err := r.StampID.Validate(); err != nil {
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
	if r.Material.Projection != r.Request.Material.Projection {
		return errors.New("pki: resolved stamp material projection does not match its request")
	}
	requestedForm, err := r.Request.Material.Form()
	if err != nil {
		return err
	}
	if r.Material.Form != requestedForm {
		return errors.New("pki: resolved stamp material form does not match its request")
	}
	if err := validateExpectedMaterialDigests(r.Request.Material, r.ExpectedDigests); err != nil {
		return err
	}
	if len(r.Material.Data) > 0 && uint64(len(r.Material.Data)) != r.Request.EncodedBytes {
		return errors.New("pki: resolved stamp material size does not match its request")
	}
	if len(r.Input.Data) > MaximumBundleBinaryBytes-len(r.Material.Data) {
		return errors.New("pki: credential stamp execution binary inputs exceed limits")
	}
	return r.Scope.Validate()
}

type CredentialStampExecutionResult struct {
	StampID          StampID                 `json:"stampId"`
	Output           CredentialStampOutput   `json:"output"`
	TargetResolution StampTargetResolution   `json:"targetResolution"`
	ResolvedTarget   StampTarget             `json:"resolvedTarget"`
	BytesWritten     CanonicalUint64         `json:"bytesWritten"`
	MaterialDigests  []StampedMaterialDigest `json:"materialDigests"`
}

func (r *CredentialStampExecutionResult) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential stamp execution result destination is nil")
	}
	type wire CredentialStampExecutionResult
	var value wire
	if err := strictDecodeJSONObject(data, MaximumCredentialExecutionJSON, &value, "credential stamp execution result"); err != nil {
		return err
	}
	validated := CredentialStampExecutionResult(value)
	if err := validated.Validate(); err != nil {
		return err
	}
	*r = validated.Clone()
	return nil
}

func (r CredentialStampExecutionResult) Clone() CredentialStampExecutionResult {
	result := r
	result.Output = r.Output.Clone()
	result.ResolvedTarget = r.ResolvedTarget.Clone()
	result.MaterialDigests = append([]StampedMaterialDigest(nil), r.MaterialDigests...)
	return result
}

func (r CredentialStampExecutionResult) Validate() error {
	if err := r.StampID.Validate(); err != nil {
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
	if err != nil || bytesWritten == 0 || bytesWritten > MaximumBundleBinaryBytes {
		return errors.New("pki: credential stamp execution byte count is invalid")
	}
	if len(r.MaterialDigests) == 0 || len(r.MaterialDigests) > MaximumStampedMaterialHashes {
		return errors.New("pki: credential stamp execution digests are empty or exceed limits")
	}
	seen := make(map[string]struct{}, len(r.MaterialDigests))
	for _, digest := range r.MaterialDigests {
		if err := digest.Validate(); err != nil {
			return err
		}
		key := stampedMaterialKey(digest.Projection, digest.Reference)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("pki: credential stamp execution digests contain a duplicate")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (r CredentialStampExecutionResult) ValidateFor(request CredentialStampExecutionRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.StampID != request.StampID {
		return errors.New("pki: credential stamp execution result id does not match its request")
	}
	bytesWritten, err := r.BytesWritten.Uint64()
	if err != nil {
		return fmt.Errorf("pki: credential stamp execution byte count: %w", err)
	}
	if bytesWritten != request.Request.EncodedBytes {
		return errors.New("pki: credential stamp execution byte count does not match its request")
	}
	if err := validateTargetResolution(request.Request.Target, r.ResolvedTarget, r.TargetResolution); err != nil {
		return err
	}
	if len(request.ExpectedDigests) != len(r.MaterialDigests) {
		return errors.New("pki: credential stamp execution digest set does not match its request")
	}
	for _, expected := range request.ExpectedDigests {
		if !slices.ContainsFunc(r.MaterialDigests, func(digest StampedMaterialDigest) bool {
			return digest == expected
		}) {
			return fmt.Errorf("pki: credential stamp execution omits expected material digest %q", expected.Reference)
		}
	}
	return nil
}

func validateExpectedMaterialDigests(
	material StampMaterial,
	digests []StampedMaterialDigest,
) error {
	required := requiredMaterialDigestReferences(material)
	if len(digests) == 0 || len(digests) != len(required) || len(digests) > MaximumStampedMaterialHashes {
		return errors.New("pki: expected material digests do not exactly match the stamp material")
	}
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if err := digest.Validate(); err != nil {
			return err
		}
		key := stampedMaterialKey(digest.Projection, digest.Reference)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("pki: expected material digests contain a duplicate")
		}
		seen[key] = struct{}{}
	}
	for _, reference := range required {
		if _, exists := seen[stampedMaterialKey(reference.Projection, reference.Reference)]; !exists {
			return fmt.Errorf("pki: expected material digests omit reference %q", reference.Reference)
		}
	}
	return nil
}

func validateExecutionEnvelope(schemaVersion string, requestID CredentialExecutionRequestID) error {
	if err := validateSchemaVersion(schemaVersion, CredentialProviderExecutionSchemaV1); err != nil {
		return err
	}
	return requestID.Validate()
}

func validateCredentialDeliveryInputs(
	assignmentID AssignmentID,
	slotName CredentialSlotName,
	credential ResolvedCredentialMetadata,
	scope CredentialOperationScope,
) error {
	if err := assignmentID.Validate(); err != nil {
		return err
	}
	if err := slotName.Validate(); err != nil {
		return err
	}
	if err := credential.Validate(); err != nil {
		return err
	}
	return scope.Validate()
}

func validateCredentialDigest(data []byte, digest, name string) error {
	if err := validateCanonicalSHA256(digest, name); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != strings.ToLower(digest) {
		return fmt.Errorf("pki: %s sha256 does not match its bytes", name)
	}
	return nil
}
