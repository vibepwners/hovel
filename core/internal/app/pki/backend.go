package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const MaximumEncodedKeyBytes = 1 << 20

const (
	MaximumExternalKeyHandleBytes    = 4096
	MaximumExternalKeyCapabilities   = 64
	MaximumCRLValidationMessageBytes = 1024
)

type ExternalKeyHandle struct {
	BackendID    domainpki.BackendID `json:"backendId"`
	Handle       string              `json:"handle"`
	Capabilities []string            `json:"capabilities"`
}

func (h ExternalKeyHandle) Clone() ExternalKeyHandle {
	result := h
	result.Capabilities = append([]string(nil), h.Capabilities...)
	return result
}

func (h ExternalKeyHandle) Validate() error {
	if err := h.BackendID.Validate(); err != nil {
		return err
	}
	if h.Handle == "" || h.Handle != strings.TrimSpace(h.Handle) || len(h.Handle) > MaximumExternalKeyHandleBytes || strings.ContainsAny(h.Handle, "\x00\r\n") {
		return errors.New("pki: external key handle is not canonical")
	}
	if len(h.Capabilities) == 0 || len(h.Capabilities) > MaximumExternalKeyCapabilities {
		return errors.New("pki: external key capabilities have an invalid count")
	}
	seen := make(map[string]struct{}, len(h.Capabilities))
	for _, capability := range h.Capabilities {
		if capability == "" || capability != strings.TrimSpace(capability) || len(capability) > domainpki.MaxIDLength || strings.ContainsAny(capability, "\x00\r\n") {
			return errors.New("pki: external key capability is not canonical")
		}
		if _, exists := seen[capability]; exists {
			return fmt.Errorf("pki: duplicate external key capability %q", capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

type KeyMaterial struct {
	ID              domainpki.KeyID        `json:"keyId"`
	Algorithm       domainpki.KeyAlgorithm `json:"algorithm"`
	PublicKeySPKI   []byte                 `json:"publicKeySpki"`
	PrivateKeyPKCS8 []byte                 `json:"privateKeyPkcs8,omitempty"`
	ExternalHandle  *ExternalKeyHandle     `json:"externalKeyHandle,omitempty"`
}

func (m KeyMaterial) Clone() KeyMaterial {
	result := m
	result.PublicKeySPKI = append([]byte(nil), m.PublicKeySPKI...)
	result.PrivateKeyPKCS8 = append([]byte(nil), m.PrivateKeyPKCS8...)
	if m.ExternalHandle != nil {
		handle := m.ExternalHandle.Clone()
		result.ExternalHandle = &handle
	}
	return result
}

func (m KeyMaterial) Validate() error {
	if err := m.ID.Validate(); err != nil {
		return err
	}
	switch m.Algorithm {
	case domainpki.KeyAlgorithmECDSA, domainpki.KeyAlgorithmRSA, domainpki.KeyAlgorithmEd25519,
		domainpki.KeyAlgorithmMLDSA44, domainpki.KeyAlgorithmMLDSA65, domainpki.KeyAlgorithmMLDSA87:
	default:
		return errors.New("pki: supported key material algorithm is required")
	}
	if len(m.PublicKeySPKI) == 0 {
		return errors.New("pki: key public material is required")
	}
	if (len(m.PrivateKeyPKCS8) == 0) == (m.ExternalHandle == nil) {
		return errors.New("pki: key material requires exactly one local private key or external handle")
	}
	if m.ExternalHandle != nil {
		if err := m.ExternalHandle.Validate(); err != nil {
			return err
		}
	}
	if len(m.PublicKeySPKI) > MaximumEncodedKeyBytes || len(m.PrivateKeyPKCS8) > MaximumEncodedKeyBytes {
		return fmt.Errorf("pki: encoded key material exceeds %d bytes", MaximumEncodedKeyBytes)
	}
	return nil
}

// ValidatedKeyMaterial is key material that passed an independent validator
// for its declared key specification. Its fields are intentionally private so
// persistence adapters cannot be handed merely shape-valid key bytes.
type ValidatedKeyMaterial struct {
	material KeyMaterial
}

func ValidateKeyMaterial(ctx context.Context, validator Validator, spec domainpki.KeySpec, material KeyMaterial) (ValidatedKeyMaterial, error) {
	if validator == nil {
		return ValidatedKeyMaterial{}, errors.New("pki: key validator is required")
	}
	material = material.Clone()
	if err := material.Validate(); err != nil {
		return ValidatedKeyMaterial{}, err
	}
	if err := validator.ValidateKey(ctx, KeyValidationRequest{Spec: spec, Material: material}); err != nil {
		return ValidatedKeyMaterial{}, fmt.Errorf("pki: key validation failed: %w", err)
	}
	return ValidatedKeyMaterial{material: material}, nil
}

func (m ValidatedKeyMaterial) Material() KeyMaterial {
	return m.material.Clone()
}

func (m *ValidatedKeyMaterial) Clear() {
	if m == nil {
		return
	}
	clear(m.material.PublicKeySPKI)
	clear(m.material.PrivateKeyPKCS8)
	m.material = KeyMaterial{}
}

func (m ValidatedKeyMaterial) Matches(expected KeyMaterial) bool {
	return KeyMaterialsEqual(m.material, expected)
}

func KeyMaterialsEqual(left, right KeyMaterial) bool {
	return left.ID == right.ID && left.Algorithm == right.Algorithm &&
		bytes.Equal(left.PublicKeySPKI, right.PublicKeySPKI) &&
		bytes.Equal(left.PrivateKeyPKCS8, right.PrivateKeyPKCS8) && externalKeyHandlesEqual(left.ExternalHandle, right.ExternalHandle)
}

func externalKeyHandlesEqual(left, right *ExternalKeyHandle) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.BackendID == right.BackendID && left.Handle == right.Handle && slices.Equal(left.Capabilities, right.Capabilities)
}

func ValidateGenerationKeyBinding(generation domainpki.CertificateGeneration, material KeyMaterial) error {
	if generation.KeyID != material.ID || generation.Template.Key.Algorithm != material.Algorithm ||
		!bytes.Equal(generation.PublicKeySPKI, material.PublicKeySPKI) {
		return errors.New("pki: certificate generation and key material do not match")
	}
	return nil
}

func ValidateBackendKeyIdentity(backendID domainpki.BackendID, material KeyMaterial) error {
	if err := backendID.Validate(); err != nil {
		return err
	}
	if material.ExternalHandle != nil && material.ExternalHandle.BackendID != backendID {
		return fmt.Errorf("pki: external key handle backend %q does not match selected backend %q", material.ExternalHandle.BackendID, backendID)
	}
	return nil
}

type IssueRequest struct {
	Template             domainpki.CertificateTemplate
	SubjectPublicKeySPKI []byte
	IssuerCertificateDER []byte
	Signer               KeyMaterial
}

type IssuedCertificate struct {
	CertificateDER     []byte
	PublicKeySPKI      []byte
	FingerprintSHA256  string
	SubjectKeyID       []byte
	AuthorityKeyID     []byte
	SignatureAlgorithm domainpki.SignatureAlgorithm
}

type CRLEntry struct {
	RevocationID domainpki.RevocationID     `json:"revocationId"`
	SerialNumber domainpki.SerialNumber     `json:"serialNumber"`
	RevokedAt    time.Time                  `json:"revokedAt"`
	Reason       domainpki.RevocationReason `json:"reason"`
}

func (e CRLEntry) Validate() error {
	if err := e.RevocationID.Validate(); err != nil {
		return err
	}
	if _, err := e.SerialNumber.Bytes(); err != nil {
		return err
	}
	if e.RevokedAt.IsZero() || e.RevokedAt != e.RevokedAt.UTC().Truncate(time.Second) {
		return errors.New("pki: crl entry revocation time is not canonical")
	}
	return e.Reason.Validate()
}

type CRLIssueRequest struct {
	Number               uint64                       `json:"number"`
	ThisUpdate           time.Time                    `json:"thisUpdate"`
	NextUpdate           time.Time                    `json:"nextUpdate"`
	Entries              []CRLEntry                   `json:"entries"`
	SignatureAlgorithm   domainpki.SignatureAlgorithm `json:"signatureAlgorithm"`
	IssuerCertificateDER []byte                       `json:"issuerCertificateDer"`
	Signer               KeyMaterial                  `json:"signer"`
}

func (r CRLIssueRequest) Clone() CRLIssueRequest {
	result := r
	result.Entries = append([]CRLEntry(nil), r.Entries...)
	result.IssuerCertificateDER = append([]byte(nil), r.IssuerCertificateDER...)
	result.Signer = r.Signer.Clone()
	return result
}

func (r CRLIssueRequest) Validate() error {
	if err := r.ValidationRequest().Validate(); err != nil {
		return err
	}
	if err := r.Signer.Validate(); err != nil {
		return err
	}
	if !r.SignatureAlgorithm.CompatibleWith(r.Signer.Algorithm) {
		return errors.New("pki: crl signature algorithm is incompatible with its signer")
	}
	return nil
}

// ValidationRequest returns the public, independently cloneable CRL contract.
// It intentionally excludes signing key material and provider-private handles.
func (r CRLIssueRequest) ValidationRequest() CRLValidationRequest {
	return CRLValidationRequest{
		Number:               r.Number,
		ThisUpdate:           r.ThisUpdate,
		NextUpdate:           r.NextUpdate,
		Entries:              append([]CRLEntry(nil), r.Entries...),
		SignatureAlgorithm:   r.SignatureAlgorithm,
		IssuerCertificateDER: append([]byte(nil), r.IssuerCertificateDER...),
	}
}

// CRLValidationRequest is the public expectation passed across the independent
// validator trust boundary. It cannot expose authority key material.
type CRLValidationRequest struct {
	Number               uint64                       `json:"number"`
	ThisUpdate           time.Time                    `json:"thisUpdate"`
	NextUpdate           time.Time                    `json:"nextUpdate"`
	Entries              []CRLEntry                   `json:"entries"`
	SignatureAlgorithm   domainpki.SignatureAlgorithm `json:"signatureAlgorithm"`
	IssuerCertificateDER []byte                       `json:"issuerCertificateDer"`
}

func (r CRLValidationRequest) Clone() CRLValidationRequest {
	result := r
	result.Entries = append([]CRLEntry(nil), r.Entries...)
	result.IssuerCertificateDER = append([]byte(nil), r.IssuerCertificateDER...)
	return result
}

func (r CRLValidationRequest) Validate() error {
	if r.Number == 0 || r.Number > domainpki.MaximumSequenceNumber {
		return errors.New("pki: crl validation number is outside the supported range")
	}
	validity := r.NextUpdate.Sub(r.ThisUpdate)
	if r.ThisUpdate.IsZero() || r.NextUpdate.IsZero() ||
		r.ThisUpdate != r.ThisUpdate.UTC().Truncate(time.Second) ||
		r.NextUpdate != r.NextUpdate.UTC().Truncate(time.Second) ||
		validity < domainpki.MinimumCRLValidity || validity > domainpki.MaximumCRLValidity {
		return errors.New("pki: crl validation update window is invalid")
	}
	if len(r.Entries) > domainpki.MaximumCRLRevocations {
		return errors.New("pki: crl validation has too many entries")
	}
	for index, entry := range r.Entries {
		if err := entry.Validate(); err != nil {
			return err
		}
		if entry.RevokedAt.After(r.ThisUpdate) {
			return errors.New("pki: crl entry postdates thisUpdate")
		}
		if index > 0 && r.Entries[index-1].RevocationID >= entry.RevocationID {
			return errors.New("pki: crl entries must be unique and sorted by revocation id")
		}
	}
	if len(r.IssuerCertificateDER) == 0 || len(r.IssuerCertificateDER) > domainpki.MaximumCertificateDERBytes {
		return errors.New("pki: crl issuer certificate der is empty or too large")
	}
	if err := r.SignatureAlgorithm.Validate(); err != nil {
		return err
	}
	return nil
}

type IssuedCRL struct {
	CRLDER               []byte                       `json:"crlDer"`
	FingerprintSHA256    string                       `json:"fingerprintSha256"`
	SignatureAlgorithm   domainpki.SignatureAlgorithm `json:"signatureAlgorithm"`
	ProviderOperationRef ProviderOperationRef         `json:"providerOperationRef,omitempty"`
}

func (c IssuedCRL) Clone() IssuedCRL {
	result := c
	result.CRLDER = append([]byte(nil), c.CRLDER...)
	return result
}

func (c IssuedCRL) Validate() error {
	if len(c.CRLDER) == 0 || len(c.CRLDER) > domainpki.MaximumCRLDERBytes {
		return errors.New("pki: issued crl der is empty or too large")
	}
	if err := c.SignatureAlgorithm.Validate(); err != nil {
		return err
	}
	if err := c.ProviderOperationRef.Validate(); err != nil {
		return err
	}
	digest := sha256.Sum256(c.CRLDER)
	if c.FingerprintSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("pki: issued crl fingerprint does not match its der")
	}
	return nil
}

// CRLIssuer is an optional backend capability. Backends only implement it
// when their descriptor advertises SupportsCRL.
type CRLIssuer interface {
	IssueCRL(context.Context, CRLIssueRequest) (IssuedCRL, error)
}

type CRLValidationDecision string

const (
	CRLValidationDecisionAccepted CRLValidationDecision = "accepted"
	CRLValidationDecisionRejected CRLValidationDecision = "rejected"
)

func (d CRLValidationDecision) Validate() error {
	switch d {
	case CRLValidationDecisionAccepted, CRLValidationDecisionRejected:
		return nil
	default:
		return fmt.Errorf("pki: unsupported crl validation decision %q", d)
	}
}

type CRLValidationRejectionCode string

const CRLValidationRejectionInvalidCRL CRLValidationRejectionCode = "invalid-crl"

func (c CRLValidationRejectionCode) Validate() error {
	if c != CRLValidationRejectionInvalidCRL {
		return fmt.Errorf("pki: unsupported crl validation rejection code %q", c)
	}
	return nil
}

type CRLValidationRejection struct {
	Code    CRLValidationRejectionCode `json:"code"`
	Message string                     `json:"message"`
}

func (r CRLValidationRejection) Validate() error {
	if err := r.Code.Validate(); err != nil {
		return err
	}
	if r.Message == "" || r.Message != strings.TrimSpace(r.Message) ||
		len(r.Message) > MaximumCRLValidationMessageBytes || strings.IndexFunc(r.Message, unicode.IsControl) >= 0 {
		return errors.New("pki: crl validation rejection message is not canonical")
	}
	return nil
}

type CRLValidationResult struct {
	Decision  CRLValidationDecision   `json:"decision"`
	Accepted  *IssuedCRL              `json:"accepted,omitempty"`
	Rejection *CRLValidationRejection `json:"rejection,omitempty"`
}

func NewAcceptedCRLValidation(issued IssuedCRL) (CRLValidationResult, error) {
	issued = issued.Clone()
	result := CRLValidationResult{Decision: CRLValidationDecisionAccepted, Accepted: &issued}
	if err := result.Validate(); err != nil {
		return CRLValidationResult{}, err
	}
	return result, nil
}

func NewRejectedCRLValidation(
	code CRLValidationRejectionCode,
	message string,
) (CRLValidationResult, error) {
	rejection := CRLValidationRejection{Code: code, Message: message}
	result := CRLValidationResult{Decision: CRLValidationDecisionRejected, Rejection: &rejection}
	if err := result.Validate(); err != nil {
		return CRLValidationResult{}, err
	}
	return result, nil
}

func (r CRLValidationResult) Clone() CRLValidationResult {
	result := r
	if r.Accepted != nil {
		accepted := r.Accepted.Clone()
		result.Accepted = &accepted
	}
	if r.Rejection != nil {
		rejection := *r.Rejection
		result.Rejection = &rejection
	}
	return result
}

func (r CRLValidationResult) Validate() error {
	if err := r.Decision.Validate(); err != nil {
		return err
	}
	switch r.Decision {
	case CRLValidationDecisionAccepted:
		if r.Accepted == nil || r.Rejection != nil {
			return errors.New("pki: accepted crl validation requires only an accepted result")
		}
		return r.Accepted.Validate()
	case CRLValidationDecisionRejected:
		if r.Accepted != nil || r.Rejection == nil {
			return errors.New("pki: rejected crl validation requires only a rejection")
		}
		return r.Rejection.Validate()
	default:
		return errors.New("pki: invalid crl validation result")
	}
}

// CRLValidator independently parses and verifies backend-issued CRL bytes.
// A semantic rejection is a typed result; errors are operational and retryable.
type CRLValidator interface {
	ValidateCRL(context.Context, CRLValidationRequest, []byte) (CRLValidationResult, error)
}

func (c IssuedCertificate) Clone() IssuedCertificate {
	result := c
	result.CertificateDER = append([]byte(nil), c.CertificateDER...)
	result.PublicKeySPKI = append([]byte(nil), c.PublicKeySPKI...)
	result.SubjectKeyID = append([]byte(nil), c.SubjectKeyID...)
	result.AuthorityKeyID = append([]byte(nil), c.AuthorityKeyID...)
	return result
}

type Backend interface {
	Descriptor() domainpki.BackendDescriptor
	GenerateKey(context.Context, domainpki.KeyID, domainpki.KeySpec) (KeyMaterial, error)
	Issue(context.Context, IssueRequest) (IssuedCertificate, error)
}

type BackendRegistry interface {
	ResolveBackend(context.Context, domainpki.BackendID) (Backend, error)
	BackendDescriptors(context.Context) ([]domainpki.BackendDescriptor, error)
}

type StaticBackendRegistry struct {
	backends map[domainpki.BackendID]Backend
}

func NewStaticBackendRegistry(backends ...Backend) (StaticBackendRegistry, error) {
	if len(backends) == 0 {
		return StaticBackendRegistry{}, errors.New("pki: at least one crypto backend is required")
	}
	registry := StaticBackendRegistry{backends: make(map[domainpki.BackendID]Backend, len(backends))}
	for _, backend := range backends {
		if backend == nil {
			return StaticBackendRegistry{}, errors.New("pki: crypto backend is required")
		}
		descriptor := backend.Descriptor()
		if err := descriptor.Validate(); err != nil {
			return StaticBackendRegistry{}, fmt.Errorf("pki: validate crypto backend descriptor: %w", err)
		}
		if _, exists := registry.backends[descriptor.ID]; exists {
			return StaticBackendRegistry{}, fmt.Errorf("pki: duplicate crypto backend %q", descriptor.ID)
		}
		registry.backends[descriptor.ID] = backend
	}
	return registry, nil
}

func (r StaticBackendRegistry) ResolveBackend(ctx context.Context, id domainpki.BackendID) (Backend, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	backend, ok := r.backends[id]
	if !ok {
		return nil, fmt.Errorf("pki: crypto backend %q is unavailable", id)
	}
	descriptor := backend.Descriptor()
	if err := descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("pki: validate crypto backend %q: %w", id, err)
	}
	if descriptor.ID != id {
		return nil, errors.New("pki: crypto backend descriptor identity changed")
	}
	return backend, nil
}

func (r StaticBackendRegistry) BackendDescriptors(ctx context.Context) ([]domainpki.BackendDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]domainpki.BackendDescriptor, 0, len(r.backends))
	for id, backend := range r.backends {
		descriptor := backend.Descriptor()
		if err := descriptor.Validate(); err != nil {
			return nil, fmt.Errorf("pki: validate crypto backend %q: %w", id, err)
		}
		if descriptor.ID != id {
			return nil, errors.New("pki: crypto backend descriptor identity changed")
		}
		result = append(result, descriptor.Clone())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

var _ BackendRegistry = StaticBackendRegistry{}

type ValidationRequest struct {
	Template             domainpki.CertificateTemplate
	CertificateDER       []byte
	SubjectPublicKeySPKI []byte
	IssuerCertificateDER []byte
}

type KeyValidationRequest struct {
	Spec     domainpki.KeySpec
	Material KeyMaterial
}

type Validator interface {
	ValidateKey(context.Context, KeyValidationRequest) error
	ValidateIssued(context.Context, ValidationRequest) (IssuedCertificate, error)
	ValidateBundle(context.Context, domainpki.Bundle, time.Time) error
}

type ValidatorRegistry interface {
	ResolveValidator(context.Context, domainpki.BackendID) (Validator, error)
}

type StaticValidatorRegistry struct {
	validators map[domainpki.BackendID]Validator
}

func NewStaticValidatorRegistry(validators map[domainpki.BackendID]Validator) (StaticValidatorRegistry, error) {
	if len(validators) == 0 {
		return StaticValidatorRegistry{}, errors.New("pki: at least one independent backend validator is required")
	}
	registry := StaticValidatorRegistry{validators: make(map[domainpki.BackendID]Validator, len(validators))}
	for id, validator := range validators {
		if err := id.Validate(); err != nil {
			return StaticValidatorRegistry{}, err
		}
		if validator == nil {
			return StaticValidatorRegistry{}, fmt.Errorf("pki: validator for backend %q is required", id)
		}
		registry.validators[id] = validator
	}
	return registry, nil
}

func (r StaticValidatorRegistry) ResolveValidator(ctx context.Context, id domainpki.BackendID) (Validator, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	validator, exists := r.validators[id]
	if !exists {
		return nil, fmt.Errorf("pki: independent validator for backend %q is unavailable", id)
	}
	return validator, nil
}

var _ ValidatorRegistry = StaticValidatorRegistry{}
