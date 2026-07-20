package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const credentialRuntimeAccessPurpose = "credential-runtime-delivery"

var ErrCredentialOperationLeaseClosed = errors.New("pki: credential operation lease is closed")

type credentialAssignmentSnapshot struct {
	assignment domainpki.Assignment
	generation domainpki.CertificateGeneration
}

// CredentialOperationLease owns ephemeral credential deliveries resolved from
// one checked assignment snapshot. BorrowedDeliveries returns the lease-owned
// slice without copying secret material; callers must not retain or mutate it
// and must close the lease after the provider operation finishes.
type CredentialOperationLease struct {
	mu         sync.Mutex
	service    Service
	deliveries domainpki.CredentialOperationDeliveries
	snapshots  []*credentialAssignmentSnapshot
	consumers  []domainpki.CredentialConsumerBinding
	closed     bool
}

// BorrowedDeliveries returns the lease-owned deliveries without copying their
// secret material. The returned data remains valid only until Close or Clear.
func (l *CredentialOperationLease) BorrowedDeliveries() (
	domainpki.CredentialOperationDeliveries,
	error,
) {
	if l == nil {
		return nil, errors.New("pki: credential operation lease is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, ErrCredentialOperationLeaseClosed
	}
	return l.deliveries, nil
}

// Revalidate confirms that every assignment still has the exact authorized
// revision, state, active generation, and certificate validity captured during
// resolution. Call this immediately before credential delivery.
func (l *CredentialOperationLease) Revalidate(ctx context.Context) error {
	if l == nil {
		return errors.New("pki: credential operation lease is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrCredentialOperationLeaseClosed
	}
	return l.service.revalidateCredentialOperation(ctx, l.snapshots, l.consumers)
}

// Close clears all lease-owned secret material. It is safe to call repeatedly.
func (l *CredentialOperationLease) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.deliveries.Clear()
	l.deliveries = nil
	clear(l.snapshots)
	l.snapshots = nil
	l.consumers = nil
	l.service = Service{}
	l.closed = true
}

// Clear is an alias for Close for code that treats the lease as secret data.
func (l *CredentialOperationLease) Clear() {
	l.Close()
}

// ResolveCredentialOperation resolves non-secret assignment selections into
// ephemeral runtime deliveries for one exact provider process. Callers must
// invoke the cleanup function after the provider operation returns.
func (s Service) ResolveCredentialOperation(
	ctx context.Context,
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
	consumers []domainpki.CredentialConsumerBinding,
) (domainpki.CredentialOperationDeliveries, func(), error) {
	lease, err := s.ResolveCredentialOperationLease(
		ctx,
		provider,
		descriptor,
		selections,
		scope,
		consumers,
	)
	if err != nil {
		return nil, func() {}, err
	}
	deliveries, err := lease.BorrowedDeliveries()
	if err != nil {
		lease.Close()
		return nil, func() {}, err
	}
	return deliveries, lease.Close, nil
}

// ResolveCredentialOperationLease resolves every unique assignment once,
// materializes all requested slots from those snapshots, and returns the
// lease that must be revalidated immediately before provider delivery.
func (s Service) ResolveCredentialOperationLease(
	ctx context.Context,
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
	consumers []domainpki.CredentialConsumerBinding,
) (*CredentialOperationLease, error) {
	if err := s.validateCredentialOperationRequest(
		ctx,
		provider,
		descriptor,
		selections,
		scope,
		consumers,
	); err != nil {
		return nil, err
	}

	lease := &CredentialOperationLease{
		service:    s,
		deliveries: make(domainpki.CredentialOperationDeliveries, 0, len(selections)),
		snapshots:  make([]*credentialAssignmentSnapshot, 0, len(selections)),
		consumers:  append([]domainpki.CredentialConsumerBinding(nil), consumers...),
	}
	if len(selections) == 0 {
		return lease, nil
	}

	snapshots := make(map[domainpki.AssignmentID]*credentialAssignmentSnapshot, len(selections))
	for _, selection := range selections {
		if _, exists := snapshots[selection.AssignmentID]; exists {
			continue
		}
		snapshot, err := s.resolveCredentialAssignmentSnapshot(
			ctx,
			selection.AssignmentID,
			consumers,
		)
		if err != nil {
			lease.Close()
			return nil, err
		}
		snapshots[selection.AssignmentID] = snapshot
		lease.snapshots = append(lease.snapshots, snapshot)
	}

	for _, selection := range selections {
		delivery, err := s.resolveCredentialSelection(
			ctx,
			provider,
			descriptor,
			selection,
			scope,
			snapshots[selection.AssignmentID],
		)
		if err != nil {
			lease.Close()
			return nil, err
		}
		lease.deliveries = append(lease.deliveries, delivery)
	}
	if err := lease.deliveries.ValidateForModule(provider.ModuleID); err != nil {
		lease.Close()
		return nil, err
	}
	if err := lease.Revalidate(ctx); err != nil {
		lease.Close()
		return nil, err
	}
	return lease, nil
}

func (s Service) validateCredentialOperationRequest(
	ctx context.Context,
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selections domainpki.CredentialSelections,
	scope domainpki.CredentialOperationScope,
	consumers []domainpki.CredentialConsumerBinding,
) error {
	if ctx == nil {
		return errors.New("pki: credential operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.credentialUse == nil {
		return errors.New("pki: credential use authorizer is not configured")
	}
	if s.clock == nil {
		return errors.New("pki: credential operation clock is not configured")
	}
	if err := provider.Validate(); err != nil {
		return err
	}
	if err := descriptor.Validate(); err != nil {
		return err
	}
	descriptorDigest, err := descriptor.DigestSHA256()
	if err != nil {
		return err
	}
	if descriptorDigest != provider.DescriptorSHA256 {
		return errors.New(
			"pki: credential provider target does not match its delivery descriptor",
		)
	}
	if err := selections.Validate(); err != nil {
		return err
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	if len(selections) == 0 {
		return nil
	}
	if len(consumers) == 0 {
		return errors.New("pki: credential operation has no allowed consumers")
	}
	for _, consumer := range consumers {
		if err := consumer.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) resolveCredentialAssignmentSnapshot(
	ctx context.Context,
	assignmentID domainpki.AssignmentID,
	consumers []domainpki.CredentialConsumerBinding,
) (*credentialAssignmentSnapshot, error) {
	if err := s.credentialUse.AuthorizeCredentialUse(ctx, assignmentID); err != nil {
		return nil, fmt.Errorf(
			"pki: authorize credential use: %w",
			err,
		)
	}
	inspection, err := s.InspectAssignment(ctx, assignmentID)
	if err != nil {
		return nil, err
	}
	assignment := inspection.Assignment
	if !slices.ContainsFunc(consumers, func(binding domainpki.CredentialConsumerBinding) bool {
		return binding.Matches(assignment)
	}) {
		return nil, errors.New(
			"pki: credential assignment is not bound to this operation",
		)
	}
	if err := validateCredentialAssignmentState(assignment); err != nil {
		return nil, err
	}
	if inspection.ActiveGeneration == nil {
		return nil, errors.New(
			"pki: credential assignment has no active certificate generation",
		)
	}
	generation := inspection.ActiveGeneration.Clone()
	if assignment.ActiveGenerationID != generation.ID {
		return nil, errors.New(
			"pki: credential assignment active generation does not match its inventory",
		)
	}
	if err := validateAssignmentGenerationAt(assignment, generation, s.clock.Now().UTC()); err != nil {
		return nil, err
	}
	return &credentialAssignmentSnapshot{
		assignment: assignment,
		generation: generation,
	}, nil
}

func validateCredentialAssignmentState(assignment domainpki.Assignment) error {
	switch assignment.State {
	case domainpki.AssignmentStateActive, domainpki.AssignmentStateDegraded:
	case domainpki.AssignmentStatePending, domainpki.AssignmentStateDisabled,
		domainpki.AssignmentStateRetired:
		return fmt.Errorf(
			"pki: credential assignment is not usable while %s",
			assignment.State,
		)
	default:
		return fmt.Errorf(
			"pki: credential assignment has unsupported state %q",
			assignment.State,
		)
	}
	return nil
}

func (s Service) resolveCredentialSelection(
	ctx context.Context,
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selection domainpki.CredentialSelection,
	scope domainpki.CredentialOperationScope,
	snapshot *credentialAssignmentSnapshot,
) (domainpki.CredentialOperationDelivery, error) {
	if snapshot == nil {
		return domainpki.CredentialOperationDelivery{}, errors.New(
			"pki: credential assignment snapshot is required",
		)
	}
	assignment := snapshot.assignment
	generation := snapshot.generation

	metadata := domainpki.ResolvedCredentialMetadata{
		BundleVersion:         domainpki.BundleSchemaV1,
		Purpose:               assignment.Purpose,
		ConsumerType:          assignment.ConsumerType,
		ProfileID:             generation.ProfileID,
		CompatibilityTargetID: generation.CompatibilityTargetID,
	}
	material, err := s.resolveCredentialSelectionMaterial(
		ctx,
		assignment.ID,
		generation,
		selection.Material,
	)
	if err != nil {
		return domainpki.CredentialOperationDelivery{}, err
	}
	request := domainpki.CredentialRuntimeRequest{
		SchemaVersion: domainpki.CredentialProviderExecutionSchemaV1,
		Provider:      provider,
		RequestID:     selection.RequestID,
		AssignmentID:  assignment.ID,
		SlotName:      selection.SlotName,
		Credential:    metadata,
		Material:      material,
		Scope:         scope,
	}
	if err := descriptor.ValidateRuntimeRequest(request); err != nil {
		clear(request.Material.Data)
		return domainpki.CredentialOperationDelivery{}, err
	}
	return domainpki.CredentialOperationDelivery{
		Capability: domainpki.DeliveryCapabilityRuntime,
		Runtime:    &request,
	}, nil
}

func (s Service) revalidateCredentialOperation(
	ctx context.Context,
	snapshots []*credentialAssignmentSnapshot,
	consumers []domainpki.CredentialConsumerBinding,
) error {
	if ctx == nil {
		return errors.New("pki: credential operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.credentialUse == nil {
		return errors.New("pki: credential use authorizer is not configured")
	}
	if s.clock == nil {
		return errors.New("pki: credential operation clock is not configured")
	}
	now := s.clock.Now().UTC()
	for _, snapshot := range snapshots {
		if snapshot == nil {
			return errors.New("pki: credential assignment snapshot is required")
		}
		assignmentID := snapshot.assignment.ID
		if err := s.credentialUse.AuthorizeCredentialUse(ctx, assignmentID); err != nil {
			return fmt.Errorf("pki: reauthorize credential use: %w", err)
		}
		inspection, err := s.InspectAssignment(ctx, assignmentID)
		if err != nil {
			return fmt.Errorf("pki: revalidate credential assignment: %w", err)
		}
		assignment := inspection.Assignment
		if assignment != snapshot.assignment {
			return fmt.Errorf(
				"pki: credential assignment %q changed after resolution",
				assignmentID,
			)
		}
		if err := validateCredentialAssignmentState(assignment); err != nil {
			return err
		}
		if !slices.ContainsFunc(consumers, func(binding domainpki.CredentialConsumerBinding) bool {
			return binding.Matches(assignment)
		}) {
			return errors.New("pki: credential assignment authorization changed after resolution")
		}
		if inspection.ActiveGeneration == nil {
			return errors.New("pki: credential assignment lost its active certificate generation")
		}
		generation := *inspection.ActiveGeneration
		if assignment.ActiveGenerationID != snapshot.generation.ID ||
			!sameCredentialGenerationSnapshot(generation, snapshot.generation) {
			return fmt.Errorf(
				"pki: credential assignment %q active generation changed after resolution",
				assignmentID,
			)
		}
		if err := validateAssignmentGenerationAt(assignment, generation, now); err != nil {
			return err
		}
	}
	return nil
}

func sameCredentialGenerationSnapshot(
	current domainpki.CertificateGeneration,
	snapshot domainpki.CertificateGeneration,
) bool {
	return current.ID == snapshot.ID &&
		current.CertificateID == snapshot.CertificateID &&
		current.Generation == snapshot.Generation &&
		current.KeyID == snapshot.KeyID &&
		current.ProfileID == snapshot.ProfileID &&
		current.Purpose == snapshot.Purpose &&
		current.State == snapshot.State &&
		current.FingerprintSHA256 == snapshot.FingerprintSHA256 &&
		current.Template.NotBefore.Equal(snapshot.Template.NotBefore) &&
		current.Template.NotAfter.Equal(snapshot.Template.NotAfter) &&
		bytes.Equal(current.CertificateDER, snapshot.CertificateDER) &&
		bytes.Equal(current.PublicKeySPKI, snapshot.PublicKeySPKI)
}

func (s Service) resolveCredentialSelectionMaterial(
	ctx context.Context,
	assignmentID domainpki.AssignmentID,
	generation domainpki.CertificateGeneration,
	selection domainpki.CredentialMaterialSelection,
) (domainpki.ResolvedCredentialMaterial, error) {
	var data []byte
	encoding := domainpki.EncodingBase64DER
	switch selection.Projection {
	case domainpki.CredentialProjectionCertificateDER:
		data = append([]byte(nil), generation.CertificateDER...)
	case domainpki.CredentialProjectionPublicKeySPKI:
		data = append([]byte(nil), generation.PublicKeySPKI...)
	case domainpki.CredentialProjectionPrivateKeyPKCS8:
		validated, err := s.accessKey(ctx, generation, credentialRuntimeAccessPurpose)
		if err != nil {
			return domainpki.ResolvedCredentialMaterial{}, err
		}
		defer validated.Clear()
		key := validated.Material()
		defer clear(key.PrivateKeyPKCS8)
		if key.ExternalHandle != nil {
			return domainpki.ResolvedCredentialMaterial{}, errors.New(
				"pki: runtime private-key byte delivery is unavailable for externally held keys",
			)
		}
		data = append([]byte(nil), key.PrivateKeyPKCS8...)
	case domainpki.CredentialProjectionBundle:
		if selection.Form == domainpki.CredentialMaterialPrivateReference {
			return domainpki.ResolvedCredentialMaterial{}, errors.New(
				"pki: runtime bundle delivery does not support an outer private reference",
			)
		}
		bundle, err := s.resolveRuntimeCredentialBundle(
			ctx,
			assignmentID,
			generation,
			selection.Form == domainpki.CredentialMaterialPrivateBytes,
		)
		if err != nil {
			return domainpki.ResolvedCredentialMaterial{}, err
		}
		data, err = json.Marshal(bundle)
		bundle.Clear()
		if err != nil {
			return domainpki.ResolvedCredentialMaterial{}, fmt.Errorf(
				"pki: encode runtime credential bundle: %w",
				err,
			)
		}
		encoding = domainpki.EncodingJSON
	case domainpki.CredentialProjectionChainDER,
		domainpki.CredentialProjectionTrustDER,
		domainpki.CredentialProjectionCRLDER,
		domainpki.CredentialProjectionSignerReference,
		domainpki.CredentialProjectionProviderEncoding,
		domainpki.CredentialProjectionLiteralReference:
		return domainpki.ResolvedCredentialMaterial{}, fmt.Errorf(
			"pki: runtime credential projection %q is not implemented",
			selection.Projection,
		)
	default:
		return domainpki.ResolvedCredentialMaterial{}, fmt.Errorf(
			"pki: unsupported runtime credential projection %q",
			selection.Projection,
		)
	}
	if len(data) == 0 {
		return domainpki.ResolvedCredentialMaterial{}, errors.New(
			"pki: resolved credential material is empty",
		)
	}
	digest := sha256.Sum256(data)
	material := domainpki.ResolvedCredentialMaterial{
		Projection: selection.Projection,
		Form:       selection.Form,
		Encoding:   encoding,
		SHA256:     hex.EncodeToString(digest[:]),
		Data:       domainpki.CredentialBytes(data),
	}
	if err := material.Validate(); err != nil {
		clear(data)
		return domainpki.ResolvedCredentialMaterial{}, err
	}
	return material, nil
}

func (s Service) resolveRuntimeCredentialBundle(
	ctx context.Context,
	assignmentID domainpki.AssignmentID,
	generation domainpki.CertificateGeneration,
	includePrivate bool,
) (result domainpki.Bundle, resultErr error) {
	defer func() {
		if resultErr != nil {
			result.Clear()
		}
	}()
	certificate, err := domainpki.NewBinary(
		domainpki.MediaTypeCertificate,
		generation.CertificateDER,
	)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	publicKey, err := domainpki.NewBinary(
		domainpki.MediaTypePublicKey,
		generation.PublicKeySPKI,
	)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	var privateKey *domainpki.Binary
	if includePrivate {
		validated, accessErr := s.accessKey(ctx, generation, credentialRuntimeAccessPurpose)
		if accessErr != nil {
			return domainpki.Bundle{}, accessErr
		}
		defer validated.Clear()
		key := validated.Material()
		defer key.Clear()
		if key.ExternalHandle != nil {
			return domainpki.Bundle{}, errors.New(
				"pki: runtime private bundle delivery is unavailable for externally held keys",
			)
		}
		binary, binaryErr := domainpki.NewBinary(
			domainpki.MediaTypePrivateKey,
			key.PrivateKeyPKCS8,
		)
		if binaryErr != nil {
			return domainpki.Bundle{}, binaryErr
		}
		privateKey = &binary
	}
	chain, trust, err := s.bundleChain(ctx, generation)
	if err != nil {
		return domainpki.Bundle{}, err
	}
	publicDigest := sha256.Sum256(generation.PublicKeySPKI)
	bundleIDDigest := sha256.Sum256([]byte(
		"hovel.pki.runtime-bundle/v1\x00" + string(assignmentID) + "\x00" + string(generation.ID),
	))
	bundleID := domainpki.BundleID("runtime-bundle-" + hex.EncodeToString(bundleIDDigest[:]))
	result, err = domainpki.NewBundle(domainpki.BundleArgs{
		SchemaVersion:           domainpki.BundleSchemaV1,
		ID:                      bundleID,
		AssignmentID:            assignmentID,
		CertificateID:           generation.CertificateID,
		CertificateGenerationID: generation.ID,
		Generation:              generation.Generation,
		Purpose:                 generation.Purpose,
		CompatibilityTargetID:   generation.CompatibilityTargetID,
		CompatibilityVersion:    generation.CompatibilityVersion,
		KeyEstablishmentPolicy:  generation.KeyEstablishment,
		TLSNamedGroups:          generation.TLSNamedGroups,
		Certificate:             certificate,
		PublicKey:               publicKey,
		PrivateKey:              privateKey,
		Chain:                   chain,
		TrustAnchors:            trust,
		Fingerprints: domainpki.Fingerprints{
			CertificateSHA256: generation.FingerprintSHA256,
			PublicKeySHA256:   hex.EncodeToString(publicDigest[:]),
		},
		NotBefore: generation.Template.NotBefore,
		NotAfter:  generation.Template.NotAfter,
	})
	if err != nil {
		return domainpki.Bundle{}, err
	}
	validator, err := s.validators.ResolveValidator(ctx, generation.BackendID)
	if err != nil {
		return result, err
	}
	if err := validator.ValidateBundle(ctx, result, s.clock.Now().UTC()); err != nil {
		return result, fmt.Errorf("pki: verify runtime credential bundle: %w", err)
	}
	return result, nil
}
