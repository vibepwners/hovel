package pki

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const credentialRuntimeAccessPurpose = "credential-runtime-delivery"

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
	cleanup := func() {}
	if ctx == nil {
		return nil, cleanup, errors.New("pki: credential operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, cleanup, err
	}
	if s.credentialUse == nil {
		return nil, cleanup, errors.New("pki: credential use authorizer is not configured")
	}
	if err := provider.Validate(); err != nil {
		return nil, cleanup, err
	}
	if err := descriptor.Validate(); err != nil {
		return nil, cleanup, err
	}
	descriptorDigest, err := descriptor.DigestSHA256()
	if err != nil {
		return nil, cleanup, err
	}
	if descriptorDigest != provider.DescriptorSHA256 {
		return nil, cleanup, errors.New(
			"pki: credential provider target does not match its delivery descriptor",
		)
	}
	if err := selections.Validate(); err != nil {
		return nil, cleanup, err
	}
	if err := scope.Validate(); err != nil {
		return nil, cleanup, err
	}
	if len(selections) == 0 {
		return nil, cleanup, nil
	}
	if len(consumers) == 0 {
		return nil, cleanup, errors.New("pki: credential operation has no allowed consumers")
	}
	for _, consumer := range consumers {
		if err := consumer.Validate(); err != nil {
			return nil, cleanup, err
		}
	}

	deliveries := make(domainpki.CredentialOperationDeliveries, 0, len(selections))
	cleanup = func() { deliveries.Clear() }
	for _, selection := range selections {
		delivery, err := s.resolveCredentialSelection(
			ctx,
			provider,
			descriptor,
			selection,
			scope,
			consumers,
		)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		deliveries = append(deliveries, delivery)
	}
	if err := deliveries.ValidateForModule(provider.ModuleID); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return deliveries, cleanup, nil
}

func (s Service) resolveCredentialSelection(
	ctx context.Context,
	provider domainpki.CredentialProviderTarget,
	descriptor domainpki.CredentialDeliveryDescriptor,
	selection domainpki.CredentialSelection,
	scope domainpki.CredentialOperationScope,
	consumers []domainpki.CredentialConsumerBinding,
) (domainpki.CredentialOperationDelivery, error) {
	if err := s.credentialUse.AuthorizeCredentialUse(ctx, selection.AssignmentID); err != nil {
		return domainpki.CredentialOperationDelivery{}, fmt.Errorf(
			"pki: authorize credential use: %w",
			err,
		)
	}
	inspection, err := s.InspectAssignment(ctx, selection.AssignmentID)
	if err != nil {
		return domainpki.CredentialOperationDelivery{}, err
	}
	assignment := inspection.Assignment
	if !slices.ContainsFunc(consumers, func(binding domainpki.CredentialConsumerBinding) bool {
		return binding.Matches(assignment)
	}) {
		return domainpki.CredentialOperationDelivery{}, errors.New(
			"pki: credential assignment is not bound to this operation",
		)
	}
	switch assignment.State {
	case domainpki.AssignmentStateActive, domainpki.AssignmentStateDegraded:
	case domainpki.AssignmentStatePending, domainpki.AssignmentStateDisabled,
		domainpki.AssignmentStateRetired:
		return domainpki.CredentialOperationDelivery{}, fmt.Errorf(
			"pki: credential assignment is not usable while %s",
			assignment.State,
		)
	default:
		return domainpki.CredentialOperationDelivery{}, fmt.Errorf(
			"pki: credential assignment has unsupported state %q",
			assignment.State,
		)
	}
	if inspection.ActiveGeneration == nil {
		return domainpki.CredentialOperationDelivery{}, errors.New(
			"pki: credential assignment has no active certificate generation",
		)
	}
	generation := inspection.ActiveGeneration.Clone()
	if assignment.ActiveGenerationID != generation.ID {
		return domainpki.CredentialOperationDelivery{}, errors.New(
			"pki: credential assignment active generation does not match its inventory",
		)
	}
	if err := validateAssignmentGeneration(assignment, generation); err != nil {
		return domainpki.CredentialOperationDelivery{}, err
	}

	metadata := domainpki.ResolvedCredentialMetadata{
		BundleVersion:         domainpki.BundleSchemaV1,
		Purpose:               assignment.Purpose,
		ConsumerType:          assignment.ConsumerType,
		ProfileID:             generation.ProfileID,
		CompatibilityTargetID: generation.CompatibilityTargetID,
	}
	material, err := s.resolveCredentialSelectionMaterial(ctx, generation, selection.Material)
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

func (s Service) resolveCredentialSelectionMaterial(
	ctx context.Context,
	generation domainpki.CertificateGeneration,
	selection domainpki.CredentialMaterialSelection,
) (domainpki.ResolvedCredentialMaterial, error) {
	var data []byte
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
	case domainpki.CredentialProjectionBundle,
		domainpki.CredentialProjectionChainDER,
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
		Encoding:   domainpki.EncodingBase64DER,
		SHA256:     hex.EncodeToString(digest[:]),
		Data:       domainpki.CredentialBytes(data),
	}
	if err := material.Validate(); err != nil {
		clear(data)
		return domainpki.ResolvedCredentialMaterial{}, err
	}
	return material, nil
}
