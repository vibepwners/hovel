package pki

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// TrustMaterial is the complete immutable material referenced by one trust-set generation.
type TrustMaterial struct {
	Certificates []CertificateGeneration
	CRLs         []CRLGeneration
}

// ValidateTrustSetGenerationMaterial verifies certificate usability, CRL freshness,
// and exact membership for a trust-set generation at a caller-supplied instant.
func ValidateTrustSetGenerationMaterial(
	generation TrustSetGeneration,
	material TrustMaterial,
	now time.Time,
) error {
	if err := generation.Validate(); err != nil {
		return err
	}
	if now.IsZero() || now != now.UTC() {
		return errors.New("pki: trust material validation time must be canonical utc")
	}
	referencedCertificates := make(map[GenerationID]struct{},
		len(generation.AnchorGenerationIDs)+len(generation.IntermediateGenerationIDs))
	for _, id := range generation.AnchorGenerationIDs {
		referencedCertificates[id] = struct{}{}
	}
	for _, id := range generation.IntermediateGenerationIDs {
		referencedCertificates[id] = struct{}{}
	}
	certificates := make(map[GenerationID]CertificateGeneration, len(material.Certificates))
	for _, certificate := range material.Certificates {
		if err := certificate.Validate(); err != nil {
			return fmt.Errorf("pki: validate trust certificate generation %q: %w", certificate.ID, err)
		}
		if _, referenced := referencedCertificates[certificate.ID]; !referenced {
			return fmt.Errorf("pki: unreferenced trust certificate generation %q", certificate.ID)
		}
		if _, duplicate := certificates[certificate.ID]; duplicate {
			return fmt.Errorf("pki: duplicate trust certificate generation %q", certificate.ID)
		}
		if !certificate.Template.BasicConstraints.IsCA {
			return fmt.Errorf("pki: trust certificate generation %q is not a certificate authority", certificate.ID)
		}
		if certificate.State != CertificateStateActive && certificate.State != CertificateStateSuperseded {
			return fmt.Errorf("pki: trust certificate generation %q is not usable", certificate.ID)
		}
		if now.Before(certificate.Template.NotBefore) || !now.Before(certificate.Template.NotAfter) {
			return fmt.Errorf("pki: trust certificate generation %q is not currently valid", certificate.ID)
		}
		certificates[certificate.ID] = certificate.Clone()
	}
	if len(certificates) != len(referencedCertificates) {
		return errors.New("pki: trust certificate material is incomplete")
	}

	referencedCRLs := make(map[CRLGenerationID]struct{}, len(generation.CRLGenerationIDs))
	for _, id := range generation.CRLGenerationIDs {
		referencedCRLs[id] = struct{}{}
	}
	crls := make(map[CRLGenerationID]struct{}, len(material.CRLs))
	for _, crl := range material.CRLs {
		if err := crl.Validate(); err != nil {
			return fmt.Errorf("pki: validate trust crl generation %q: %w", crl.ID, err)
		}
		if _, referenced := referencedCRLs[crl.ID]; !referenced {
			return fmt.Errorf("pki: unreferenced trust crl generation %q", crl.ID)
		}
		if _, duplicate := crls[crl.ID]; duplicate {
			return fmt.Errorf("pki: duplicate trust crl generation %q", crl.ID)
		}
		if !crl.FreshAt(now) {
			return fmt.Errorf("pki: trust crl generation %q is not fresh", crl.ID)
		}
		if _, trusted := referencedCertificates[crl.IssuerGenerationID]; !trusted {
			return fmt.Errorf("pki: trust crl generation %q issuer is not in the trust generation", crl.ID)
		}
		crls[crl.ID] = struct{}{}
	}
	if len(crls) != len(referencedCRLs) {
		return errors.New("pki: trust crl material is incomplete")
	}
	return nil
}

// ValidateAuthorityRolloverOverlapMaterial verifies usable overlap trust and
// proves that both authority generations terminate at a configured anchor.
func ValidateAuthorityRolloverOverlapMaterial(
	generation TrustSetGeneration,
	previous Authority,
	replacement Authority,
	previousGeneration CertificateGeneration,
	replacementGeneration CertificateGeneration,
	material TrustMaterial,
	now time.Time,
) error {
	if err := ValidateAuthorityRolloverOverlapTrust(generation, previous, replacement); err != nil {
		return err
	}
	if err := ValidateTrustSetGenerationMaterial(generation, material, now); err != nil {
		return err
	}
	certificates := trustCertificateMap(material.Certificates)
	if err := validateRolloverAuthorityGeneration(
		generation, previous, previousGeneration, certificates, true,
	); err != nil {
		return fmt.Errorf("pki: validate previous rollover authority chain: %w", err)
	}
	if err := validateRolloverAuthorityGeneration(
		generation, replacement, replacementGeneration, certificates, true,
	); err != nil {
		return fmt.Errorf("pki: validate replacement rollover authority chain: %w", err)
	}
	return nil
}

// ValidateAuthorityRolloverFinalMaterial verifies usable final trust and proves
// that the replacement authority generation terminates at a configured anchor.
func ValidateAuthorityRolloverFinalMaterial(
	generation TrustSetGeneration,
	previous Authority,
	replacement Authority,
	previousGeneration CertificateGeneration,
	replacementGeneration CertificateGeneration,
	material TrustMaterial,
	now time.Time,
) error {
	if err := ValidateAuthorityRolloverFinalTrust(generation, previous, replacement); err != nil {
		return err
	}
	if err := ValidateTrustSetGenerationMaterial(generation, material, now); err != nil {
		return err
	}
	if err := validateAuthorityGenerationSnapshot(previous, previousGeneration); err != nil {
		return fmt.Errorf("pki: validate previous rollover authority generation: %w", err)
	}
	if err := validateRolloverAuthorityGeneration(
		generation, replacement, replacementGeneration, trustCertificateMap(material.Certificates), true,
	); err != nil {
		return fmt.Errorf("pki: validate replacement rollover authority chain: %w", err)
	}
	return nil
}

func trustCertificateMap(certificates []CertificateGeneration) map[GenerationID]CertificateGeneration {
	result := make(map[GenerationID]CertificateGeneration, len(certificates))
	for _, certificate := range certificates {
		result[certificate.ID] = certificate
	}
	return result
}

func validateAuthorityGenerationSnapshot(authority Authority, generation CertificateGeneration) error {
	if err := authority.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if generation.ID != authority.ActiveGenerationID || generation.OwningAuthorityID != authority.ID ||
		!generation.Template.BasicConstraints.IsCA ||
		(generation.State != CertificateStateActive && generation.State != CertificateStateSuperseded) {
		return errors.New("pki: authority certificate generation does not match its active usable snapshot")
	}
	return nil
}

func validateRolloverAuthorityGeneration(
	trust TrustSetGeneration,
	authority Authority,
	generation CertificateGeneration,
	certificates map[GenerationID]CertificateGeneration,
	requireTrusted bool,
) error {
	if err := validateAuthorityGenerationSnapshot(authority, generation); err != nil {
		return err
	}
	trusted, wrong := authorityTrustCollections(trust, authority.Role)
	if requireTrusted && (!slices.Contains(trusted, generation.ID) || slices.Contains(wrong, generation.ID)) {
		return errors.New("pki: authority generation is not in the role-appropriate trust collection")
	}
	if authority.Role == AuthorityRoleRoot {
		if generation.IssuerAuthorityID != "" || generation.IssuerGenerationID != "" ||
			len(generation.ChainGenerationIDs) != 0 {
			return errors.New("pki: root authority generation has a non-root issuer chain")
		}
		return nil
	}
	if generation.IssuerAuthorityID != authority.ParentAuthorityID || generation.IssuerGenerationID == "" ||
		len(generation.ChainGenerationIDs) == 0 || generation.ChainGenerationIDs[0] != generation.IssuerGenerationID {
		return errors.New("pki: subordinate authority generation does not identify its parent chain")
	}

	anchors := make(map[GenerationID]struct{}, len(trust.AnchorGenerationIDs))
	for _, id := range trust.AnchorGenerationIDs {
		anchors[id] = struct{}{}
	}
	intermediates := make(map[GenerationID]struct{}, len(trust.IntermediateGenerationIDs))
	for _, id := range trust.IntermediateGenerationIDs {
		intermediates[id] = struct{}{}
	}
	current := generation
	for index, parentID := range generation.ChainGenerationIDs {
		parent, exists := certificates[parentID]
		if !exists {
			return fmt.Errorf("pki: authority chain generation %q is missing from trust material", parentID)
		}
		if current.IssuerGenerationID != parent.ID || current.IssuerAuthorityID != parent.OwningAuthorityID {
			return errors.New("pki: authority chain issuer identity is inconsistent")
		}
		if !slices.Equal(current.ChainGenerationIDs, generation.ChainGenerationIDs[index:]) {
			return errors.New("pki: authority chain lineage is inconsistent")
		}
		last := index == len(generation.ChainGenerationIDs)-1
		if last {
			if _, anchored := anchors[parent.ID]; !anchored {
				return errors.New("pki: authority chain does not terminate at a trust anchor")
			}
		} else if _, intermediate := intermediates[parent.ID]; !intermediate {
			return errors.New("pki: authority chain member is not a trusted intermediate")
		}
		current = parent
	}
	return nil
}
