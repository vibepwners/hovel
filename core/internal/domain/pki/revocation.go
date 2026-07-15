package pki

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"
)

// RevocationReason is an RFC 5280 reason that can invalidate a certificate.
// removeFromCRL is intentionally absent because it is a later unhold/delta-CRL
// transition, not a reason to create a revocation.
type RevocationReason string

const (
	RevocationReasonUnspecified          RevocationReason = "unspecified"
	RevocationReasonKeyCompromise        RevocationReason = "key-compromise"
	RevocationReasonCACompromise         RevocationReason = "ca-compromise"
	RevocationReasonAffiliationChanged   RevocationReason = "affiliation-changed"
	RevocationReasonSuperseded           RevocationReason = "superseded"
	RevocationReasonCessationOfOperation RevocationReason = "cessation-of-operation"
	RevocationReasonCertificateHold      RevocationReason = "certificate-hold"
	RevocationReasonPrivilegeWithdrawn   RevocationReason = "privilege-withdrawn"
	RevocationReasonAACompromise         RevocationReason = "aa-compromise"
)

func (r RevocationReason) Validate() error {
	switch r {
	case RevocationReasonUnspecified, RevocationReasonKeyCompromise,
		RevocationReasonCACompromise, RevocationReasonAffiliationChanged,
		RevocationReasonSuperseded, RevocationReasonCessationOfOperation,
		RevocationReasonCertificateHold, RevocationReasonPrivilegeWithdrawn,
		RevocationReasonAACompromise:
		return nil
	default:
		return fmt.Errorf("pki: unsupported revocation reason %q", r)
	}
}

// Revocation records why and when one immutable certificate generation was
// invalidated. PreviousState preserves whether the generation was active,
// superseded, or expired before revocation.
type Revocation struct {
	ID                 RevocationID     `json:"id"`
	CertificateID      CertificateID    `json:"certificateId"`
	GenerationID       GenerationID     `json:"generationId"`
	IssuerAuthorityID  AuthorityID      `json:"issuerAuthorityId"`
	IssuerGenerationID GenerationID     `json:"issuerGenerationId"`
	SerialNumber       SerialNumber     `json:"serialNumber"`
	Reason             RevocationReason `json:"reason"`
	PreviousState      CertificateState `json:"previousState"`
	EffectiveAt        time.Time        `json:"effectiveAt"`
	RecordedAt         time.Time        `json:"recordedAt"`
}

type RevocationArgs Revocation

func NewRevocation(args RevocationArgs) (Revocation, error) {
	if err := args.ID.Validate(); err != nil {
		return Revocation{}, err
	}
	if err := args.CertificateID.Validate(); err != nil {
		return Revocation{}, err
	}
	if err := args.GenerationID.Validate(); err != nil {
		return Revocation{}, err
	}
	if err := args.IssuerAuthorityID.Validate(); err != nil {
		return Revocation{}, err
	}
	if err := args.IssuerGenerationID.Validate(); err != nil {
		return Revocation{}, err
	}
	if _, err := args.SerialNumber.Bytes(); err != nil {
		return Revocation{}, err
	}
	if err := args.Reason.Validate(); err != nil {
		return Revocation{}, err
	}
	if !revocableCertificateState(args.PreviousState) {
		return Revocation{}, fmt.Errorf("pki: certificate state %q cannot be revoked", args.PreviousState)
	}
	effectiveAt := args.EffectiveAt.UTC().Truncate(time.Second)
	recordedAt := args.RecordedAt.UTC().Truncate(time.Second)
	if effectiveAt.IsZero() || recordedAt.IsZero() || effectiveAt.After(recordedAt) {
		return Revocation{}, errors.New("pki: revocation times are invalid")
	}
	return Revocation{
		ID: args.ID, CertificateID: args.CertificateID, GenerationID: args.GenerationID,
		IssuerAuthorityID: args.IssuerAuthorityID, IssuerGenerationID: args.IssuerGenerationID,
		SerialNumber: args.SerialNumber, Reason: args.Reason, PreviousState: args.PreviousState,
		EffectiveAt: effectiveAt, RecordedAt: recordedAt,
	}, nil
}

func (r Revocation) Validate() error {
	normalized, err := NewRevocation(RevocationArgs(r))
	if err != nil {
		return err
	}
	if normalized != r {
		return errors.New("pki: revocation is not canonical")
	}
	return nil
}

func RevokeCertificateGeneration(
	generation CertificateGeneration,
	id RevocationID,
	reason RevocationReason,
	effectiveAt time.Time,
	recordedAt time.Time,
) (CertificateGeneration, Revocation, error) {
	if err := generation.Validate(); err != nil {
		return CertificateGeneration{}, Revocation{}, err
	}
	if !revocableCertificateState(generation.State) {
		return CertificateGeneration{}, Revocation{}, fmt.Errorf("pki: certificate generation cannot be revoked while %s", generation.State)
	}
	if generation.IssuerAuthorityID == "" || generation.IssuerGenerationID == "" {
		return CertificateGeneration{}, Revocation{}, errors.New("pki: a self-signed root must be distrusted, not revoked")
	}
	if effectiveAt.Before(generation.Template.NotBefore) {
		return CertificateGeneration{}, Revocation{}, errors.New("pki: revocation cannot predate certificate validity")
	}
	revocation, err := NewRevocation(RevocationArgs{
		ID: id, CertificateID: generation.CertificateID, GenerationID: generation.ID,
		IssuerAuthorityID: generation.IssuerAuthorityID, IssuerGenerationID: generation.IssuerGenerationID,
		SerialNumber: generation.Template.SerialNumber, Reason: reason, PreviousState: generation.State,
		EffectiveAt: effectiveAt, RecordedAt: recordedAt,
	})
	if err != nil {
		return CertificateGeneration{}, Revocation{}, err
	}
	revoked := generation.Clone()
	revoked.State = CertificateStateRevoked
	if err := revoked.Validate(); err != nil {
		return CertificateGeneration{}, Revocation{}, err
	}
	return revoked, revocation, nil
}

// ValidateRevocationTransition verifies that persistence was given the exact
// state transition and immutable record derived from the current generation.
func ValidateRevocationTransition(current, revoked CertificateGeneration, revocation Revocation) error {
	expectedGeneration, expectedRevocation, err := RevokeCertificateGeneration(
		current, revocation.ID, revocation.Reason, revocation.EffectiveAt, revocation.RecordedAt,
	)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expectedGeneration, revoked) || expectedRevocation != revocation {
		return errors.New("pki: revocation transition does not match the current certificate generation")
	}
	return nil
}

// ApplyGenerationRevocation updates one assignment affected by a revoked
// generation. Serving assignments degrade; staged-only references are cleared.
func ApplyGenerationRevocation(assignment Assignment, generationID GenerationID, updatedAt time.Time) (Assignment, bool, error) {
	if err := assignment.Validate(); err != nil {
		return Assignment{}, false, err
	}
	if err := generationID.Validate(); err != nil {
		return Assignment{}, false, err
	}
	if assignment.State == AssignmentStateDisabled || assignment.State == AssignmentStateRetired {
		return assignment, false, nil
	}
	activeAffected := assignment.ActiveGenerationID == generationID
	stagedAffected := assignment.StagedGenerationID == generationID
	if !activeAffected && !stagedAffected {
		return assignment, false, nil
	}
	if assignment.Revision == MaximumSequenceNumber {
		return Assignment{}, false, errors.New("pki: assignment revision is exhausted")
	}
	updated := assignment
	if activeAffected {
		updated.State = AssignmentStateDegraded
	}
	if stagedAffected {
		updated.StagedGenerationID = ""
		updated.StagedTrustGenerationID = ""
	}
	updated.Revision++
	updated.UpdatedAt = updatedAt.UTC()
	if err := updated.Validate(); err != nil {
		return Assignment{}, false, err
	}
	return updated, true, nil
}

// ValidateGenerationRevocationAssignments verifies the complete assignment
// impact set derived from an atomic inventory snapshot.
func ValidateGenerationRevocationAssignments(
	current []Assignment,
	generationID GenerationID,
	updatedAt time.Time,
	updates []Assignment,
) error {
	expected := make([]Assignment, 0, len(updates))
	for _, assignment := range current {
		updated, changed, err := ApplyGenerationRevocation(assignment, generationID, updatedAt)
		if err != nil {
			return err
		}
		if changed {
			expected = append(expected, updated)
		}
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i].ID < expected[j].ID })
	if !reflect.DeepEqual(expected, updates) {
		return errors.New("pki: revocation assignment updates do not match the current inventory")
	}
	return nil
}

func revocableCertificateState(state CertificateState) bool {
	switch state {
	case CertificateStateActive, CertificateStateSuperseded, CertificateStateExpired:
		return true
	default:
		return false
	}
}
