package pki

import (
	"errors"
	"fmt"
	"slices"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

// RolloverReservationAction identifies a mutation against state reserved by a
// live authority rollover. It is intentionally narrower than MutationKind so
// persistence adapters can enforce the same durable policy.
type RolloverReservationAction string

const (
	RolloverReservationTrustSetStage      RolloverReservationAction = "trust-set-stage"
	RolloverReservationTrustSetActivate   RolloverReservationAction = "trust-set-activate"
	RolloverReservationAssignmentBind     RolloverReservationAction = "assignment-bind"
	RolloverReservationAssignmentStage    RolloverReservationAction = "assignment-stage"
	RolloverReservationAssignmentActivate RolloverReservationAction = "assignment-activate"
	RolloverReservationAssignmentUnbind   RolloverReservationAction = "assignment-unbind"
)

func (a RolloverReservationAction) Validate() error {
	switch a {
	case RolloverReservationTrustSetStage,
		RolloverReservationTrustSetActivate,
		RolloverReservationAssignmentBind,
		RolloverReservationAssignmentStage,
		RolloverReservationAssignmentActivate,
		RolloverReservationAssignmentUnbind:
		return nil
	default:
		return fmt.Errorf("pki: unsupported rollover reservation action %q", a)
	}
}

// RejectRolloverReservedMutation returns the stable reservation error for a
// mutation that has no valid operation-scoped exception.
func RejectRolloverReservedMutation(
	operation domainpki.Operation,
	action RolloverReservationAction,
) error {
	if _, err := liveRolloverReservation(operation, action); err != nil {
		return err
	}
	return reservedRolloverResourceError(operation, action)
}

// ValidateRolloverTrustSetReservation permits only final-trust staging while a
// rollover is awaiting leaf rotation. Dedicated rollover commits own overlap
// and final activation.
func ValidateRolloverTrustSetReservation(
	operation domainpki.Operation,
	action RolloverReservationAction,
	previous domainpki.TrustSet,
	next domainpki.TrustSet,
	generation domainpki.TrustSetGeneration,
) error {
	rollover, err := liveRolloverReservation(operation, action)
	if err != nil {
		return err
	}
	if action != RolloverReservationTrustSetStage ||
		rollover.Phase != domainpki.AuthorityRolloverPhaseAwaitingLeafRotation {
		return reservedRolloverResourceError(operation, action)
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if previous.ID != rollover.TrustSetID || next.ID != previous.ID ||
		previous.Name != next.Name || !previous.CreatedAt.Equal(next.CreatedAt) ||
		previous.ActiveGenerationID != rollover.OverlapTrustGenerationID ||
		next.ActiveGenerationID != previous.ActiveGenerationID ||
		previous.StagedGenerationID != "" || next.StagedGenerationID != generation.ID ||
		generation.TrustSetID != next.ID || previous.State != domainpki.TrustSetStateActive ||
		next.State != previous.State || previous.Revision == domainpki.MaximumSequenceNumber ||
		next.Revision != previous.Revision+1 || next.UpdatedAt.Before(previous.UpdatedAt) {
		return reservedRolloverResourceError(operation, action)
	}
	return nil
}

// ValidateRolloverAssignmentReservation permits a required consumer to stage
// and activate only a replacement-issued leaf bound to overlap trust while the
// operation is in its leaf-rotation phase.
func ValidateRolloverAssignmentReservation(
	operation domainpki.Operation,
	action RolloverReservationAction,
	previous domainpki.Assignment,
	next domainpki.Assignment,
	generation domainpki.CertificateGeneration,
) error {
	rollover, err := liveRolloverReservation(operation, action)
	if err != nil {
		return err
	}
	if rollover.Phase != domainpki.AuthorityRolloverPhaseAwaitingLeafRotation ||
		!slices.Contains(rollover.RequiredAssignmentIDs, next.ID) {
		return reservedRolloverResourceError(operation, action)
	}
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if previous.ID != next.ID || previous.TrustSetID != rollover.TrustSetID ||
		next.TrustSetID != rollover.TrustSetID || next.UpdatedAt.Before(previous.UpdatedAt) ||
		generation.IssuerAuthorityID != rollover.ReplacementAuthorityID ||
		generation.IssuerGenerationID != rollover.ReplacementAuthorityGenerationID {
		return reservedRolloverResourceError(operation, action)
	}

	switch action {
	case RolloverReservationAssignmentStage:
		if previous.StagedGenerationID == "" && previous.StagedTrustGenerationID == "" &&
			next.ActiveGenerationID == previous.ActiveGenerationID &&
			next.ActiveTrustGenerationID == previous.ActiveTrustGenerationID &&
			next.State == previous.State && next.StagedGenerationID == generation.ID &&
			next.StagedTrustGenerationID == rollover.OverlapTrustGenerationID {
			return nil
		}
	case RolloverReservationAssignmentActivate:
		if previous.StagedGenerationID == generation.ID &&
			previous.StagedTrustGenerationID == rollover.OverlapTrustGenerationID &&
			next.ActiveGenerationID == previous.StagedGenerationID &&
			next.ActiveTrustGenerationID == previous.StagedTrustGenerationID &&
			next.StagedGenerationID == "" && next.StagedTrustGenerationID == "" &&
			next.State == domainpki.AssignmentStateActive {
			return nil
		}
	}
	return reservedRolloverResourceError(operation, action)
}

func liveRolloverReservation(
	operation domainpki.Operation,
	action RolloverReservationAction,
) (*domainpki.AuthorityRollover, error) {
	if err := action.Validate(); err != nil {
		return nil, err
	}
	if err := operation.Validate(); err != nil {
		return nil, fmt.Errorf("pki: validate rollover reservation operation: %w", err)
	}
	if operation.Kind != domainpki.OperationKindAuthorityRollover ||
		operation.Status != domainpki.OperationStatusWaiting || operation.AuthorityRollover == nil {
		return nil, errors.New("pki: rollover reservation operation is not live")
	}
	return operation.AuthorityRollover, nil
}

func reservedRolloverResourceError(
	operation domainpki.Operation,
	action RolloverReservationAction,
) error {
	return NewRolloverPreconditionError(
		RolloverPreconditionResourceReserved,
		fmt.Sprintf("operation %q reserves this resource against %s", operation.ID, action),
	)
}
