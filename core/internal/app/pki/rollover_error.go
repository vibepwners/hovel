package pki

import (
	"fmt"
	"strings"
)

// RolloverPreconditionReason is a stable, machine-readable reason that an
// authority rollover cannot advance.
type RolloverPreconditionReason string

const (
	RolloverPreconditionWrongPhase              RolloverPreconditionReason = "wrong-phase"
	RolloverPreconditionMissingAcknowledgements RolloverPreconditionReason = "missing-acknowledgements"
	RolloverPreconditionTrustChanged            RolloverPreconditionReason = "trust-changed"
	RolloverPreconditionAssignmentsNotRotated   RolloverPreconditionReason = "assignments-not-rotated"
	RolloverPreconditionAuthorityChanged        RolloverPreconditionReason = "authority-changed"
	RolloverPreconditionAssignmentIneligible    RolloverPreconditionReason = "assignment-ineligible"
	RolloverPreconditionTrustLayoutInvalid      RolloverPreconditionReason = "trust-layout-invalid"
	RolloverPreconditionResourceReserved        RolloverPreconditionReason = "resource-reserved"
)

func (r RolloverPreconditionReason) Validate() error {
	switch r {
	case RolloverPreconditionWrongPhase,
		RolloverPreconditionMissingAcknowledgements,
		RolloverPreconditionTrustChanged,
		RolloverPreconditionAssignmentsNotRotated,
		RolloverPreconditionAuthorityChanged,
		RolloverPreconditionAssignmentIneligible,
		RolloverPreconditionTrustLayoutInvalid,
		RolloverPreconditionResourceReserved:
		return nil
	default:
		return fmt.Errorf("pki: unsupported rollover precondition reason %q", r)
	}
}

// RolloverPreconditionError reports a stable reason plus human-readable
// context. errors.Is compares reasons; errors.As exposes the detail.
type RolloverPreconditionError struct {
	Reason RolloverPreconditionReason `json:"reason"`
	Detail string                     `json:"detail"`
}

func NewRolloverPreconditionError(
	reason RolloverPreconditionReason,
	detail string,
) error {
	if err := reason.Validate(); err != nil {
		return err
	}
	return &RolloverPreconditionError{Reason: reason, Detail: strings.TrimSpace(detail)}
}

func (e *RolloverPreconditionError) Error() string {
	if e == nil {
		return "pki: authority rollover precondition failed"
	}
	if e.Detail == "" {
		return fmt.Sprintf("pki: authority rollover precondition failed: %s", e.Reason)
	}
	return fmt.Sprintf("pki: authority rollover precondition failed: %s: %s", e.Reason, e.Detail)
}

func (e *RolloverPreconditionError) Is(target error) bool {
	other, ok := target.(*RolloverPreconditionError)
	return ok && e != nil && other != nil && e.Reason == other.Reason
}
