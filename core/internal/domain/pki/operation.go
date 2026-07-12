package pki

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	MaximumOperationFailureBytes        = 1024
	MaximumAcknowledgementEvidenceBytes = 1024
	MaximumRolloverAssignments          = 4096
)

type OperationKind string

const OperationKindAuthorityRollover OperationKind = "authority-rollover"

func (k OperationKind) Validate() error {
	switch k {
	case OperationKindAuthorityRollover:
		return nil
	default:
		return fmt.Errorf("pki: unsupported operation kind %q", k)
	}
}

type OperationStatus string

const (
	OperationStatusWaiting   OperationStatus = "waiting"
	OperationStatusCompleted OperationStatus = "completed"
	OperationStatusFailed    OperationStatus = "failed"
	OperationStatusCanceled  OperationStatus = "canceled"
)

func (s OperationStatus) Validate() error {
	switch s {
	case OperationStatusWaiting,
		OperationStatusCompleted, OperationStatusFailed, OperationStatusCanceled:
		return nil
	default:
		return fmt.Errorf("pki: unsupported operation status %q", s)
	}
}

type AuthorityRolloverPhase string

const (
	AuthorityRolloverPhaseAwaitingOverlapAcknowledgements AuthorityRolloverPhase = "awaiting-overlap-acknowledgements"
	AuthorityRolloverPhaseAwaitingLeafRotation            AuthorityRolloverPhase = "awaiting-leaf-rotation"
	AuthorityRolloverPhaseAwaitingFinalAcknowledgements   AuthorityRolloverPhase = "awaiting-final-acknowledgements"
	AuthorityRolloverPhaseCompleted                       AuthorityRolloverPhase = "completed"
)

func (p AuthorityRolloverPhase) Validate() error {
	switch p {
	case AuthorityRolloverPhaseAwaitingOverlapAcknowledgements,
		AuthorityRolloverPhaseAwaitingLeafRotation,
		AuthorityRolloverPhaseAwaitingFinalAcknowledgements,
		AuthorityRolloverPhaseCompleted:
		return nil
	default:
		return fmt.Errorf("pki: unsupported authority rollover phase %q", p)
	}
}

// AuthorityRolloverTransition identifies one legal state-machine edge.
type AuthorityRolloverTransition string

const (
	AuthorityRolloverTransitionActivateOverlap AuthorityRolloverTransition = "activate-overlap"
	AuthorityRolloverTransitionBeginFinalTrust AuthorityRolloverTransition = "begin-final-trust"
	AuthorityRolloverTransitionComplete        AuthorityRolloverTransition = "complete"
	AuthorityRolloverTransitionCancel          AuthorityRolloverTransition = "cancel"
)

func (t AuthorityRolloverTransition) Validate() error {
	switch t {
	case AuthorityRolloverTransitionActivateOverlap,
		AuthorityRolloverTransitionBeginFinalTrust,
		AuthorityRolloverTransitionComplete,
		AuthorityRolloverTransitionCancel:
		return nil
	default:
		return fmt.Errorf("pki: unsupported authority rollover transition %q", t)
	}
}

type RolloverConsumerTracking string

const (
	RolloverConsumerTrackingAllTracked RolloverConsumerTracking = "all-tracked"
	RolloverConsumerTrackingExplicit   RolloverConsumerTracking = "explicit"
	RolloverConsumerTrackingNone       RolloverConsumerTracking = "none"
)

func (t RolloverConsumerTracking) Validate() error {
	switch t {
	case RolloverConsumerTrackingAllTracked, RolloverConsumerTrackingExplicit, RolloverConsumerTrackingNone:
		return nil
	default:
		return fmt.Errorf("pki: unsupported rollover consumer tracking %q", t)
	}
}

// ValidateAuthorityRolloverAuthorities verifies that two authorities can
// participate in one rollover and binds the transition to distinct active
// certificate generations.
func ValidateAuthorityRolloverAuthorities(previous, replacement Authority) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := replacement.Validate(); err != nil {
		return err
	}
	if previous.ID == replacement.ID || previous.Role != replacement.Role ||
		previous.ParentAuthorityID != replacement.ParentAuthorityID {
		return errors.New("pki: rollover authorities do not represent compatible issuer roles")
	}
	if previous.ActiveGenerationID == "" || replacement.ActiveGenerationID == "" ||
		previous.ActiveGenerationID == replacement.ActiveGenerationID {
		return errors.New("pki: rollover authorities require distinct active generations")
	}
	return nil
}

// ValidateAuthorityRolloverOverlapTrust requires both authority generations
// in the role-appropriate trust collection.
func ValidateAuthorityRolloverOverlapTrust(
	generation TrustSetGeneration,
	previous Authority,
	replacement Authority,
) error {
	if err := ValidateAuthorityRolloverAuthorities(previous, replacement); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	trusted, wrong := authorityTrustCollections(generation, previous.Role)
	if !slices.Contains(trusted, previous.ActiveGenerationID) ||
		!slices.Contains(trusted, replacement.ActiveGenerationID) ||
		slices.Contains(wrong, previous.ActiveGenerationID) ||
		slices.Contains(wrong, replacement.ActiveGenerationID) {
		return errors.New("pki: rollover overlap trust does not match authority roles")
	}
	return nil
}

// ValidateAuthorityRolloverFinalTrust requires the replacement in the
// role-appropriate trust collection and removes the previous generation from
// every trust collection.
func ValidateAuthorityRolloverFinalTrust(
	generation TrustSetGeneration,
	previous Authority,
	replacement Authority,
) error {
	if err := ValidateAuthorityRolloverAuthorities(previous, replacement); err != nil {
		return err
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	trusted, wrong := authorityTrustCollections(generation, previous.Role)
	if !slices.Contains(trusted, replacement.ActiveGenerationID) ||
		slices.Contains(wrong, replacement.ActiveGenerationID) ||
		slices.Contains(generation.AnchorGenerationIDs, previous.ActiveGenerationID) ||
		slices.Contains(generation.IntermediateGenerationIDs, previous.ActiveGenerationID) {
		return errors.New("pki: rollover final trust does not match authority roles")
	}
	return nil
}

func authorityTrustCollections(
	generation TrustSetGeneration,
	role AuthorityRole,
) (trusted []GenerationID, wrong []GenerationID) {
	if role == AuthorityRoleSubordinate {
		return generation.IntermediateGenerationIDs, generation.AnchorGenerationIDs
	}
	return generation.AnchorGenerationIDs, generation.IntermediateGenerationIDs
}

type AuthorityRollover struct {
	PreviousAuthorityID              AuthorityID              `json:"previousAuthorityId"`
	PreviousAuthorityGenerationID    GenerationID             `json:"previousAuthorityGenerationId"`
	ReplacementAuthorityID           AuthorityID              `json:"replacementAuthorityId"`
	ReplacementAuthorityGenerationID GenerationID             `json:"replacementAuthorityGenerationId"`
	TrustSetID                       TrustSetID               `json:"trustSetId"`
	OverlapTrustGenerationID         TrustSetGenerationID     `json:"overlapTrustGenerationId"`
	FinalTrustGenerationID           TrustSetGenerationID     `json:"finalTrustGenerationId,omitempty"`
	ConsumerTracking                 RolloverConsumerTracking `json:"consumerTracking"`
	RequiredAssignmentIDs            []AssignmentID           `json:"requiredAssignmentIds"`
	Phase                            AuthorityRolloverPhase   `json:"phase"`
}

func (r AuthorityRollover) Clone() AuthorityRollover {
	result := r
	result.RequiredAssignmentIDs = append([]AssignmentID(nil), r.RequiredAssignmentIDs...)
	return result
}

// ActiveAcknowledgementTarget returns the trust generation consumers must
// acknowledge in the current phase.
func (r AuthorityRollover) ActiveAcknowledgementTarget() (TrustSetGenerationID, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	switch r.Phase {
	case AuthorityRolloverPhaseAwaitingOverlapAcknowledgements:
		return r.OverlapTrustGenerationID, nil
	case AuthorityRolloverPhaseAwaitingFinalAcknowledgements:
		return r.FinalTrustGenerationID, nil
	default:
		return "", fmt.Errorf("pki: authority rollover phase %q does not accept acknowledgements", r.Phase)
	}
}

func (r AuthorityRollover) Validate() error {
	if err := r.PreviousAuthorityID.Validate(); err != nil {
		return err
	}
	if err := r.ReplacementAuthorityID.Validate(); err != nil {
		return err
	}
	if r.PreviousAuthorityID == r.ReplacementAuthorityID {
		return errors.New("pki: authority rollover replacement must differ from the previous authority")
	}
	if err := r.PreviousAuthorityGenerationID.Validate(); err != nil {
		return err
	}
	if err := r.ReplacementAuthorityGenerationID.Validate(); err != nil {
		return err
	}
	if err := r.TrustSetID.Validate(); err != nil {
		return err
	}
	if err := r.OverlapTrustGenerationID.Validate(); err != nil {
		return err
	}
	if r.FinalTrustGenerationID != "" {
		if err := r.FinalTrustGenerationID.Validate(); err != nil {
			return err
		}
		if r.FinalTrustGenerationID == r.OverlapTrustGenerationID {
			return errors.New("pki: rollover final and overlap trust generations must differ")
		}
	}
	if err := r.ConsumerTracking.Validate(); err != nil {
		return err
	}
	if len(r.RequiredAssignmentIDs) > MaximumRolloverAssignments {
		return fmt.Errorf("pki: authority rollover exceeds %d required assignments", MaximumRolloverAssignments)
	}
	if r.ConsumerTracking == RolloverConsumerTrackingNone && len(r.RequiredAssignmentIDs) != 0 {
		return errors.New("pki: rollover without consumer tracking cannot require assignments")
	}
	if r.ConsumerTracking == RolloverConsumerTrackingExplicit && len(r.RequiredAssignmentIDs) == 0 {
		return errors.New("pki: explicit rollover consumer tracking requires assignments")
	}
	for index, id := range r.RequiredAssignmentIDs {
		if err := id.Validate(); err != nil {
			return err
		}
		if index > 0 && r.RequiredAssignmentIDs[index-1] >= id {
			return errors.New("pki: rollover required assignments must be unique and sorted")
		}
	}
	if err := r.Phase.Validate(); err != nil {
		return err
	}
	if r.Phase == AuthorityRolloverPhaseAwaitingFinalAcknowledgements && r.FinalTrustGenerationID == "" {
		return errors.New("pki: final rollover acknowledgements require a final trust generation")
	}
	if r.Phase == AuthorityRolloverPhaseCompleted && r.FinalTrustGenerationID == "" {
		return errors.New("pki: completed rollover requires a final trust generation")
	}
	return nil
}

type OperationArgs struct {
	ID                OperationID
	Kind              OperationKind
	Status            OperationStatus
	Revision          uint64
	AuthorityRollover *AuthorityRollover
	CreatedAt         time.Time
	UpdatedAt         time.Time
	CompletedAt       time.Time
	Failure           string
}

type Operation struct {
	ID                OperationID        `json:"id"`
	Kind              OperationKind      `json:"kind"`
	Status            OperationStatus    `json:"status"`
	Revision          uint64             `json:"revision"`
	AuthorityRollover *AuthorityRollover `json:"authorityRollover,omitempty"`
	CreatedAt         time.Time          `json:"createdAt"`
	UpdatedAt         time.Time          `json:"updatedAt"`
	CompletedAt       time.Time          `json:"completedAt,omitempty"`
	Failure           string             `json:"failure,omitempty"`
}

func NewOperation(args OperationArgs) (Operation, error) {
	if err := args.ID.Validate(); err != nil {
		return Operation{}, err
	}
	if err := args.Kind.Validate(); err != nil {
		return Operation{}, err
	}
	if err := args.Status.Validate(); err != nil {
		return Operation{}, err
	}
	if args.Revision == 0 || args.Revision > MaximumSequenceNumber {
		return Operation{}, errors.New("pki: operation revision is invalid")
	}
	if args.Kind != OperationKindAuthorityRollover || args.AuthorityRollover == nil {
		return Operation{}, errors.New("pki: operation kind requires its typed payload")
	}
	rollover := args.AuthorityRollover.Clone()
	slices.Sort(rollover.RequiredAssignmentIDs)
	if err := rollover.Validate(); err != nil {
		return Operation{}, err
	}
	if err := validateRolloverOperationStatus(args.Status, rollover.Phase); err != nil {
		return Operation{}, err
	}
	if args.CreatedAt.IsZero() || args.CreatedAt != args.CreatedAt.UTC() {
		return Operation{}, errors.New("pki: operation creation time must be canonical utc")
	}
	if args.UpdatedAt.IsZero() {
		args.UpdatedAt = args.CreatedAt
	}
	if args.UpdatedAt != args.UpdatedAt.UTC() || args.UpdatedAt.Before(args.CreatedAt) {
		return Operation{}, errors.New("pki: operation update time is invalid")
	}
	terminal := args.Status == OperationStatusCompleted || args.Status == OperationStatusFailed || args.Status == OperationStatusCanceled
	if terminal != !args.CompletedAt.IsZero() {
		return Operation{}, errors.New("pki: operation completion time does not match terminal status")
	}
	if !args.CompletedAt.IsZero() && (args.CompletedAt != args.CompletedAt.UTC() || args.CompletedAt.Before(args.UpdatedAt)) {
		return Operation{}, errors.New("pki: operation completion time is invalid")
	}
	failure := strings.TrimSpace(args.Failure)
	if args.Status == OperationStatusFailed {
		if failure == "" || len(failure) > MaximumOperationFailureBytes || strings.IndexFunc(failure, unicode.IsControl) >= 0 {
			return Operation{}, errors.New("pki: failed operation requires a canonical failure")
		}
	} else if failure != "" {
		return Operation{}, errors.New("pki: non-failed operation cannot retain a failure")
	}
	return Operation{
		ID: args.ID, Kind: args.Kind, Status: args.Status, Revision: args.Revision,
		AuthorityRollover: &rollover, CreatedAt: args.CreatedAt, UpdatedAt: args.UpdatedAt,
		CompletedAt: args.CompletedAt, Failure: failure,
	}, nil
}

func (o Operation) Clone() Operation {
	result := o
	if o.AuthorityRollover != nil {
		rollover := o.AuthorityRollover.Clone()
		result.AuthorityRollover = &rollover
	}
	return result
}

func (o Operation) Validate() error {
	normalized, err := NewOperation(OperationArgs(o))
	if err != nil {
		return err
	}
	if normalized.ID != o.ID || normalized.Kind != o.Kind || normalized.Status != o.Status ||
		normalized.Revision != o.Revision || normalized.CreatedAt != o.CreatedAt || normalized.UpdatedAt != o.UpdatedAt ||
		normalized.CompletedAt != o.CompletedAt || normalized.Failure != o.Failure ||
		(normalized.AuthorityRollover == nil) != (o.AuthorityRollover == nil) {
		return errors.New("pki: operation is not canonical")
	}
	if normalized.AuthorityRollover != nil {
		left, right := normalized.AuthorityRollover, o.AuthorityRollover
		if left.PreviousAuthorityID != right.PreviousAuthorityID ||
			left.PreviousAuthorityGenerationID != right.PreviousAuthorityGenerationID ||
			left.ReplacementAuthorityID != right.ReplacementAuthorityID || left.TrustSetID != right.TrustSetID ||
			left.ReplacementAuthorityGenerationID != right.ReplacementAuthorityGenerationID ||
			left.OverlapTrustGenerationID != right.OverlapTrustGenerationID ||
			left.FinalTrustGenerationID != right.FinalTrustGenerationID || left.ConsumerTracking != right.ConsumerTracking ||
			left.Phase != right.Phase || !slices.Equal(left.RequiredAssignmentIDs, right.RequiredAssignmentIDs) {
			return errors.New("pki: operation is not canonical")
		}
	}
	return nil
}

// ValidateAuthorityRolloverTransition verifies a complete, typed state-machine
// edge without relying on persistence-specific column comparisons.
func ValidateAuthorityRolloverTransition(
	previous Operation,
	next Operation,
	transition AuthorityRolloverTransition,
) error {
	if err := transition.Validate(); err != nil {
		return err
	}
	if err := previous.Validate(); err != nil {
		return fmt.Errorf("pki: validate previous authority rollover operation: %w", err)
	}
	if err := next.Validate(); err != nil {
		return fmt.Errorf("pki: validate next authority rollover operation: %w", err)
	}
	if previous.AuthorityRollover == nil || next.AuthorityRollover == nil ||
		previous.ID != next.ID || previous.Kind != next.Kind || previous.Status != OperationStatusWaiting ||
		previous.Revision == MaximumSequenceNumber || next.Revision != previous.Revision+1 ||
		!previous.CreatedAt.Equal(next.CreatedAt) || next.UpdatedAt.Before(previous.UpdatedAt) ||
		previous.AuthorityRollover.PreviousAuthorityID != next.AuthorityRollover.PreviousAuthorityID ||
		previous.AuthorityRollover.PreviousAuthorityGenerationID != next.AuthorityRollover.PreviousAuthorityGenerationID ||
		previous.AuthorityRollover.ReplacementAuthorityID != next.AuthorityRollover.ReplacementAuthorityID ||
		previous.AuthorityRollover.ReplacementAuthorityGenerationID != next.AuthorityRollover.ReplacementAuthorityGenerationID ||
		previous.AuthorityRollover.TrustSetID != next.AuthorityRollover.TrustSetID ||
		previous.AuthorityRollover.OverlapTrustGenerationID != next.AuthorityRollover.OverlapTrustGenerationID ||
		previous.AuthorityRollover.ConsumerTracking != next.AuthorityRollover.ConsumerTracking ||
		!slices.Equal(previous.AuthorityRollover.RequiredAssignmentIDs, next.AuthorityRollover.RequiredAssignmentIDs) {
		return errors.New("pki: authority rollover transition changed immutable state")
	}

	previousRollover := previous.AuthorityRollover
	nextRollover := next.AuthorityRollover
	switch transition {
	case AuthorityRolloverTransitionActivateOverlap:
		if previousRollover.Phase != AuthorityRolloverPhaseAwaitingOverlapAcknowledgements ||
			nextRollover.Phase != AuthorityRolloverPhaseAwaitingLeafRotation ||
			previousRollover.FinalTrustGenerationID != "" || nextRollover.FinalTrustGenerationID != "" ||
			next.Status != OperationStatusWaiting || !next.CompletedAt.IsZero() {
			return errors.New("pki: invalid overlap activation transition")
		}
	case AuthorityRolloverTransitionBeginFinalTrust:
		if previousRollover.Phase != AuthorityRolloverPhaseAwaitingLeafRotation ||
			nextRollover.Phase != AuthorityRolloverPhaseAwaitingFinalAcknowledgements ||
			previousRollover.FinalTrustGenerationID != "" || nextRollover.FinalTrustGenerationID == "" ||
			next.Status != OperationStatusWaiting || !next.CompletedAt.IsZero() {
			return errors.New("pki: invalid final trust transition")
		}
	case AuthorityRolloverTransitionComplete:
		if previousRollover.Phase != AuthorityRolloverPhaseAwaitingFinalAcknowledgements ||
			nextRollover.Phase != AuthorityRolloverPhaseCompleted ||
			previousRollover.FinalTrustGenerationID != nextRollover.FinalTrustGenerationID ||
			next.Status != OperationStatusCompleted || !next.CompletedAt.Equal(next.UpdatedAt) {
			return errors.New("pki: invalid authority rollover completion transition")
		}
	case AuthorityRolloverTransitionCancel:
		if previousRollover.Phase != AuthorityRolloverPhaseAwaitingOverlapAcknowledgements ||
			nextRollover.Phase != previousRollover.Phase ||
			previousRollover.FinalTrustGenerationID != nextRollover.FinalTrustGenerationID ||
			next.Status != OperationStatusCanceled || !next.CompletedAt.Equal(next.UpdatedAt) {
			return errors.New("pki: invalid authority rollover cancellation transition")
		}
	}
	return nil
}

// ValidateAuthorityRolloverAggregateTransition verifies the operation,
// authority, and trust-set changes that must commit atomically.
func ValidateAuthorityRolloverAggregateTransition(
	previousOperation Operation,
	nextOperation Operation,
	previousAuthority Authority,
	nextAuthority Authority,
	previousTrustSet TrustSet,
	nextTrustSet TrustSet,
	transition AuthorityRolloverTransition,
) error {
	if transition == AuthorityRolloverTransitionBeginFinalTrust {
		return errors.New("pki: final trust transition does not mutate the rollover aggregate")
	}
	if err := ValidateAuthorityRolloverTransition(previousOperation, nextOperation, transition); err != nil {
		return err
	}
	if err := previousAuthority.Validate(); err != nil {
		return err
	}
	if err := nextAuthority.Validate(); err != nil {
		return err
	}
	if err := previousTrustSet.Validate(); err != nil {
		return err
	}
	if err := nextTrustSet.Validate(); err != nil {
		return err
	}
	rollover := nextOperation.AuthorityRollover
	if rollover == nil || rollover.PreviousAuthorityID != previousAuthority.ID ||
		rollover.PreviousAuthorityGenerationID != previousAuthority.ActiveGenerationID ||
		previousAuthority.ID != nextAuthority.ID || rollover.TrustSetID != previousTrustSet.ID ||
		previousTrustSet.ID != nextTrustSet.ID || !sameAuthorityIdentity(previousAuthority, nextAuthority) ||
		!sameTrustSetIdentity(previousTrustSet, nextTrustSet) ||
		previousTrustSet.Revision == MaximumSequenceNumber || nextTrustSet.Revision != previousTrustSet.Revision+1 ||
		nextTrustSet.StagedGenerationID != "" || nextTrustSet.State != TrustSetStateActive {
		return errors.New("pki: authority rollover aggregate changed immutable or unrelated state")
	}

	switch transition {
	case AuthorityRolloverTransitionActivateOverlap:
		if previousTrustSet.StagedGenerationID != rollover.OverlapTrustGenerationID ||
			nextTrustSet.ActiveGenerationID != rollover.OverlapTrustGenerationID ||
			!validRolloverAuthorityStateTransition(
				previousAuthority.State, nextAuthority.State, AuthorityStateRetiring,
			) {
			return errors.New("pki: invalid authority rollover overlap aggregate transition")
		}
	case AuthorityRolloverTransitionComplete:
		if previousTrustSet.StagedGenerationID != rollover.FinalTrustGenerationID ||
			nextTrustSet.ActiveGenerationID != rollover.FinalTrustGenerationID ||
			!validRolloverAuthorityStateTransition(
				previousAuthority.State, nextAuthority.State, AuthorityStateRetired,
			) {
			return errors.New("pki: invalid authority rollover completion aggregate transition")
		}
	}
	return nil
}

func validRolloverAuthorityStateTransition(previous, next, expected AuthorityState) bool {
	if previous == AuthorityStateCompromised {
		return next == AuthorityStateCompromised
	}
	if expected == AuthorityStateRetiring {
		return (previous == AuthorityStateActive || previous == AuthorityStateLocked) && next == expected
	}
	return previous == AuthorityStateRetiring && next == expected
}

func sameAuthorityIdentity(left, right Authority) bool {
	return left.ID == right.ID && left.Name == right.Name && left.Role == right.Role && left.Origin == right.Origin &&
		left.SignerMode == right.SignerMode && left.ParentAuthorityID == right.ParentAuthorityID &&
		left.ActiveGenerationID == right.ActiveGenerationID && left.ProfileID == right.ProfileID &&
		left.SignerRef == right.SignerRef && left.ExportPolicy == right.ExportPolicy &&
		left.CreatedAt.Equal(right.CreatedAt) && maps.Equal(left.Labels, right.Labels) &&
		!right.UpdatedAt.Before(left.UpdatedAt)
}

func sameTrustSetIdentity(left, right TrustSet) bool {
	return left.ID == right.ID && left.Name == right.Name && left.CreatedAt.Equal(right.CreatedAt) &&
		!right.UpdatedAt.Before(left.UpdatedAt)
}

func validateRolloverOperationStatus(status OperationStatus, phase AuthorityRolloverPhase) error {
	if status == OperationStatusFailed || status == OperationStatusCanceled {
		if phase == AuthorityRolloverPhaseCompleted {
			return errors.New("pki: completed authority rollover cannot fail or be canceled")
		}
		return nil
	}
	want := OperationStatusWaiting
	switch phase {
	case AuthorityRolloverPhaseAwaitingOverlapAcknowledgements,
		AuthorityRolloverPhaseAwaitingLeafRotation,
		AuthorityRolloverPhaseAwaitingFinalAcknowledgements:
		want = OperationStatusWaiting
	case AuthorityRolloverPhaseCompleted:
		want = OperationStatusCompleted
	}
	if status != want {
		return fmt.Errorf("pki: authority rollover phase %q requires operation status %q", phase, want)
	}
	return nil
}

type AcknowledgementKind string

const AcknowledgementKindTrustSetGeneration AcknowledgementKind = "trust-set-generation"

func (k AcknowledgementKind) Validate() error {
	if k != AcknowledgementKindTrustSetGeneration {
		return fmt.Errorf("pki: unsupported acknowledgement kind %q", k)
	}
	return nil
}

type ConsumerAcknowledgementArgs struct {
	ID                   AcknowledgementID
	OperationID          OperationID
	AssignmentID         AssignmentID
	ConsumerType         ConsumerType
	ConsumerID           ConsumerID
	Kind                 AcknowledgementKind
	TrustSetGenerationID TrustSetGenerationID
	EvidenceRef          string
	AcknowledgedAt       time.Time
}

type ConsumerAcknowledgement struct {
	ID                   AcknowledgementID    `json:"id"`
	OperationID          OperationID          `json:"operationId"`
	AssignmentID         AssignmentID         `json:"assignmentId"`
	ConsumerType         ConsumerType         `json:"consumerType"`
	ConsumerID           ConsumerID           `json:"consumerId"`
	Kind                 AcknowledgementKind  `json:"kind"`
	TrustSetGenerationID TrustSetGenerationID `json:"trustSetGenerationId"`
	EvidenceRef          string               `json:"evidenceRef,omitempty"`
	AcknowledgedAt       time.Time            `json:"acknowledgedAt"`
}

func NewConsumerAcknowledgement(args ConsumerAcknowledgementArgs) (ConsumerAcknowledgement, error) {
	if err := args.ID.Validate(); err != nil {
		return ConsumerAcknowledgement{}, err
	}
	if err := args.OperationID.Validate(); err != nil {
		return ConsumerAcknowledgement{}, err
	}
	if err := args.AssignmentID.Validate(); err != nil {
		return ConsumerAcknowledgement{}, err
	}
	if err := args.ConsumerType.Validate(); err != nil {
		return ConsumerAcknowledgement{}, err
	}
	if err := args.ConsumerID.Validate(); err != nil {
		return ConsumerAcknowledgement{}, err
	}
	if err := args.Kind.Validate(); err != nil {
		return ConsumerAcknowledgement{}, err
	}
	if err := args.TrustSetGenerationID.Validate(); err != nil {
		return ConsumerAcknowledgement{}, err
	}
	evidenceRef := strings.TrimSpace(args.EvidenceRef)
	if len(evidenceRef) > MaximumAcknowledgementEvidenceBytes || strings.IndexFunc(evidenceRef, unicode.IsControl) >= 0 {
		return ConsumerAcknowledgement{}, errors.New("pki: acknowledgement evidence reference is not canonical")
	}
	if args.AcknowledgedAt.IsZero() || args.AcknowledgedAt != args.AcknowledgedAt.UTC() {
		return ConsumerAcknowledgement{}, errors.New("pki: acknowledgement time must be canonical utc")
	}
	return ConsumerAcknowledgement{
		ID: args.ID, OperationID: args.OperationID, AssignmentID: args.AssignmentID,
		ConsumerType: args.ConsumerType, ConsumerID: args.ConsumerID, Kind: args.Kind,
		TrustSetGenerationID: args.TrustSetGenerationID, EvidenceRef: evidenceRef,
		AcknowledgedAt: args.AcknowledgedAt,
	}, nil
}

func (a ConsumerAcknowledgement) Validate() error {
	normalized, err := NewConsumerAcknowledgement(ConsumerAcknowledgementArgs(a))
	if err != nil {
		return err
	}
	if normalized != a {
		return errors.New("pki: consumer acknowledgement is not canonical")
	}
	return nil
}
