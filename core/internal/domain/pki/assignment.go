package pki

import (
	"errors"
	"fmt"
	"time"
)

type ConsumerType string

const (
	ConsumerMeshProvider  ConsumerType = "mesh-provider"
	ConsumerMeshListener  ConsumerType = "mesh-listener"
	ConsumerListeningPost ConsumerType = "listening-post"
	ConsumerMeshNode      ConsumerType = "mesh-node"
	ConsumerImplant       ConsumerType = "implant"
	ConsumerStager        ConsumerType = "stager"
	ConsumerPayload       ConsumerType = "payload"
	ConsumerC2Service     ConsumerType = "c2-service"
	ConsumerService       ConsumerType = "service"
	ConsumerExternal      ConsumerType = "external"
)

func (t ConsumerType) Validate() error {
	switch t {
	case ConsumerMeshProvider, ConsumerMeshListener, ConsumerListeningPost,
		ConsumerMeshNode, ConsumerImplant, ConsumerStager, ConsumerPayload,
		ConsumerC2Service, ConsumerService, ConsumerExternal:
		return nil
	default:
		return fmt.Errorf("pki: unsupported assignment consumer type %q", t)
	}
}

type AssignmentState string

const (
	AssignmentStatePending  AssignmentState = "pending"
	AssignmentStateActive   AssignmentState = "active"
	AssignmentStateDegraded AssignmentState = "degraded"
	AssignmentStateDisabled AssignmentState = "disabled"
	AssignmentStateRetired  AssignmentState = "retired"
)

func (s AssignmentState) Validate() error {
	switch s {
	case AssignmentStatePending, AssignmentStateActive, AssignmentStateDegraded,
		AssignmentStateDisabled, AssignmentStateRetired:
		return nil
	default:
		return fmt.Errorf("pki: unsupported assignment state %q", s)
	}
}

type AssignmentArgs struct {
	ID                      AssignmentID
	Purpose                 Purpose
	ConsumerType            ConsumerType
	ConsumerID              ConsumerID
	ProfileID               ProfileID
	ActiveGenerationID      GenerationID
	StagedGenerationID      GenerationID
	TrustSetID              TrustSetID
	ActiveTrustGenerationID TrustSetGenerationID
	StagedTrustGenerationID TrustSetGenerationID
	RotationPolicyID        RotationPolicyID
	State                   AssignmentState
	Revision                uint64
	UpdatedAt               time.Time
}

type Assignment struct {
	ID                      AssignmentID         `json:"id"`
	Purpose                 Purpose              `json:"purpose"`
	ConsumerType            ConsumerType         `json:"consumerType"`
	ConsumerID              ConsumerID           `json:"consumerId"`
	ProfileID               ProfileID            `json:"profileId"`
	ActiveGenerationID      GenerationID         `json:"activeGenerationId,omitempty"`
	StagedGenerationID      GenerationID         `json:"stagedGenerationId,omitempty"`
	TrustSetID              TrustSetID           `json:"trustSetId"`
	ActiveTrustGenerationID TrustSetGenerationID `json:"activeTrustGenerationId,omitempty"`
	StagedTrustGenerationID TrustSetGenerationID `json:"stagedTrustGenerationId,omitempty"`
	RotationPolicyID        RotationPolicyID     `json:"rotationPolicyId,omitempty"`
	State                   AssignmentState      `json:"state"`
	Revision                uint64               `json:"revision"`
	UpdatedAt               time.Time            `json:"updatedAt"`
}

func NewAssignment(args AssignmentArgs) (Assignment, error) {
	if err := args.ID.Validate(); err != nil {
		return Assignment{}, err
	}
	if err := args.Purpose.Validate(); err != nil {
		return Assignment{}, err
	}
	if err := args.ConsumerType.Validate(); err != nil {
		return Assignment{}, err
	}
	if err := args.ConsumerID.Validate(); err != nil {
		return Assignment{}, err
	}
	if err := args.ProfileID.Validate(); err != nil {
		return Assignment{}, err
	}
	if err := validateOptionalGenerationID(args.ActiveGenerationID); err != nil {
		return Assignment{}, err
	}
	if err := validateOptionalGenerationID(args.StagedGenerationID); err != nil {
		return Assignment{}, err
	}
	if args.ActiveGenerationID != "" && args.ActiveGenerationID == args.StagedGenerationID {
		return Assignment{}, errors.New("pki: assignment active and staged generations must differ")
	}
	if args.TrustSetID != "" {
		if err := args.TrustSetID.Validate(); err != nil {
			return Assignment{}, err
		}
	} else if args.Purpose.RequiresPeerTrust() {
		return Assignment{}, errors.New("pki: assignment purpose requires a trust set")
	}
	if err := validateOptionalTrustSetGenerationID(args.ActiveTrustGenerationID); err != nil {
		return Assignment{}, err
	}
	if err := validateOptionalTrustSetGenerationID(args.StagedTrustGenerationID); err != nil {
		return Assignment{}, err
	}
	if args.TrustSetID == "" && (args.ActiveTrustGenerationID != "" || args.StagedTrustGenerationID != "") {
		return Assignment{}, errors.New("pki: assignment trust generations require a trust set")
	}
	if args.RotationPolicyID != "" {
		if err := args.RotationPolicyID.Validate(); err != nil {
			return Assignment{}, err
		}
	}
	if err := args.State.Validate(); err != nil {
		return Assignment{}, err
	}
	if err := validateAssignmentGenerations(args); err != nil {
		return Assignment{}, err
	}
	if err := validateSequenceNumber(args.Revision, "assignment revision"); err != nil {
		return Assignment{}, err
	}
	if args.UpdatedAt.IsZero() {
		return Assignment{}, errors.New("pki: assignment update time is required")
	}
	return Assignment{
		ID: args.ID, Purpose: args.Purpose, ConsumerType: args.ConsumerType, ConsumerID: args.ConsumerID,
		ProfileID: args.ProfileID, ActiveGenerationID: args.ActiveGenerationID, StagedGenerationID: args.StagedGenerationID,
		TrustSetID: args.TrustSetID, ActiveTrustGenerationID: args.ActiveTrustGenerationID,
		StagedTrustGenerationID: args.StagedTrustGenerationID, RotationPolicyID: args.RotationPolicyID,
		State: args.State, Revision: args.Revision, UpdatedAt: args.UpdatedAt.UTC(),
	}, nil
}

func (a Assignment) Validate() error {
	normalized, err := NewAssignment(AssignmentArgs(a))
	if err != nil {
		return err
	}
	if normalized != a {
		return errors.New("pki: assignment is not canonical")
	}
	return nil
}

func (p Purpose) RequiresPeerTrust() bool {
	switch p {
	case PurposeTLSClient, PurposeMTLSServer, PurposeMTLSClient, PurposeDualRoleMTLS:
		return true
	default:
		return false
	}
}

func validateOptionalGenerationID(id GenerationID) error {
	if id == "" {
		return nil
	}
	return id.Validate()
}

func validateAssignmentGenerations(args AssignmentArgs) error {
	if args.Purpose.RequiresPeerTrust() &&
		(args.StagedGenerationID == "") != (args.StagedTrustGenerationID == "") {
		return errors.New("pki: staged certificate and trust generations must be specified together")
	}
	if !args.Purpose.RequiresPeerTrust() && (args.ActiveTrustGenerationID != "" || args.StagedTrustGenerationID != "") {
		return errors.New("pki: assignment purpose does not use peer trust generations")
	}
	if args.Purpose.RequiresPeerTrust() && args.ActiveGenerationID != "" && args.ActiveTrustGenerationID == "" {
		return errors.New("pki: active assignment certificate requires an active trust generation")
	}
	switch args.State {
	case AssignmentStatePending:
		if args.ActiveGenerationID != "" || args.ActiveTrustGenerationID != "" {
			return errors.New("pki: pending assignment cannot have an active generation")
		}
	case AssignmentStateActive, AssignmentStateDegraded:
		if args.ActiveGenerationID == "" {
			return fmt.Errorf("pki: %s assignment requires an active generation", args.State)
		}
	case AssignmentStateDisabled, AssignmentStateRetired:
		if args.StagedGenerationID != "" || args.StagedTrustGenerationID != "" {
			return fmt.Errorf("pki: %s assignment cannot have a staged generation", args.State)
		}
	}
	return nil
}
