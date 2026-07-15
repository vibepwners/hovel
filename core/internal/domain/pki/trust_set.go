package pki

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	MaximumTrustSetCertificates = 256
	MaximumTrustSetCRLs         = 256
)

type TrustSetState string

const (
	TrustSetStatePending  TrustSetState = "pending"
	TrustSetStateActive   TrustSetState = "active"
	TrustSetStateDegraded TrustSetState = "degraded"
	TrustSetStateRetired  TrustSetState = "retired"
)

func (s TrustSetState) Validate() error {
	switch s {
	case TrustSetStatePending, TrustSetStateActive, TrustSetStateDegraded, TrustSetStateRetired:
		return nil
	default:
		return fmt.Errorf("pki: unsupported trust set state %q", s)
	}
}

type TrustSetArgs struct {
	ID                 TrustSetID
	Name               string
	ActiveGenerationID TrustSetGenerationID
	StagedGenerationID TrustSetGenerationID
	State              TrustSetState
	Revision           uint64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type TrustSet struct {
	ID                 TrustSetID           `json:"id"`
	Name               string               `json:"name"`
	ActiveGenerationID TrustSetGenerationID `json:"activeGenerationId,omitempty"`
	StagedGenerationID TrustSetGenerationID `json:"stagedGenerationId,omitempty"`
	State              TrustSetState        `json:"state"`
	Revision           uint64               `json:"revision"`
	CreatedAt          time.Time            `json:"createdAt"`
	UpdatedAt          time.Time            `json:"updatedAt"`
}

func NewTrustSet(args TrustSetArgs) (TrustSet, error) {
	if err := args.ID.Validate(); err != nil {
		return TrustSet{}, err
	}
	name, err := validateName(args.Name, "trust set name")
	if err != nil {
		return TrustSet{}, err
	}
	if err := validateOptionalTrustSetGenerationID(args.ActiveGenerationID); err != nil {
		return TrustSet{}, err
	}
	if err := validateOptionalTrustSetGenerationID(args.StagedGenerationID); err != nil {
		return TrustSet{}, err
	}
	if args.ActiveGenerationID != "" && args.ActiveGenerationID == args.StagedGenerationID {
		return TrustSet{}, errors.New("pki: trust set active and staged generations must differ")
	}
	if err := args.State.Validate(); err != nil {
		return TrustSet{}, err
	}
	if err := validateTrustSetGenerations(args.State, args.ActiveGenerationID, args.StagedGenerationID); err != nil {
		return TrustSet{}, err
	}
	if err := validateSequenceNumber(args.Revision, "trust set revision"); err != nil {
		return TrustSet{}, err
	}
	if args.CreatedAt.IsZero() {
		return TrustSet{}, errors.New("pki: trust set creation time is required")
	}
	if args.UpdatedAt.IsZero() {
		args.UpdatedAt = args.CreatedAt
	}
	if args.UpdatedAt.Before(args.CreatedAt) {
		return TrustSet{}, errors.New("pki: trust set update time precedes creation time")
	}
	return TrustSet{
		ID:                 args.ID,
		Name:               name,
		ActiveGenerationID: args.ActiveGenerationID,
		StagedGenerationID: args.StagedGenerationID,
		State:              args.State,
		Revision:           args.Revision,
		CreatedAt:          args.CreatedAt.UTC(),
		UpdatedAt:          args.UpdatedAt.UTC(),
	}, nil
}

func (s TrustSet) Validate() error {
	normalized, err := NewTrustSet(TrustSetArgs(s))
	if err != nil {
		return err
	}
	if normalized != s {
		return errors.New("pki: trust set is not canonical")
	}
	return nil
}

type TrustSetGenerationArgs struct {
	ID                        TrustSetGenerationID
	TrustSetID                TrustSetID
	Generation                uint64
	AnchorGenerationIDs       []GenerationID
	IntermediateGenerationIDs []GenerationID
	CRLGenerationIDs          []CRLGenerationID
	CreatedAt                 time.Time
}

type TrustSetGeneration struct {
	ID                        TrustSetGenerationID `json:"id"`
	TrustSetID                TrustSetID           `json:"trustSetId"`
	Generation                uint64               `json:"generation"`
	AnchorGenerationIDs       []GenerationID       `json:"anchorGenerationIds"`
	IntermediateGenerationIDs []GenerationID       `json:"intermediateGenerationIds,omitempty"`
	CRLGenerationIDs          []CRLGenerationID    `json:"crlGenerationIds,omitempty"`
	CreatedAt                 time.Time            `json:"createdAt"`
}

func NewTrustSetGeneration(args TrustSetGenerationArgs) (TrustSetGeneration, error) {
	if err := args.ID.Validate(); err != nil {
		return TrustSetGeneration{}, err
	}
	if err := args.TrustSetID.Validate(); err != nil {
		return TrustSetGeneration{}, err
	}
	if err := validateSequenceNumber(args.Generation, "trust set generation number"); err != nil {
		return TrustSetGeneration{}, err
	}
	if len(args.AnchorGenerationIDs) == 0 {
		return TrustSetGeneration{}, errors.New("pki: trust set generation requires at least one anchor")
	}
	certificateCount := len(args.AnchorGenerationIDs) + len(args.IntermediateGenerationIDs)
	if certificateCount > MaximumTrustSetCertificates {
		return TrustSetGeneration{}, fmt.Errorf("pki: trust set generation exceeds %d certificates", MaximumTrustSetCertificates)
	}
	if len(args.CRLGenerationIDs) > MaximumTrustSetCRLs {
		return TrustSetGeneration{}, fmt.Errorf("pki: trust set generation exceeds %d crls", MaximumTrustSetCRLs)
	}
	seenCertificates := make(map[GenerationID]struct{}, certificateCount)
	if err := validateUniqueCertificateGenerationIDs(args.AnchorGenerationIDs, seenCertificates); err != nil {
		return TrustSetGeneration{}, err
	}
	if err := validateUniqueCertificateGenerationIDs(args.IntermediateGenerationIDs, seenCertificates); err != nil {
		return TrustSetGeneration{}, err
	}
	seenCRLs := make(map[CRLGenerationID]struct{}, len(args.CRLGenerationIDs))
	for _, id := range args.CRLGenerationIDs {
		if err := id.Validate(); err != nil {
			return TrustSetGeneration{}, err
		}
		if _, exists := seenCRLs[id]; exists {
			return TrustSetGeneration{}, fmt.Errorf("pki: duplicate trust set crl generation id %q", id)
		}
		seenCRLs[id] = struct{}{}
	}
	if args.CreatedAt.IsZero() {
		return TrustSetGeneration{}, errors.New("pki: trust set generation creation time is required")
	}
	return TrustSetGeneration{
		ID:                        args.ID,
		TrustSetID:                args.TrustSetID,
		Generation:                args.Generation,
		AnchorGenerationIDs:       append([]GenerationID(nil), args.AnchorGenerationIDs...),
		IntermediateGenerationIDs: append([]GenerationID(nil), args.IntermediateGenerationIDs...),
		CRLGenerationIDs:          append([]CRLGenerationID(nil), args.CRLGenerationIDs...),
		CreatedAt:                 args.CreatedAt.UTC(),
	}, nil
}

func (g TrustSetGeneration) Clone() TrustSetGeneration {
	result := g
	result.AnchorGenerationIDs = append([]GenerationID(nil), g.AnchorGenerationIDs...)
	result.IntermediateGenerationIDs = append([]GenerationID(nil), g.IntermediateGenerationIDs...)
	result.CRLGenerationIDs = append([]CRLGenerationID(nil), g.CRLGenerationIDs...)
	return result
}

func (g TrustSetGeneration) Validate() error {
	normalized, err := NewTrustSetGeneration(TrustSetGenerationArgs(g))
	if err != nil {
		return err
	}
	if normalized.ID != g.ID || normalized.TrustSetID != g.TrustSetID ||
		normalized.Generation != g.Generation || normalized.CreatedAt != g.CreatedAt ||
		!slices.Equal(normalized.AnchorGenerationIDs, g.AnchorGenerationIDs) ||
		!slices.Equal(normalized.IntermediateGenerationIDs, g.IntermediateGenerationIDs) ||
		!slices.Equal(normalized.CRLGenerationIDs, g.CRLGenerationIDs) {
		return errors.New("pki: trust set generation is not canonical")
	}
	return nil
}

func validateOptionalTrustSetGenerationID(id TrustSetGenerationID) error {
	if id == "" {
		return nil
	}
	return id.Validate()
}

func validateTrustSetGenerations(state TrustSetState, activeID, stagedID TrustSetGenerationID) error {
	switch state {
	case TrustSetStatePending:
		if activeID != "" {
			return errors.New("pki: pending trust set cannot have an active generation")
		}
	case TrustSetStateActive, TrustSetStateDegraded:
		if activeID == "" {
			return fmt.Errorf("pki: %s trust set requires an active generation", state)
		}
	case TrustSetStateRetired:
		if stagedID != "" {
			return errors.New("pki: retired trust set cannot have a staged generation")
		}
	}
	return nil
}

func validateUniqueCertificateGenerationIDs(ids []GenerationID, seen map[GenerationID]struct{}) error {
	for _, id := range ids {
		if err := id.Validate(); err != nil {
			return err
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("pki: duplicate trust set certificate generation id %q", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
