package pki

import (
	"testing"
	"time"
)

func TestTrustSetStatesAndGenerationInvariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		state    TrustSetState
		activeID TrustSetGenerationID
		stagedID TrustSetGenerationID
	}{
		{name: "pending empty", state: TrustSetStatePending},
		{name: "pending staged", state: TrustSetStatePending, stagedID: "trust-generation-next"},
		{name: "active", state: TrustSetStateActive, activeID: "trust-generation-current"},
		{name: "active staged", state: TrustSetStateActive, activeID: "trust-generation-current", stagedID: "trust-generation-next"},
		{name: "degraded", state: TrustSetStateDegraded, activeID: "trust-generation-current"},
		{name: "retired empty", state: TrustSetStateRetired},
		{name: "retired retains active", state: TrustSetStateRetired, activeID: "trust-generation-current"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := validTrustSetArgs()
			args.State = test.state
			args.ActiveGenerationID = test.activeID
			args.StagedGenerationID = test.stagedID
			trustSet, err := NewTrustSet(args)
			if err != nil {
				t.Fatal(err)
			}
			if err := trustSet.Validate(); err != nil {
				t.Fatalf("TrustSet.Validate() error = %v", err)
			}
		})
	}

	invalid := []struct {
		name     string
		state    TrustSetState
		activeID TrustSetGenerationID
		stagedID TrustSetGenerationID
	}{
		{name: "pending active", state: TrustSetStatePending, activeID: "trust-generation-current"},
		{name: "active empty", state: TrustSetStateActive},
		{name: "degraded empty", state: TrustSetStateDegraded},
		{name: "retired staged", state: TrustSetStateRetired, stagedID: "trust-generation-next"},
		{name: "same active and staged", state: TrustSetStateActive, activeID: "trust-generation-current", stagedID: "trust-generation-current"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := validTrustSetArgs()
			args.State = test.state
			args.ActiveGenerationID = test.activeID
			args.StagedGenerationID = test.stagedID
			if _, err := NewTrustSet(args); err == nil {
				t.Fatal("NewTrustSet() accepted invalid generation state")
			}
		})
	}

	if err := TrustSetState("unknown").Validate(); err == nil {
		t.Fatal("TrustSetState.Validate() accepted an unknown value")
	}
}

func TestTrustSetRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*TrustSetArgs)
	}{
		{name: "id", mutate: func(args *TrustSetArgs) { args.ID = "bad id" }},
		{name: "name", mutate: func(args *TrustSetArgs) { args.Name = " " }},
		{name: "name control", mutate: func(args *TrustSetArgs) { args.Name = "bad\nname" }},
		{name: "active generation", mutate: func(args *TrustSetArgs) { args.ActiveGenerationID = "bad id" }},
		{name: "staged generation", mutate: func(args *TrustSetArgs) { args.StagedGenerationID = "bad id" }},
		{name: "state", mutate: func(args *TrustSetArgs) { args.State = "unknown" }},
		{name: "revision", mutate: func(args *TrustSetArgs) { args.Revision = 0 }},
		{name: "revision overflow", mutate: func(args *TrustSetArgs) { args.Revision = MaximumSequenceNumber + 1 }},
		{name: "creation time", mutate: func(args *TrustSetArgs) { args.CreatedAt = time.Time{} }},
		{name: "update before creation", mutate: func(args *TrustSetArgs) { args.UpdatedAt = args.CreatedAt.Add(-time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := validTrustSetArgs()
			test.mutate(&args)
			if _, err := NewTrustSet(args); err == nil {
				t.Fatal("NewTrustSet() accepted an invalid contract")
			}
		})
	}
}

func TestTrustSetGenerationValidationAndDefensiveCopies(t *testing.T) {
	t.Parallel()

	args := validTrustSetGenerationArgs()
	generation, err := NewTrustSetGeneration(args)
	if err != nil {
		t.Fatal(err)
	}
	args.AnchorGenerationIDs[0] = "mutated-anchor"
	args.IntermediateGenerationIDs[0] = "mutated-intermediate"
	args.CRLGenerationIDs[0] = "mutated-crl"
	if generation.AnchorGenerationIDs[0] != "root-generation-old" ||
		generation.IntermediateGenerationIDs[0] != "issuer-generation" ||
		generation.CRLGenerationIDs[0] != "issuer-crl-generation" {
		t.Fatal("NewTrustSetGeneration() retained caller-owned slices")
	}
	clone := generation.Clone()
	clone.AnchorGenerationIDs[0] = "mutated-anchor"
	clone.IntermediateGenerationIDs[0] = "mutated-intermediate"
	clone.CRLGenerationIDs[0] = "mutated-crl"
	if generation.AnchorGenerationIDs[0] != "root-generation-old" ||
		generation.IntermediateGenerationIDs[0] != "issuer-generation" ||
		generation.CRLGenerationIDs[0] != "issuer-crl-generation" {
		t.Fatal("TrustSetGeneration.Clone() aliased slices")
	}
	if err := generation.Validate(); err != nil {
		t.Fatalf("TrustSetGeneration.Validate() error = %v", err)
	}
}

func TestTrustSetGenerationSupportsRolloverOverlap(t *testing.T) {
	t.Parallel()

	args := validTrustSetGenerationArgs()
	args.AnchorGenerationIDs = []GenerationID{"root-generation-old", "root-generation-new"}
	if _, err := NewTrustSetGeneration(args); err != nil {
		t.Fatalf("NewTrustSetGeneration() rejected overlapping trust anchors: %v", err)
	}
}

func TestTrustContractsRejectNoncanonicalValues(t *testing.T) {
	t.Parallel()

	trustSet, err := NewTrustSet(validTrustSetArgs())
	if err != nil {
		t.Fatal(err)
	}
	trustSet.Name = " Edge trust "
	if err := trustSet.Validate(); err == nil {
		t.Fatal("TrustSet.Validate() accepted a noncanonical name")
	}

	generation, err := NewTrustSetGeneration(validTrustSetGenerationArgs())
	if err != nil {
		t.Fatal(err)
	}
	generation.CreatedAt = generation.CreatedAt.In(time.FixedZone("noncanonical", int(time.Hour/time.Second)))
	if err := generation.Validate(); err == nil {
		t.Fatal("TrustSetGeneration.Validate() accepted a noncanonical timestamp")
	}
}

func TestTrustSetGenerationRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*TrustSetGenerationArgs)
	}{
		{name: "id", mutate: func(args *TrustSetGenerationArgs) { args.ID = "bad id" }},
		{name: "trust set id", mutate: func(args *TrustSetGenerationArgs) { args.TrustSetID = "bad id" }},
		{name: "generation", mutate: func(args *TrustSetGenerationArgs) { args.Generation = 0 }},
		{name: "generation overflow", mutate: func(args *TrustSetGenerationArgs) { args.Generation = MaximumSequenceNumber + 1 }},
		{name: "missing anchor", mutate: func(args *TrustSetGenerationArgs) { args.AnchorGenerationIDs = nil }},
		{name: "invalid anchor", mutate: func(args *TrustSetGenerationArgs) { args.AnchorGenerationIDs = []GenerationID{"bad id"} }},
		{name: "duplicate anchor", mutate: func(args *TrustSetGenerationArgs) {
			args.AnchorGenerationIDs = []GenerationID{"root-generation-old", "root-generation-old"}
		}},
		{name: "anchor repeated as intermediate", mutate: func(args *TrustSetGenerationArgs) {
			args.IntermediateGenerationIDs = []GenerationID{"root-generation-old"}
		}},
		{name: "invalid intermediate", mutate: func(args *TrustSetGenerationArgs) {
			args.IntermediateGenerationIDs = []GenerationID{"bad id"}
		}},
		{name: "invalid crl", mutate: func(args *TrustSetGenerationArgs) { args.CRLGenerationIDs = []CRLGenerationID{"bad id"} }},
		{name: "duplicate crl", mutate: func(args *TrustSetGenerationArgs) {
			args.CRLGenerationIDs = []CRLGenerationID{"issuer-crl-generation", "issuer-crl-generation"}
		}},
		{name: "too many certificates", mutate: func(args *TrustSetGenerationArgs) {
			args.AnchorGenerationIDs = make([]GenerationID, MaximumTrustSetCertificates+1)
		}},
		{name: "too many crls", mutate: func(args *TrustSetGenerationArgs) {
			args.CRLGenerationIDs = make([]CRLGenerationID, MaximumTrustSetCRLs+1)
		}},
		{name: "creation time", mutate: func(args *TrustSetGenerationArgs) { args.CreatedAt = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := validTrustSetGenerationArgs()
			test.mutate(&args)
			if _, err := NewTrustSetGeneration(args); err == nil {
				t.Fatal("NewTrustSetGeneration() accepted an invalid contract")
			}
		})
	}
}

func validTrustSetArgs() TrustSetArgs {
	createdAt := time.Date(2026, 7, 12, 2, 3, 4, 0, time.UTC)
	return TrustSetArgs{
		ID:                 "trust-edge",
		Name:               "Edge trust",
		ActiveGenerationID: "trust-generation-current",
		State:              TrustSetStateActive,
		Revision:           1,
		CreatedAt:          createdAt,
		UpdatedAt:          createdAt.Add(time.Minute),
	}
}

func validTrustSetGenerationArgs() TrustSetGenerationArgs {
	return TrustSetGenerationArgs{
		ID:                        "trust-generation-current",
		TrustSetID:                "trust-edge",
		Generation:                1,
		AnchorGenerationIDs:       []GenerationID{"root-generation-old"},
		IntermediateGenerationIDs: []GenerationID{"issuer-generation"},
		CRLGenerationIDs:          []CRLGenerationID{"issuer-crl-generation"},
		CreatedAt:                 time.Date(2026, 7, 12, 2, 3, 4, 0, time.UTC),
	}
}
