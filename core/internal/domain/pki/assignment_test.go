package pki

import (
	"testing"
	"time"
)

func TestConsumerTypes(t *testing.T) {
	t.Parallel()

	valid := []ConsumerType{
		ConsumerMeshProvider,
		ConsumerMeshListener,
		ConsumerListeningPost,
		ConsumerMeshNode,
		ConsumerImplant,
		ConsumerStager,
		ConsumerPayload,
		ConsumerC2Service,
		ConsumerService,
		ConsumerExternal,
	}
	for _, consumerType := range valid {
		if err := consumerType.Validate(); err != nil {
			t.Errorf("ConsumerType(%q).Validate() error = %v", consumerType, err)
		}
	}
	if err := ConsumerType("unknown").Validate(); err == nil {
		t.Fatal("ConsumerType.Validate() accepted an unknown value")
	}
}

func TestAssignmentStatesAndGenerationInvariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		state    AssignmentState
		activeID GenerationID
		stagedID GenerationID
	}{
		{name: "pending empty", state: AssignmentStatePending},
		{name: "pending staged", state: AssignmentStatePending, stagedID: "generation-next"},
		{name: "active", state: AssignmentStateActive, activeID: "generation-current"},
		{name: "active staged", state: AssignmentStateActive, activeID: "generation-current", stagedID: "generation-next"},
		{name: "degraded", state: AssignmentStateDegraded, activeID: "generation-current"},
		{name: "disabled empty", state: AssignmentStateDisabled},
		{name: "disabled retains active", state: AssignmentStateDisabled, activeID: "generation-current"},
		{name: "retired empty", state: AssignmentStateRetired},
		{name: "retired retains active", state: AssignmentStateRetired, activeID: "generation-current"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := validAssignmentArgs()
			args.State = test.state
			args.ActiveGenerationID = test.activeID
			args.StagedGenerationID = test.stagedID
			args.ActiveTrustGenerationID = trustGenerationFor(test.activeID)
			args.StagedTrustGenerationID = trustGenerationFor(test.stagedID)
			assignment, err := NewAssignment(args)
			if err != nil {
				t.Fatal(err)
			}
			if err := assignment.Validate(); err != nil {
				t.Fatalf("Assignment.Validate() error = %v", err)
			}
		})
	}

	invalid := []struct {
		name     string
		state    AssignmentState
		activeID GenerationID
		stagedID GenerationID
	}{
		{name: "pending active", state: AssignmentStatePending, activeID: "generation-current"},
		{name: "active empty", state: AssignmentStateActive},
		{name: "degraded empty", state: AssignmentStateDegraded},
		{name: "disabled staged", state: AssignmentStateDisabled, stagedID: "generation-next"},
		{name: "retired staged", state: AssignmentStateRetired, stagedID: "generation-next"},
		{name: "same active and staged", state: AssignmentStateActive, activeID: "generation-current", stagedID: "generation-current"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := validAssignmentArgs()
			args.State = test.state
			args.ActiveGenerationID = test.activeID
			args.StagedGenerationID = test.stagedID
			args.ActiveTrustGenerationID = trustGenerationFor(test.activeID)
			args.StagedTrustGenerationID = trustGenerationFor(test.stagedID)
			if _, err := NewAssignment(args); err == nil {
				t.Fatal("NewAssignment() accepted invalid generation state")
			}
		})
	}

	if err := AssignmentState("unknown").Validate(); err == nil {
		t.Fatal("AssignmentState.Validate() accepted an unknown value")
	}
}

func TestAssignmentTrustRequirements(t *testing.T) {
	t.Parallel()

	requiringTrust := []Purpose{
		PurposeTLSClient,
		PurposeMTLSServer,
		PurposeMTLSClient,
		PurposeDualRoleMTLS,
	}
	for _, purpose := range requiringTrust {
		args := validAssignmentArgs()
		args.Purpose = purpose
		args.TrustSetID = ""
		args.ActiveTrustGenerationID = ""
		if _, err := NewAssignment(args); err == nil {
			t.Errorf("NewAssignment() accepted purpose %q without a trust set", purpose)
		}
		if !purpose.RequiresPeerTrust() {
			t.Errorf("Purpose(%q).RequiresPeerTrust() = false", purpose)
		}
	}

	withoutRequiredTrust := []Purpose{PurposeTLSServer, PurposeCodeSigning, PurposeCustom}
	for _, purpose := range withoutRequiredTrust {
		args := validAssignmentArgs()
		args.Purpose = purpose
		args.TrustSetID = ""
		args.ActiveTrustGenerationID = ""
		if _, err := NewAssignment(args); err != nil {
			t.Errorf("NewAssignment() rejected purpose %q without a trust set: %v", purpose, err)
		}
		if purpose.RequiresPeerTrust() {
			t.Errorf("Purpose(%q).RequiresPeerTrust() = true", purpose)
		}
	}
}

func TestAssignmentRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*AssignmentArgs)
	}{
		{name: "id", mutate: func(args *AssignmentArgs) { args.ID = "bad id" }},
		{name: "purpose", mutate: func(args *AssignmentArgs) { args.Purpose = "unknown" }},
		{name: "consumer type", mutate: func(args *AssignmentArgs) { args.ConsumerType = "unknown" }},
		{name: "consumer id", mutate: func(args *AssignmentArgs) { args.ConsumerID = "bad id" }},
		{name: "consumer id control", mutate: func(args *AssignmentArgs) { args.ConsumerID = "mesh-listener:bad\nvalue" }},
		{name: "profile", mutate: func(args *AssignmentArgs) { args.ProfileID = "bad id" }},
		{name: "active generation", mutate: func(args *AssignmentArgs) { args.ActiveGenerationID = "bad id" }},
		{name: "staged generation", mutate: func(args *AssignmentArgs) { args.StagedGenerationID = "bad id" }},
		{name: "trust set", mutate: func(args *AssignmentArgs) { args.TrustSetID = "bad id" }},
		{name: "active trust generation", mutate: func(args *AssignmentArgs) { args.ActiveTrustGenerationID = "bad id" }},
		{name: "staged trust generation", mutate: func(args *AssignmentArgs) { args.StagedTrustGenerationID = "bad id" }},
		{name: "rotation policy", mutate: func(args *AssignmentArgs) { args.RotationPolicyID = "bad id" }},
		{name: "state", mutate: func(args *AssignmentArgs) { args.State = "unknown" }},
		{name: "revision", mutate: func(args *AssignmentArgs) { args.Revision = 0 }},
		{name: "revision overflow", mutate: func(args *AssignmentArgs) { args.Revision = MaximumSequenceNumber + 1 }},
		{name: "updated at", mutate: func(args *AssignmentArgs) { args.UpdatedAt = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			args := validAssignmentArgs()
			test.mutate(&args)
			if _, err := NewAssignment(args); err == nil {
				t.Fatal("NewAssignment() accepted an invalid contract")
			}
		})
	}
}

func TestAssignmentValidateRejectsNoncanonicalTime(t *testing.T) {
	t.Parallel()

	assignment, err := NewAssignment(validAssignmentArgs())
	if err != nil {
		t.Fatal(err)
	}
	assignment.UpdatedAt = assignment.UpdatedAt.In(time.FixedZone("noncanonical", int(time.Hour/time.Second)))
	if err := assignment.Validate(); err == nil {
		t.Fatal("Assignment.Validate() accepted a noncanonical timestamp")
	}
}

func TestAssignmentNormalizesUpdateTime(t *testing.T) {
	t.Parallel()

	location := time.FixedZone("assignment-test", -7*60*60)
	args := validAssignmentArgs()
	args.UpdatedAt = time.Date(2026, 7, 12, 4, 5, 6, 7, location)
	assignment, err := NewAssignment(args)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.UpdatedAt.Location() != time.UTC {
		t.Fatalf("Assignment.UpdatedAt location = %v, want UTC", assignment.UpdatedAt.Location())
	}
}

func validAssignmentArgs() AssignmentArgs {
	return AssignmentArgs{
		ID:                      "assignment-edge-listener",
		Purpose:                 PurposeMTLSServer,
		ConsumerType:            ConsumerMeshListener,
		ConsumerID:              "mesh-provider/listener-edge",
		ProfileID:               ProfileMTLSServer,
		ActiveGenerationID:      "generation-current",
		TrustSetID:              "trust-edge",
		ActiveTrustGenerationID: "trust-generation-current",
		RotationPolicyID:        "rotation-default",
		State:                   AssignmentStateActive,
		Revision:                1,
		UpdatedAt:               time.Date(2026, 7, 12, 1, 2, 3, 0, time.UTC),
	}
}

func trustGenerationFor(id GenerationID) TrustSetGenerationID {
	if id == "" {
		return ""
	}
	return TrustSetGenerationID("trust-" + id)
}
