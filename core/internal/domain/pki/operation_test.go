package pki

import (
	"slices"
	"testing"
	"time"
)

func TestOperationNormalizesAndDefensivelyCopiesRolloverAssignments(t *testing.T) {
	t.Parallel()

	args := validOperationArgs()
	args.AuthorityRollover.RequiredAssignmentIDs = []AssignmentID{"assignment-z", "assignment-a"}
	operation, err := NewOperation(args)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(operation.AuthorityRollover.RequiredAssignmentIDs, []AssignmentID{"assignment-a", "assignment-z"}) {
		t.Fatalf("required assignments = %v", operation.AuthorityRollover.RequiredAssignmentIDs)
	}
	args.AuthorityRollover.RequiredAssignmentIDs[0] = "assignment-mutated"
	if operation.AuthorityRollover.RequiredAssignmentIDs[0] != "assignment-a" {
		t.Fatal("NewOperation() retained caller-owned required assignments")
	}
	clone := operation.Clone()
	clone.AuthorityRollover.RequiredAssignmentIDs[0] = "assignment-clone"
	if operation.AuthorityRollover.RequiredAssignmentIDs[0] != "assignment-a" {
		t.Fatal("Operation.Clone() aliased required assignments")
	}
	if err := operation.Validate(); err != nil {
		t.Fatalf("Operation.Validate() error = %v", err)
	}
}

func TestOperationRejectsInvalidTypedRolloverStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*OperationArgs)
	}{
		{name: "same authority", mutate: func(args *OperationArgs) {
			args.AuthorityRollover.ReplacementAuthorityID = args.AuthorityRollover.PreviousAuthorityID
		}},
		{name: "explicit tracking without assignments", mutate: func(args *OperationArgs) {
			args.AuthorityRollover.RequiredAssignmentIDs = nil
		}},
		{name: "none tracking with assignments", mutate: func(args *OperationArgs) {
			args.AuthorityRollover.ConsumerTracking = RolloverConsumerTrackingNone
		}},
		{name: "wrong phase status", mutate: func(args *OperationArgs) {
			args.Status = OperationStatusCompleted
			args.CompletedAt = args.UpdatedAt
		}},
		{name: "missing final trust generation", mutate: func(args *OperationArgs) {
			args.AuthorityRollover.Phase = AuthorityRolloverPhaseCompleted
			args.Status = OperationStatusCompleted
			args.CompletedAt = args.UpdatedAt
		}},
		{name: "completed phase failed", mutate: func(args *OperationArgs) {
			args.AuthorityRollover.Phase = AuthorityRolloverPhaseCompleted
			args.AuthorityRollover.FinalTrustGenerationID = "trustgen-final"
			args.Status = OperationStatusFailed
			args.Failure = "rollover failed"
			args.CompletedAt = args.UpdatedAt
		}},
		{name: "failure on waiting operation", mutate: func(args *OperationArgs) {
			args.Failure = "unexpected failure"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := validOperationArgs()
			test.mutate(&args)
			if _, err := NewOperation(args); err == nil {
				t.Fatal("NewOperation() accepted an invalid typed state")
			}
		})
	}
}

func TestConsumerAcknowledgementValidation(t *testing.T) {
	t.Parallel()

	args := validConsumerAcknowledgementArgs()
	args.EvidenceRef = "  provider-receipt:17  "
	acknowledgement, err := NewConsumerAcknowledgement(args)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledgement.EvidenceRef != "provider-receipt:17" {
		t.Fatalf("evidence ref = %q", acknowledgement.EvidenceRef)
	}
	if err := acknowledgement.Validate(); err != nil {
		t.Fatalf("ConsumerAcknowledgement.Validate() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ConsumerAcknowledgementArgs)
	}{
		{name: "operation", mutate: func(args *ConsumerAcknowledgementArgs) { args.OperationID = "bad id" }},
		{name: "assignment", mutate: func(args *ConsumerAcknowledgementArgs) { args.AssignmentID = "bad id" }},
		{name: "kind", mutate: func(args *ConsumerAcknowledgementArgs) { args.Kind = "unknown" }},
		{name: "trust generation", mutate: func(args *ConsumerAcknowledgementArgs) { args.TrustSetGenerationID = "bad id" }},
		{name: "evidence control", mutate: func(args *ConsumerAcknowledgementArgs) { args.EvidenceRef = "bad\nref" }},
		{name: "time", mutate: func(args *ConsumerAcknowledgementArgs) { args.AcknowledgedAt = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := validConsumerAcknowledgementArgs()
			test.mutate(&args)
			if _, err := NewConsumerAcknowledgement(args); err == nil {
				t.Fatal("NewConsumerAcknowledgement() accepted an invalid contract")
			}
		})
	}
}

func TestAuthorityRolloverTypedTransitions(t *testing.T) {
	t.Parallel()

	overlap, err := NewOperation(validOperationArgs())
	if err != nil {
		t.Fatal(err)
	}
	if target, err := overlap.AuthorityRollover.ActiveAcknowledgementTarget(); err != nil ||
		target != overlap.AuthorityRollover.OverlapTrustGenerationID {
		t.Fatalf("overlap acknowledgement target = %q, %v", target, err)
	}

	leafArgs := OperationArgs(overlap)
	leafArgs.Revision++
	leafArgs.UpdatedAt = leafArgs.UpdatedAt.Add(time.Minute)
	leafRollover := overlap.AuthorityRollover.Clone()
	leafRollover.Phase = AuthorityRolloverPhaseAwaitingLeafRotation
	leafArgs.AuthorityRollover = &leafRollover
	leaf, err := NewOperation(leafArgs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverTransition(
		overlap, leaf, AuthorityRolloverTransitionActivateOverlap,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.AuthorityRollover.ActiveAcknowledgementTarget(); err == nil {
		t.Fatal("leaf-rotation phase exposed an acknowledgement target")
	}
	lateCancellationArgs := OperationArgs(leaf)
	lateCancellationArgs.Revision++
	lateCancellationArgs.Status = OperationStatusCanceled
	lateCancellationArgs.UpdatedAt = lateCancellationArgs.UpdatedAt.Add(30 * time.Second)
	lateCancellationArgs.CompletedAt = lateCancellationArgs.UpdatedAt
	lateCancellation, err := NewOperation(lateCancellationArgs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverTransition(
		leaf, lateCancellation, AuthorityRolloverTransitionCancel,
	); err == nil {
		t.Fatal("ValidateAuthorityRolloverTransition() accepted cancellation after overlap activation")
	}
	canceledArgs := OperationArgs(overlap)
	canceledArgs.Revision++
	canceledArgs.Status = OperationStatusCanceled
	canceledArgs.UpdatedAt = canceledArgs.UpdatedAt.Add(30 * time.Second)
	canceledArgs.CompletedAt = canceledArgs.UpdatedAt
	canceled, err := NewOperation(canceledArgs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverTransition(
		overlap, canceled, AuthorityRolloverTransitionCancel,
	); err != nil {
		t.Fatal(err)
	}
	if canceled.AuthorityRollover.Phase != overlap.AuthorityRollover.Phase {
		t.Fatal("cancellation changed the recorded rollover phase")
	}

	finalArgs := OperationArgs(leaf)
	finalArgs.Revision++
	finalArgs.UpdatedAt = finalArgs.UpdatedAt.Add(time.Minute)
	finalRollover := leaf.AuthorityRollover.Clone()
	finalRollover.Phase = AuthorityRolloverPhaseAwaitingFinalAcknowledgements
	finalRollover.FinalTrustGenerationID = "trustgen-final"
	finalArgs.AuthorityRollover = &finalRollover
	final, err := NewOperation(finalArgs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverTransition(
		leaf, final, AuthorityRolloverTransitionBeginFinalTrust,
	); err != nil {
		t.Fatal(err)
	}
	if target, err := final.AuthorityRollover.ActiveAcknowledgementTarget(); err != nil ||
		target != final.AuthorityRollover.FinalTrustGenerationID {
		t.Fatalf("final acknowledgement target = %q, %v", target, err)
	}

	completedArgs := OperationArgs(final)
	completedArgs.Revision++
	completedArgs.Status = OperationStatusCompleted
	completedArgs.UpdatedAt = completedArgs.UpdatedAt.Add(time.Minute)
	completedArgs.CompletedAt = completedArgs.UpdatedAt
	completedRollover := final.AuthorityRollover.Clone()
	completedRollover.Phase = AuthorityRolloverPhaseCompleted
	completedArgs.AuthorityRollover = &completedRollover
	completed, err := NewOperation(completedArgs)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverTransition(
		final, completed, AuthorityRolloverTransitionComplete,
	); err != nil {
		t.Fatal(err)
	}

	illegal := completed.Clone()
	illegal.AuthorityRollover.FinalTrustGenerationID = "trustgen-other"
	if err := ValidateAuthorityRolloverTransition(
		final, illegal, AuthorityRolloverTransitionComplete,
	); err == nil {
		t.Fatal("completion accepted a changed final trust generation")
	}
	if err := ValidateAuthorityRolloverTransition(
		completed, canceled, AuthorityRolloverTransitionCancel,
	); err == nil {
		t.Fatal("cancellation accepted a completed rollover")
	}
}

func TestAuthorityRolloverAggregateTransition(t *testing.T) {
	t.Parallel()

	previousOperation, err := NewOperation(validOperationArgs())
	if err != nil {
		t.Fatal(err)
	}
	nextOperationArgs := OperationArgs(previousOperation)
	nextOperationArgs.Revision++
	nextOperationArgs.UpdatedAt = nextOperationArgs.UpdatedAt.Add(time.Minute)
	nextRollover := previousOperation.AuthorityRollover.Clone()
	nextRollover.Phase = AuthorityRolloverPhaseAwaitingLeafRotation
	nextOperationArgs.AuthorityRollover = &nextRollover
	nextOperation, err := NewOperation(nextOperationArgs)
	if err != nil {
		t.Fatal(err)
	}
	previousAuthority, err := NewAuthority(AuthorityArgs{
		ID: "authority-old", Name: "Old authority", Role: AuthorityRoleRoot,
		Origin: OriginGenerated, SignerMode: SignerModeLocal, State: AuthorityStateActive,
		ActiveGenerationID: "generation-old", ProfileID: ProfileRootModern,
		SignerRef: "key-old", ExportPolicy: ExportPolicyNever,
		CreatedAt: previousOperation.CreatedAt, UpdatedAt: previousOperation.CreatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	nextAuthority := previousAuthority.Clone()
	nextAuthority.State = AuthorityStateRetiring
	nextAuthority.UpdatedAt = nextOperation.UpdatedAt
	previousTrustSet, err := NewTrustSet(TrustSetArgs{
		ID: "trust-rollover", Name: "Rollover trust", ActiveGenerationID: "trustgen-initial",
		StagedGenerationID: "trustgen-overlap", State: TrustSetStateActive, Revision: 3,
		CreatedAt: previousOperation.CreatedAt, UpdatedAt: previousOperation.CreatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	nextTrustSet := previousTrustSet
	nextTrustSet.ActiveGenerationID = previousTrustSet.StagedGenerationID
	nextTrustSet.StagedGenerationID = ""
	nextTrustSet.Revision++
	nextTrustSet.UpdatedAt = nextOperation.UpdatedAt
	if err := ValidateAuthorityRolloverAggregateTransition(
		previousOperation, nextOperation, previousAuthority, nextAuthority,
		previousTrustSet, nextTrustSet, AuthorityRolloverTransitionActivateOverlap,
	); err != nil {
		t.Fatal(err)
	}

	invalidAuthority := nextAuthority.Clone()
	invalidAuthority.State = AuthorityStateRetired
	if err := ValidateAuthorityRolloverAggregateTransition(
		previousOperation, nextOperation, previousAuthority, invalidAuthority,
		previousTrustSet, nextTrustSet, AuthorityRolloverTransitionActivateOverlap,
	); err == nil {
		t.Fatal("overlap activation accepted direct authority retirement")
	}
	compromisedPrevious := previousAuthority.Clone()
	compromisedPrevious.State = AuthorityStateCompromised
	compromisedNext := compromisedPrevious.Clone()
	compromisedNext.UpdatedAt = nextOperation.UpdatedAt
	if err := ValidateAuthorityRolloverAggregateTransition(
		previousOperation, nextOperation, compromisedPrevious, compromisedNext,
		previousTrustSet, nextTrustSet, AuthorityRolloverTransitionActivateOverlap,
	); err != nil {
		t.Fatalf("compromised authority state was not preserved: %v", err)
	}
}

func TestAuthorityRolloverTrustPlacementFollowsAuthorityRole(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 16, 0, 0, 0, time.UTC)
	newSubordinate := func(id AuthorityID, generationID GenerationID) Authority {
		authority, err := NewAuthority(AuthorityArgs{
			ID: id, Name: string(id), Role: AuthorityRoleSubordinate,
			Origin: OriginGenerated, SignerMode: SignerModeLocal, ParentAuthorityID: "authority-parent",
			State: AuthorityStateActive, ActiveGenerationID: generationID, ProfileID: ProfileSubordinateModern,
			SignerRef: "key-" + string(id), ExportPolicy: ExportPolicyNever,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		})
		if err != nil {
			t.Fatal(err)
		}
		return authority
	}
	previous := newSubordinate("authority-sub-old", "generation-sub-old")
	replacement := newSubordinate("authority-sub-new", "generation-sub-new")
	overlap, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-sub-overlap", TrustSetID: "trust-sub", Generation: 1,
		AnchorGenerationIDs: []GenerationID{"generation-parent"},
		IntermediateGenerationIDs: []GenerationID{
			previous.ActiveGenerationID, replacement.ActiveGenerationID,
		},
		CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverOverlapTrust(overlap, previous, replacement); err != nil {
		t.Fatal(err)
	}
	final, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-sub-final", TrustSetID: "trust-sub", Generation: 2,
		AnchorGenerationIDs:       []GenerationID{"generation-parent"},
		IntermediateGenerationIDs: []GenerationID{replacement.ActiveGenerationID},
		CreatedAt:                 createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverFinalTrust(final, previous, replacement); err != nil {
		t.Fatal(err)
	}
	wrongPlacement, err := NewTrustSetGeneration(TrustSetGenerationArgs{
		ID: "trustgen-sub-wrong", TrustSetID: "trust-sub", Generation: 3,
		AnchorGenerationIDs: []GenerationID{previous.ActiveGenerationID, replacement.ActiveGenerationID},
		CreatedAt:           createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuthorityRolloverOverlapTrust(wrongPlacement, previous, replacement); err == nil {
		t.Fatal("subordinate rollover accepted authority certificates as trust anchors")
	}

	sameGeneration := replacement.Clone()
	sameGeneration.ActiveGenerationID = previous.ActiveGenerationID
	if err := ValidateAuthorityRolloverAuthorities(previous, sameGeneration); err == nil {
		t.Fatal("rollover accepted authorities sharing one active generation")
	}
}

func validOperationArgs() OperationArgs {
	createdAt := time.Date(2026, 7, 12, 13, 0, 0, 0, time.UTC)
	rollover := AuthorityRollover{
		PreviousAuthorityID: "authority-old", PreviousAuthorityGenerationID: "generation-old",
		ReplacementAuthorityID: "authority-new", ReplacementAuthorityGenerationID: "generation-new",
		TrustSetID: "trust-rollover", OverlapTrustGenerationID: "trustgen-overlap",
		ConsumerTracking:      RolloverConsumerTrackingExplicit,
		RequiredAssignmentIDs: []AssignmentID{"assignment-a"},
		Phase:                 AuthorityRolloverPhaseAwaitingOverlapAcknowledgements,
	}
	return OperationArgs{
		ID: "operation-rollover", Kind: OperationKindAuthorityRollover,
		Status: OperationStatusWaiting, Revision: 1, AuthorityRollover: &rollover,
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

func validConsumerAcknowledgementArgs() ConsumerAcknowledgementArgs {
	return ConsumerAcknowledgementArgs{
		ID: "ack-rollover", OperationID: "operation-rollover", AssignmentID: "assignment-a",
		ConsumerType: ConsumerMeshNode, ConsumerID: "mesh-node:a",
		Kind: AcknowledgementKindTrustSetGeneration, TrustSetGenerationID: "trustgen-overlap",
		AcknowledgedAt: time.Date(2026, 7, 12, 13, 5, 0, 0, time.UTC),
	}
}
