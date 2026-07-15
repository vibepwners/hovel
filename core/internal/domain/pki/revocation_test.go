package pki

import (
	"strings"
	"testing"
	"time"
)

func TestRevocationReasonValidation(t *testing.T) {
	t.Parallel()

	reasons := []RevocationReason{
		RevocationReasonUnspecified,
		RevocationReasonKeyCompromise,
		RevocationReasonCACompromise,
		RevocationReasonAffiliationChanged,
		RevocationReasonSuperseded,
		RevocationReasonCessationOfOperation,
		RevocationReasonCertificateHold,
		RevocationReasonPrivilegeWithdrawn,
		RevocationReasonAACompromise,
	}
	for _, reason := range reasons {
		if err := reason.Validate(); err != nil {
			t.Errorf("RevocationReason(%q).Validate() error = %v", reason, err)
		}
	}
	if err := RevocationReason("remove-from-crl").Validate(); err == nil {
		t.Fatal("RevocationReason.Validate() accepted an unsupported transition reason")
	}
}

func TestRevocationConstructionAndValidation(t *testing.T) {
	t.Parallel()

	args := validRevocationArgs(t)
	revocation, err := NewRevocation(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := revocation.Validate(); err != nil {
		t.Fatalf("Revocation.Validate() error = %v", err)
	}
	if revocation.EffectiveAt.Nanosecond() != 0 || revocation.RecordedAt.Nanosecond() != 0 {
		t.Fatal("NewRevocation() did not truncate timestamps to whole seconds")
	}
	if revocation.EffectiveAt.Location() != time.UTC || revocation.RecordedAt.Location() != time.UTC {
		t.Fatal("NewRevocation() did not normalize timestamps to UTC")
	}

	noncanonical := revocation
	noncanonical.RecordedAt = noncanonical.RecordedAt.In(time.FixedZone("revocation-test", int(time.Hour/time.Second)))
	if err := noncanonical.Validate(); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("Revocation.Validate() error = %v, want canonical timestamp error", err)
	}

	tests := []struct {
		name   string
		mutate func(*RevocationArgs)
	}{
		{name: "revocation id", mutate: func(args *RevocationArgs) { args.ID = "bad id" }},
		{name: "certificate id", mutate: func(args *RevocationArgs) { args.CertificateID = "bad id" }},
		{name: "generation id", mutate: func(args *RevocationArgs) { args.GenerationID = "bad id" }},
		{name: "issuer authority id", mutate: func(args *RevocationArgs) { args.IssuerAuthorityID = "bad id" }},
		{name: "issuer generation id", mutate: func(args *RevocationArgs) { args.IssuerGenerationID = "bad id" }},
		{name: "serial number", mutate: func(args *RevocationArgs) { args.SerialNumber = "not-hex" }},
		{name: "reason", mutate: func(args *RevocationArgs) { args.Reason = "unknown" }},
		{name: "previous state pending", mutate: func(args *RevocationArgs) { args.PreviousState = CertificateStatePending }},
		{name: "previous state revoked", mutate: func(args *RevocationArgs) { args.PreviousState = CertificateStateRevoked }},
		{name: "effective time", mutate: func(args *RevocationArgs) { args.EffectiveAt = time.Time{} }},
		{name: "recorded time", mutate: func(args *RevocationArgs) { args.RecordedAt = time.Time{} }},
		{name: "effective after recorded", mutate: func(args *RevocationArgs) {
			args.EffectiveAt = args.RecordedAt.Add(time.Second)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := args
			test.mutate(&candidate)
			if _, err := NewRevocation(candidate); err == nil {
				t.Fatal("NewRevocation() accepted an invalid contract")
			}
		})
	}
}

func TestRevokeCertificateGenerationAndValidateTransition(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	generation := revocableTestGeneration(t, now)
	effectiveAt := now.Add(-30 * time.Minute)
	recordedAt := now

	revoked, revocation, err := RevokeCertificateGeneration(
		generation,
		"revocation-certgen-service",
		RevocationReasonKeyCompromise,
		effectiveAt,
		recordedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if generation.State != CertificateStateActive {
		t.Fatal("RevokeCertificateGeneration() mutated its input")
	}
	if revoked.State != CertificateStateRevoked || revocation.PreviousState != CertificateStateActive {
		t.Fatalf("revocation result = state %q, previous %q", revoked.State, revocation.PreviousState)
	}
	if err := ValidateRevocationTransition(generation, revoked, revocation); err != nil {
		t.Fatalf("ValidateRevocationTransition() error = %v", err)
	}

	tampered := revoked.Clone()
	tampered.CertificateDER = append(tampered.CertificateDER, 0)
	if err := ValidateRevocationTransition(generation, tampered, revocation); err == nil {
		t.Fatal("ValidateRevocationTransition() accepted a tampered generation")
	}

	tests := []struct {
		name       string
		generation func() CertificateGeneration
		effective  time.Time
		reason     RevocationReason
		id         RevocationID
		want       string
	}{
		{name: "invalid generation", generation: func() CertificateGeneration {
			candidate := generation.Clone()
			candidate.ID = "bad id"
			return candidate
		}, effective: effectiveAt, reason: RevocationReasonUnspecified, id: "revocation-invalid", want: "id"},
		{name: "nonrevocable state", generation: func() CertificateGeneration {
			candidate := generation.Clone()
			candidate.State = CertificateStatePending
			return candidate
		}, effective: effectiveAt, reason: RevocationReasonUnspecified, id: "revocation-pending", want: "cannot be revoked"},
		{name: "self signed root", generation: func() CertificateGeneration {
			return newTrustTestGeneration(t, trustTestGenerationArgs{
				certificateID: "certificate-root-revocation", generationID: "certgen-root-revocation",
				authorityID: "authority-root-revocation", profileID: ProfileRootModern,
				role: AuthorityRoleRoot, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
			})
		}, effective: effectiveAt, reason: RevocationReasonUnspecified, id: "revocation-root", want: "distrusted"},
		{name: "predates validity", generation: func() CertificateGeneration { return generation },
			effective: generation.Template.NotBefore.Add(-time.Second), reason: RevocationReasonUnspecified,
			id: "revocation-too-early", want: "predate"},
		{name: "invalid reason", generation: func() CertificateGeneration { return generation },
			effective: effectiveAt, reason: "unknown", id: "revocation-reason", want: "reason"},
		{name: "invalid revocation id", generation: func() CertificateGeneration { return generation },
			effective: effectiveAt, reason: RevocationReasonUnspecified, id: "bad id", want: "id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := RevokeCertificateGeneration(
				test.generation(), test.id, test.reason, test.effective, recordedAt,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("RevokeCertificateGeneration() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestApplyGenerationRevocation(t *testing.T) {
	t.Parallel()

	const revokedID GenerationID = "generation-current"
	updatedAt := time.Date(2026, 7, 12, 13, 0, 0, 0, time.UTC)

	active, changed, err := ApplyGenerationRevocation(validAssignment(t, "assignment-active"), revokedID, updatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || active.State != AssignmentStateDegraded || active.Revision != 2 || active.UpdatedAt != updatedAt {
		t.Fatalf("active assignment result = %#v, changed = %v", active, changed)
	}

	stagedArgs := validAssignmentArgs()
	stagedArgs.ID = "assignment-staged"
	stagedArgs.ActiveGenerationID = "generation-other"
	stagedArgs.ActiveTrustGenerationID = "trust-generation-other"
	stagedArgs.StagedGenerationID = revokedID
	stagedArgs.StagedTrustGenerationID = "trust-generation-current"
	staged, err := NewAssignment(stagedArgs)
	if err != nil {
		t.Fatal(err)
	}
	staged, changed, err = ApplyGenerationRevocation(staged, revokedID, updatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || staged.State != AssignmentStateActive || staged.StagedGenerationID != "" || staged.StagedTrustGenerationID != "" {
		t.Fatalf("staged assignment result = %#v, changed = %v", staged, changed)
	}

	for _, state := range []AssignmentState{AssignmentStateDisabled, AssignmentStateRetired} {
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()
			args := validAssignmentArgs()
			args.ID = AssignmentID("assignment-" + state)
			args.State = state
			assignment, err := NewAssignment(args)
			if err != nil {
				t.Fatal(err)
			}
			result, changed, err := ApplyGenerationRevocation(assignment, revokedID, updatedAt)
			if err != nil || changed || result != assignment {
				t.Fatalf("ApplyGenerationRevocation() = (%#v, %v, %v), want unchanged", result, changed, err)
			}
		})
	}

	unrelated, changed, err := ApplyGenerationRevocation(validAssignment(t, "assignment-unrelated"), "generation-unrelated", updatedAt)
	if err != nil || changed || unrelated.State != AssignmentStateActive {
		t.Fatalf("unrelated result = (%#v, %v, %v)", unrelated, changed, err)
	}

	errorTests := []struct {
		name       string
		assignment func() Assignment
		generation GenerationID
		updatedAt  time.Time
		want       string
	}{
		{name: "invalid assignment", assignment: func() Assignment {
			candidate := validAssignment(t, "assignment-invalid")
			candidate.ID = "bad id"
			return candidate
		}, generation: revokedID, updatedAt: updatedAt, want: "id"},
		{name: "invalid generation", assignment: func() Assignment {
			return validAssignment(t, "assignment-invalid-generation")
		}, generation: "bad id", updatedAt: updatedAt, want: "id"},
		{name: "revision exhausted", assignment: func() Assignment {
			candidate := validAssignment(t, "assignment-exhausted")
			candidate.Revision = MaximumSequenceNumber
			return candidate
		}, generation: revokedID, updatedAt: updatedAt, want: "exhausted"},
		{name: "invalid update time", assignment: func() Assignment {
			return validAssignment(t, "assignment-invalid-time")
		}, generation: revokedID, updatedAt: time.Time{}, want: "time"},
	}
	for _, test := range errorTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ApplyGenerationRevocation(test.assignment(), test.generation, test.updatedAt)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ApplyGenerationRevocation() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateGenerationRevocationAssignments(t *testing.T) {
	t.Parallel()

	updatedAt := time.Date(2026, 7, 12, 14, 0, 0, 0, time.UTC)
	current := []Assignment{
		validAssignment(t, "assignment-zeta"),
		validAssignment(t, "assignment-alpha"),
	}
	updates := make([]Assignment, 0, len(current))
	for index := len(current) - 1; index >= 0; index-- {
		updated, changed, err := ApplyGenerationRevocation(current[index], "generation-current", updatedAt)
		if err != nil {
			t.Fatal(err)
		}
		if !changed {
			t.Fatal("ApplyGenerationRevocation() did not produce an expected update")
		}
		updates = append(updates, updated)
	}
	if err := ValidateGenerationRevocationAssignments(current, "generation-current", updatedAt, updates); err != nil {
		t.Fatalf("ValidateGenerationRevocationAssignments() error = %v", err)
	}

	if err := ValidateGenerationRevocationAssignments(current, "generation-current", updatedAt, updates[:1]); err == nil {
		t.Fatal("ValidateGenerationRevocationAssignments() accepted an incomplete update set")
	}
	invalid := current[0]
	invalid.ID = "bad id"
	if err := ValidateGenerationRevocationAssignments([]Assignment{invalid}, "generation-current", updatedAt, nil); err == nil {
		t.Fatal("ValidateGenerationRevocationAssignments() accepted invalid inventory")
	}
}

func validRevocationArgs(t *testing.T) RevocationArgs {
	t.Helper()
	const testNanosecond = 987654321
	now := time.Date(2026, 7, 12, 12, 0, 0, testNanosecond, time.FixedZone("revocation-args", -5*int(time.Hour/time.Second)))
	generation := revocableTestGeneration(t, now.UTC().Truncate(time.Second))
	return RevocationArgs{
		ID: "revocation-certgen-service", CertificateID: generation.CertificateID,
		GenerationID: generation.ID, IssuerAuthorityID: generation.IssuerAuthorityID,
		IssuerGenerationID: generation.IssuerGenerationID, SerialNumber: generation.Template.SerialNumber,
		Reason: RevocationReasonKeyCompromise, PreviousState: generation.State,
		EffectiveAt: now.Add(-30 * time.Minute), RecordedAt: now,
	}
}

func revocableTestGeneration(t *testing.T, now time.Time) CertificateGeneration {
	t.Helper()
	return newTrustTestGeneration(t, trustTestGenerationArgs{
		certificateID: "certificate-service", generationID: "certgen-service",
		authorityID: "authority-service", profileID: ProfileSubordinateModern,
		role: AuthorityRoleSubordinate, issuerAuthorityID: "authority-root",
		issuerGenerationID: "certgen-root", chainGenerationIDs: []GenerationID{"certgen-root"},
		notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour),
	})
}

func validAssignment(t *testing.T, id AssignmentID) Assignment {
	t.Helper()
	args := validAssignmentArgs()
	args.ID = id
	assignment, err := NewAssignment(args)
	if err != nil {
		t.Fatal(err)
	}
	return assignment
}
