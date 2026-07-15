package pki

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

type uncertainHeartbeatPersistence struct {
	Persistence
	intent CRLPublicationIntent
	loads  int
}

type claimTestMode uint8

const (
	claimTestCommitThenError claimTestMode = iota + 1
	claimTestInvalidFirstResult
)

type uncertainClaimPersistence struct {
	Persistence
	intent                 CRLPublicationIntent
	mode                   claimTestMode
	calls                  int
	loadFailuresAfterClaim int
}

func (p *uncertainClaimPersistence) CRLPublication(
	context.Context,
	domainpki.CRLPublicationID,
) (CRLPublicationIntent, error) {
	if p.calls > 0 && p.loadFailuresAfterClaim > 0 {
		p.loadFailuresAfterClaim--
		return CRLPublicationIntent{}, errors.New("transient claim reload failure")
	}
	return p.intent.Clone(), nil
}

func (p *uncertainClaimPersistence) ClaimCRLPublication(
	_ context.Context,
	_ domainpki.CRLPublicationID,
	_ CRLPublicationOwnership,
	ownerToken string,
	claimedAt time.Time,
) (CRLPublicationIntent, bool, error) {
	p.calls++
	expected, err := ClaimCRLPublicationIntent(p.intent, ownerToken, claimedAt)
	if err != nil {
		return CRLPublicationIntent{}, false, err
	}
	if p.calls == 1 {
		switch p.mode {
		case claimTestCommitThenError:
			p.intent = expected.Clone()
			return CRLPublicationIntent{}, false, errors.New("committed claim response lost")
		case claimTestInvalidFirstResult:
			invalid := expected.Clone()
			invalid.OwnerToken = "unexpected-claim-owner"
			return invalid, true, nil
		}
	}
	p.intent = expected.Clone()
	return expected.Clone(), true, nil
}

func (p *uncertainHeartbeatPersistence) CRLPublication(
	context.Context,
	domainpki.CRLPublicationID,
) (CRLPublicationIntent, error) {
	p.loads++
	if p.loads == 1 {
		return CRLPublicationIntent{}, errors.New("transient reload failure")
	}
	return p.intent.Clone(), nil
}

func (p *uncertainHeartbeatPersistence) RenewCRLPublicationLease(
	_ context.Context,
	_ domainpki.CRLPublicationID,
	ownership CRLPublicationOwnership,
	renewedAt time.Time,
) (CRLPublicationIntent, error) {
	if err := ValidateCRLPublicationOwnership(p.intent, ownership); err != nil {
		return CRLPublicationIntent{}, err
	}
	renewed, err := RenewCRLPublicationLeaseIntent(p.intent, renewedAt)
	if err != nil {
		return CRLPublicationIntent{}, err
	}
	p.intent = renewed.Clone()
	return renewed, nil
}

type crlTestClock struct{ now time.Time }

func (c crlTestClock) Now() time.Time { return c.now }

func TestCRLPublicationSignedCheckpointStateMachine(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC)
	intent := CRLPublicationIntent{
		ID: "crl-publication-state", IdempotencyKey: "test:crl-state",
		RequestSHA256: strings.Repeat("a", sha256.Size*2), CRLGenerationID: "crl-state",
		AuthorityID: "authority-state", IssuerGenerationID: "certgen-state", Number: 1,
		ThisUpdate: createdAt, NextUpdate: createdAt.Add(time.Hour),
		SigningBackendID: "backend-state", SigningBackendVersion: "1",
		SigningBackendCapabilityHash: strings.Repeat("b", sha256.Size*2),
		SignatureAlgorithm:           domainpki.SignatureAlgorithmECDSASHA256,
		Status:                       CRLPublicationStatusPending, Phase: CRLPublicationPhasePlanned,
		OwnerToken: "worker-state", Revision: 1, LeaseExpiresAt: createdAt.Add(DefaultCRLLease),
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	signing, err := StartCRLPublicationSigningIntent(intent, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenewCRLPublicationLeaseIntent(signing, signing.LeaseExpiresAt); err == nil {
		t.Fatal("RenewCRLPublicationLeaseIntent() revived an expired ownership lease")
	}
	encoded := []byte{1, 2, 3, 4}
	digest := sha256.Sum256(encoded)
	checkpoint, err := NewCRLSignedCheckpoint(IssuedCRL{
		CRLDER: encoded, FingerprintSHA256: hex.EncodeToString(digest[:]),
		SignatureAlgorithm:   domainpki.SignatureAlgorithmECDSASHA256,
		ProviderOperationRef: "provider-operation-7",
	}, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	renewedAt := createdAt.Add(time.Minute)
	signing, err = RenewCRLPublicationLeaseIntent(signing, renewedAt)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := CheckpointCRLPublicationSignedIntent(signing, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !signed.UpdatedAt.Equal(renewedAt) {
		t.Fatalf("signed checkpoint update time = %s, want lease renewal %s", signed.UpdatedAt, renewedAt)
	}
	clone := signed.Clone()
	clone.SignedCheckpoint.CRLDER[0] ^= 0xff
	if signed.SignedCheckpoint.CRLDER[0] != encoded[0] {
		t.Fatal("CRLPublicationIntent.Clone() retained signed checkpoint DER alias")
	}
	if _, err := CompleteCRLPublicationIntent(signed, signed.NextUpdate); err == nil {
		t.Fatal("CompleteCRLPublicationIntent() accepted completion at nextUpdate")
	}
	completed, err := CompleteCRLPublicationIntent(signed, signed.NextUpdate.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != CRLPublicationStatusCompleted || completed.Phase != CRLPublicationPhaseSigned {
		t.Fatalf("completed intent = %#v", completed)
	}
}

func TestServiceRetainsSignedOutputAcrossUncertainHeartbeatReload(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	intent := CRLPublicationIntent{
		ID: "crl-publication-heartbeat", IdempotencyKey: "test:crl-heartbeat",
		RequestSHA256: strings.Repeat("a", sha256.Size*2), CRLGenerationID: "crl-heartbeat",
		AuthorityID: "authority-heartbeat", IssuerGenerationID: "certgen-heartbeat", Number: 1,
		ThisUpdate: createdAt, NextUpdate: createdAt.Add(time.Hour),
		SigningBackendID: "backend-heartbeat", SigningBackendVersion: "1",
		SigningBackendCapabilityHash: strings.Repeat("b", sha256.Size*2),
		SignatureAlgorithm:           domainpki.SignatureAlgorithmECDSASHA256,
		Status:                       CRLPublicationStatusPending, Phase: CRLPublicationPhaseSigning,
		OwnerToken: "worker-heartbeat", Revision: 2, LeaseExpiresAt: createdAt.Add(DefaultCRLLease),
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	heartbeatRenewed, err := RenewCRLPublicationLeaseIntent(intent, createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	persistence := &uncertainHeartbeatPersistence{intent: heartbeatRenewed}
	done := make(chan struct{})
	close(done)
	lease := &crlPublicationLease{
		cancel: func() {}, done: done, intent: intent,
		err: errors.New("heartbeat renewal response lost"),
	}
	service := Service{persistence: persistence, clock: crlTestClock{now: createdAt.Add(2 * time.Minute)}}
	fenced, err := service.stopAndFenceCRLPublicationLease(
		t.Context(), lease, crlLeaseResolutionUntilOwnershipChanges,
	)
	if err != nil {
		t.Fatal(err)
	}
	if fenced.Revision != heartbeatRenewed.Revision+1 || persistence.loads != 2 {
		t.Fatalf("fenced intent = %#v after %d loads", fenced, persistence.loads)
	}
}

func TestCRLOwnedTransitionBudgetLeavesLeaseSafetyMargin(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	service := Service{clock: crlTestClock{now: now}}
	intent := CRLPublicationIntent{LeaseExpiresAt: now.Add(DefaultCRLLease)}
	ctx, cancel, err := service.crlOwnedTransitionContext(t.Context(), intent)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("owned transition context has no deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > crlTransitionTimeout {
		t.Fatalf("owned transition timeout = %s, want at most %s", remaining, crlTransitionTimeout)
	}
	if crlTransitionTimeout+crlLeaseSafetyMargin >= DefaultCRLLease {
		t.Fatal("owned transition budget leaves no lease safety margin")
	}
	if _, _, err := service.crlOwnedTransitionContext(t.Context(), CRLPublicationIntent{
		LeaseExpiresAt: now.Add(crlLeaseSafetyMargin),
	}); err == nil {
		t.Fatal("crlOwnedTransitionContext() accepted an exhausted lease budget")
	}
}

func TestServiceReacquiresOnlyExactCRLClaimTransition(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name                   string
		mode                   claimTestMode
		loadFailuresAfterClaim int
		wantCalls              int
	}{
		{name: "commit then error", mode: claimTestCommitThenError, wantCalls: 1},
		{
			name: "commit then error with transient reload", mode: claimTestCommitThenError,
			loadFailuresAfterClaim: 1, wantCalls: 1,
		},
		{name: "invalid first result", mode: claimTestInvalidFirstResult, wantCalls: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			createdAt := time.Date(2026, 7, 12, 11, 0, 0, 0, time.UTC)
			intent := CRLPublicationIntent{
				ID: "crl-publication-claim", IdempotencyKey: "test:crl-claim",
				RequestSHA256: strings.Repeat("a", sha256.Size*2), CRLGenerationID: "crl-claim",
				AuthorityID: "authority-claim", IssuerGenerationID: "certgen-claim", Number: 1,
				ThisUpdate: createdAt, NextUpdate: createdAt.Add(time.Hour),
				SigningBackendID: "backend-claim", SigningBackendVersion: "1",
				SigningBackendCapabilityHash: strings.Repeat("b", sha256.Size*2),
				SignatureAlgorithm:           domainpki.SignatureAlgorithmECDSASHA256,
				Status:                       CRLPublicationStatusPending, Phase: CRLPublicationPhaseSigning,
				OwnerToken: "worker-claim", Revision: 2, LeaseExpiresAt: createdAt.Add(DefaultCRLLease),
				CreatedAt: createdAt, UpdatedAt: createdAt,
			}
			persistence := &uncertainClaimPersistence{
				intent: intent, mode: test.mode, loadFailuresAfterClaim: test.loadFailuresAfterClaim,
			}
			service := Service{
				persistence: persistence, clock: crlTestClock{now: intent.LeaseExpiresAt},
				random: strings.NewReader(strings.Repeat("r", 256)), randomMu: &sync.Mutex{},
			}
			claimed, err := service.reacquireCRLPublicationOwnership(t.Context(), intent)
			if err != nil {
				t.Fatal(err)
			}
			if !crlPublicationIntentsEqual(claimed, persistence.intent) || persistence.calls != test.wantCalls {
				t.Fatalf("claimed intent = %#v after %d calls", claimed, persistence.calls)
			}
		})
	}
}
