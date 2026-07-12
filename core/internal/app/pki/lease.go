package pki

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

const (
	DefaultSigningLeaseDuration = 5 * time.Minute
	MaximumSigningLeaseDuration = 15 * time.Minute
)

var ErrAuthoritySigningLocked = errors.New("pki: authority signing is locked")

type SigningLeaseApprover interface {
	AuthorizeSigningLease(context.Context, domainpki.AuthorityID, time.Duration, AuditContext) error
}

type SigningLease struct {
	AuthorityID domainpki.AuthorityID `json:"authorityId"`
	GrantedAt   time.Time             `json:"grantedAt"`
	ExpiresAt   time.Time             `json:"expiresAt"`
	ActorID     string                `json:"actorId"`
	OperationID string                `json:"operationId"`
}

func (l SigningLease) Validate() error {
	if err := l.AuthorityID.Validate(); err != nil {
		return err
	}
	if l.GrantedAt.IsZero() || l.ExpiresAt.IsZero() || !l.ExpiresAt.After(l.GrantedAt) {
		return errors.New("pki: signing lease requires an ordered grant and expiry time")
	}
	if l.ExpiresAt.Sub(l.GrantedAt) > MaximumSigningLeaseDuration {
		return fmt.Errorf("pki: signing lease exceeds maximum duration %s", MaximumSigningLeaseDuration)
	}
	if err := validateCanonicalAuditText(l.ActorID, "signing lease actor id", maximumAuditIDBytes); err != nil {
		return err
	}
	if err := validateCanonicalAuditText(l.OperationID, "signing lease operation id", maximumAuditIDBytes); err != nil {
		return err
	}
	return nil
}

func (l SigningLease) matches(scope AuditContext) bool {
	return l.ActorID == scope.ActorID && l.OperationID == scope.OperationID
}

type SigningLeaseController interface {
	UnlockSigning(context.Context, domainpki.AuthorityID, time.Duration, AuditContext) (SigningLease, error)
	LockSigning(context.Context, domainpki.AuthorityID, AuditContext) error
	SigningLease(context.Context, domainpki.AuthorityID, AuditContext) (SigningLease, bool, error)
}

type SigningLeaseManager struct {
	mu       sync.Mutex
	clock    Clock
	approver SigningLeaseApprover
	leases   map[domainpki.AuthorityID]SigningLease
}

func NewSigningLeaseManager(clock Clock, approver SigningLeaseApprover) (*SigningLeaseManager, error) {
	if clock == nil || approver == nil {
		return nil, errors.New("pki: signing lease clock and approver are required")
	}
	return &SigningLeaseManager{clock: clock, approver: approver, leases: make(map[domainpki.AuthorityID]SigningLease)}, nil
}

func (m *SigningLeaseManager) UnlockSigning(ctx context.Context, id domainpki.AuthorityID, duration time.Duration, scope AuditContext) (SigningLease, error) {
	if err := ctx.Err(); err != nil {
		return SigningLease{}, err
	}
	if err := id.Validate(); err != nil {
		return SigningLease{}, err
	}
	if err := scope.Validate(); err != nil {
		return SigningLease{}, err
	}
	if duration == 0 {
		duration = DefaultSigningLeaseDuration
	}
	if duration < time.Second || duration > MaximumSigningLeaseDuration {
		return SigningLease{}, fmt.Errorf("pki: signing lease duration must be between %s and %s", time.Second, MaximumSigningLeaseDuration)
	}
	if err := m.approver.AuthorizeSigningLease(ctx, id, duration, scope); err != nil {
		return SigningLease{}, fmt.Errorf("pki: authorize signing lease: %w", err)
	}
	now := m.clock.Now().UTC()
	lease := SigningLease{AuthorityID: id, GrantedAt: now, ExpiresAt: now.Add(duration), ActorID: scope.ActorID, OperationID: scope.OperationID}
	if err := lease.Validate(); err != nil {
		return SigningLease{}, err
	}
	m.mu.Lock()
	m.leases[id] = lease
	m.mu.Unlock()
	return lease, nil
}

func (m *SigningLeaseManager) LockSigning(ctx context.Context, id domainpki.AuthorityID, scope AuditContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := id.Validate(); err != nil {
		return err
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	lease, ok := m.leases[id]
	if ok && !lease.matches(scope) {
		m.mu.Unlock()
		return errors.New("pki: signing lease belongs to another actor or operation")
	}
	delete(m.leases, id)
	m.mu.Unlock()
	return nil
}

func (m *SigningLeaseManager) SigningLease(ctx context.Context, id domainpki.AuthorityID, scope AuditContext) (SigningLease, bool, error) {
	if err := ctx.Err(); err != nil {
		return SigningLease{}, false, err
	}
	if err := id.Validate(); err != nil {
		return SigningLease{}, false, err
	}
	if err := scope.Validate(); err != nil {
		return SigningLease{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	lease, ok := m.leases[id]
	if !ok {
		return SigningLease{}, false, nil
	}
	if !m.clock.Now().UTC().Before(lease.ExpiresAt) {
		delete(m.leases, id)
		return SigningLease{}, false, nil
	}
	if !lease.matches(scope) {
		return SigningLease{}, false, nil
	}
	return lease, true, nil
}

func (m *SigningLeaseManager) AuthorizeSigning(ctx context.Context, id domainpki.AuthorityID, scope AuditContext) error {
	_, active, err := m.SigningLease(ctx, id, scope)
	if err != nil {
		return err
	}
	if !active {
		return ErrAuthoritySigningLocked
	}
	return nil
}

var _ SigningAuthorizer = (*SigningLeaseManager)(nil)
var _ SigningLeaseController = (*SigningLeaseManager)(nil)
