package daemonlocal

import (
	"context"
	"errors"
	"testing"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
	"github.com/vibepwners/hovel/internal/app/services"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/infra/daemonruntime"
	infrapki "github.com/vibepwners/hovel/internal/infra/pki"
)

func TestWorkspacePKIControlDoesNotBlockLegacyWorkspaceStartup(t *testing.T) {
	t.Parallel()

	control, err := newWorkspacePKIControl(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	status := control.Status(t.Context())
	if status.Initialized || status.Error == "" {
		t.Fatalf("Status() = %#v, want unavailable and uninitialized", status)
	}
	backends, err := control.BackendDescriptors(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(backends) != 1 || backends[0].ID == "" {
		t.Fatalf("BackendDescriptors() = %#v", backends)
	}
}

func TestWithDefaultsInjectsPKICryptoRegistries(t *testing.T) {
	t.Parallel()

	backend := infrapki.NewBackend()
	backends, err := apppki.NewStaticBackendRegistry(backend)
	if err != nil {
		t.Fatal(err)
	}
	validators, err := apppki.NewStaticValidatorRegistry(map[domainpki.BackendID]apppki.Validator{
		backend.Descriptor().ID: infrapki.NewValidator(),
	})
	if err != nil {
		t.Fatal(err)
	}
	args := WithDefaults(daemonruntime.Args{
		PKIBackends:   backends,
		PKIValidators: validators,
	})
	control, err := args.NewPKIControl(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	descriptors, err := control.BackendDescriptors(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptors) != 1 || descriptors[0].ID != backend.Descriptor().ID {
		t.Fatalf("BackendDescriptors() = %#v", descriptors)
	}
}

func TestWithDefaultsRejectsIncompletePKICryptoRegistryInjection(t *testing.T) {
	t.Parallel()

	backends, err := apppki.NewStaticBackendRegistry(infrapki.NewBackend())
	if err != nil {
		t.Fatal(err)
	}
	args := WithDefaults(daemonruntime.Args{PKIBackends: backends})
	if _, err := args.NewPKIControl(t.Context(), t.TempDir()); err == nil {
		t.Fatal("NewPKIControl() accepted an incomplete crypto registry pair")
	}
}

func TestWorkspaceCredentialOperationLeaseRevalidatesAndReleasesExactlyOnce(t *testing.T) {
	t.Parallel()

	inner := &fakeWorkspaceCredentialOperationLease{
		deliveries: domainpki.CredentialOperationDeliveries{},
	}
	releases := 0
	lease, err := newWorkspaceCredentialOperationLease(inner, func() { releases++ })
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := services.NewCredentialOperationResolution(lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolution.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := resolution.BorrowedDeliveries(); err != nil {
		t.Fatal(err)
	}
	resolution.Close()
	resolution.Clear()
	lease.Close()
	if inner.revalidations != 1 || inner.closes != 1 || releases != 1 {
		t.Fatalf(
			"revalidations/closes/releases = %d/%d/%d, want 1/1/1",
			inner.revalidations,
			inner.closes,
			releases,
		)
	}
	if !errors.Is(
		resolution.Revalidate(t.Context()),
		services.ErrCredentialOperationResolutionClosed,
	) {
		t.Fatal("closed workspace credential resolution remained usable")
	}
}

func TestWorkspaceCredentialOperationLeaseRejectsMissingOwnership(t *testing.T) {
	t.Parallel()

	if _, err := newWorkspaceCredentialOperationLease(nil, func() {}); err == nil {
		t.Fatal("newWorkspaceCredentialOperationLease() accepted a nil lease")
	}
	if _, err := newWorkspaceCredentialOperationLease(
		&fakeWorkspaceCredentialOperationLease{},
		nil,
	); err == nil {
		t.Fatal("newWorkspaceCredentialOperationLease() accepted a nil release")
	}
}

type fakeWorkspaceCredentialOperationLease struct {
	deliveries    domainpki.CredentialOperationDeliveries
	revalidations int
	closes        int
	isClosed      bool
}

func (l *fakeWorkspaceCredentialOperationLease) BorrowedDeliveries() (
	domainpki.CredentialOperationDeliveries,
	error,
) {
	if l.isClosed {
		return nil, errors.New("fake workspace credential lease is closed")
	}
	return l.deliveries, nil
}

func (l *fakeWorkspaceCredentialOperationLease) Revalidate(context.Context) error {
	if l.isClosed {
		return errors.New("fake workspace credential lease is closed")
	}
	l.revalidations++
	return nil
}

func (l *fakeWorkspaceCredentialOperationLease) Close() {
	if l.isClosed {
		return
	}
	l.deliveries.Clear()
	l.isClosed = true
	l.closes++
}
