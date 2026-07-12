package daemonlocal

import (
	"testing"

	apppki "github.com/vibepwners/hovel/internal/app/pki"
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
