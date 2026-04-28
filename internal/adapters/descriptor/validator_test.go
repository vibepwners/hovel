package descriptor

import (
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/domain/module"
	"github.com/Vibe-Pwners/hovel/internal/domain/service"
)

// ---------------------------------------------------------------------------
// Module descriptor tests
// ---------------------------------------------------------------------------

func TestValidateModuleDescriptorAcceptsValidMinimal(t *testing.T) {
	data := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Module",
		"metadata": {"name": "ssh-survey", "version": "0.1.0"},
		"spec": {
			"runtime": {"type": "python-rpc", "entrypoint": "python -m hovel_ssh_survey"},
			"moduleType": "survey"
		}
	}`)

	got, err := ValidateModuleDescriptor(data)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.Name != module.Name("ssh-survey") {
		t.Errorf("Name = %q, want %q", got.Name, "ssh-survey")
	}
	if got.Version != module.Version("0.1.0") {
		t.Errorf("Version = %q, want %q", got.Version, "0.1.0")
	}
	if got.Type != module.Type("survey") {
		t.Errorf("Type = %q, want %q", got.Type, "survey")
	}
	wantID := "ssh-survey@0.1.0"
	if got.ID != module.ID(wantID) {
		t.Errorf("ID = %q, want %q", got.ID, wantID)
	}
}

func TestValidateModuleDescriptorRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name: "missing apiVersion",
			json: `{
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-rpc", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong apiVersion",
			json: `{
				"apiVersion": "hovel.dev/v2",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-rpc", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong kind",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-rpc", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "invalid kind",
		},
		{
			name: "missing metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"version": "0.1.0"},
				"spec": {"runtime": {"type": "python-rpc", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "metadata.name is required",
		},
		{
			name: "missing metadata version",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey"},
				"spec": {"runtime": {"type": "python-rpc", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "metadata.version is required",
		},
		{
			name: "missing moduleType",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-rpc", "entrypoint": "main"}}
			}`,
			wantErr: "spec.moduleType is required",
		},
		{
			name: "missing runtime",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"moduleType": "survey"}
			}`,
			wantErr: "spec.runtime.type is required",
		},
		{
			name: "missing runtime type",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "spec.runtime.type is required",
		},
		{
			name: "missing runtime entrypoint",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-rpc"}, "moduleType": "survey"}
			}`,
			wantErr: "spec.runtime.entrypoint is required",
		},
		{
			name: "invalid metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "Invalid Name", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-rpc", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "module name",
		},
		{
			name: "malformed spec object",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": "not-an-object"
			}`,
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateModuleDescriptor([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateModuleDescriptorRejectsInvalidModuleType(t *testing.T) {
	data := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Module",
		"metadata": {"name": "ssh-survey", "version": "0.1.0"},
		"spec": {
			"runtime": {"type": "python-rpc", "entrypoint": "main"},
			"moduleType": "not-a-real-type"
		}
	}`)

	_, err := ValidateModuleDescriptor(data)
	if err == nil {
		t.Fatal("expected error for invalid moduleType, got nil")
	}
}

func TestValidateModuleDescriptorRejectsMalformedJSON(t *testing.T) {
	_, err := ValidateModuleDescriptor([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// Service descriptor tests
// ---------------------------------------------------------------------------

func TestValidateServiceDescriptorAcceptsValidMinimal(t *testing.T) {
	data := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Service",
		"metadata": {"name": "picblob-provider", "version": "0.1.0"},
		"spec": {
			"runtime": {"type": "python-service-rpc", "entrypoint": "hovel_picblob:main"},
			"serviceType": "payload_provider",
			"lifecycle": {}
		}
	}`)

	got, err := ValidateServiceDescriptor(data)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.Name != service.Name("picblob-provider") {
		t.Errorf("Name = %q, want %q", got.Name, "picblob-provider")
	}
	if got.Version != service.Version("0.1.0") {
		t.Errorf("Version = %q, want %q", got.Version, "0.1.0")
	}
	if got.Type != service.Type("payload_provider") {
		t.Errorf("Type = %q, want %q", got.Type, "payload_provider")
	}
	wantID := "picblob-provider@0.1.0"
	if got.ID != service.ID(wantID) {
		t.Errorf("ID = %q, want %q", got.ID, wantID)
	}
}

func TestValidateServiceDescriptorRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name: "missing apiVersion",
			json: `{
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong apiVersion",
			json: `{
				"apiVersion": "hovel.dev/v2",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong kind",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "invalid kind",
		},
		{
			name: "missing metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "metadata.name is required",
		},
		{
			name: "missing metadata version",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "metadata.version is required",
		},
		{
			name: "missing serviceType",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "lifecycle": {}}
			}`,
			wantErr: "spec.serviceType is required",
		},
		{
			name: "missing lifecycle",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "payload_provider"}
			}`,
			wantErr: "spec.lifecycle is required",
		},
		{
			name: "missing runtime",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "spec.runtime is required",
		},
		{
			name: "missing runtime type",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "spec.runtime.type is required",
		},
		{
			name: "missing runtime entrypoint",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "spec.runtime.entrypoint is required",
		},
		{
			name: "invalid metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "Invalid Name", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "service name",
		},
		{
			name: "malformed spec object",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": "not-an-object"
			}`,
			wantErr: "",
		},
		{
			name: "malformed runtime value",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": "not-an-object", "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "",
		},
		{
			name: "empty serviceType string",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "python-service-rpc", "entrypoint": "main"}, "serviceType": "", "lifecycle": {}}
			}`,
			wantErr: "spec.serviceType is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateServiceDescriptor([]byte(tc.json))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateServiceDescriptorRejectsInvalidServiceType(t *testing.T) {
	data := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Service",
		"metadata": {"name": "picblob-provider", "version": "0.1.0"},
		"spec": {
			"runtime": {"type": "python-service-rpc", "entrypoint": "main"},
			"serviceType": "not-a-real-type",
			"lifecycle": {}
		}
	}`)

	_, err := ValidateServiceDescriptor(data)
	if err == nil {
		t.Fatal("expected error for invalid serviceType, got nil")
	}
}

func TestValidateServiceDescriptorRejectsMalformedJSON(t *testing.T) {
	_, err := ValidateServiceDescriptor([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}
