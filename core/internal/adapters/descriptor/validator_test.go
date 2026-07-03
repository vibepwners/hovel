package descriptor

import (
	"strings"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
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
			"runtime": {"type": "jsonrpc-stdio", "entrypoint": "python -m hovel_ssh_survey"},
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

func TestValidateModuleDescriptorAcceptsRuntimeCatalogModuleTypes(t *testing.T) {
	data := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Module",
		"metadata": {"name": "mock-exploit", "version": "0.1.0"},
		"spec": {
			"runtime": {"type": "jsonrpc-stdio", "entrypoint": "python -m hovel_example_exploit"},
			"moduleType": "exploit"
		}
	}`)

	got, err := ValidateModuleDescriptor(data)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got.Type != module.Type("exploit") {
		t.Errorf("Type = %q, want %q", got.Type, "exploit")
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
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong apiVersion",
			json: `{
				"apiVersion": "hovel.dev/v2",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong kind",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "invalid kind",
		},
		{
			name: "missing metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "metadata.name is required",
		},
		{
			name: "missing metadata version",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "moduleType": "survey"}
			}`,
			wantErr: "metadata.version is required",
		},
		{
			name: "missing moduleType",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "ssh-survey", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}}
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
				"spec": {"runtime": {"type": "jsonrpc-stdio"}, "moduleType": "survey"}
			}`,
			wantErr: "spec.runtime.entrypoint is required",
		},
		{
			name: "invalid metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "Invalid Name", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "moduleType": "survey"}
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
			"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"},
			"moduleType": "not-a-real-type"
		}
	}`)

	_, err := ValidateModuleDescriptor(data)
	if err == nil {
		t.Fatal("expected error for invalid moduleType, got nil")
	}
}

func TestValidateModuleDescriptorRejectsInvalidRuntimeType(t *testing.T) {
	data := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Module",
		"metadata": {"name": "ssh-survey", "version": "0.1.0"},
		"spec": {
			"runtime": {"type": "python", "entrypoint": "main"},
			"moduleType": "survey"
		}
	}`)

	_, err := ValidateModuleDescriptor(data)
	if err == nil || !strings.Contains(err.Error(), "spec.runtime.type is not valid") {
		t.Fatalf("error = %v, want invalid runtime type", err)
	}
}

func TestValidateModuleDescriptorRejectsMalformedJSON(t *testing.T) {
	_, err := ValidateModuleDescriptor([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestParseChainFileAcceptsConfiguredJSONAndYAML(t *testing.T) {
	want := commands.ChainFile{
		APIVersion: "hovel.dev/v1alpha1",
		Kind:       "Chain",
		Metadata:   commands.ChainFileMetadata{Name: "alpha"},
		Spec: commands.ChainFileSpec{
			Mode:   "configured",
			Config: map[string]string{"operator.confirmed_lab": "true"},
			Steps:  []commands.ChainFileStep{{ID: "step-1", Uses: "module:mock-exploit@v0.0.0-example", Step: "mock.exploit"}},
			Targets: []commands.ChainFileTarget{{
				ID:     "mock://target",
				Config: map[string]string{"target.host": "router-01"},
			}},
		},
	}

	jsonText := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Chain",
		"metadata": {"name": "alpha"},
		"spec": {
			"mode": "configured",
			"config": {"operator.confirmed_lab": "true"},
			"steps": [{"id": "step-1", "uses": "module:mock-exploit@v0.0.0-example", "step": "mock.exploit"}],
			"targets": [{"id": "mock://target", "config": {"target.host": "router-01"}}]
		}
	}`)
	got, err := ParseChainFile(jsonText)
	if err != nil {
		t.Fatal(err)
	}
	if !chainFilesEqual(got, want) {
		t.Fatalf("json chain = %#v, want %#v", got, want)
	}

	yamlText := []byte(`
apiVersion: "hovel.dev/v1alpha1"
kind: "Chain"
metadata:
  name: "alpha"
spec:
  mode: "configured"
  steps:
    - id: "step-1"
      uses: "module:mock-exploit@v0.0.0-example"
      step: "mock.exploit"
  config:
    "operator.confirmed_lab": "true"
  targets:
    - id: "mock://target"
      config:
        "target.host": "router-01"
`)
	got, err = ParseChainFile(yamlText)
	if err != nil {
		t.Fatal(err)
	}
	if !chainFilesEqual(got, want) {
		t.Fatalf("yaml chain = %#v, want %#v", got, want)
	}
}

func TestParseChainFileRejectsSchemaViolationsBeforeSemanticValidation(t *testing.T) {
	_, err := ParseChainFile([]byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Chain",
		"metadata": {"name": "alpha"},
		"spec": {
			"mode": "configured",
			"steps": [{"id": "step-1", "uses": "mock-exploit"}],
			"surprise": true
		}
	}`))
	if err == nil {
		t.Fatal("expected schema error")
	}
	if !strings.Contains(err.Error(), "unexpected key surprise") {
		t.Fatalf("error = %v, want unexpected schema key", err)
	}
}

func TestParseChainFileRejectsUnknownYAMLKeysBeforeCanonicalization(t *testing.T) {
	_, err := ParseChainFile([]byte(`
apiVersion: "hovel.dev/v1alpha1"
kind: "Chain"
metadata:
  name: "alpha"
spec:
  mode: "configured"
  surprise: true
  steps:
    - id: "step-1"
      uses: "module:mock-exploit@v0.0.0-example"
`))
	if err == nil {
		t.Fatal("expected schema error")
	}
	if !strings.Contains(err.Error(), "unexpected key surprise") {
		t.Fatalf("error = %v, want unexpected schema key", err)
	}
}

func chainFilesEqual(got, want commands.ChainFile) bool {
	if got.APIVersion != want.APIVersion || got.Kind != want.Kind || got.Metadata != want.Metadata || got.Spec.Mode != want.Spec.Mode {
		return false
	}
	if len(got.Spec.Steps) != len(want.Spec.Steps) || len(got.Spec.Targets) != len(want.Spec.Targets) {
		return false
	}
	for i := range got.Spec.Steps {
		if got.Spec.Steps[i] != want.Spec.Steps[i] {
			return false
		}
	}
	for key, value := range want.Spec.Config {
		if got.Spec.Config[key] != value {
			return false
		}
	}
	for i := range got.Spec.Targets {
		if got.Spec.Targets[i].ID != want.Spec.Targets[i].ID {
			return false
		}
		for key, value := range want.Spec.Targets[i].Config {
			if got.Spec.Targets[i].Config[key] != value {
				return false
			}
		}
	}
	return true
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
			"runtime": {"type": "jsonrpc-stdio", "entrypoint": "hovel_picblob:main"},
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
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong apiVersion",
			json: `{
				"apiVersion": "hovel.dev/v2",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "invalid apiVersion",
		},
		{
			name: "wrong kind",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Module",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "invalid kind",
		},
		{
			name: "missing metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "metadata.name is required",
		},
		{
			name: "missing metadata version",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "metadata.version is required",
		},
		{
			name: "missing serviceType",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "lifecycle": {}}
			}`,
			wantErr: "spec.serviceType is required",
		},
		{
			name: "missing lifecycle",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "picblob-provider", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "payload_provider"}
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
				"spec": {"runtime": {"type": "jsonrpc-stdio"}, "serviceType": "payload_provider", "lifecycle": {}}
			}`,
			wantErr: "spec.runtime.entrypoint is required",
		},
		{
			name: "invalid metadata name",
			json: `{
				"apiVersion": "hovel.dev/v1alpha1",
				"kind": "Service",
				"metadata": {"name": "Invalid Name", "version": "0.1.0"},
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "payload_provider", "lifecycle": {}}
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
				"spec": {"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"}, "serviceType": "", "lifecycle": {}}
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
			"runtime": {"type": "jsonrpc-stdio", "entrypoint": "main"},
			"serviceType": "not-a-real-type",
			"lifecycle": {}
		}
	}`)

	_, err := ValidateServiceDescriptor(data)
	if err == nil {
		t.Fatal("expected error for invalid serviceType, got nil")
	}
}

func TestValidateServiceDescriptorRejectsInvalidRuntimeType(t *testing.T) {
	data := []byte(`{
		"apiVersion": "hovel.dev/v1alpha1",
		"kind": "Service",
		"metadata": {"name": "picblob-provider", "version": "0.1.0"},
		"spec": {
			"runtime": {"type": "python", "entrypoint": "main"},
			"serviceType": "payload_provider",
			"lifecycle": {}
		}
	}`)

	_, err := ValidateServiceDescriptor(data)
	if err == nil || !strings.Contains(err.Error(), "spec.runtime.type is not valid") {
		t.Fatalf("error = %v, want invalid runtime type", err)
	}
}

func TestValidateServiceDescriptorRejectsMalformedJSON(t *testing.T) {
	_, err := ValidateServiceDescriptor([]byte(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}
