package modulecatalog

import (
	"strings"
	"testing"
)

func TestBuiltInsExposeMockModulesByType(t *testing.T) {
	catalog := BuiltIns()

	modules := catalog.List()
	if len(modules) != 7 {
		t.Fatalf("module count = %d, want 7", len(modules))
	}
	if _, ok := catalog.Find("mock-simple-exploit"); !ok {
		t.Fatal("mock-simple-exploit not found")
	}
	if surveys := catalog.ByType(TypeSurvey); len(surveys) != 4 {
		t.Fatalf("survey count = %d, want 4", len(surveys))
	}
}

func TestValidateValueCoversTypedConfig(t *testing.T) {
	cases := []struct {
		name        string
		requirement Requirement
		value       string
		wantErr     bool
	}{
		{name: "string", requirement: Requirement{Type: ValueString}, value: "operator"},
		{name: "secret", requirement: Requirement{Type: ValueSecret}, value: "redacted"},
		{name: "bool", requirement: Requirement{Type: ValueBool}, value: "true"},
		{name: "int", requirement: Requirement{Type: ValueInt}, value: "7"},
		{name: "float", requirement: Requirement{Type: ValueFloat}, value: "7.5"},
		{name: "enum", requirement: Requirement{Type: ValueEnum, Allowed: []string{"alpha"}}, value: "alpha"},
		{name: "duration", requirement: Requirement{Type: ValueDuration}, value: "250ms"},
		{name: "url", requirement: Requirement{Type: ValueURL}, value: "https://example.test/payload"},
		{name: "host", requirement: Requirement{Type: ValueHost}, value: "router-01.local"},
		{name: "port", requirement: Requirement{Type: ValuePort}, value: "443"},
		{name: "cidr", requirement: Requirement{Type: ValueCIDR}, value: "10.0.0.0/24"},
		{name: "path", requirement: Requirement{Type: ValuePath}, value: "/tmp/payload"},
		{name: "list", requirement: Requirement{Type: ValueStringList}, value: "one,two"},
		{name: "map", requirement: Requirement{Type: ValueStringStringMap}, value: "one=1,two=2"},
		{name: "bad bool", requirement: Requirement{Type: ValueBool}, value: "sure", wantErr: true},
		{name: "bad enum", requirement: Requirement{Type: ValueEnum, Allowed: []string{"alpha"}}, value: "beta", wantErr: true},
		{name: "bad port", requirement: Requirement{Type: ValuePort}, value: "70000", wantErr: true},
		{name: "bad map", requirement: Requirement{Type: ValueStringStringMap}, value: "one", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateValue(tc.requirement, tc.value)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCatalogValidationFindsMissingAndInvalidConfig(t *testing.T) {
	catalog := BuiltIns()
	result := catalog.Validate(ConfigView{
		Steps:   []StepRef{{ID: "step-1", ModuleID: "mock-simple-exploit"}},
		Targets: []string{"mock://target"},
		ChainConfig: map[string]string{
			"operator.confirmed_lab": "definitely",
		},
		TargetConfigs: map[string]map[string]string{
			"mock://target": {"target.host": "router-01"},
		},
	})

	if result.Valid {
		t.Fatal("validation valid = true, want false")
	}
	for _, want := range []string{
		"invalid chain config operator.confirmed_lab",
		"missing target config target.port",
	} {
		if !hasIssue(result, want) {
			t.Fatalf("issues missing %q: %#v", want, result.Issues)
		}
	}
}

func TestCatalogValidationAcceptsCompleteConfig(t *testing.T) {
	catalog := BuiltIns()
	result := catalog.Validate(ConfigView{
		Steps:   []StepRef{{ID: "step-1", ModuleID: "mock-simple-exploit"}},
		Targets: []string{"mock://target"},
		ChainConfig: map[string]string{
			"operator.confirmed_lab": "true",
		},
		TargetConfigs: map[string]map[string]string{
			"mock://target": {
				"target.host": "router-01",
				"target.port": "22",
			},
		},
	})

	if !result.Valid {
		t.Fatalf("validation issues = %#v, want none", result.Issues)
	}
}

func TestDisplayValueRedactsSecrets(t *testing.T) {
	if got := DisplayValue(Requirement{Type: ValueSecret}, "hunter2"); got != "<secret:set>" {
		t.Fatalf("secret display = %q", got)
	}
	if got := DisplayValue(Requirement{Type: ValueString}, "visible"); got != "visible" {
		t.Fatalf("string display = %q", got)
	}
}

func hasIssue(validation Validation, want string) bool {
	for _, issue := range validation.Issues {
		if strings.Contains(issue.Message, want) {
			return true
		}
	}
	return false
}
