package modulecatalog

import (
	"reflect"
	"testing"
)

func TestBuiltInsExposeMockModulesByType(t *testing.T) {
	catalog := BuiltIns()

	modules := catalog.List()
	if len(modules) != 0 {
		t.Fatalf("module count = %d, want 0", len(modules))
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

func TestCatalogNormalizesVersionedIdentityAndResolvesLatest(t *testing.T) {
	catalog := New(
		Module{ID: "loader", Type: TypeExploit, Version: "v1.0.0", Summary: "old"},
		Module{ID: "loader", Type: TypeExploit, Version: "v1.2.0", Summary: "new"},
		Module{ID: "loader@v1.1.0", Type: TypeExploit, Summary: "middle"},
	)

	modules := catalog.List()
	wantIDs := []string{"loader@v1.0.0", "loader@v1.1.0", "loader@v1.2.0"}
	var gotIDs []string
	for _, module := range modules {
		gotIDs = append(gotIDs, module.ID)
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("ids = %#v, want %#v", gotIDs, wantIDs)
	}

	module, ok := catalog.Find("loader")
	if !ok {
		t.Fatal("Find(loader) failed")
	}
	if module.ID != "loader@v1.2.0" {
		t.Fatalf("latest id = %q, want loader@v1.2.0", module.ID)
	}
	if _, ok := catalog.Find("loader@v1.1.0"); !ok {
		t.Fatal("Find(loader@v1.1.0) failed")
	}
}

func TestCatalogValidationFindsMissingAndInvalidConfig(t *testing.T) {
	catalog := exampleCatalog()
	result := catalog.Validate(ConfigView{
		Steps:   []StepRef{{ID: "step-1", ModuleID: "mock-exploit"}},
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
	want := []Issue{
		{
			Scope:    ScopeChain,
			StepID:   "step-1",
			ModuleID: "mock-exploit",
			Key:      "operator.confirmed_lab",
			Message:  "invalid chain config operator.confirmed_lab: strconv.ParseBool: parsing \"definitely\": invalid syntax",
		},
		{
			Scope:    ScopeTarget,
			StepID:   "step-1",
			ModuleID: "mock-exploit",
			Target:   "mock://target",
			Key:      "target.port",
			Message:  "missing target config target.port",
		},
	}
	if !reflect.DeepEqual(result.Issues, want) {
		t.Fatalf("issues = %#v, want %#v", result.Issues, want)
	}
}

func TestCatalogValidationKeepsIssuesTiedToTheirStepTargetAndModule(t *testing.T) {
	catalog := exampleCatalog()
	result := catalog.Validate(ConfigView{
		Steps: []StepRef{
			{ID: "survey-1", ModuleID: "mock-survey"},
			{ID: "exploit-1", ModuleID: "mock-exploit"},
		},
		Targets: []string{"mock://router-01", "mock://router-02"},
		ChainConfig: map[string]string{
			"operator.confirmed_lab": "true",
		},
		TargetConfigs: map[string]map[string]string{
			"mock://router-01": {
				"target.host": "router-01",
				"target.port": "22",
			},
			"mock://router-02": {
				"target.host": "router-02",
			},
		},
	})

	if result.Valid {
		t.Fatal("validation valid = true, want false")
	}
	want := []Issue{
		{
			Scope:    ScopeTarget,
			StepID:   "exploit-1",
			ModuleID: "mock-exploit",
			Target:   "mock://router-02",
			Key:      "target.port",
			Message:  "missing target config target.port",
		},
		{
			Scope:    ScopeTarget,
			StepID:   "survey-1",
			ModuleID: "mock-survey",
			Target:   "mock://router-02",
			Key:      "target.port",
			Message:  "missing target config target.port",
		},
	}
	if !reflect.DeepEqual(result.Issues, want) {
		t.Fatalf("issues = %#v, want %#v", result.Issues, want)
	}
}

func TestCatalogValidationAcceptsCompleteConfig(t *testing.T) {
	catalog := exampleCatalog()
	result := catalog.Validate(ConfigView{
		Steps:   []StepRef{{ID: "step-1", ModuleID: "mock-exploit"}},
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

func exampleCatalog() Catalog {
	return New(
		Module{
			ID:          "mock-survey",
			Name:        "Mock Survey",
			Type:        TypeSurvey,
			Version:     "v0.0.0-example",
			Summary:     "Collect example target facts.",
			RuntimeKind: "jsonrpc-stdio",
			Enabled:     true,
			TargetConfig: []Requirement{
				{Key: "target.host", Type: ValueHost, Required: true},
				{Key: "target.port", Type: ValuePort, Required: true},
			},
		},
		Module{
			ID:          "mock-exploit",
			Name:        "Mock Exploit",
			Type:        TypeExploit,
			Version:     "v0.0.0-example",
			Summary:     "Run an example exploit flow.",
			RuntimeKind: "jsonrpc-stdio",
			Enabled:     true,
			ChainConfig: []Requirement{
				{Key: "operator.confirmed_lab", Type: ValueBool, Required: true},
			},
			TargetConfig: []Requirement{
				{Key: "target.host", Type: ValueHost, Required: true},
				{Key: "target.port", Type: ValuePort, Required: true},
			},
		},
	)
}

func TestDisplayValueRedactsSecrets(t *testing.T) {
	for _, requirement := range []Requirement{
		{Type: ValueSecret},
		{Type: ValueString, Secret: true},
	} {
		if got := DisplayValue(requirement, "hunter2"); got != "********" {
			t.Fatalf("secret display = %q, want redacted", got)
		}
	}
	if got := DisplayValue(Requirement{Type: ValueString}, "visible"); got != "visible" {
		t.Fatalf("string display = %q", got)
	}
}

func TestModuleDangerous(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want bool
	}{
		{name: "no tags", tags: nil, want: false},
		{name: "benign tags", tags: []string{"recon", "safe"}, want: false},
		{name: "dangerous tag", tags: []string{"dangerous"}, want: true},
		{name: "mixed tags", tags: []string{"recon", "dangerous"}, want: true},
		{name: "case insensitive", tags: []string{"Dangerous"}, want: true},
		{name: "whitespace padded", tags: []string{" dangerous "}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			module := Module{ID: "m@1", Tags: tc.tags}
			if got := module.Dangerous(); got != tc.want {
				t.Fatalf("Dangerous() = %v, want %v", got, tc.want)
			}
		})
	}
}
