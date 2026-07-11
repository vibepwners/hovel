package modulecatalog

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	domainmesh "github.com/Vibe-Pwners/hovel/internal/domain/mesh"
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

func TestCatalogSearchesAndClonesModuleContext(t *testing.T) {
	catalog := New(Module{
		ID:      "ctx-module",
		Type:    TypeExploit,
		Version: "v1.0.0",
		Discovery: Context{
			Keywords:     []string{"ms17-010"},
			Capabilities: []string{"remote-exec"},
		},
		Planning: Context{
			Risk: RiskContext{Level: "high", Reasons: []string{"writes payload"}},
			Examples: []ContextExample{{
				Name:        "bind shell",
				Modules:     []string{"ctx-module@v1.0.0"},
				ChainConfig: map[string]string{"operator.confirmed_lab": "true"},
			}},
		},
	})
	if got := catalog.Search("remote-exec"); len(got) != 1 || got[0].ID != "ctx-module@v1.0.0" {
		t.Fatalf("search = %#v, want context module", got)
	}
	module, ok := catalog.Find("ctx-module")
	if !ok {
		t.Fatal("Find(ctx-module) failed")
	}
	module.Planning.Examples[0].ChainConfig["operator.confirmed_lab"] = "false"
	again, _ := catalog.Find("ctx-module")
	if again.Planning.Examples[0].ChainConfig["operator.confirmed_lab"] != "true" {
		t.Fatalf("catalog context was mutated through clone: %#v", again.Planning.Examples[0].ChainConfig)
	}
}

func TestCatalogDeepClonesMeshMetadata(t *testing.T) {
	nested := map[string]any{
		"policy": map[string]any{
			"allowed": []any{"survey", map[string]any{"kind": "command"}},
		},
	}
	listenerSchema := map[string]any{
		"properties": map[string]any{
			"endpoint": map[string]any{"type": "string"},
		},
	}
	catalog := New(Module{
		ID:      "mesh-module",
		Type:    TypeExploit,
		Version: "v1.0.0",
		Mesh: domainmesh.Descriptor{
			Attributes: nested,
			ListenerTypes: []domainmesh.ListenerSpec{{
				Kind:            "https",
				Deployments:     []domainmesh.ListenerDeployment{domainmesh.ListenerDeploymentSeparate},
				ManagementModes: []domainmesh.ListenerManagement{domainmesh.ListenerManagementProvider},
				Protocols:       []string{"https"},
				ConfigSchema:    listenerSchema,
				Capabilities:    []string{"beacon"},
			}},
		},
	})
	if got := catalog.Search("beacon"); len(got) != 1 || got[0].ID != "mesh-module@v1.0.0" {
		t.Fatalf("listener metadata search = %#v, want mesh-module", got)
	}

	nested["policy"].(map[string]any)["allowed"].([]any)[1].(map[string]any)["kind"] = "mutated input"
	listenerSchema["properties"].(map[string]any)["endpoint"].(map[string]any)["type"] = "integer"
	module, ok := catalog.Find("mesh-module")
	if !ok {
		t.Fatal("Find(mesh-module) failed")
	}
	allowed := module.Mesh.Attributes["policy"].(map[string]any)["allowed"].([]any)
	if got := allowed[1].(map[string]any)["kind"]; got != "command" {
		t.Fatalf("stored mesh metadata = %q, want original value", got)
	}
	listener := module.Mesh.ListenerTypes[0]
	endpoint := listener.ConfigSchema["properties"].(map[string]any)["endpoint"].(map[string]any)
	if got := endpoint["type"]; got != "string" {
		t.Fatalf("stored listener schema = %q, want original value", got)
	}

	allowed[1].(map[string]any)["kind"] = "mutated result"
	listener.Deployments[0] = domainmesh.ListenerDeploymentEmbedded
	listener.ManagementModes[0] = domainmesh.ListenerManagementExternal
	listener.Protocols[0] = "mutated"
	listener.Capabilities[0] = "mutated"
	endpoint["type"] = "boolean"
	again, _ := catalog.Find("mesh-module")
	againAllowed := again.Mesh.Attributes["policy"].(map[string]any)["allowed"].([]any)
	if got := againAllowed[1].(map[string]any)["kind"]; got != "command" {
		t.Fatalf("catalog mesh metadata was mutated through clone: %q", got)
	}
	againListener := again.Mesh.ListenerTypes[0]
	if got := againListener.Deployments[0]; got != domainmesh.ListenerDeploymentSeparate {
		t.Fatalf("catalog listener deployments were mutated through clone: %q", got)
	}
	if got := againListener.ManagementModes[0]; got != domainmesh.ListenerManagementProvider {
		t.Fatalf("catalog listener management modes were mutated through clone: %q", got)
	}
	if got := againListener.Protocols[0]; got != "https" {
		t.Fatalf("catalog listener protocols were mutated through clone: %q", got)
	}
	if got := againListener.Capabilities[0]; got != "beacon" {
		t.Fatalf("catalog listener capabilities were mutated through clone: %q", got)
	}
	againEndpoint := againListener.ConfigSchema["properties"].(map[string]any)["endpoint"].(map[string]any)
	if got := againEndpoint["type"]; got != "string" {
		t.Fatalf("catalog listener schema was mutated through clone: %q", got)
	}
}

func TestContextJSONOmitsAbsentNestedRisk(t *testing.T) {
	data, err := json.Marshal(Context{Summary: "Find SMB exposure"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"risk"`) {
		t.Fatalf("context JSON includes absent risk: %s", data)
	}

	data, err = json.Marshal(Context{Risk: RiskContext{Level: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"risk"`) || !strings.Contains(string(data), `"level":"high"`) {
		t.Fatalf("context JSON missing present risk: %s", data)
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

func TestValidateStepContractsReportsMalformedContracts(t *testing.T) {
	module := Module{
		ID:      "bad-provider",
		Enabled: true,
		StepContracts: StepContractSet{Steps: []StepContract{
			{
				Kind: "payload.install",
				Requires: []CapabilityRequirement{{
					Type:          CapabilityCredential,
					SchemaVersion: "v1",
				}},
			},
			{
				ID:   "squatter.connect_smb",
				Kind: "session.connector",
				Requires: []CapabilityRequirement{{
					SchemaVersion: "v1",
				}},
				Produces: []CapabilityRequirement{{
					Type: CapabilitySessionRef,
				}},
			},
		}},
	}

	issues := ValidateStepContracts(module)
	want := []StepContractIssue{
		{ModuleID: "bad-provider", StepID: "", Message: "step id is required"},
		{ModuleID: "bad-provider", StepID: "squatter.connect_smb", Message: "requirement 1 type is required"},
		{ModuleID: "bad-provider", StepID: "squatter.connect_smb", Message: "produced capability 1 schemaVersion is required"},
	}
	if !reflect.DeepEqual(issues, want) {
		t.Fatalf("issues = %#v, want %#v", issues, want)
	}
}

func TestValidateStepContractsAcceptsLegacyEmptyContracts(t *testing.T) {
	if issues := ValidateStepContracts(Module{ID: "legacy"}); len(issues) != 0 {
		t.Fatalf("legacy issues = %#v, want none", issues)
	}
}

func TestCapabilitySatisfiesRequirementMatchesTypeAttributesAndState(t *testing.T) {
	capability := Capability{
		Type:          CapabilityCredential,
		SchemaVersion: "v1",
		State:         "active",
		Attributes: map[string]any{
			"protocol":  "smb",
			"principal": "local",
		},
	}
	requirement := CapabilityRequirement{
		Type:          CapabilityCredential,
		SchemaVersion: "v1",
		Attributes:    map[string]any{"protocol": "smb"},
		States:        []string{"active"},
	}
	if !CapabilitySatisfiesRequirement(capability, requirement) {
		t.Fatal("capability should satisfy requirement")
	}

	requirement.Type = CapabilityPayloadInstance
	if CapabilitySatisfiesRequirement(capability, requirement) {
		t.Fatal("different type should not satisfy requirement")
	}

	requirement.Type = CapabilityCredential
	requirement.Attributes = map[string]any{"protocol": "ssh"}
	if CapabilitySatisfiesRequirement(capability, requirement) {
		t.Fatal("different attribute should not satisfy requirement")
	}

	requirement.Attributes = map[string]any{"protocol": "smb"}
	requirement.States = []string{"planned"}
	if CapabilitySatisfiesRequirement(capability, requirement) {
		t.Fatal("disallowed state should not satisfy requirement")
	}
}

func TestCapabilitySatisfiesRequirementRejectsDifferentSchemaVersion(t *testing.T) {
	capability := Capability{
		ID:            "cred-v2",
		Type:          CapabilityCredential,
		SchemaVersion: "v2",
		State:         "active",
		Attributes:    map[string]any{"protocol": "smb"},
	}
	requirement := CapabilityRequirement{
		Type:          CapabilityCredential,
		SchemaVersion: "v1",
		States:        []string{"active"},
		Attributes:    map[string]any{"protocol": "smb"},
	}
	if CapabilitySatisfiesRequirement(capability, requirement) {
		t.Fatal("v2 capability satisfied v1 requirement")
	}
}

func TestCapabilitySatisfiesRequirementAllowsUnconstrainedState(t *testing.T) {
	if !CapabilitySatisfiesRequirement(
		Capability{Type: CapabilityTransport, State: "planned", Attributes: map[string]any{"kind": "smb-pipe"}},
		CapabilityRequirement{Type: CapabilityTransport, Attributes: map[string]any{"kind": "smb-pipe"}},
	) {
		t.Fatal("missing state requirement should allow any state")
	}
}

func TestFindSatisfyingCapabilityReturnsFirstMatch(t *testing.T) {
	capabilities := []Capability{
		{ID: "tcp", Type: CapabilityTransport, State: "planned", Attributes: map[string]any{"kind": "tcp-bind"}},
		{ID: "smb-1", Type: CapabilityTransport, State: "planned", Attributes: map[string]any{"kind": "smb-pipe"}},
		{ID: "smb-2", Type: CapabilityTransport, State: "active", Attributes: map[string]any{"kind": "smb-pipe"}},
	}

	capability, ok := FindSatisfyingCapability(
		CapabilityRequirement{
			Type:       CapabilityTransport,
			Attributes: map[string]any{"kind": "smb-pipe"},
			States:     []string{"planned"},
		},
		capabilities,
	)
	if !ok {
		t.Fatal("expected matching capability")
	}
	if capability.ID != "smb-1" {
		t.Fatalf("capability id = %q, want smb-1", capability.ID)
	}

	_, ok = FindSatisfyingCapability(
		CapabilityRequirement{Type: CapabilityCredential, Attributes: map[string]any{"protocol": "smb"}},
		capabilities,
	)
	if ok {
		t.Fatal("unexpected credential match")
	}
}

func TestResolveStepInputsBindsRequirementsToCapabilities(t *testing.T) {
	step := StepContract{
		ID: "squatter.install_smb",
		Requires: []CapabilityRequirement{
			{
				Type:       CapabilityPayloadArtifact,
				Attributes: map[string]any{"runtime": "windows-x86"},
				States:     []string{"built"},
			},
			{
				Type:       CapabilityCredential,
				Attributes: map[string]any{"protocol": "smb"},
				States:     []string{"active"},
			},
		},
	}
	capabilities := []Capability{
		{ID: "artifact-1", Type: CapabilityPayloadArtifact, SchemaVersion: "v1", State: "built", Attributes: map[string]any{"runtime": "windows-x86"}},
		{ID: "credential-1", Type: CapabilityCredential, SchemaVersion: "v1", State: "active", Attributes: map[string]any{"protocol": "smb"}},
	}

	resolution := ResolveStepInputs(step, capabilities)
	if !resolution.Ready {
		t.Fatalf("resolution ready = false, missing %#v", resolution.Missing)
	}
	want := []CapabilityBinding{
		{RequirementIndex: 0, CapabilityID: "artifact-1"},
		{RequirementIndex: 1, CapabilityID: "credential-1"},
	}
	if !reflect.DeepEqual(resolution.Bindings, want) {
		t.Fatalf("bindings = %#v, want %#v", resolution.Bindings, want)
	}
}

func TestResolveStepInputsDoesNotBindDifferentSchemaVersion(t *testing.T) {
	step := StepContract{
		ID: "squatter.connect_smb",
		Requires: []CapabilityRequirement{{
			Type:          CapabilityPayloadInstance,
			SchemaVersion: "v1",
			States:        []string{"installed"},
			Attributes:    map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
		}},
	}
	capabilities := []Capability{{
		ID:            "payload-v2",
		Type:          CapabilityPayloadInstance,
		SchemaVersion: "v2",
		State:         "installed",
		Attributes:    map[string]any{"provider": "squatter", "transport": "smb-named-pipe"},
	}}

	resolution := ResolveStepInputs(step, capabilities)
	if resolution.Ready {
		t.Fatalf("resolution ready = true, bindings %#v", resolution.Bindings)
	}
	if len(resolution.Missing) != 1 || resolution.Missing[0].SchemaVersion != "v1" {
		t.Fatalf("missing = %#v, want v1 requirement missing", resolution.Missing)
	}
}

func TestResolveStepInputsReportsMissingRequirements(t *testing.T) {
	step := StepContract{
		ID: "squatter.connect_smb",
		Requires: []CapabilityRequirement{
			{
				Type:       CapabilityTransport,
				Attributes: map[string]any{"kind": "smb-pipe"},
				States:     []string{"active"},
			},
			{
				Type:       CapabilityCredential,
				Attributes: map[string]any{"protocol": "smb"},
				States:     []string{"active"},
			},
		},
	}
	capabilities := []Capability{
		{ID: "transport-1", Type: CapabilityTransport, State: "planned", Attributes: map[string]any{"kind": "smb-pipe"}},
	}

	resolution := ResolveStepInputs(step, capabilities)
	if resolution.Ready {
		t.Fatal("resolution ready = true, want false")
	}
	want := []MissingCapability{
		{
			RequirementIndex: 0,
			Type:             CapabilityTransport,
			Attributes:       map[string]any{"kind": "smb-pipe"},
			States:           []string{"active"},
		},
		{
			RequirementIndex: 1,
			Type:             CapabilityCredential,
			Attributes:       map[string]any{"protocol": "smb"},
			States:           []string{"active"},
		},
	}
	if !reflect.DeepEqual(resolution.Missing, want) {
		t.Fatalf("missing = %#v, want %#v", resolution.Missing, want)
	}
}

func TestCatalogResolveStepAvailabilityUsesEnabledModuleContracts(t *testing.T) {
	catalog := New(
		Module{
			ID:      "squatter-provider@v1",
			Enabled: true,
			StepContracts: StepContractSet{Steps: []StepContract{
				{
					ID:   "squatter.connect_smb",
					Kind: "session.connector",
					Requires: []CapabilityRequirement{{
						Type:       CapabilityTransport,
						Attributes: map[string]any{"kind": "smb-pipe"},
						States:     []string{"active"},
					}},
				},
				{
					ID:   "squatter.generate",
					Kind: "payload.generate",
				},
			}},
		},
		Module{
			ID:      "disabled-provider@v1",
			Enabled: false,
			StepContracts: StepContractSet{Steps: []StepContract{{
				ID:   "disabled.step",
				Kind: "payload.generate",
			}}},
		},
	)

	availability := catalog.ResolveStepAvailability([]Capability{{
		ID:         "transport-1",
		Type:       CapabilityTransport,
		State:      "active",
		Attributes: map[string]any{"kind": "smb-pipe"},
	}})

	if len(availability) != 2 {
		t.Fatalf("availability count = %d, want 2", len(availability))
	}
	if availability[0].ModuleID != "squatter-provider@v1" || availability[0].Step.ID != "squatter.connect_smb" {
		t.Fatalf("first availability = %#v", availability[0])
	}
	if !availability[0].Resolution.Ready {
		t.Fatalf("connect resolution = %#v, want ready", availability[0].Resolution)
	}
	if availability[1].Step.ID != "squatter.generate" || !availability[1].Resolution.Ready {
		t.Fatalf("generate availability = %#v, want ready without inputs", availability[1])
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
