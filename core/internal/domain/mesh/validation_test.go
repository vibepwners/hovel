package mesh

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vibepwners/hovel/internal/domain/run"
)

func TestMeshCloneRecursivelyCopiesMutableGenericValues(t *testing.T) {
	t.Parallel()

	raw := json.RawMessage(`{"secret":"value"}`)
	typed := map[string][]byte{"bytes": {1, 2, 3}}
	pointed := &[]string{"first"}
	cycle := map[string]any{}
	cycle["self"] = cycle
	original := TaskRequest{
		Kind: TaskSurvey,
		Config: map[string]any{
			"raw":     raw,
			"typed":   typed,
			"pointed": pointed,
			"cycle":   cycle,
		},
	}

	cloned := original.Clone()
	raw[0] = '['
	typed["bytes"][0] = 9
	(*pointed)[0] = "changed"
	cycle["original-only"] = true

	clonedRaw := cloned.Config["raw"].(json.RawMessage)
	if string(clonedRaw) != `{"secret":"value"}` {
		t.Fatalf("cloned raw JSON = %q", clonedRaw)
	}
	clonedTyped := cloned.Config["typed"].(map[string][]byte)
	if clonedTyped["bytes"][0] != 1 {
		t.Fatalf("cloned typed bytes = %v", clonedTyped["bytes"])
	}
	clonedPointed := cloned.Config["pointed"].(*[]string)
	if (*clonedPointed)[0] != "first" {
		t.Fatalf("cloned pointed slice = %v", *clonedPointed)
	}
	clonedCycle := cloned.Config["cycle"].(map[string]any)
	if _, exists := clonedCycle["original-only"]; exists {
		t.Fatal("cloned cycle retained an alias to the original map")
	}
	clonedSelf := clonedCycle["self"].(map[string]any)
	clonedSelf["clone-only"] = true
	if _, exists := clonedCycle["clone-only"]; !exists {
		t.Fatal("self-referential map topology was not preserved")
	}
	if _, exists := cycle["clone-only"]; exists {
		t.Fatal("self-referential clone mutated the original map")
	}
}

func TestTopologyValidateReferentialIntegrity(t *testing.T) {
	t.Parallel()

	valid := Topology{
		Root: "root",
		Nodes: []Node{
			{ID: "root"},
			{ID: "relay", ParentID: "root"},
			{ID: "edge", ParentID: "relay"},
		},
		Links: []Link{
			{ID: "root-relay", Source: "root", Target: "relay"},
			{ID: "relay-edge", Source: "relay", Target: "edge"},
		},
		Routes: []Route{{
			ID:    "to-edge",
			Nodes: []string{"root", "relay", "edge"},
			Links: []string{"root-relay", "relay-edge"},
		}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid topology: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Topology)
		message string
	}{
		{
			name: "missing root",
			mutate: func(topology *Topology) {
				topology.Root = "missing"
			},
			message: "root",
		},
		{
			name: "duplicate node",
			mutate: func(topology *Topology) {
				topology.Nodes = append(topology.Nodes, Node{ID: "edge"})
			},
			message: "duplicated",
		},
		{
			name: "noncanonical node id",
			mutate: func(topology *Topology) {
				topology.Nodes[1].ID = " relay"
			},
			message: "canonical",
		},
		{
			name: "missing parent",
			mutate: func(topology *Topology) {
				topology.Nodes[2].ParentID = "missing"
			},
			message: "missing parent",
		},
		{
			name: "parent cycle",
			mutate: func(topology *Topology) {
				topology.Nodes[1].ParentID = "edge"
			},
			message: "parent cycle",
		},
		{
			name: "root has parent",
			mutate: func(topology *Topology) {
				topology.Nodes[0].ParentID = "relay"
			},
			message: "must not have a parent",
		},
		{
			name: "node disconnected from root",
			mutate: func(topology *Topology) {
				topology.Nodes[2].ParentID = ""
			},
			message: "not connected to root",
		},
		{
			name: "missing link endpoint",
			mutate: func(topology *Topology) {
				topology.Links[1].Target = "missing"
			},
			message: "does not exist",
		},
		{
			name: "noncanonical link endpoint",
			mutate: func(topology *Topology) {
				topology.Links[1].Target = "edge "
			},
			message: "canonical",
		},
		{
			name: "missing route node",
			mutate: func(topology *Topology) {
				topology.Routes[0].Nodes[2] = "missing"
			},
			message: "missing node",
		},
		{
			name: "missing route link",
			mutate: func(topology *Topology) {
				topology.Routes[0].Links[1] = "missing"
			},
			message: "missing link",
		},
		{
			name: "disconnected route link",
			mutate: func(topology *Topology) {
				topology.Links[0].Target = "edge"
			},
			message: "does not connect",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			topology := cloneTestTopology(valid)
			test.mutate(&topology)
			err := topology.Validate()
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestMeshRequestValidation(t *testing.T) {
	t.Parallel()

	route := &Route{Nodes: []string{"root", "edge"}, Links: []string{"root-edge"}}
	if err := (TaskRequest{Kind: TaskCommand, DestinationPort: MaximumNetworkPort, Route: route}).Validate(); err != nil {
		t.Fatalf("valid task request: %v", err)
	}
	if err := (StreamRequest{DestinationPort: MaximumNetworkPort, Route: route}).Validate(); err != nil {
		t.Fatalf("valid stream request: %v", err)
	}

	tests := []struct {
		name    string
		request interface{ Validate() error }
		message string
	}{
		{name: "missing task kind", request: TaskRequest{}, message: "task kind"},
		{
			name:    "noncanonical task kind",
			request: TaskRequest{Kind: " command"},
			message: "canonical",
		},
		{
			name:    "task port overflow",
			request: TaskRequest{Kind: TaskCommand, DestinationPort: MaximumNetworkPort + 1},
			message: "destination port",
		},
		{
			name:    "negative stream port",
			request: StreamRequest{DestinationPort: -1},
			message: "destination port",
		},
		{
			name:    "empty route",
			request: StreamRequest{Route: &Route{}},
			message: "at least one node",
		},
		{
			name:    "noncanonical result status",
			request: TaskResult{Status: "succeeded "},
			message: "canonical",
		},
		{
			name:    "missing result status",
			request: TaskResult{},
			message: "task status",
		},
		{
			name:    "provider-defined result status",
			request: TaskResult{Status: "partial"},
			message: "not supported",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.request.Validate()
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestDescriptorRejectsDuplicateCapabilityKinds(t *testing.T) {
	t.Parallel()

	descriptor := Descriptor{
		Tasks:         []TaskSpec{{Kind: TaskSurvey}, {Kind: TaskSurvey}},
		ListenerTypes: []ListenerSpec{{Kind: "https"}},
	}
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate task descriptor error = %v", err)
	}
	descriptor.Tasks = []TaskSpec{{Kind: TaskSurvey}}
	descriptor.ListenerTypes = append(descriptor.ListenerTypes, ListenerSpec{Kind: "https"})
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate listener descriptor error = %v", err)
	}
	descriptor.ListenerTypes = []ListenerSpec{{Kind: " https"}}
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical listener descriptor error = %v", err)
	}
}

func TestBeaconValidation(t *testing.T) {
	t.Parallel()

	if err := (BeaconRequest{Limit: -1}).Validate(); err == nil {
		t.Fatal("negative beacon limit was accepted")
	}
	if err := (Beacon{ID: "beacon-1", NodeID: "node-1"}).Validate(); err != nil {
		t.Fatalf("valid beacon: %v", err)
	}
	err := (Beacon{ID: " beacon-1", NodeID: "node-1"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical beacon error = %v", err)
	}
}

func TestMeshClonesDoNotAliasMutableFields(t *testing.T) {
	t.Parallel()

	descriptor := Descriptor{
		Capabilities: []string{"routing"},
		Topology: &Topology{
			Nodes: []Node{{
				ID:           "node-1",
				Capabilities: []string{"task"},
				Labels:       map[string]any{"region": map[string]any{"name": "west"}},
			}},
		},
		Tasks: []TaskSpec{{
			Kind:         TaskSurvey,
			TargetScopes: []TargetScope{TargetNode},
			ConfigSchema: map[string]any{"properties": []any{"target"}},
		}},
		Attributes: map[string]any{"nested": map[string]any{"value": "original"}},
	}
	clonedDescriptor := descriptor.Clone()
	clonedDescriptor.Capabilities[0] = "mutated"
	clonedDescriptor.Topology.Nodes[0].Capabilities[0] = "mutated"
	clonedDescriptor.Topology.Nodes[0].Labels["region"].(map[string]any)["name"] = "mutated"
	clonedDescriptor.Tasks[0].TargetScopes[0] = TargetDestination
	clonedDescriptor.Tasks[0].ConfigSchema["properties"].([]any)[0] = "mutated"
	clonedDescriptor.Attributes["nested"].(map[string]any)["value"] = "mutated"
	if descriptor.Capabilities[0] != "routing" {
		t.Fatalf("descriptor capabilities were aliased: %#v", descriptor.Capabilities)
	}
	if descriptor.Topology.Nodes[0].Capabilities[0] != "task" {
		t.Fatalf("descriptor node capabilities were aliased: %#v", descriptor.Topology.Nodes)
	}
	if descriptor.Topology.Nodes[0].Labels["region"].(map[string]any)["name"] != "west" {
		t.Fatalf("descriptor node labels were aliased: %#v", descriptor.Topology.Nodes)
	}
	if descriptor.Tasks[0].TargetScopes[0] != TargetNode {
		t.Fatalf("descriptor task scopes were aliased: %#v", descriptor.Tasks)
	}
	if descriptor.Tasks[0].ConfigSchema["properties"].([]any)[0] != "target" {
		t.Fatalf("descriptor task schema was aliased: %#v", descriptor.Tasks)
	}
	if descriptor.Attributes["nested"].(map[string]any)["value"] != "original" {
		t.Fatalf("descriptor attributes were aliased: %#v", descriptor.Attributes)
	}

	request := TaskRequest{
		Kind:   TaskCommand,
		Route:  &Route{Nodes: []string{"node-1"}},
		Config: map[string]any{"nested": map[string]any{"value": "original"}},
		Args:   []string{"whoami"},
		Agent:  &run.AgentContext{Resources: []string{"node-1"}},
	}
	clonedRequest := request.Clone()
	clonedRequest.Route.Nodes[0] = "mutated"
	clonedRequest.Config["nested"].(map[string]any)["value"] = "mutated"
	clonedRequest.Args[0] = "mutated"
	clonedRequest.Agent.Resources[0] = "mutated"
	if request.Route.Nodes[0] != "node-1" {
		t.Fatalf("task request route was aliased: %#v", request.Route)
	}
	if request.Config["nested"].(map[string]any)["value"] != "original" {
		t.Fatalf("task request config was aliased: %#v", request.Config)
	}
	if request.Args[0] != "whoami" {
		t.Fatalf("task request arguments were aliased: %#v", request.Args)
	}
	if request.Agent.Resources[0] != "node-1" {
		t.Fatalf("task request agent was aliased: %#v", request.Agent)
	}

	result := TaskResult{
		Status:   TaskStatusSucceeded,
		Outputs:  map[string]any{"nested": map[string]any{"value": "original"}},
		Sessions: []run.SessionRef{{ID: "session-1", Capabilities: []string{"datagram"}}},
		Beacons:  []Beacon{{ID: "beacon-1", NodeID: "node-1", Fields: map[string]any{"value": "original"}}},
		Events:   []Event{{Kind: "progress", Fields: map[string]any{"value": "original"}}},
		AgentHints: []run.AgentHint{{
			AppliesTo:  map[string]string{"node": "node-1"},
			Provenance: map[string]string{"provider": "mesh"},
		}},
	}
	clonedResult := result.Clone()
	clonedResult.Outputs["nested"].(map[string]any)["value"] = "mutated"
	clonedResult.Sessions[0].Capabilities[0] = "mutated"
	clonedResult.Beacons[0].Fields["value"] = "mutated"
	clonedResult.Events[0].Fields["value"] = "mutated"
	clonedResult.AgentHints[0].AppliesTo["node"] = "mutated"
	clonedResult.AgentHints[0].Provenance["provider"] = "mutated"
	if result.Outputs["nested"].(map[string]any)["value"] != "original" {
		t.Fatalf("task result outputs were aliased: %#v", result.Outputs)
	}
	if result.Sessions[0].Capabilities[0] != "datagram" {
		t.Fatalf("task result session capabilities were aliased: %#v", result.Sessions)
	}
	if result.Beacons[0].Fields["value"] != "original" {
		t.Fatalf("task result beacon fields were aliased: %#v", result.Beacons)
	}
	if result.Events[0].Fields["value"] != "original" {
		t.Fatalf("task result event fields were aliased: %#v", result.Events)
	}
	if result.AgentHints[0].AppliesTo["node"] != "node-1" {
		t.Fatalf("task result hint targets were aliased: %#v", result.AgentHints)
	}
	if result.AgentHints[0].Provenance["provider"] != "mesh" {
		t.Fatalf("task result hint provenance was aliased: %#v", result.AgentHints)
	}
}

func cloneTestTopology(topology Topology) Topology {
	result := topology
	result.Nodes = append([]Node(nil), topology.Nodes...)
	result.Links = append([]Link(nil), topology.Links...)
	result.Routes = make([]Route, len(topology.Routes))
	for index, route := range topology.Routes {
		result.Routes[index] = route
		result.Routes[index].Nodes = append([]string(nil), route.Nodes...)
		result.Routes[index].Links = append([]string(nil), route.Links...)
	}
	return result
}
