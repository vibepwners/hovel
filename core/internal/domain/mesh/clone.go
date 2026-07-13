package mesh

import (
	"reflect"

	"github.com/vibepwners/hovel/internal/domain/run"
)

// Clone returns a deep copy of the listener's mutable fields.
func (l Listener) Clone() Listener {
	l.Addresses = append([]string(nil), l.Addresses...)
	l.Protocols = append([]string(nil), l.Protocols...)
	l.Capabilities = append([]string(nil), l.Capabilities...)
	l.Labels = cloneAnyMap(l.Labels)
	l.Attributes = cloneAnyMap(l.Attributes)
	return l
}

// Clone returns a deep copy of the listener list request's mutable fields.
func (r ListenerListRequest) Clone() ListenerListRequest {
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

// Clone returns a deep copy of the listener start request's mutable fields.
func (r ListenerStartRequest) Clone() ListenerStartRequest {
	r.Config = cloneAnyMap(r.Config)
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

// Clone returns a deep copy of the listener stop request's mutable fields.
func (r ListenerStopRequest) Clone() ListenerStopRequest {
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

// Clone returns a deep copy of the route's mutable fields.
func (r Route) Clone() Route {
	r.Nodes = append([]string(nil), r.Nodes...)
	r.Links = append([]string(nil), r.Links...)
	r.Attributes = cloneAnyMap(r.Attributes)
	return r
}

// Clone returns a deep copy of the topology's mutable fields.
func (t Topology) Clone() Topology {
	t.Nodes = append([]Node(nil), t.Nodes...)
	for index := range t.Nodes {
		t.Nodes[index].Labels = cloneAnyMap(t.Nodes[index].Labels)
		t.Nodes[index].Attributes = cloneAnyMap(t.Nodes[index].Attributes)
		t.Nodes[index].Capabilities = append(
			[]string(nil),
			t.Nodes[index].Capabilities...,
		)
	}
	t.Links = append([]Link(nil), t.Links...)
	for index := range t.Links {
		t.Links[index].Attributes = cloneAnyMap(t.Links[index].Attributes)
	}
	t.Routes = append([]Route(nil), t.Routes...)
	for index := range t.Routes {
		t.Routes[index] = t.Routes[index].Clone()
	}
	t.Attributes = cloneAnyMap(t.Attributes)
	return t
}

// Clone returns a deep copy of the provider descriptor's mutable fields.
func (d Descriptor) Clone() Descriptor {
	d.Capabilities = append([]string(nil), d.Capabilities...)
	if d.Topology != nil {
		topology := d.Topology.Clone()
		d.Topology = &topology
	}
	d.Tasks = append([]TaskSpec(nil), d.Tasks...)
	for index := range d.Tasks {
		d.Tasks[index].ConfigSchema = cloneAnyMap(d.Tasks[index].ConfigSchema)
		d.Tasks[index].TargetScopes = append(
			[]TargetScope(nil),
			d.Tasks[index].TargetScopes...,
		)
		d.Tasks[index].Capabilities = append(
			[]string(nil),
			d.Tasks[index].Capabilities...,
		)
	}
	d.ListenerTypes = append([]ListenerSpec(nil), d.ListenerTypes...)
	for index := range d.ListenerTypes {
		d.ListenerTypes[index].Deployments = append(
			[]ListenerDeployment(nil),
			d.ListenerTypes[index].Deployments...,
		)
		d.ListenerTypes[index].ManagementModes = append(
			[]ListenerManagement(nil),
			d.ListenerTypes[index].ManagementModes...,
		)
		d.ListenerTypes[index].Protocols = append(
			[]string(nil),
			d.ListenerTypes[index].Protocols...,
		)
		d.ListenerTypes[index].ConfigSchema = cloneAnyMap(
			d.ListenerTypes[index].ConfigSchema,
		)
		d.ListenerTypes[index].Capabilities = append(
			[]string(nil),
			d.ListenerTypes[index].Capabilities...,
		)
	}
	d.Triggers = append([]Trigger(nil), d.Triggers...)
	for index := range d.Triggers {
		d.Triggers[index].Config = cloneAnyMap(d.Triggers[index].Config)
	}
	if d.CredentialDelivery != nil {
		delivery := d.CredentialDelivery.Clone()
		d.CredentialDelivery = &delivery
	}
	d.Attributes = cloneAnyMap(d.Attributes)
	return d
}

// Clone returns a deep copy of the beacon's mutable fields.
func (b Beacon) Clone() Beacon {
	b.Fields = cloneAnyMap(b.Fields)
	return b
}

// Clone returns a deep copy of the describe request's mutable fields.
func (r DescribeRequest) Clone() DescribeRequest {
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

// Clone returns a deep copy of the topology request's mutable fields.
func (r TopologyRequest) Clone() TopologyRequest {
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

// Clone returns a deep copy of the beacon request's mutable fields.
func (r BeaconRequest) Clone() BeaconRequest {
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

// Clone returns a deep copy of the task request's mutable fields.
func (r TaskRequest) Clone() TaskRequest {
	if r.Route != nil {
		route := r.Route.Clone()
		r.Route = &route
	}
	r.Config = cloneAnyMap(r.Config)
	r.Args = append([]string(nil), r.Args...)
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

// Clone returns a deep copy of the task result's mutable fields.
func (r TaskResult) Clone() TaskResult {
	if r.Route != nil {
		route := r.Route.Clone()
		r.Route = &route
	}
	r.Outputs = cloneAnyMap(r.Outputs)
	r.Findings = append([]run.Finding(nil), r.Findings...)
	r.Artifacts = append([]run.Artifact(nil), r.Artifacts...)
	r.Sessions = append([]run.SessionRef(nil), r.Sessions...)
	for index := range r.Sessions {
		r.Sessions[index].Capabilities = append(
			[]string(nil),
			r.Sessions[index].Capabilities...,
		)
	}
	r.Beacons = append([]Beacon(nil), r.Beacons...)
	for index := range r.Beacons {
		r.Beacons[index] = r.Beacons[index].Clone()
	}
	r.Events = append([]Event(nil), r.Events...)
	for index := range r.Events {
		r.Events[index].Fields = cloneAnyMap(r.Events[index].Fields)
	}
	r.AgentHints = append([]run.AgentHint(nil), r.AgentHints...)
	for index := range r.AgentHints {
		r.AgentHints[index].AppliesTo = cloneStringMap(r.AgentHints[index].AppliesTo)
		r.AgentHints[index].Provenance = cloneStringMap(r.AgentHints[index].Provenance)
	}
	return r
}

// Clone returns a deep copy of the stream request's mutable fields.
func (r StreamRequest) Clone() StreamRequest {
	if r.Route != nil {
		route := r.Route.Clone()
		r.Route = &route
	}
	r.Config = cloneAnyMap(r.Config)
	r.Agent = cloneAgentContext(r.Agent)
	return r
}

func cloneAgentContext(agent *run.AgentContext) *run.AgentContext {
	if agent == nil {
		return nil
	}
	result := *agent
	result.Resources = append([]string(nil), agent.Resources...)
	return &result
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	return cloneReflectValue(
		reflect.ValueOf(values),
		make(map[cloneVisit]reflect.Value),
	).Interface().(map[string]any)
}

type cloneVisit struct {
	kind      reflect.Kind
	valueType reflect.Type
	pointer   uintptr
	length    int
	capacity  int
}

func cloneReflectValue(value reflect.Value, visited map[cloneVisit]reflect.Value) reflect.Value {
	if !value.IsValid() {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		cloned := cloneReflectValue(value.Elem(), visited)
		result := reflect.New(value.Type()).Elem()
		result.Set(cloned)
		return result
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := cloneVisit{
			kind: value.Kind(), valueType: value.Type(), pointer: value.Pointer(),
		}
		if cloned, ok := visited[visit]; ok {
			return cloned
		}
		result := reflect.New(value.Type().Elem())
		visited[visit] = result
		result.Elem().Set(cloneReflectValue(value.Elem(), visited))
		return result
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := cloneVisit{
			kind: value.Kind(), valueType: value.Type(), pointer: value.Pointer(),
		}
		if cloned, ok := visited[visit]; ok {
			return cloned
		}
		result := reflect.MakeMapWithSize(value.Type(), value.Len())
		visited[visit] = result
		iterator := value.MapRange()
		for iterator.Next() {
			result.SetMapIndex(
				cloneReflectValue(iterator.Key(), visited),
				cloneReflectValue(iterator.Value(), visited),
			)
		}
		return result
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		visit := cloneVisit{
			kind:      value.Kind(),
			valueType: value.Type(),
			pointer:   value.Pointer(),
			length:    value.Len(),
			capacity:  value.Cap(),
		}
		if cloned, ok := visited[visit]; ok {
			return cloned
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		visited[visit] = result
		for index := range value.Len() {
			result.Index(index).Set(cloneReflectValue(value.Index(index), visited))
		}
		return result
	case reflect.Array:
		result := reflect.New(value.Type()).Elem()
		for index := range value.Len() {
			result.Index(index).Set(cloneReflectValue(value.Index(index), visited))
		}
		return result
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		result.Set(value)
		for index := range value.NumField() {
			if result.Field(index).CanSet() && value.Type().Field(index).IsExported() {
				result.Field(index).Set(cloneReflectValue(value.Field(index), visited))
			}
		}
		return result
	default:
		return value
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
