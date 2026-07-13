package mesh

import (
	"errors"
	"fmt"
	"strings"
)

// MaximumNetworkPort is the highest valid value for an optional destination port.
const MaximumNetworkPort = int(^uint16(0))

// Validate checks an ordered route's structural invariants.
func (r Route) Validate() error {
	if len(r.Nodes) == 0 {
		return errors.New("mesh route must contain at least one node")
	}
	if err := validateUniqueRequiredStrings(r.Nodes, "route node"); err != nil {
		return err
	}
	if len(r.Links) > 0 && len(r.Links) != len(r.Nodes)-1 {
		return errors.New("mesh route links must connect each consecutive node")
	}
	return validateUniqueRequiredStrings(r.Links, "route link")
}

// Validate checks topology identifiers, references, parent chains, and routes.
func (t Topology) Validate() error {
	nodes, err := validateTopologyNodes(t)
	if err != nil {
		return err
	}
	links, err := validateTopologyLinks(t.Links, nodes)
	if err != nil {
		return err
	}
	return validateTopologyRoutes(t.Routes, nodes, links)
}

// Validate checks the optional capability sets advertised by a provider.
func (d Descriptor) Validate() error {
	if d.Topology != nil {
		if err := d.Topology.Validate(); err != nil {
			return err
		}
	}
	seenTasks := make(map[TaskKind]struct{}, len(d.Tasks))
	for _, task := range d.Tasks {
		kind, err := validateRequiredCanonicalString(string(task.Kind), "task kind")
		if err != nil {
			return err
		}
		taskKind := TaskKind(kind)
		if _, exists := seenTasks[taskKind]; exists {
			return fmt.Errorf("mesh task kind %q is duplicated", taskKind)
		}
		seenTasks[taskKind] = struct{}{}
	}
	seenListeners := make(map[string]struct{}, len(d.ListenerTypes))
	for _, listener := range d.ListenerTypes {
		kind, err := validateRequiredCanonicalString(listener.Kind, "listener kind")
		if err != nil {
			return err
		}
		if _, exists := seenListeners[kind]; exists {
			return fmt.Errorf("mesh listener kind %q is duplicated", kind)
		}
		seenListeners[kind] = struct{}{}
	}
	seenTriggers := make(map[string]struct{}, len(d.Triggers))
	for _, trigger := range d.Triggers {
		id, err := validateRequiredCanonicalString(trigger.ID, "trigger id")
		if err != nil {
			return err
		}
		if _, exists := seenTriggers[id]; exists {
			return fmt.Errorf("mesh trigger id %q is duplicated", id)
		}
		seenTriggers[id] = struct{}{}
		if trigger.ActionKind != "" {
			if _, err := validateRequiredCanonicalString(
				string(trigger.ActionKind),
				"trigger action kind",
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// Validate checks topology query identifiers before provider dispatch.
func (r TopologyRequest) Validate() error {
	if _, err := validateOptionalCanonicalString(r.Root, "topology request root"); err != nil {
		return err
	}
	if _, err := validateOptionalCanonicalString(
		r.ListenerID,
		"topology request listener id",
	); err != nil {
		return err
	}
	return nil
}

// Validate rejects invalid beacon query bounds.
func (r BeaconRequest) Validate() error {
	if r.Limit < 0 {
		return errors.New("mesh beacon limit cannot be negative")
	}
	if _, err := validateOptionalCanonicalString(r.NodeID, "beacon request node id"); err != nil {
		return err
	}
	if _, err := validateOptionalCanonicalString(
		r.ListenerID,
		"beacon request listener id",
	); err != nil {
		return err
	}
	return nil
}

// Validate checks the identity fields required for a provider beacon.
func (b Beacon) Validate() error {
	if _, err := validateRequiredCanonicalString(b.ID, "beacon id"); err != nil {
		return err
	}
	if _, err := validateRequiredCanonicalString(b.NodeID, "beacon node id"); err != nil {
		return err
	}
	return nil
}

// Validate checks a task request before it crosses the provider boundary.
func (r TaskRequest) Validate() error {
	if _, err := validateRequiredCanonicalString(string(r.Kind), "task kind"); err != nil {
		return err
	}
	if err := validateDestinationPort(r.DestinationPort); err != nil {
		return err
	}
	if r.Route != nil {
		return r.Route.Validate()
	}
	return nil
}

// Validate checks a provider task result before it enters daemon bookkeeping.
func (r TaskResult) Validate() error {
	status, err := validateRequiredCanonicalString(string(r.Status), "task status")
	if err != nil {
		return err
	}
	switch TaskStatus(status) {
	case TaskStatusSucceeded, TaskStatusFailed:
	default:
		return fmt.Errorf("mesh task status %q is not supported", status)
	}
	if err := validateDestinationPort(r.DestinationPort); err != nil {
		return err
	}
	if r.Route != nil {
		if err := r.Route.Validate(); err != nil {
			return err
		}
	}
	seenBeacons := make(map[string]struct{}, len(r.Beacons))
	for _, beacon := range r.Beacons {
		if err := beacon.Validate(); err != nil {
			return err
		}
		if _, exists := seenBeacons[beacon.ID]; exists {
			return fmt.Errorf("mesh beacon id %q is duplicated", beacon.ID)
		}
		seenBeacons[beacon.ID] = struct{}{}
	}
	return nil
}

// Validate checks a stream request before it crosses the provider boundary.
func (r StreamRequest) Validate() error {
	if err := validateDestinationPort(r.DestinationPort); err != nil {
		return err
	}
	if r.Route != nil {
		return r.Route.Validate()
	}
	return nil
}

func validateTopologyNodes(topology Topology) (map[string]Node, error) {
	nodes := make(map[string]Node, len(topology.Nodes))
	for _, node := range topology.Nodes {
		id, err := validateRequiredCanonicalString(node.ID, "topology node id")
		if err != nil {
			return nil, err
		}
		if _, err := validateOptionalCanonicalString(
			node.ParentID,
			"topology node parent id",
		); err != nil {
			return nil, err
		}
		if _, exists := nodes[id]; exists {
			return nil, fmt.Errorf("mesh topology node id %q is duplicated", id)
		}
		nodes[id] = node
	}
	root, err := validateOptionalCanonicalString(topology.Root, "topology root")
	if err != nil {
		return nil, err
	}
	if root != "" {
		if _, exists := nodes[root]; !exists {
			return nil, fmt.Errorf("mesh topology root %q does not exist", root)
		}
	}
	for _, node := range topology.Nodes {
		id := node.ID
		parent := node.ParentID
		if id == root && parent != "" {
			return nil, fmt.Errorf("mesh topology root %q must not have a parent", root)
		}
		if parent != "" {
			if _, exists := nodes[parent]; !exists {
				return nil, fmt.Errorf("mesh topology node %q references missing parent %q", id, parent)
			}
		}
		chainRoot, err := validateParentChain(id, nodes)
		if err != nil {
			return nil, err
		}
		if root != "" && chainRoot != root {
			return nil, fmt.Errorf(
				"mesh topology node %q is not connected to root %q",
				id,
				root,
			)
		}
	}
	return nodes, nil
}

func validateParentChain(start string, nodes map[string]Node) (string, error) {
	seen := map[string]struct{}{start: {}}
	current := start
	for {
		parent := nodes[current].ParentID
		if parent == "" {
			return current, nil
		}
		if _, exists := seen[parent]; exists {
			return "", fmt.Errorf("mesh topology parent cycle includes node %q", parent)
		}
		seen[parent] = struct{}{}
		current = parent
	}
}

func validateTopologyLinks(links []Link, nodes map[string]Node) (map[string]Link, error) {
	result := make(map[string]Link, len(links))
	for _, link := range links {
		id, err := validateRequiredCanonicalString(link.ID, "topology link id")
		if err != nil {
			return nil, err
		}
		if _, exists := result[id]; exists {
			return nil, fmt.Errorf("mesh topology link id %q is duplicated", id)
		}
		source, err := validateRequiredCanonicalString(link.Source, "topology link source")
		if err != nil {
			return nil, err
		}
		if _, exists := nodes[source]; !exists {
			return nil, fmt.Errorf(
				"mesh topology link %q source %q does not exist",
				id,
				source,
			)
		}
		target, err := validateRequiredCanonicalString(link.Target, "topology link target")
		if err != nil {
			return nil, err
		}
		if _, exists := nodes[target]; !exists {
			return nil, fmt.Errorf(
				"mesh topology link %q target %q does not exist",
				id,
				target,
			)
		}
		if source == target {
			return nil, fmt.Errorf("mesh topology link %q must connect distinct nodes", id)
		}
		result[id] = link
	}
	return result, nil
}

func validateTopologyRoutes(
	routes []Route,
	nodes map[string]Node,
	links map[string]Link,
) error {
	seenIDs := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return err
		}
		id, err := validateOptionalCanonicalString(route.ID, "topology route id")
		if err != nil {
			return err
		}
		if id != "" {
			if _, exists := seenIDs[id]; exists {
				return fmt.Errorf("mesh topology route id %q is duplicated", id)
			}
			seenIDs[id] = struct{}{}
		}
		for _, nodeID := range route.Nodes {
			if _, exists := nodes[nodeID]; !exists {
				return fmt.Errorf("mesh topology route references missing node %q", nodeID)
			}
		}
		for index, linkID := range route.Links {
			link, exists := links[linkID]
			if !exists {
				return fmt.Errorf("mesh topology route references missing link %q", linkID)
			}
			if !linkConnects(link, route.Nodes[index], route.Nodes[index+1]) {
				return fmt.Errorf("mesh topology route link %q does not connect its consecutive nodes", linkID)
			}
		}
	}
	return nil
}

func linkConnects(link Link, left string, right string) bool {
	return link.Source == left && link.Target == right || link.Source == right && link.Target == left
}

func validateUniqueRequiredStrings(values []string, field string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value, err := validateRequiredCanonicalString(value, field)
		if err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("mesh %s %q is duplicated", field, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateRequiredCanonicalString(value, field string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("mesh %s is required", field)
	}
	if strings.TrimSpace(value) != value {
		return "", fmt.Errorf("mesh %s %q must be canonical", field, value)
	}
	return value, nil
}

func validateOptionalCanonicalString(value, field string) (string, error) {
	if value == "" {
		return "", nil
	}
	return validateRequiredCanonicalString(value, field)
}

func validateDestinationPort(port int) error {
	if port < 0 || port > MaximumNetworkPort {
		return fmt.Errorf("mesh destination port must be between 0 and %d", MaximumNetworkPort)
	}
	return nil
}
