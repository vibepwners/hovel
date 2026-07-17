package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

const (
	meshRootNodeID          = "squatter-provider"
	meshTLSCredentialSlot   = "mesh-stream-tls-server"
	meshProtocolRaw         = "squatter"
	meshProtocolTLS         = "squatter+tls"
	meshMaximumBundleBytes  = 8 << 20
	meshStreamReadChunkSize = 32 << 10
)

type runtimeCredentialReceipt struct {
	requestSHA256 string
	receipt       hovel.CredentialDeliveryReceipt
}

type meshEndpoint struct {
	NodeID   string
	Host     string
	Port     int
	State    string
	LastSeen time.Time
}

func (Provider) DescribeCredentialDelivery() (hovel.CredentialDeliveryDescriptor, error) {
	return squatterCredentialDeliveryDescriptor(), nil
}

func squatterCredentialDeliveryDescriptor() hovel.CredentialDeliveryDescriptor {
	return hovel.CredentialDeliveryDescriptor{
		SchemaVersion: hovel.CredentialDeliverySchemaV1,
		Slots: []hovel.CredentialSlot{{
			Name:                         meshTLSCredentialSlot,
			Purpose:                      hovel.CredentialPurposeTLSServer,
			EndpointRole:                 hovel.CredentialEndpointServer,
			ConsumerType:                 hovel.CredentialConsumerMeshProvider,
			AcceptedBundleVersions:       []string{hovel.CredentialBundleSchemaV1},
			AcceptedProfiles:             []string{"tls-server"},
			AcceptedCompatibilityTargets: []string{"portable-x509"},
			AcceptedProjections:          []hovel.CredentialProjection{hovel.CredentialProjectionBundle},
			AcceptedMaterialForms:        []hovel.CredentialMaterialForm{hovel.CredentialMaterialPrivateBytes},
			MaximumEncodedBytes:          meshMaximumBundleBytes,
			RemainderPolicy:              hovel.CredentialStampRemainderPreserve,
			PrivateMaterial:              hovel.CredentialPrivateMaterialRequired,
		}},
		Capabilities: []hovel.CredentialDeliveryCapability{hovel.CredentialDeliveryRuntime},
	}
}

func (p Provider) DescribeMesh(hovel.MeshDescribeRequest) (hovel.MeshDescriptor, error) {
	credentialDelivery := squatterCredentialDeliveryDescriptor()
	topology := p.squatterMeshTopology(false)
	return hovel.MeshDescriptor{
		Name:    payloadName,
		Version: version,
		Summary: "Destination-scoped Squatter mesh streams with provider-terminated TLS.",
		Capabilities: []string{
			"topology.tree",
			"topology.multi-node",
			"task.survey",
			"stream.squatter",
			"stream.squatter+tls",
		},
		Topology: &topology,
		Tasks: []hovel.MeshTaskSpec{{
			Kind:         hovel.MeshTaskSurvey,
			Summary:      "Check whether a destination exposes a Squatter TCP bind endpoint.",
			ReadOnly:     true,
			TargetScopes: []hovel.MeshTargetScope{hovel.MeshTargetDestination},
			Capabilities: []string{"transport.tcp-bind"},
		}},
		CredentialDelivery: &credentialDelivery,
		Attributes: map[string]any{
			"tlsTermination":  "provider",
			"targetTransport": "squatter/tcp-bind",
			"protocols":       []string{meshProtocolRaw, meshProtocolTLS},
		},
	}, nil
}

func (p Provider) MeshTopology(req hovel.MeshTopologyRequest) (hovel.MeshTopology, error) {
	if strings.TrimSpace(req.ListenerID) != "" {
		return hovel.MeshTopology{}, errors.New("squatter: mesh topology is not listener-scoped")
	}
	topology := p.squatterMeshTopology(req.IncludeRoutes)
	root := strings.TrimSpace(req.Root)
	if root != "" && root != meshRootNodeID {
		known := false
		for _, node := range topology.Nodes {
			known = known || node.ID == root
		}
		if !known {
			return hovel.MeshTopology{}, fmt.Errorf("squatter: unknown mesh root %q", req.Root)
		}
	}
	return topology, nil
}

func (p Provider) squatterMeshTopology(includeRoutes bool) hovel.MeshTopology {
	endpoints := p.meshEndpointSnapshot()
	topology := hovel.MeshTopology{
		Root: meshRootNodeID,
		Nodes: []hovel.MeshNode{{
			ID:           meshRootNodeID,
			Name:         "Squatter provider",
			Kind:         "provider",
			State:        "ready",
			Capabilities: []string{"survey", "stream"},
		}},
		Attributes: map[string]any{
			"scope":     "destination",
			"nodeCount": len(endpoints) + 1,
		},
	}
	for _, endpoint := range endpoints {
		linkID := meshLinkID(endpoint.NodeID)
		topology.Nodes = append(topology.Nodes, hovel.MeshNode{
			ID:         endpoint.NodeID,
			ParentID:   meshRootNodeID,
			Name:       "Squatter " + net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)),
			Kind:       "squatter-agent",
			State:      endpoint.State,
			Address:    net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)),
			Platform:   platform,
			OS:         platform,
			Arch:       arch,
			LastSeen:   endpoint.LastSeen.UTC().Format(time.RFC3339Nano),
			Attributes: map[string]any{"host": endpoint.Host, "port": endpoint.Port},
			Capabilities: []string{
				"survey", "stream", "squatter.frames", "tls.provider-terminated",
			},
		})
		topology.Links = append(topology.Links, hovel.MeshLink{
			ID:        linkID,
			Source:    meshRootNodeID,
			Target:    endpoint.NodeID,
			Kind:      "provider-direct",
			State:     meshLinkState(endpoint.State),
			Transport: "squatter/tcp-bind",
			Cost:      1,
		})
		if includeRoutes {
			topology.Routes = append(topology.Routes, meshRoute(endpoint))
		}
	}
	return topology
}

func (p Provider) meshEndpointSnapshot() []meshEndpoint {
	lp := p.listeningPost()
	lp.mu.Lock()
	defer lp.mu.Unlock()
	result := make([]meshEndpoint, 0, len(lp.meshNodes))
	for _, endpoint := range lp.meshNodes {
		result = append(result, endpoint)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].NodeID < result[right].NodeID
	})
	return result
}

func meshNodeID(host string, port int) string {
	digest := sha256.Sum256([]byte(net.JoinHostPort(host, strconv.Itoa(port))))
	return "squatter-node-" + hex.EncodeToString(digest[:8])
}

func meshLinkID(nodeID string) string { return "squatter-link-" + nodeID }

func meshRoute(endpoint meshEndpoint) hovel.MeshRoute {
	return hovel.MeshRoute{
		ID:    "squatter-route-" + endpoint.NodeID,
		Nodes: []string{meshRootNodeID, endpoint.NodeID},
		Links: []string{meshLinkID(endpoint.NodeID)},
		Cost:  1,
		Attributes: map[string]any{
			"destinationHost": endpoint.Host,
			"destinationPort": endpoint.Port,
		},
	}
}

func meshLinkState(nodeState string) string {
	if nodeState == "ready" {
		return "up"
	}
	return "down"
}

func (p Provider) LoadRuntimeCredential(
	req hovel.CredentialRuntimeRequest,
) (hovel.CredentialDeliveryReceipt, error) {
	if err := req.Validate(); err != nil {
		return hovel.CredentialDeliveryReceipt{}, err
	}
	if req.Provider.ModuleID != payloadName+"@"+version ||
		req.Provider.ProviderID != payloadName || req.Provider.ProviderVersion != version {
		return hovel.CredentialDeliveryReceipt{}, errors.New(
			"squatter: runtime credential targets a different provider",
		)
	}
	if req.SlotName != meshTLSCredentialSlot ||
		req.Material.Projection != hovel.CredentialProjectionBundle ||
		req.Material.Form() != hovel.CredentialMaterialPrivateBytes ||
		req.Material.Encoding != hovel.CredentialEncodingJSON {
		return hovel.CredentialDeliveryReceipt{}, errors.New(
			"squatter: runtime credential does not match the TLS mesh-stream slot",
		)
	}
	if req.Credential.Purpose != hovel.CredentialPurposeTLSServer ||
		req.Credential.ConsumerType != hovel.CredentialConsumerMeshProvider ||
		req.Credential.ProfileID != "tls-server" ||
		req.Credential.CompatibilityTargetID != "portable-x509" {
		return hovel.CredentialDeliveryReceipt{}, errors.New(
			"squatter: runtime credential metadata does not match the TLS mesh-stream slot",
		)
	}
	requestSHA256, err := runtimeCredentialRequestSHA256(req)
	if err != nil {
		return hovel.CredentialDeliveryReceipt{}, err
	}
	lp := p.listeningPost()
	lp.mu.Lock()
	if previous, ok := lp.receipts[req.RequestID]; ok {
		lp.mu.Unlock()
		if previous.requestSHA256 != requestSHA256 {
			return hovel.CredentialDeliveryReceipt{}, errors.New(
				"squatter: runtime credential request id was reused with different input",
			)
		}
		return previous.receipt, nil
	}
	lp.mu.Unlock()
	material, ok := req.Material.Bytes()
	if !ok {
		return hovel.CredentialDeliveryReceipt{}, errors.New(
			"squatter: TLS mesh-stream bundle did not contain private bytes",
		)
	}
	if len(material) > meshMaximumBundleBytes {
		clear(material)
		return hovel.CredentialDeliveryReceipt{}, errors.New(
			"squatter: TLS mesh-stream bundle exceeds the advertised size limit",
		)
	}
	bundle, err := hovel.DecodeCredentialBundleJSON(material)
	clear(material)
	if err != nil {
		return hovel.CredentialDeliveryReceipt{}, fmt.Errorf(
			"squatter: validate TLS mesh-stream bundle: %w",
			err,
		)
	}
	if bundle.AssignmentID != req.AssignmentID ||
		bundle.Purpose != req.Credential.Purpose ||
		bundle.CompatibilityTargetID != req.Credential.CompatibilityTargetID ||
		req.Credential.BundleVersion != bundle.SchemaVersion {
		bundle.Clear()
		return hovel.CredentialDeliveryReceipt{}, errors.New(
			"squatter: TLS mesh-stream bundle metadata does not match its delivery envelope",
		)
	}
	if _, err := bundle.TLSServerConfigAt(time.Now().UTC()); err != nil {
		bundle.Clear()
		return hovel.CredentialDeliveryReceipt{}, fmt.Errorf(
			"squatter: configure TLS mesh-stream credential: %w",
			err,
		)
	}
	receipt := hovel.CredentialDeliveryReceipt{
		RequestID:         req.RequestID,
		ProviderReference: "squatter-tls:" + requestSHA256[:32],
		ReceiptSHA256:     requestSHA256,
	}
	lp.mu.Lock()
	if previous, ok := lp.receipts[req.RequestID]; ok {
		lp.mu.Unlock()
		bundle.Clear()
		if previous.requestSHA256 != requestSHA256 {
			return hovel.CredentialDeliveryReceipt{}, errors.New(
				"squatter: runtime credential request id was reused with different input",
			)
		}
		return previous.receipt, nil
	}
	lp.tlsBundle.Clear()
	lp.tlsBundle = bundle
	lp.receipts[req.RequestID] = runtimeCredentialReceipt{
		requestSHA256: requestSHA256,
		receipt:       receipt,
	}
	lp.mu.Unlock()
	return receipt, nil
}

func runtimeCredentialRequestSHA256(req hovel.CredentialRuntimeRequest) (string, error) {
	binding := struct {
		SchemaVersion string                           `json:"schemaVersion"`
		Provider      hovel.CredentialProviderTarget   `json:"provider"`
		AssignmentID  string                           `json:"assignmentId"`
		SlotName      string                           `json:"slotName"`
		Credential    hovel.ResolvedCredentialMetadata `json:"credential"`
		Projection    hovel.CredentialProjection       `json:"projection"`
		Form          hovel.CredentialMaterialForm     `json:"form"`
		Encoding      string                           `json:"encoding"`
		MaterialSHA   string                           `json:"materialSha256"`
		Scope         hovel.CredentialOperationScope   `json:"scope"`
	}{
		SchemaVersion: req.SchemaVersion,
		Provider:      req.Provider,
		AssignmentID:  req.AssignmentID,
		SlotName:      req.SlotName,
		Credential:    req.Credential,
		Projection:    req.Material.Projection,
		Form:          req.Material.Form(),
		Encoding:      req.Material.Encoding,
		MaterialSHA:   req.Material.SHA256,
		Scope:         req.Scope,
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("squatter: bind runtime credential request: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (p Provider) RunMeshTask(
	_ *hovel.MeshContext,
	req hovel.MeshTaskRequest,
) (hovel.MeshTaskResult, error) {
	if req.Kind != hovel.MeshTaskSurvey {
		return hovel.MeshTaskResult{
			TaskID:  req.TaskID,
			Status:  hovel.MeshTaskStatusFailed,
			Summary: "Squatter does not support this mesh task kind",
			NodeID:  req.NodeID,
		}, nil
	}
	opts, _, err := p.resolveSquatterMeshAddress(
		req.NodeID,
		req.ListenerID,
		req.Route,
		req.DestinationHost,
		req.DestinationPort,
		req.Target,
		req.Config,
	)
	if err != nil {
		return hovel.MeshTaskResult{}, err
	}
	conn, err := dialSquatterMeshDestination(opts)
	if err != nil {
		endpoint := p.rememberMeshEndpoint(opts, "offline")
		route := meshRoute(endpoint)
		return hovel.MeshTaskResult{
			TaskID:          req.TaskID,
			Status:          hovel.MeshTaskStatusFailed,
			Summary:         "Squatter TCP bind endpoint is unreachable",
			NodeID:          endpoint.NodeID,
			Route:           &route,
			DestinationHost: opts.Host,
			DestinationPort: opts.Port,
			Protocol:        meshProtocolRaw,
			Outputs:         map[string]any{"reachable": false},
		}, nil
	}
	if err := conn.Close(); err != nil {
		return hovel.MeshTaskResult{}, err
	}
	endpoint := p.rememberMeshEndpoint(opts, "ready")
	route := meshRoute(endpoint)
	return hovel.MeshTaskResult{
		TaskID:          req.TaskID,
		Status:          hovel.MeshTaskStatusSucceeded,
		Summary:         "Squatter TCP bind endpoint is reachable",
		NodeID:          endpoint.NodeID,
		Route:           &route,
		DestinationHost: opts.Host,
		DestinationPort: opts.Port,
		Protocol:        meshProtocolRaw,
		Outputs: map[string]any{
			"reachable": true,
			"transport": tcpBind,
		},
	}, nil
}

func (p Provider) OpenMeshStream(
	ctx *hovel.MeshContext,
	req hovel.MeshStreamRequest,
) (hovel.SessionRef, error) {
	opts, _, err := p.resolveSquatterMeshAddress(
		req.NodeID,
		req.ListenerID,
		req.Route,
		req.DestinationHost,
		req.DestinationPort,
		req.Target,
		req.Config,
	)
	if err != nil {
		return hovel.SessionRef{}, err
	}
	protocol := strings.TrimSpace(req.Protocol)
	if protocol == "" {
		protocol = meshProtocolRaw
	}
	if protocol != meshProtocolRaw && protocol != meshProtocolTLS {
		return hovel.SessionRef{}, fmt.Errorf("squatter: unsupported mesh stream protocol %q", protocol)
	}
	raw, err := dialSquatterMeshDestination(opts)
	if err != nil {
		p.rememberMeshEndpoint(opts, "offline")
		return hovel.SessionRef{}, err
	}
	endpoint := p.rememberMeshEndpoint(opts, "ready")
	var session hovel.Session = newMeshConnSession(raw, nil)
	capabilities := []string{"read", "write", "close", "stream.tcp", "squatter.frames"}
	transport := "squatter/tcp-bind"
	if protocol == meshProtocolTLS {
		tlsConfig, configErr := p.meshTLSServerConfig()
		if configErr != nil {
			logProviderError("close Squatter mesh destination", raw.Close())
			return hovel.SessionRef{}, configErr
		}
		session = newTLSMeshGatewaySession(raw, tlsConfig)
		capabilities = append(capabilities, "tls")
		transport = "squatter+tls/tcp-bind"
	}
	return ctx.OpenSession(
		session,
		hovel.WithName("Squatter mesh stream through "+endpoint.NodeID+" to "+net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))),
		hovel.WithKind("stream"),
		hovel.WithTransport(transport),
		hovel.WithCapabilities(capabilities...),
	)
}

func (p Provider) resolveSquatterMeshAddress(
	nodeID string,
	listenerID string,
	route *hovel.MeshRoute,
	destinationHost string,
	destinationPort int,
	target string,
	config map[string]any,
) (tcpBindOptions, string, error) {
	if strings.TrimSpace(listenerID) != "" {
		return tcpBindOptions{}, "", errors.New("squatter: mesh operation is not listener-scoped")
	}
	selectedNode := strings.TrimSpace(nodeID)
	if route != nil {
		routeNode, err := validateSquatterMeshRoute(*route)
		if err != nil {
			return tcpBindOptions{}, "", err
		}
		if selectedNode != "" && selectedNode != routeNode {
			return tcpBindOptions{}, "", errors.New("squatter: mesh node does not match route terminal node")
		}
		selectedNode = routeNode
	}
	if selectedNode == "" || selectedNode == meshRootNodeID {
		opts, err := meshTCPBindOptions(destinationHost, destinationPort, target, config)
		return opts, meshRootNodeID, err
	}
	endpoint, ok := p.meshEndpoint(selectedNode)
	if !ok {
		return tcpBindOptions{}, "", fmt.Errorf("squatter: unknown mesh node %q", selectedNode)
	}
	if strings.TrimSpace(destinationHost) != "" && strings.TrimSpace(destinationHost) != endpoint.Host {
		return tcpBindOptions{}, "", errors.New("squatter: destination host conflicts with the selected mesh node")
	}
	if destinationPort != 0 && destinationPort != endpoint.Port {
		return tcpBindOptions{}, "", errors.New("squatter: destination port conflicts with the selected mesh node")
	}
	opts, err := meshTCPBindOptions(endpoint.Host, endpoint.Port, target, config)
	return opts, selectedNode, err
}

func validateSquatterMeshRoute(route hovel.MeshRoute) (string, error) {
	if len(route.Nodes) == 1 && route.Nodes[0] == meshRootNodeID && len(route.Links) == 0 {
		return meshRootNodeID, nil
	}
	if len(route.Nodes) != 2 || route.Nodes[0] != meshRootNodeID ||
		len(route.Links) != 1 || route.Links[0] != meshLinkID(route.Nodes[1]) {
		return "", errors.New("squatter: mesh route must be a provider-to-Squatter-node path")
	}
	return route.Nodes[1], nil
}

func (p Provider) meshEndpoint(nodeID string) (meshEndpoint, bool) {
	lp := p.listeningPost()
	lp.mu.Lock()
	defer lp.mu.Unlock()
	endpoint, ok := lp.meshNodes[nodeID]
	return endpoint, ok
}

func (p Provider) rememberMeshEndpoint(opts tcpBindOptions, state string) meshEndpoint {
	endpoint := meshEndpoint{
		NodeID:   meshNodeID(opts.Host, opts.Port),
		Host:     opts.Host,
		Port:     opts.Port,
		State:    state,
		LastSeen: time.Now().UTC(),
	}
	lp := p.listeningPost()
	lp.mu.Lock()
	lp.meshNodes[endpoint.NodeID] = endpoint
	lp.mu.Unlock()
	return endpoint
}

func (p Provider) meshTLSServerConfig() (*tls.Config, error) {
	lp := p.listeningPost()
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if lp.tlsBundle.SchemaVersion == "" {
		return nil, errors.New(
			"squatter: TLS mesh stream requires a runtime credential bundle",
		)
	}
	config, err := lp.tlsBundle.TLSServerConfigAt(time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("squatter: configure TLS mesh stream: %w", err)
	}
	return config, nil
}

func meshTCPBindOptions(
	destinationHost string,
	destinationPort int,
	target string,
	config map[string]any,
) (tcpBindOptions, error) {
	stringValues := make(map[string]string, len(config)+2)
	for key, value := range config {
		switch typed := value.(type) {
		case string:
			stringValues[key] = typed
		case float64:
			if typed == math.Trunc(typed) {
				stringValues[key] = strconv.FormatFloat(typed, 'f', -1, 64)
			}
		case int:
			stringValues[key] = strconv.Itoa(typed)
		}
	}
	if strings.TrimSpace(destinationHost) != "" {
		stringValues["target.host"] = strings.TrimSpace(destinationHost)
	}
	if destinationPort != 0 {
		stringValues["payload.bind_port"] = strconv.Itoa(destinationPort)
	}
	return tcpBindOptionsFromRequest(hovel.ConnectSessionRequest{
		Target: strings.TrimSpace(target),
		Config: stringValues,
	})
}

func dialSquatterMeshDestination(opts tcpBindOptions) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: opts.Timeout}).DialContext(
		ctx,
		"tcp",
		net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port)),
	)
	if err != nil {
		return nil, fmt.Errorf("squatter: connect mesh destination: %w", err)
	}
	return connection, nil
}

type meshConnSession struct {
	conn       net.Conn
	closeExtra func()
	closeOnce  sync.Once
	closed     atomic.Bool
}

func newMeshConnSession(conn net.Conn, closeExtra func()) *meshConnSession {
	return &meshConnSession{conn: conn, closeExtra: closeExtra}
}

func (s *meshConnSession) Open() error { return nil }

func (s *meshConnSession) Write(data []byte) error {
	for len(data) > 0 {
		written, err := s.conn.Write(data)
		if err != nil {
			s.closed.Store(true)
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func (s *meshConnSession) Read(wait time.Duration) ([]byte, error) {
	if wait < 0 {
		if err := s.conn.SetReadDeadline(time.Time{}); err != nil {
			return nil, err
		}
	} else {
		if err := s.conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
			return nil, err
		}
	}
	buffer := make([]byte, meshStreamReadChunkSize)
	read, err := s.conn.Read(buffer)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			s.closed.Store(true)
			return nil, nil
		}
		s.closed.Store(true)
		return nil, err
	}
	return buffer[:read], nil
}

func (s *meshConnSession) Close(string) error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		closeErr = s.conn.Close()
		if s.closeExtra != nil {
			s.closeExtra()
		}
	})
	return closeErr
}

func (s *meshConnSession) Closed() bool { return s.closed.Load() }

func newTLSMeshGatewaySession(raw net.Conn, config *tls.Config) hovel.Session {
	external, internal := net.Pipe()
	session := newMeshConnSession(external, func() {
		logProviderError("close internal TLS mesh transport", internal.Close())
		logProviderError("close Squatter TLS mesh destination", raw.Close())
	})
	go serveTLSMeshGateway(session, internal, raw, config)
	return session
}

func serveTLSMeshGateway(
	session *meshConnSession,
	transport net.Conn,
	raw net.Conn,
	config *tls.Config,
) {
	server := tls.Server(transport, config)
	if err := server.Handshake(); err != nil {
		logProviderError("close failed TLS mesh session", session.Close("TLS handshake failed"))
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(raw, server)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(server, raw)
		done <- struct{}{}
	}()
	<-done
	logProviderError("close completed TLS mesh session", session.Close("TLS mesh stream ended"))
	<-done
}
