package daemonrpc

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vibepwners/hovel/internal/app/services"
	"github.com/vibepwners/hovel/internal/domain/mesh"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
	"github.com/vibepwners/hovel/internal/domain/run"
)

const (
	defaultMeshBridgeHost    = "127.0.0.1"
	meshBridgeReadTimeout    = 250 * time.Millisecond
	meshBridgeAuthTimeout    = 2 * time.Second
	meshBridgeCleanupTimeout = 5 * time.Second
	meshBridgeBufferSize     = 32 * 1024

	// MeshBridgeNetworkTCP selects the daemon's loopback TCP adapter.
	MeshBridgeNetworkTCP MeshBridgeNetwork = "tcp"
	// MeshBridgeNetworkUDP selects the daemon's loopback UDP adapter.
	MeshBridgeNetworkUDP MeshBridgeNetwork = "udp"

	// UDP over IPv4 can carry at most 65,507 payload bytes. Using the IPv4
	// ceiling keeps the bridge behavior stable for either loopback family.
	maxMeshBridgeDatagramSize    = 65_507
	meshBridgeDatagramBufferSize = maxMeshBridgeDatagramSize + 1
	meshBridgeConfigFieldCount   = 4

	meshBridgeConfigLocalAddress = "bridge.localAddress"
	meshBridgeConfigOwner        = "bridge.owner"
	meshBridgeConfigLocalNetwork = "bridge.localNetwork"
	meshBridgeConfigDatagram     = "bridge.datagram"
	meshBridgeOwnerDaemon        = "daemon"
	meshBridgeCapabilityBytes    = 32
	meshBridgeMaxPendingAuth     = 8
	redactedMeshBridgeCapability = "<mesh bridge capability redacted>"
)

// MeshBridgeCapability is an ephemeral bearer secret that authorizes one
// local TCP connection or UDP peer to use a Mesh bridge. The pointer-boxed
// representation prevents unsupported fmt verbs from embedding the secret in
// a formatting diagnostic.
type MeshBridgeCapability struct {
	value *string
}

// String redacts the bearer secret in formatted diagnostics.
func (MeshBridgeCapability) String() string { return redactedMeshBridgeCapability }

// GoString redacts the bearer secret in Go-syntax diagnostics.
func (MeshBridgeCapability) GoString() string { return redactedMeshBridgeCapability }

// Format redacts the bearer secret for every fmt formatting verb.
func (MeshBridgeCapability) Format(state fmt.State, _ rune) {
	if _, err := io.WriteString(state, redactedMeshBridgeCapability); err != nil {
		return
	}
}

func meshBridgeCapabilityValue(value string) MeshBridgeCapability {
	return MeshBridgeCapability{value: &value}
}

func parseMeshBridgeCapability(value string) (MeshBridgeCapability, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != meshBridgeCapabilityBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return MeshBridgeCapability{}, errors.New(
			"mesh bridge capability must be canonical 256-bit base64url",
		)
	}
	return meshBridgeCapabilityValue(value), nil
}

func (c MeshBridgeCapability) reveal() string {
	if c.value == nil {
		return ""
	}
	return *c.value
}

func (c MeshBridgeCapability) MarshalJSON() ([]byte, error) {
	if c.value == nil {
		return nil, errors.New("mesh bridge capability is required")
	}
	return json.Marshal(c.reveal())
}

func (c *MeshBridgeCapability) UnmarshalJSON(data []byte) error {
	if c == nil {
		return errors.New("mesh bridge capability destination is nil")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode mesh bridge capability: %w", err)
	}
	parsed, err := parseMeshBridgeCapability(value)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// MeshBridgeNetwork selects the daemon-local socket adapter. It is separate
// from the provider-defined protocol carried by mesh.StreamRequest.
type MeshBridgeNetwork string

// Validate rejects local adapter types the daemon does not implement.
func (n MeshBridgeNetwork) Validate() error {
	switch n {
	case MeshBridgeNetworkTCP, MeshBridgeNetworkUDP:
		return nil
	default:
		return fmt.Errorf("mesh bridge local network %q is not supported", n)
	}
}

// MeshStreamOpener opens a provider-owned Mesh session flow. It is the narrow
// application-service seam required by the local bridge adapter.
type MeshStreamOpener interface {
	OpenMeshStream(context.Context, string, mesh.StreamRequest) (run.SessionRef, error)
}

type MeshCredentialStreamOpener interface {
	OpenMeshStreamWithCredentialSelections(
		context.Context,
		string,
		mesh.StreamRequest,
		domainpki.CredentialSelections,
		domainpki.CredentialOperationScope,
	) (run.SessionRef, error)
}

// MeshBridgeOpenArgs gathers the collaborators needed to create a daemon-owned
// local listener for a provider-owned Mesh session flow.
type MeshBridgeOpenArgs struct {
	ModuleID        string
	Request         mesh.StreamRequest
	Host            string
	Port            int
	LocalNetwork    MeshBridgeNetwork
	Credentials     domainpki.CredentialSelections
	CredentialScope domainpki.CredentialOperationScope
	Runs            MeshStreamOpener
	Sessions        services.SessionBroker
	Book            *MeshBook
	Bridges         *MeshBridgeManager
	Now             func() time.Time
}

// MeshBridgeManager owns active daemon-local listeners that bridge local
// clients to Mesh session flows.
type MeshBridgeManager struct {
	mu          sync.RWMutex
	byOperation map[string]*MeshBridge
	bySession   map[string]*MeshBridge
}

// NewMeshBridgeManager creates an empty, concurrency-safe bridge registry.
func NewMeshBridgeManager() *MeshBridgeManager {
	return &MeshBridgeManager{
		byOperation: map[string]*MeshBridge{},
		bySession:   map[string]*MeshBridge{},
	}
}

// Add indexes a bridge by its operation and provider session identifiers.
func (m *MeshBridgeManager) Add(bridge *MeshBridge) error {
	if m == nil {
		return errors.New("mesh bridge manager is not configured")
	}
	if bridge == nil {
		return errors.New("mesh bridge is required")
	}
	operationID := strings.TrimSpace(bridge.OperationID())
	sessionID := strings.TrimSpace(bridge.SessionID())
	if operationID == "" || sessionID == "" {
		return errors.New("mesh bridge operation id and session id are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byOperation == nil {
		m.byOperation = map[string]*MeshBridge{}
	}
	if m.bySession == nil {
		m.bySession = map[string]*MeshBridge{}
	}
	if _, exists := m.byOperation[operationID]; exists {
		return fmt.Errorf("mesh bridge operation %q is already tracked", operationID)
	}
	if _, exists := m.bySession[sessionID]; exists {
		return fmt.Errorf("mesh bridge session %q is already tracked", sessionID)
	}
	m.byOperation[operationID] = bridge
	m.bySession[sessionID] = bridge
	return nil
}

// Find returns a bridge by operation ID, or by session ID when operationID is empty.
func (m *MeshBridgeManager) Find(operationID, sessionID string) (*MeshBridge, bool) {
	if m == nil {
		return nil, false
	}
	operationID = strings.TrimSpace(operationID)
	sessionID = strings.TrimSpace(sessionID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if operationID != "" {
		bridge, ok := m.byOperation[operationID]
		return bridge, ok
	}
	if sessionID == "" {
		return nil, false
	}
	bridge, ok := m.bySession[sessionID]
	return bridge, ok
}

// Remove deletes both indexes for the bridge identified by operationID.
func (m *MeshBridgeManager) Remove(operationID string) {
	if m == nil {
		return
	}
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bridge, ok := m.byOperation[operationID]
	if !ok {
		return
	}
	delete(m.byOperation, operationID)
	delete(m.bySession, strings.TrimSpace(bridge.SessionID()))
}

// MeshBridge is a daemon-owned local socket endpoint backed by one Mesh session
// flow. The bridge is intentionally local-only; exposing it beyond loopback
// should require a separate, explicit policy decision.
type MeshBridge struct {
	operationID  string
	sessionID    string
	localHost    string
	localPort    int
	localNetwork MeshBridgeNetwork
	capability   MeshBridgeCapability

	listener   net.Listener
	packetConn net.PacketConn
	sessions   services.SessionBroker
	book       *MeshBook
	manager    *MeshBridgeManager
	now        func() time.Time

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	conn      net.Conn
	peer      net.Addr
	peerReady chan struct{}
	closed    bool

	closeMu           sync.Mutex
	endpointCloseOnce sync.Once
	sessionClosed     bool
	closeErr          error
}

// OpenMeshBridge opens a local loopback listener and connects it to a
// provider-owned Mesh session flow.
func OpenMeshBridge(ctx context.Context, args MeshBridgeOpenArgs) (MeshBridgeOpenResponse, error) {
	if ctx == nil {
		ctx = context.TODO()
	}
	now := args.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	args.Now = now
	if args.Sessions == nil {
		return MeshBridgeOpenResponse{}, errors.New("session broker is not configured")
	}
	if args.Book == nil {
		return MeshBridgeOpenResponse{}, errors.New("mesh operation book is not configured")
	}
	if args.Bridges == nil {
		return MeshBridgeOpenResponse{}, errors.New("mesh bridge manager is not configured")
	}
	if args.Runs == nil {
		return MeshBridgeOpenResponse{}, errors.New("mesh stream opener is not configured")
	}
	moduleID := strings.TrimSpace(args.ModuleID)
	if moduleID == "" {
		return MeshBridgeOpenResponse{}, errors.New("mesh bridge module id is required")
	}
	localNetwork, err := normalizeMeshBridgeNetwork(args.LocalNetwork)
	if err != nil {
		return MeshBridgeOpenResponse{}, err
	}
	host, port, err := normalizeMeshBridgeListen(args.Host, args.Port)
	if err != nil {
		return MeshBridgeOpenResponse{}, err
	}
	listenConfig := &net.ListenConfig{}
	localEndpoint := net.JoinHostPort(host, strconv.Itoa(port))
	capability, err := newMeshBridgeCapability()
	if err != nil {
		return MeshBridgeOpenResponse{}, err
	}
	var listener net.Listener
	var packetConn net.PacketConn
	switch localNetwork {
	case MeshBridgeNetworkTCP:
		listener, err = listenConfig.Listen(ctx, string(localNetwork), localEndpoint)
	case MeshBridgeNetworkUDP:
		packetConn, err = listenConfig.ListenPacket(ctx, string(localNetwork), localEndpoint)
	default:
		err = fmt.Errorf("mesh bridge local network %q is not supported", localNetwork)
	}
	if err != nil {
		return MeshBridgeOpenResponse{}, fmt.Errorf("listen on local mesh bridge endpoint %s: %w", localEndpoint, err)
	}
	localHost, localPort, localAddress := socketEndpoint(meshBridgeLocalAddr(listener, packetConn))
	request := meshBridgeRequest(args.Request, localAddress, localNetwork)
	request.ModuleID = moduleID
	operation := args.Book.StartBridge(moduleID, request, localNetwork, localAddress, now())
	var session run.SessionRef
	if len(args.Credentials) == 0 {
		session, err = args.Runs.OpenMeshStream(ctx, moduleID, request)
	} else {
		credentialOpener, ok := args.Runs.(MeshCredentialStreamOpener)
		if !ok {
			return MeshBridgeOpenResponse{}, failMeshBridgeOpen(
				context.WithoutCancel(ctx),
				args,
				operation.ID,
				listener,
				packetConn,
				"",
				errors.New("credential-aware mesh stream opener is not configured"),
			)
		}
		session, err = credentialOpener.OpenMeshStreamWithCredentialSelections(
			ctx,
			moduleID,
			request,
			args.Credentials,
			args.CredentialScope,
		)
	}
	if err != nil {
		return MeshBridgeOpenResponse{}, failMeshBridgeOpen(
			context.WithoutCancel(ctx),
			args,
			operation.ID,
			listener,
			packetConn,
			"",
			fmt.Errorf("open mesh bridge session flow: %w", err),
		)
	}
	session.ID = strings.TrimSpace(session.ID)
	if session.ID == "" {
		return MeshBridgeOpenResponse{}, failMeshBridgeOpen(
			context.WithoutCancel(ctx),
			args,
			operation.ID,
			listener,
			packetConn,
			"",
			errors.New("mesh bridge stream session id is required"),
		)
	}
	if localNetwork == MeshBridgeNetworkUDP && !session.HasCapability(run.SessionCapabilityDatagram) {
		return MeshBridgeOpenResponse{}, failMeshBridgeOpen(
			context.WithoutCancel(ctx),
			args,
			operation.ID,
			listener,
			packetConn,
			session.ID,
			errors.New("mesh bridge udp session must advertise the datagram capability"),
		)
	}
	bridge := newMeshBridge(context.WithoutCancel(ctx), meshBridgeConfig{
		operationID:  operation.ID,
		sessionID:    session.ID,
		localHost:    localHost,
		localPort:    localPort,
		localNetwork: localNetwork,
		capability:   capability,
		listener:     listener,
		packetConn:   packetConn,
		sessions:     args.Sessions,
		book:         args.Book,
		manager:      args.Bridges,
		now:          now,
	})
	if err := args.Bridges.Add(bridge); err != nil {
		// A duplicate session ID may already back another live bridge. Do not
		// close that provider session while rejecting the new local endpoint.
		return MeshBridgeOpenResponse{}, failMeshBridgeOpen(
			context.WithoutCancel(ctx),
			args,
			operation.ID,
			listener,
			packetConn,
			"",
			fmt.Errorf("track mesh bridge: %w", err),
		)
	}
	args.Book.ActivateBridge(operation.ID, session, localAddress, now())
	go bridge.Serve()
	return MeshBridgeOpenResponse{
		OperationID:  operation.ID,
		SessionID:    session.ID,
		LocalHost:    localHost,
		LocalPort:    localPort,
		LocalNetwork: localNetwork,
		Capability:   capability,
		LocalAddress: localAddress,
	}, nil
}

type meshBridgeConfig struct {
	operationID  string
	sessionID    string
	localHost    string
	localPort    int
	localNetwork MeshBridgeNetwork
	capability   MeshBridgeCapability
	listener     net.Listener
	packetConn   net.PacketConn
	sessions     services.SessionBroker
	book         *MeshBook
	manager      *MeshBridgeManager
	now          func() time.Time
}

func newMeshBridge(parent context.Context, config meshBridgeConfig) *MeshBridge {
	ctx, cancel := context.WithCancel(parent)
	if config.now == nil {
		config.now = func() time.Time { return time.Now().UTC() }
	}
	return &MeshBridge{
		operationID:  config.operationID,
		sessionID:    config.sessionID,
		localHost:    config.localHost,
		localPort:    config.localPort,
		localNetwork: config.localNetwork,
		capability:   config.capability,
		listener:     config.listener,
		packetConn:   config.packetConn,
		sessions:     config.sessions,
		book:         config.book,
		manager:      config.manager,
		now:          config.now,
		ctx:          ctx,
		cancel:       cancel,
		peerReady:    make(chan struct{}),
	}
}

// OperationID returns the daemon bookkeeping identifier for the bridge.
func (b *MeshBridge) OperationID() string {
	if b == nil {
		return ""
	}
	return b.operationID
}

// SessionID returns the provider-owned session backing the bridge.
func (b *MeshBridge) SessionID() string {
	if b == nil {
		return ""
	}
	return b.sessionID
}

// Serve transfers data until the local endpoint or provider session closes.
func (b *MeshBridge) Serve() {
	switch b.localNetwork {
	case MeshBridgeNetworkUDP:
		b.serveDatagrams()
	default:
		b.serveStream()
	}
}

func (b *MeshBridge) serveStream() {
	authSlots := make(chan struct{}, meshBridgeMaxPendingAuth)
	var authWG sync.WaitGroup
	defer authWG.Wait()
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			if b.isClosed() || b.currentConn() != nil {
				return
			}
			b.finish(err)
			return
		}
		select {
		case authSlots <- struct{}{}:
			authWG.Add(1)
			go func() {
				defer authWG.Done()
				defer func() { <-authSlots }()
				reader, authorized := b.authorizeStream(conn)
				if !authorized || !b.setConn(conn) {
					logDaemonRPCError(
						"close unauthorized mesh bridge connection",
						conn.Close(),
					)
					return
				}
				listenerCloseErr := closeMeshBridgeEndpoint(b.listener, nil)
				copyErr := b.handleConn(conn, reader)
				b.finish(errors.Join(listenerCloseErr, copyErr))
			}()
		default:
			logDaemonRPCError(
				"close excess unauthenticated mesh bridge connection",
				conn.Close(),
			)
		}
	}
}

func (b *MeshBridge) serveDatagrams() {
	errs := make(chan error, 2)
	go func() {
		errs <- b.copyDatagramsToSession(b.ctx)
	}()
	go func() {
		errs <- b.copySessionToDatagrams(b.ctx)
	}()

	firstErr := <-errs
	b.cancel()
	endpointErr := closeMeshBridgeEndpoint(nil, b.packetConn)
	secondErr := <-errs
	b.finish(errors.Join(
		normalizeMeshBridgeCopyError(firstErr),
		normalizeMeshBridgeCopyError(secondErr),
		endpointErr,
	))
}

// Close stops the endpoint, closes the provider session, and updates bookkeeping.
func (b *MeshBridge) Close(ctx context.Context) error {
	return b.close(ctx, nil)
}

func (b *MeshBridge) close(ctx context.Context, cause error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	b.closeMu.Lock()
	defer b.closeMu.Unlock()
	b.endpointCloseOnce.Do(func() {
		b.setClosed()
		b.cancel()
		b.closeErr = errors.Join(cause, closeMeshBridgeEndpoint(b.listener, b.packetConn))
		if conn := b.currentConn(); conn != nil {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				b.closeErr = errors.Join(b.closeErr, err)
			}
		}
	})
	if b.sessionClosed || b.sessionID == "" {
		return b.closeErr
	}
	cleanupContext, cancelCleanup := context.WithTimeout(
		context.WithoutCancel(ctx),
		meshBridgeCleanupTimeout,
	)
	sessionErr := b.sessions.CloseSession(cleanupContext, b.sessionID)
	cancelCleanup()
	if sessionErr != nil {
		attemptErr := errors.Join(b.closeErr, sessionErr)
		b.book.Fail(b.operationID, attemptErr, b.now())
		return attemptErr
	}
	b.sessionClosed = true
	if b.closeErr == nil {
		b.book.CloseSession(b.sessionID, b.now())
	} else {
		b.book.Fail(b.operationID, b.closeErr, b.now())
	}
	b.manager.Remove(b.operationID)
	return b.closeErr
}

func (b *MeshBridge) finish(err error) {
	if b.isClosed() {
		return
	}
	logDaemonRPCError("close mesh bridge", b.close(context.WithoutCancel(b.ctx), err))
}

func (b *MeshBridge) handleConn(conn net.Conn, local io.Reader) error {
	ctx, cancel := context.WithCancel(b.ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() {
		errs <- b.copyLocalToSession(ctx, local)
	}()
	go func() {
		errs <- b.copySessionToLocal(ctx, conn)
	}()
	firstErr := <-errs
	closeErr := conn.Close()
	cancel()
	secondErr := <-errs
	if errors.Is(closeErr, net.ErrClosed) {
		closeErr = nil
	}
	return errors.Join(
		normalizeMeshBridgeCopyError(firstErr),
		normalizeMeshBridgeCopyError(secondErr),
		closeErr,
	)
}

func (b *MeshBridge) copyDatagramsToSession(ctx context.Context) error {
	buf := make([]byte, meshBridgeDatagramBufferSize)
	for {
		n, peer, err := b.packetConn.ReadFrom(buf)
		if n > 0 && b.authorizeDatagramPeer(peer, buf[:n]) {
			if n > maxMeshBridgeDatagramSize {
				return fmt.Errorf(
					"mesh bridge datagram is %d bytes; maximum is %d",
					n,
					maxMeshBridgeDatagramSize,
				)
			}
			data := append([]byte(nil), buf[:n]...)
			if writeErr := b.sessions.WriteSession(ctx, b.sessionID, data); writeErr != nil {
				return fmt.Errorf("write local datagram to mesh session: %w", writeErr)
			}
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read local mesh bridge datagram: %w", err)
		}
	}
}

func (b *MeshBridge) copySessionToDatagrams(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, err := b.sessions.ReadSession(ctx, b.sessionID, meshBridgeReadTimeout)
		if err != nil {
			return fmt.Errorf("read mesh session datagram: %w", err)
		}
		if len(chunk.Data) > 0 {
			if len(chunk.Data) > maxMeshBridgeDatagramSize {
				return fmt.Errorf(
					"mesh bridge datagram is %d bytes; maximum is %d",
					len(chunk.Data),
					maxMeshBridgeDatagramSize,
				)
			}
			peer, err := b.waitForPeer(ctx)
			if err != nil {
				return err
			}
			n, err := b.packetConn.WriteTo(chunk.Data, peer)
			if err != nil {
				return fmt.Errorf("write mesh session datagram to local peer: %w", err)
			}
			if n != len(chunk.Data) {
				return io.ErrShortWrite
			}
		}
		if chunk.Closed {
			return nil
		}
	}
}

func (b *MeshBridge) copyLocalToSession(ctx context.Context, local io.Reader) error {
	buf := make([]byte, meshBridgeBufferSize)
	for {
		n, err := local.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			if writeErr := b.sessions.WriteSession(ctx, b.sessionID, data); writeErr != nil {
				return fmt.Errorf("write local stream data to mesh session: %w", writeErr)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read local mesh bridge stream: %w", err)
		}
	}
}

func (b *MeshBridge) copySessionToLocal(ctx context.Context, conn net.Conn) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, err := b.sessions.ReadSession(ctx, b.sessionID, meshBridgeReadTimeout)
		if err != nil {
			return fmt.Errorf("read mesh session stream: %w", err)
		}
		if len(chunk.Data) > 0 {
			if err := writeMeshBridgeStream(conn, chunk.Data); err != nil {
				return fmt.Errorf("write mesh session stream to local connection: %w", err)
			}
		}
		if chunk.Closed {
			return nil
		}
	}
}

func (b *MeshBridge) setConn(conn net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.conn != nil {
		return false
	}
	b.conn = conn
	return true
}

func (b *MeshBridge) currentConn() net.Conn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn
}

func (b *MeshBridge) authorizeDatagramPeer(peer net.Addr, data []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.peer == nil {
		if !meshBridgeDatagramCapabilityMatches(data, b.capability) {
			return false
		}
		b.peer = cloneMeshBridgeAddr(peer)
		if b.peerReady != nil {
			close(b.peerReady)
		}
		return false
	}
	return sameMeshBridgeAddr(b.peer, peer)
}

func (b *MeshBridge) authorizeStream(conn net.Conn) (*bufio.Reader, bool) {
	frame := meshBridgeCapabilityFrame(b.capability)
	reader := bufio.NewReaderSize(conn, len(frame))
	if err := conn.SetReadDeadline(time.Now().Add(meshBridgeAuthTimeout)); err != nil {
		return reader, false
	}
	candidate, err := reader.ReadSlice('\n')
	clearErr := conn.SetReadDeadline(time.Time{})
	if err != nil || clearErr != nil {
		return reader, false
	}
	return reader, meshBridgeStreamCapabilityMatches(candidate, b.capability)
}

func newMeshBridgeCapability() (MeshBridgeCapability, error) {
	var entropy [meshBridgeCapabilityBytes]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return MeshBridgeCapability{}, fmt.Errorf("generate mesh bridge capability: %w", err)
	}
	return parseMeshBridgeCapability(base64.RawURLEncoding.EncodeToString(entropy[:]))
}

func meshBridgeCapabilityFrame(capability MeshBridgeCapability) []byte {
	value := capability.reveal()
	frame := make([]byte, 0, len(value)+1)
	frame = append(frame, value...)
	return append(frame, '\n')
}

func meshBridgeStreamCapabilityMatches(candidate []byte, capability MeshBridgeCapability) bool {
	return subtle.ConstantTimeCompare(candidate, meshBridgeCapabilityFrame(capability)) == 1
}

func meshBridgeDatagramCapabilityMatches(candidate []byte, capability MeshBridgeCapability) bool {
	return subtle.ConstantTimeCompare(candidate, []byte(capability.reveal())) == 1
}

func cloneMeshBridgeAddr(addr net.Addr) net.Addr {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return addr
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), udpAddr.IP...),
		Port: udpAddr.Port,
		Zone: udpAddr.Zone,
	}
}

func (b *MeshBridge) currentPeer() net.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peer
}

func (b *MeshBridge) waitForPeer(ctx context.Context) (net.Addr, error) {
	b.mu.Lock()
	if b.peer != nil {
		peer := b.peer
		b.mu.Unlock()
		return peer, nil
	}
	ready := b.peerReady
	b.mu.Unlock()
	if ready == nil {
		return nil, errors.New("mesh bridge local UDP peer is not initialized")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ready:
		peer := b.currentPeer()
		if peer == nil {
			return nil, errors.New("mesh bridge local UDP peer is not available")
		}
		return peer, nil
	}
}

func sameMeshBridgeAddr(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Network() == right.Network() && left.String() == right.String()
}

func writeMeshBridgeStream(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func normalizeMeshBridgeCopyError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (b *MeshBridge) setClosed() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}

func (b *MeshBridge) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

func normalizeMeshBridgeNetwork(network MeshBridgeNetwork) (MeshBridgeNetwork, error) {
	if network == "" {
		return MeshBridgeNetworkTCP, nil
	}
	if strings.TrimSpace(string(network)) != string(network) {
		return "", fmt.Errorf("mesh bridge local network %q must be canonical", network)
	}
	if err := network.Validate(); err != nil {
		return "", err
	}
	return network, nil
}

func normalizeMeshBridgeListen(host string, port int) (string, int, error) {
	host = strings.TrimSpace(host)
	if host == "" || strings.EqualFold(host, "localhost") {
		host = defaultMeshBridgeHost
	}
	if port < 0 || port > mesh.MaximumNetworkPort {
		return "", 0, fmt.Errorf(
			"mesh bridge local port %d is outside 0-%d",
			port,
			mesh.MaximumNetworkPort,
		)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", 0, fmt.Errorf("mesh bridge local host %q must be a loopback IP address", host)
	}
	if !ip.IsLoopback() {
		return "", 0, fmt.Errorf("mesh bridge local host %q is not loopback", host)
	}
	return ip.String(), port, nil
}

func socketEndpoint(addr net.Addr) (string, int, string) {
	if addr == nil {
		return defaultMeshBridgeHost, 0, net.JoinHostPort(defaultMeshBridgeHost, "0")
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if ok {
		return ipPortEndpoint(tcpAddr.IP, tcpAddr.Port, addr.String())
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if ok {
		return ipPortEndpoint(udpAddr.IP, udpAddr.Port, addr.String())
	}
	return defaultMeshBridgeHost, 0, addr.String()
}

func ipPortEndpoint(ip net.IP, port int, fallback string) (string, int, string) {
	host := ip.String()
	if host == "<nil>" {
		host = defaultMeshBridgeHost
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	if fallback != "" && port == 0 {
		address = fallback
	}
	return host, port, address
}

func meshBridgeLocalAddr(listener net.Listener, packetConn net.PacketConn) net.Addr {
	if listener != nil {
		return listener.Addr()
	}
	if packetConn != nil {
		return packetConn.LocalAddr()
	}
	return nil
}

func closeMeshBridgeEndpoint(listener net.Listener, packetConn net.PacketConn) error {
	var closeErr error
	if listener != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	if packetConn != nil {
		if err := packetConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}

func meshBridgeRequest(
	request mesh.StreamRequest,
	localAddress string,
	localNetwork MeshBridgeNetwork,
) mesh.StreamRequest {
	config := make(map[string]any, len(request.Config)+meshBridgeConfigFieldCount)
	for key, value := range request.Config {
		config[key] = value
	}
	config[meshBridgeConfigLocalAddress] = localAddress
	config[meshBridgeConfigOwner] = meshBridgeOwnerDaemon
	config[meshBridgeConfigLocalNetwork] = localNetwork
	config[meshBridgeConfigDatagram] = localNetwork == MeshBridgeNetworkUDP
	request.Config = config
	return request
}

func failMeshBridgeOpen(
	ctx context.Context,
	args MeshBridgeOpenArgs,
	operationID string,
	listener net.Listener,
	packetConn net.PacketConn,
	sessionID string,
	cause error,
) error {
	cleanupErr := closeMeshBridgeEndpoint(listener, packetConn)
	if sessionID != "" {
		cleanupErr = errors.Join(
			cleanupErr,
			args.Sessions.CloseSession(ctx, sessionID),
		)
	}
	resultErr := errors.Join(cause, cleanupErr)
	args.Book.Fail(operationID, resultErr, args.Now())
	return resultErr
}
