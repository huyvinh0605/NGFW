package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionContext is created once for each accepted downstream TCP flow.
// It contains no policy decision: only ngfw-engine may supply that later.
type ConnectionContext struct {
	ConnectionID        string
	ClientAddress       netip.AddrPort
	OriginalDestination netip.AddrPort
	TLS                 bool
	AcceptedAt          time.Time
}

type connectionContextKey struct{}

func WithConnectionContext(ctx context.Context, value ConnectionContext) context.Context {
	return context.WithValue(ctx, connectionContextKey{}, value)
}

func ConnectionFromContext(ctx context.Context) (ConnectionContext, bool) {
	value, ok := ctx.Value(connectionContextKey{}).(ConnectionContext)
	return value, ok
}

type ConnectionHandler interface {
	ServeProxyConnection(context.Context, net.Conn, ConnectionContext) error
}

type ConnectionHandlerFunc func(context.Context, net.Conn, ConnectionContext) error

func (f ConnectionHandlerFunc) ServeProxyConnection(ctx context.Context, conn net.Conn, value ConnectionContext) error {
	return f(ctx, conn, value)
}

type ConnectionStats struct {
	Active           uint64
	Accepted         uint64
	CapacityRejected uint64
	SetupFailed      uint64
	ResolveFailed    uint64
	HandlerFailed    uint64
}

// ConnectionServer owns only listener capacity and connection identity. It
// does not evaluate firewall policy, inspect requests, or dial upstream.
type ConnectionServer struct {
	Resolver       OriginalDestinationResolver
	Handler        ConnectionHandler
	MaxConnections int

	active           atomic.Int64
	accepted         atomic.Uint64
	capacityRejected atomic.Uint64
	setupFailed      atomic.Uint64
	resolveFailed    atomic.Uint64
	handlerFailed    atomic.Uint64

	mu           sync.Mutex
	connections  map[net.Conn]struct{}
	shuttingDown bool
}

func NewConnectionServer(resolver OriginalDestinationResolver, handler ConnectionHandler) *ConnectionServer {
	return &ConnectionServer{Resolver: resolver, Handler: handler, MaxConnections: 1024}
}

func (server *ConnectionServer) Stats() ConnectionStats {
	if server == nil {
		return ConnectionStats{}
	}
	return ConnectionStats{
		Active: uint64(server.active.Load()), Accepted: server.accepted.Load(),
		CapacityRejected: server.capacityRejected.Load(), SetupFailed: server.setupFailed.Load(),
		ResolveFailed: server.resolveFailed.Load(), HandlerFailed: server.handlerFailed.Load(),
	}
}

// Serve shares one capacity limit across HTTP and HTTPS listeners. Overload
// closes a new connection before resolver/handler work; no unbounded queue or
// goroutine is created. Cancellation closes both listeners and active flows.
func (server *ConnectionServer) Serve(ctx context.Context, httpListener, httpsListener net.Listener) error {
	if server == nil || server.Resolver == nil || server.Handler == nil || httpListener == nil || httpsListener == nil || httpListener == httpsListener || server.MaxConnections < 1 || server.MaxConnections > 50000 {
		return errors.New("invalid proxy connection server configuration")
	}
	if !isTCPListener(httpListener) || !isTCPListener(httpsListener) {
		return errors.New("proxy connection server requires TCP listeners")
	}
	server.mu.Lock()
	if server.connections != nil {
		server.mu.Unlock()
		return errors.New("proxy connection server already started")
	}
	server.connections = make(map[net.Conn]struct{})
	server.shuttingDown = false
	server.mu.Unlock()

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	limit := make(chan struct{}, server.MaxConnections)
	var flows sync.WaitGroup
	shutdownDone := make(chan struct{})
	stop := context.AfterFunc(serveCtx, func() {
		defer close(shutdownDone)
		_ = httpListener.Close()
		_ = httpsListener.Close()
		server.closeActive()
	})
	defer stop()
	results := make(chan error, 2)
	go func() { results <- server.acceptLoop(serveCtx, httpListener, false, limit, &flows) }()
	go func() { results <- server.acceptLoop(serveCtx, httpsListener, true, limit, &flows) }()
	firstErr := <-results
	cancel()
	secondErr := <-results
	<-shutdownDone
	flows.Wait()
	server.mu.Lock()
	server.connections = nil
	server.mu.Unlock()
	if firstErr != nil {
		return firstErr
	}
	return secondErr
}

func isTCPListener(listener net.Listener) bool {
	if listener.Addr() == nil {
		return false
	}
	switch listener.Addr().Network() {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func (server *ConnectionServer) acceptLoop(ctx context.Context, listener net.Listener, tls bool, limit chan struct{}, flows *sync.WaitGroup) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept proxy connection: %w", err)
		}
		select {
		case limit <- struct{}{}:
		default:
			server.capacityRejected.Add(1)
			_ = connection.Close()
			continue
		}
		if !server.track(ctx, connection) {
			<-limit
			_ = connection.Close()
			continue
		}
		server.active.Add(1)
		server.accepted.Add(1)
		acceptedAt := time.Now().UTC()
		flows.Add(1)
		go func() {
			defer flows.Done()
			defer func() {
				_ = connection.Close()
				server.untrack(connection)
				server.active.Add(-1)
				<-limit
			}()
			server.handleConnection(ctx, connection, tls, acceptedAt)
		}()
	}
}

func (server *ConnectionServer) handleConnection(ctx context.Context, connection net.Conn, tls bool, acceptedAt time.Time) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		server.setupFailed.Add(1)
		return
	}
	client, err := netip.ParseAddrPort(connection.RemoteAddr().String())
	if err != nil || !client.IsValid() {
		server.setupFailed.Add(1)
		return
	}
	original, err := server.Resolver.ResolveOriginalDestination(ctx, connection)
	if err != nil || !validOriginalDestination(original, connection.LocalAddr()) {
		server.resolveFailed.Add(1)
		return
	}
	value := ConnectionContext{
		ConnectionID: hex.EncodeToString(id[:]), ClientAddress: client,
		OriginalDestination: original, TLS: tls, AcceptedAt: acceptedAt,
	}
	if err := server.Handler.ServeProxyConnection(WithConnectionContext(ctx, value), connection, value); err != nil {
		server.handlerFailed.Add(1)
	}
}

func (server *ConnectionServer) track(ctx context.Context, connection net.Conn) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.shuttingDown || ctx.Err() != nil {
		return false
	}
	server.connections[connection] = struct{}{}
	return true
}

func (server *ConnectionServer) untrack(connection net.Conn) {
	server.mu.Lock()
	delete(server.connections, connection)
	server.mu.Unlock()
}

func (server *ConnectionServer) closeActive() {
	server.mu.Lock()
	server.shuttingDown = true
	active := make([]net.Conn, 0, len(server.connections))
	for connection := range server.connections {
		active = append(active, connection)
	}
	server.mu.Unlock()
	for _, connection := range active {
		_ = connection.Close()
	}
}
