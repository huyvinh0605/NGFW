package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func testConnectionListeners(t *testing.T) (net.Listener, net.Listener) {
	t.Helper()
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		httpListener.Close()
		t.Fatal(err)
	}
	return httpListener, httpsListener
}

func waitConnectionCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("connection condition did not become true")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestConnectionServerAssignsDistinctIDsAndHTTPContext(t *testing.T) {
	resolver := OriginalDestinationFunc(func(context.Context, net.Conn) (netip.AddrPort, error) {
		return netip.MustParseAddrPort("203.0.113.10:443"), nil
	})
	values := make(chan ConnectionContext, 2)
	server := NewConnectionServer(resolver, ConnectionHandlerFunc(func(ctx context.Context, _ net.Conn, value ConnectionContext) error {
		attached, ok := ConnectionFromContext(ctx)
		if !ok || attached != value {
			return errors.New("ConnContext did not preserve connection identity")
		}
		values <- value
		return nil
	}))
	httpListener, httpsListener := testConnectionListeners(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, httpListener, httpsListener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("proxy server shutdown: %v", err)
		}
	}()
	connections := make([]net.Conn, 0, 2)
	for _, listener := range []net.Listener{httpListener, httpsListener} {
		connection, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	seen := make(map[string]bool)
	seenTLS := map[bool]bool{}
	for range 2 {
		select {
		case value := <-values:
			if len(value.ConnectionID) != 32 || seen[value.ConnectionID] || !value.ClientAddress.IsValid() || value.OriginalDestination.String() != "203.0.113.10:443" || value.AcceptedAt.IsZero() {
				t.Fatalf("invalid or repeated connection identity: %+v", value)
			}
			seen[value.ConnectionID] = true
			seenTLS[value.TLS] = true
		case <-time.After(2 * time.Second):
			t.Fatal("proxy handler did not receive both listeners")
		}
	}
	if !seenTLS[false] || !seenTLS[true] || server.Stats().Accepted != 2 {
		t.Fatalf("HTTP/HTTPS listener state lost: %+v", server.Stats())
	}
}

func TestConnectionServerCapacityAndGracefulShutdown(t *testing.T) {
	started := make(chan struct{}, 1)
	server := NewConnectionServer(OriginalDestinationFunc(func(context.Context, net.Conn) (netip.AddrPort, error) {
		return netip.MustParseAddrPort("203.0.113.10:80"), nil
	}), ConnectionHandlerFunc(func(ctx context.Context, _ net.Conn, _ ConnectionContext) error {
		started <- struct{}{}
		<-ctx.Done()
		return nil
	}))
	server.MaxConnections = 1
	httpListener, httpsListener := testConnectionListeners(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, httpListener, httpsListener) }()
	first, err := net.Dial("tcp", httpListener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer first.Close()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("first flow was not accepted")
	}
	second, err := net.Dial("tcp", httpsListener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer second.Close()
	waitConnectionCondition(t, func() bool { return server.Stats().CapacityRejected == 1 })
	if server.Stats().Active != 1 || server.Stats().Accepted != 1 {
		t.Fatalf("capacity limit was exceeded: %+v", server.Stats())
	}
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := second.Read(one[:]); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("over-capacity connection remained open or timed out: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil || server.Stats().Active != 0 {
			t.Fatalf("shutdown leaked active connections: %+v, %v", server.Stats(), err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy shutdown did not close active flow")
	}
}

func TestConnectionServerFailsClosedWhenOriginalDestinationUnknown(t *testing.T) {
	var handled atomic.Int32
	server := NewConnectionServer(UnavailableOriginalDestinationResolver{}, ConnectionHandlerFunc(func(context.Context, net.Conn, ConnectionContext) error {
		handled.Add(1)
		return nil
	}))
	httpListener, httpsListener := testConnectionListeners(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, httpListener, httpsListener) }()
	connection, err := net.Dial("tcp", httpListener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer connection.Close()
	waitConnectionCondition(t, func() bool { return server.Stats().ResolveFailed == 1 })
	if handled.Load() != 0 {
		t.Fatal("unresolved connection reached handler")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOriginalDestinationCannotBeProxyListener(t *testing.T) {
	server := NewConnectionServer(OriginalDestinationFunc(func(_ context.Context, conn net.Conn) (netip.AddrPort, error) {
		return netip.ParseAddrPort(conn.LocalAddr().String())
	}), ConnectionHandlerFunc(func(context.Context, net.Conn, ConnectionContext) error {
		t.Fatal("self-targeted flow reached handler")
		return nil
	}))
	httpListener, httpsListener := testConnectionListeners(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, httpListener, httpsListener) }()
	connection, err := net.Dial("tcp", httpListener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer connection.Close()
	waitConnectionCondition(t, func() bool { return server.Stats().ResolveFailed == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
