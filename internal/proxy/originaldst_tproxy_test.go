package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

type tproxyLocalConn struct {
	net.Conn
	local net.Addr
}

func (conn tproxyLocalConn) LocalAddr() net.Addr { return conn.local }

func TestTPROXYResolverUsesPostDNATSocketDestination(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := tproxyLocalConn{Conn: left, local: &net.TCPAddr{IP: net.ParseIP("10.20.0.10"), Port: 443}}
	got, err := (TPROXYOriginalDestinationResolver{}).ResolveOriginalDestination(context.Background(), conn)
	if err != nil || got != netip.MustParseAddrPort("10.20.0.10:443") {
		t.Fatalf("post-DNAT destination = %s, %v", got, err)
	}
	if !validOriginalDestination(got, conn.LocalAddr(), 18443) {
		t.Fatal("TPROXY-preserved local tuple was mistaken for the proxy listener")
	}
	if validOriginalDestination(netip.MustParseAddrPort("10.20.0.10:18443"), &net.TCPAddr{IP: net.ParseIP("10.20.0.10"), Port: 18443}, 18443) {
		t.Fatal("direct connection to proxy listener was accepted as intercepted")
	}
}

func TestTPROXYResolverRejectsInvalidSocketDestinations(t *testing.T) {
	for _, addr := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		&net.TCPAddr{IP: net.ParseIP("::1"), Port: 443},
		&net.TCPAddr{IP: net.ParseIP("10.20.0.10"), Port: 0},
		&net.TCPAddr{IP: net.ParseIP("224.0.0.1"), Port: 443},
		&net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"},
	} {
		left, right := net.Pipe()
		conn := tproxyLocalConn{Conn: left, local: addr}
		if got, err := (TPROXYOriginalDestinationResolver{}).ResolveOriginalDestination(context.Background(), conn); err == nil || got.IsValid() {
			t.Fatalf("invalid socket destination %s accepted as %s", addr, got)
		}
		left.Close()
		right.Close()
	}
}
