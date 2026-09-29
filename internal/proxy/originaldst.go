package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// ErrOriginalDestinationUnavailable is a fail-closed interception error, not
// evidence that the original destination equals the proxy listener address.
var ErrOriginalDestinationUnavailable = errors.New("PROXY_ORIGINAL_DST_UNAVAILABLE")

// OriginalDestinationResolver is the T07 kernel boundary. T01 must establish
// whether its Linux implementation uses REDIRECT's original-destination
// getsockopt or a TPROXY-preserved local address before production wiring.
type OriginalDestinationResolver interface {
	ResolveOriginalDestination(context.Context, net.Conn) (netip.AddrPort, error)
}

type OriginalDestinationFunc func(context.Context, net.Conn) (netip.AddrPort, error)

func (f OriginalDestinationFunc) ResolveOriginalDestination(ctx context.Context, conn net.Conn) (netip.AddrPort, error) {
	return f(ctx, conn)
}

// UnavailableOriginalDestinationResolver deliberately never guesses a target.
// It is useful when building on an unsupported OS or before the T01 probe.
type UnavailableOriginalDestinationResolver struct{}

func (UnavailableOriginalDestinationResolver) ResolveOriginalDestination(context.Context, net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, ErrOriginalDestinationUnavailable
}

func validOriginalDestination(original netip.AddrPort, local net.Addr) bool {
	if !original.IsValid() || original.Port() == 0 || original.Addr().IsUnspecified() || original.Addr().IsMulticast() {
		return false
	}
	if local != nil {
		if listener, err := netip.ParseAddrPort(local.String()); err == nil && listener == original {
			return false // never connect a captured flow back into this listener
		}
	}
	return true
}
