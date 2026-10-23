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

// OriginalDestinationResolver is the T07 kernel boundary. T01 established
// that the appliance needs TPROXY to preserve a post-DNAT destination.
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

func validOriginalDestination(original netip.AddrPort, local net.Addr, listenerPort uint16) bool {
	if !original.IsValid() || original.Port() == 0 || original.Addr().IsUnspecified() || original.Addr().IsMulticast() {
		return false
	}
	if local != nil {
		if acceptedLocal, err := netip.ParseAddrPort(local.String()); err == nil && acceptedLocal == original && original.Port() == listenerPort {
			return false // a direct connection to this listener is not intercepted traffic
		}
	}
	return true
}
