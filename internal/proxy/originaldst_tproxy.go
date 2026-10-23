package proxy

import (
	"context"
	"net"
	"net/netip"
)

// TPROXYOriginalDestinationResolver reads the destination preserved by the
// transparent listener. On the probed Linux path it is the post-DNAT address,
// not the proxy's listening address or the client's public DNAT target.
type TPROXYOriginalDestinationResolver struct{}

func (TPROXYOriginalDestinationResolver) ResolveOriginalDestination(ctx context.Context, conn net.Conn) (netip.AddrPort, error) {
	if ctx == nil || ctx.Err() != nil || conn == nil {
		return netip.AddrPort{}, ErrOriginalDestinationUnavailable
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || local == nil || local.Port < 1 || local.Port > 65535 || local.Zone != "" {
		return netip.AddrPort{}, ErrOriginalDestinationUnavailable
	}
	address, ok := netip.AddrFromSlice(local.IP.To4())
	if !ok || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return netip.AddrPort{}, ErrOriginalDestinationUnavailable
	}
	return netip.AddrPortFrom(address, uint16(local.Port)), nil
}
