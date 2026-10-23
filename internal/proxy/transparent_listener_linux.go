//go:build linux

package proxy

import (
	"context"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenTransparentTCP enables IP_TRANSPARENT before bind. The appliance
// grants only CAP_NET_RAW to the proxy for this socket option; nftables and
// policy routing remain privileged engine responsibilities.
func listenTransparentTCP(ctx context.Context, host string, port int) (net.Listener, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketError error
		if err := raw.Control(func(fd uintptr) {
			socketError = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}); err != nil {
			return err
		}
		return socketError
	}}
	return config.Listen(ctx, "tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
}
