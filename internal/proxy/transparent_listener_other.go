//go:build !linux

package proxy

import (
	"context"
	"net"
)

func listenTransparentTCP(context.Context, string, int) (net.Listener, error) {
	return nil, ErrOriginalDestinationUnavailable
}
