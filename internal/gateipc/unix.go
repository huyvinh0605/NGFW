package gateipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ServeUnix binds the dedicated engine-owned request-gate socket. It removes
// only a verifiably stale Unix socket, never an active socket or another file.
func (server *Server) ServeUnix(ctx context.Context, path string) error {
	if server == nil || server.Handler == nil || path == "" || !filepath.IsAbs(path) {
		return protocolError(CodeMalformed)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create request-gate socket directory: %w", err)
	}
	if stat, err := os.Lstat(path); err == nil {
		if stat.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("request-gate path exists and is not a Unix socket")
		}
		connection, probeErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if probeErr == nil {
			_ = connection.Close()
			return fmt.Errorf("request-gate socket is already active")
		}
		if !errors.Is(probeErr, syscall.ECONNREFUSED) {
			return fmt.Errorf("cannot prove request-gate socket is stale: %w", probeErr)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale request-gate socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect request-gate socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on request-gate socket: %w", err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0660); err != nil {
		return fmt.Errorf("set request-gate socket permissions: %w", err)
	}
	return server.Serve(ctx, listener)
}
