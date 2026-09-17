package engineipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

const ProtocolVersion = 1

type Applier interface {
	Apply(context.Context, domain.Config) error
}

type Request struct {
	Version   int           `json:"version"`
	RequestID string        `json:"request_id"`
	Operation string        `json:"operation"`
	Config    domain.Config `json:"config"`
}

type Response struct {
	Version   int       `json:"version"`
	RequestID string    `json:"request_id"`
	OK        bool      `json:"ok"`
	Error     string    `json:"error,omitempty"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
}

func DefaultSocketPath(stateDir string) string {
	if configured := os.Getenv("NGFW_ENGINE_SOCKET"); configured != "" {
		return configured
	}
	if runtime.GOOS == "linux" {
		return "/run/ngfw/engine.sock"
	}
	if stateDir == "" {
		stateDir = "state"
	}
	return filepath.Join(stateDir, "engine.sock")
}

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func NewClient(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: 90 * time.Second}
}

func (c *Client) Apply(ctx context.Context, config domain.Config) error {
	if c == nil || c.SocketPath == "" {
		return errors.New("engine IPC socket is not configured")
	}
	requestID, err := randomID()
	if err != nil {
		return err
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("connect to privileged engine at %s: %w", c.SocketPath, err)
	}
	defer connection.Close()
	deadline := time.Now().Add(c.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	request := Request{Version: ProtocolVersion, RequestID: requestID, Operation: "apply", Config: config}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return fmt.Errorf("send engine apply request: %w", err)
	}
	var response Response
	if err := json.NewDecoder(io.LimitReader(connection, 1<<20)).Decode(&response); err != nil {
		return fmt.Errorf("read engine apply response: %w", err)
	}
	if response.Version != ProtocolVersion || (response.RequestID != "" && response.RequestID != requestID) {
		return errors.New("invalid engine IPC response")
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "engine rejected apply request"
		}
		return errors.New(response.Error)
	}
	return nil
}

type Server struct {
	SocketPath      string
	Applier         Applier
	ApplyTimeout    time.Duration
	MaxRequestBytes int64
	MaxPending      int
}

func NewServer(socketPath string, applier Applier) *Server {
	return &Server{SocketPath: socketPath, Applier: applier, ApplyTimeout: 60 * time.Second, MaxRequestBytes: 8 << 20, MaxPending: 16}
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.Applier == nil || s.SocketPath == "" {
		return errors.New("engine IPC server is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(s.SocketPath), 0750); err != nil {
		return fmt.Errorf("create engine IPC directory: %w", err)
	}
	listener, err := listenUnix(s.SocketPath)
	if err != nil {
		return err
	}
	defer func() {
		listener.Close()
		_ = os.Remove(s.SocketPath)
	}()
	if err := os.Chmod(s.SocketPath, 0660); err != nil {
		return fmt.Errorf("set engine IPC socket permissions: %w", err)
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	maxPending := s.MaxPending
	if maxPending <= 0 {
		maxPending = 16
	}
	semaphore := make(chan struct{}, maxPending)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept engine IPC connection: %w", err)
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-semaphore }()
				s.handle(ctx, connection)
			}()
		default:
			_ = json.NewEncoder(connection).Encode(Response{Version: ProtocolVersion, OK: false, Error: "engine apply queue is full"})
			connection.Close()
		}
	}
}

func (s *Server) handle(serverContext context.Context, connection net.Conn) {
	defer connection.Close()
	requestTimeout := s.ApplyTimeout
	if requestTimeout <= 0 {
		requestTimeout = 60 * time.Second
	}
	_ = connection.SetDeadline(time.Now().Add(requestTimeout + 5*time.Second))
	maxBytes := s.MaxRequestBytes
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	decoder := json.NewDecoder(io.LimitReader(connection, maxBytes))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		s.writeResponse(connection, Response{Version: ProtocolVersion, RequestID: request.RequestID, Error: "invalid request: " + err.Error()})
		return
	}
	if request.Version != ProtocolVersion || request.RequestID == "" || request.Operation != "apply" {
		s.writeResponse(connection, Response{Version: ProtocolVersion, RequestID: request.RequestID, Error: "unsupported engine IPC request"})
		return
	}
	applyContext, cancel := context.WithTimeout(serverContext, requestTimeout)
	defer cancel()
	if err := s.Applier.Apply(applyContext, request.Config); err != nil {
		s.writeResponse(connection, Response{Version: ProtocolVersion, RequestID: request.RequestID, Error: err.Error()})
		return
	}
	s.writeResponse(connection, Response{Version: ProtocolVersion, RequestID: request.RequestID, OK: true, AppliedAt: time.Now().UTC()})
}

func (s *Server) writeResponse(connection net.Conn, response Response) {
	_ = json.NewEncoder(connection).Encode(response)
}

func listenUnix(path string) (net.Listener, error) {
	listener, err := net.Listen("unix", path)
	if err == nil {
		return listener, nil
	}
	probe, probeErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if probeErr == nil {
		probe.Close()
		return nil, fmt.Errorf("engine IPC socket %s is already active", path)
	}
	if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
		return nil, fmt.Errorf("remove stale engine IPC socket: %w", removeErr)
	}
	listener, err = net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on engine IPC socket %s: %w", path, err)
	}
	return listener, nil
}

func randomID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate engine request ID: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}
