package gateipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"
)

type Server struct {
	Handler       Handler
	Timeout       time.Duration
	MaxFrameBytes int
	MaxConcurrent int
	MaxPending    int
}

func NewServer(handler Handler) *Server {
	return &Server{Handler: handler, Timeout: 2 * time.Second, MaxFrameBytes: DefaultMaxFrameBytes, MaxConcurrent: 32, MaxPending: 64}
}

// Serve runs a fixed worker count with a bounded queue. A full queue closes a
// new connection immediately; it cannot spawn an unbounded goroutine or block
// the engine's packet path. Each connection carries exactly one exchange.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || server.Handler == nil || listener == nil {
		return protocolError(CodeInternal)
	}
	concurrent, pending := server.MaxConcurrent, server.MaxPending
	if concurrent <= 0 || concurrent > 256 || pending < 0 || pending > 1024 {
		return protocolError(CodeMalformed)
	}
	if listener.Addr().Network() != "unix" {
		return protocolError(CodeMalformed)
	}
	queue := make(chan net.Conn, pending)
	var workers sync.WaitGroup
	for range concurrent {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for connection := range queue {
				server.ServeConn(ctx, connection)
			}
		}()
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer func() {
		close(queue)
		workers.Wait()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case queue <- connection:
		default:
			_ = connection.Close()
		}
	}
}

// ServeConn owns and closes the connection. It rejects malformed or stale wire
// requests before invoking the engine handler. Handler errors are reduced to
// stable codes; raw input or handler error text is never returned to proxy.
func (server *Server) ServeConn(parent context.Context, connection net.Conn) {
	if connection == nil {
		return
	}
	defer connection.Close()
	if server == nil || server.Handler == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, boundedTimeout(server.Timeout))
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	var request requestFrame
	if err := readFrame(connection, server.MaxFrameBytes, &request); err != nil {
		server.writeError(connection, "", errorCode(ctx, err))
		return
	}
	if request.Version != ProtocolVersion {
		server.writeError(connection, request.CorrelationID, CodeVersionMismatch)
		return
	}
	if request.CorrelationID == "" || !request.Operation.Valid() || len(request.Payload) == 0 || !json.Valid(request.Payload) {
		server.writeError(connection, request.CorrelationID, CodeMalformed)
		return
	}
	result, err := server.Handler.HandleGate(ctx, request.Operation, request.Payload)
	if err != nil {
		server.writeError(connection, request.CorrelationID, errorCode(ctx, err))
		return
	}
	if result.Meta.DecisionID == "" {
		server.writeError(connection, request.CorrelationID, CodeInternal)
		return
	}
	data, err := json.Marshal(result.Data)
	if err != nil {
		server.writeError(connection, request.CorrelationID, CodeInternal)
		return
	}
	response := responseFrame{
		Version: ProtocolVersion, CorrelationID: request.CorrelationID, OK: true,
		ConfigGeneration: result.Meta.ConfigGeneration, DecisionID: result.Meta.DecisionID, Data: data,
	}
	if err := writeFrame(connection, server.MaxFrameBytes, response); err != nil {
		if errorCode(ctx, err) == CodeFrameTooLarge {
			server.writeError(connection, request.CorrelationID, CodeFrameTooLarge)
		}
	}
}

func (server *Server) writeError(connection net.Conn, correlationID, code string) {
	_ = writeFrame(connection, server.MaxFrameBytes, responseFrame{
		Version: ProtocolVersion, CorrelationID: correlationID, Code: code,
	})
}

func errorCode(ctx context.Context, err error) string {
	var protocol *ProtocolError
	if errors.As(err, &protocol) {
		return protocol.Code
	}
	var netError net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) || errors.As(err, &netError) && netError.Timeout() {
		return CodeDeadline
	}
	return CodeInternal
}
