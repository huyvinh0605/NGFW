package engineipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

const RuntimeProtocolVersion uint16 = 3

type RuntimeService interface {
	GetRunningConfig(context.Context) (domain.Config, domain.ConfigVersion, error)
	CommitConfig(context.Context, domain.Config, uint64, string, string, string) (domain.ConfigVersion, error)
	RollbackConfig(context.Context, string, string, string) (domain.ConfigVersion, error)
	ListSessions(context.Context, domain.SessionQuery) (domain.SessionPage, error)
	GetSession(context.Context, string) (domain.RuntimeSession, error)
	SessionStats(context.Context) (domain.RuntimeStats, error)
	RuntimeHealth(context.Context) (domain.RuntimeHealth, error)
	RevokeSession(context.Context, string, string) error
	AddTemporaryBlock(context.Context, domain.TemporaryBlock) error
	RemoveTemporaryBlock(context.Context, string) error
	ListTemporaryBlocks(context.Context) ([]domain.TemporaryBlock, error)
	ReadRuntimeEvents(context.Context, uint64, int) (domain.RuntimeEventPage, error)
}

type InspectionRuntimeService interface {
	InspectionHealth(context.Context) (domain.InspectionHealth, error)
	InspectionCapabilities(context.Context) (domain.InspectionCapabilities, error)
	ListSecurityEvents(context.Context, domain.SecurityQuery) (domain.SecurityEventPage, error)
	GetSecurityEvent(context.Context, string) (domain.ThreatEvent, error)
}

type runtimeRequest struct {
	Version   uint16          `json:"version"`
	RequestID string          `json:"request_id"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}
type runtimeResponse struct {
	Version   uint16          `json:"version"`
	RequestID string          `json:"request_id"`
	OK        bool            `json:"ok"`
	Code      string          `json:"code,omitempty"`
	Error     string          `json:"error,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

type RuntimeClient struct {
	SocketPath       string
	QueryTimeout     time.Duration
	MutationTimeout  time.Duration
	MaxResponseBytes int64
}

func NewRuntimeClient(socketPath string) *RuntimeClient {
	return &RuntimeClient{SocketPath: socketPath, QueryTimeout: 2 * time.Second, MutationTimeout: 60 * time.Second, MaxResponseBytes: 8 << 20}
}

type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string     { return e.Message }
func (e *RemoteError) ErrorCode() string { return e.Code }
func (e *RemoteError) Is(target error) bool {
	return (target == context.DeadlineExceeded && e.Code == "DEADLINE_EXCEEDED") ||
		(target == domain.ErrSecurityEventNotFound && e.Code == "NOT_FOUND")
}

func (c *RuntimeClient) call(ctx context.Context, operation string, value any, out any, mutation bool) error {
	if c == nil || c.SocketPath == "" {
		return errors.New("engine runtime IPC is not configured")
	}
	timeout := c.QueryTimeout
	if mutation {
		timeout = c.MutationTimeout
	}
	if timeout <= 0 {
		if mutation {
			timeout = 60 * time.Second
		} else {
			timeout = 2 * time.Second
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(callCtx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("connect engine runtime: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	requestID, err := randomID()
	if err != nil {
		return err
	}
	if err := json.NewEncoder(connection).Encode(runtimeRequest{Version: RuntimeProtocolVersion, RequestID: requestID, Operation: operation, Payload: body}); err != nil {
		return err
	}
	maxResponse := c.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = 8 << 20
	}
	encoded, err := io.ReadAll(io.LimitReader(connection, maxResponse+1))
	if err != nil {
		return err
	}
	if int64(len(encoded)) > maxResponse {
		return errors.New("runtime IPC response exceeds configured byte limit")
	}
	var response runtimeResponse
	if err := json.Unmarshal(bytes.TrimSpace(encoded), &response); err != nil {
		return fmt.Errorf("decode runtime response: %w", err)
	}
	if response.Version != RuntimeProtocolVersion || response.RequestID != requestID {
		return errors.New("invalid runtime IPC response")
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "runtime operation failed"
		}
		return &RemoteError{Code: response.Code, Message: response.Error}
	}
	if out != nil && len(response.Data) > 0 {
		if err := json.Unmarshal(response.Data, out); err != nil {
			return fmt.Errorf("decode runtime response: %w", err)
		}
	}
	return nil
}

func (c *RuntimeClient) GetRunningConfig(ctx context.Context) (domain.Config, domain.ConfigVersion, error) {
	var out struct {
		Config  domain.Config        `json:"config"`
		Version domain.ConfigVersion `json:"version"`
	}
	err := c.call(ctx, "get_running_config", nil, &out, false)
	return out.Config, out.Version, err
}
func (c *RuntimeClient) CommitConfig(ctx context.Context, config domain.Config, expected uint64, author, comment, operationID string) (domain.ConfigVersion, error) {
	var out domain.ConfigVersion
	payload := struct {
		Config      domain.Config `json:"config"`
		Expected    uint64        `json:"expected_version"`
		Author      string        `json:"author"`
		Comment     string        `json:"comment"`
		OperationID string        `json:"operation_id"`
	}{config, expected, author, comment, operationID}
	err := c.call(ctx, "commit_config", payload, &out, true)
	return out, err
}
func (c *RuntimeClient) RollbackConfig(ctx context.Context, author, comment, operationID string) (domain.ConfigVersion, error) {
	var out domain.ConfigVersion
	err := c.call(ctx, "rollback_config", struct {
		Author      string `json:"author"`
		Comment     string `json:"comment"`
		OperationID string `json:"operation_id"`
	}{author, comment, operationID}, &out, true)
	return out, err
}
func (c *RuntimeClient) ListSessions(ctx context.Context, query domain.SessionQuery) (domain.SessionPage, error) {
	var out domain.SessionPage
	err := c.call(ctx, "list_sessions", query, &out, false)
	return out, err
}
func (c *RuntimeClient) GetSession(ctx context.Context, id string) (domain.RuntimeSession, error) {
	var out domain.RuntimeSession
	err := c.call(ctx, "get_session", map[string]string{"id": id}, &out, false)
	return out, err
}
func (c *RuntimeClient) SessionStats(ctx context.Context) (domain.RuntimeStats, error) {
	var out domain.RuntimeStats
	err := c.call(ctx, "session_stats", nil, &out, false)
	return out, err
}
func (c *RuntimeClient) RuntimeHealth(ctx context.Context) (domain.RuntimeHealth, error) {
	var out domain.RuntimeHealth
	err := c.call(ctx, "runtime_health", nil, &out, false)
	return out, err
}
func (c *RuntimeClient) RevokeSession(ctx context.Context, id, reason string) error {
	return c.call(ctx, "revoke_session", map[string]string{"id": id, "reason": reason}, nil, true)
}
func (c *RuntimeClient) AddTemporaryBlock(ctx context.Context, block domain.TemporaryBlock) error {
	return c.call(ctx, "add_temporary_block", block, nil, true)
}
func (c *RuntimeClient) RemoveTemporaryBlock(ctx context.Context, indicator string) error {
	return c.call(ctx, "remove_temporary_block", map[string]string{"indicator": indicator}, nil, true)
}
func (c *RuntimeClient) ListTemporaryBlocks(ctx context.Context) ([]domain.TemporaryBlock, error) {
	var out []domain.TemporaryBlock
	err := c.call(ctx, "list_temporary_blocks", nil, &out, false)
	return out, err
}
func (c *RuntimeClient) ReadRuntimeEvents(ctx context.Context, after uint64, max int) (domain.RuntimeEventPage, error) {
	var out domain.RuntimeEventPage
	err := c.call(ctx, "read_runtime_events", struct {
		After uint64 `json:"after"`
		Max   int    `json:"max"`
	}{after, max}, &out, false)
	return out, err
}
func (c *RuntimeClient) InspectionHealth(ctx context.Context) (domain.InspectionHealth, error) {
	var out domain.InspectionHealth
	err := c.call(ctx, "inspection_health", nil, &out, false)
	return out, err
}
func (c *RuntimeClient) InspectionCapabilities(ctx context.Context) (domain.InspectionCapabilities, error) {
	var out domain.InspectionCapabilities
	err := c.call(ctx, "inspection_capabilities", nil, &out, false)
	return out, err
}
func (c *RuntimeClient) ListSecurityEvents(ctx context.Context, query domain.SecurityQuery) (domain.SecurityEventPage, error) {
	var out domain.SecurityEventPage
	err := c.call(ctx, "list_security_events", query, &out, false)
	return out, err
}
func (c *RuntimeClient) GetSecurityEvent(ctx context.Context, id string) (domain.ThreatEvent, error) {
	var out domain.ThreatEvent
	err := c.call(ctx, "get_security_event", map[string]string{"id": id}, &out, false)
	return out, err
}

type RuntimeServer struct {
	SocketPath                    string
	Service                       RuntimeService
	MaxPending                    int
	MaxRequestBytes               int64
	MaxResponseBytes              int64
	QueryTimeout, MutationTimeout time.Duration
}

func NewRuntimeServer(socketPath string, service RuntimeService) *RuntimeServer {
	return &RuntimeServer{SocketPath: socketPath, Service: service, MaxPending: 16, MaxRequestBytes: 8 << 20, MaxResponseBytes: 8 << 20, QueryTimeout: 2 * time.Second, MutationTimeout: 60 * time.Second}
}

func (s *RuntimeServer) Serve(ctx context.Context) error {
	if s == nil || s.Service == nil || s.SocketPath == "" {
		return errors.New("runtime IPC server is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(s.SocketPath), 0750); err != nil {
		return err
	}
	listener, err := listenUnix(s.SocketPath)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(s.SocketPath) }()
	_ = os.Chmod(s.SocketPath, 0660)
	go func() { <-ctx.Done(); _ = listener.Close() }()
	limit := s.MaxPending
	if limit <= 0 {
		limit = 16
	}
	semaphore := make(chan struct{}, limit)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-semaphore }(); s.handle(ctx, connection) }()
		default:
			_ = writeRuntimeResponse(connection, runtimeResponse{Version: RuntimeProtocolVersion, OK: false, Code: "IPC_CAPACITY", Error: "runtime IPC queue is full"})
			_ = connection.Close()
		}
	}
}

func (s *RuntimeServer) handle(parent context.Context, connection net.Conn) {
	defer connection.Close()
	maxBytes := s.MaxRequestBytes
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	var request runtimeRequest
	if err := readRuntimeRequest(connection, maxBytes, &request); err != nil {
		_ = writeRuntimeResponse(connection, runtimeResponse{Version: RuntimeProtocolVersion, Code: "INVALID_REQUEST", Error: err.Error()})
		return
	}
	if request.Version != RuntimeProtocolVersion || request.RequestID == "" {
		_ = writeRuntimeResponse(connection, runtimeResponse{Version: RuntimeProtocolVersion, RequestID: request.RequestID, Code: "IPC_VERSION_MISMATCH", Error: "unsupported runtime IPC version; rebuild ngfw-engine and ngfw-api"})
		return
	}
	timeout := s.QueryTimeout
	if isMutation(request.Operation) {
		timeout = s.MutationTimeout
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	_ = connection.SetDeadline(time.Now().Add(timeout + 5*time.Second))
	callContext, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	data, err := s.dispatch(callContext, request)
	response := runtimeResponse{Version: RuntimeProtocolVersion, RequestID: request.RequestID, OK: err == nil}
	if err != nil {
		response.Code = runtimeErrorCode(err)
		response.Error = err.Error()
	} else {
		response.Data = data
	}
	_ = writeRuntimeResponse(connection, response, s.MaxResponseBytes)
}

func readRuntimeRequest(reader io.Reader, maxBytes int64, out *runtimeRequest) error {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	bufferSize := 64 << 10
	if maxBytes < int64(bufferSize) {
		bufferSize = int(maxBytes)
	}
	if bufferSize < 1 {
		bufferSize = 1
	}
	buffered := bufio.NewReaderSize(reader, bufferSize)
	var encoded bytes.Buffer
	tooLarge := false
	for {
		fragment, more, err := buffered.ReadLine()
		if !tooLarge {
			if int64(encoded.Len()+len(fragment)) > maxBytes {
				tooLarge = true
			} else {
				_, _ = encoded.Write(fragment)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && (encoded.Len() > 0 || tooLarge) {
				more = false
			} else {
				return err
			}
		}
		if !more {
			break
		}
	}
	if tooLarge {
		return errors.New("runtime IPC request exceeds configured byte limit")
	}
	if err := json.Unmarshal(encoded.Bytes(), out); err != nil {
		return err
	}
	return nil
}

func runtimeErrorCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "DEADLINE_EXCEEDED"
	case errors.Is(err, domain.ErrSecurityEventNotFound):
		return "NOT_FOUND"
	default:
		return "RUNTIME_ERROR"
	}
}

func isMutation(operation string) bool {
	switch operation {
	case "commit_config", "rollback_config", "revoke_session", "add_temporary_block", "remove_temporary_block":
		return true
	default:
		return false
	}
}
func decodePayload(request runtimeRequest, out any) error {
	if len(request.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(request.Payload, out)
}
func (s *RuntimeServer) dispatch(ctx context.Context, request runtimeRequest) (json.RawMessage, error) {
	encode := func(value any) (json.RawMessage, error) { return json.Marshal(value) }
	switch request.Operation {
	case "get_running_config":
		config, version, err := s.Service.GetRunningConfig(ctx)
		if err != nil {
			return nil, err
		}
		return encode(struct {
			Config  domain.Config        `json:"config"`
			Version domain.ConfigVersion `json:"version"`
		}{config, version})
	case "commit_config":
		var p struct {
			Config      domain.Config `json:"config"`
			Expected    uint64        `json:"expected_version"`
			Author      string        `json:"author"`
			Comment     string        `json:"comment"`
			OperationID string        `json:"operation_id"`
		}
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		version, err := s.Service.CommitConfig(ctx, p.Config, p.Expected, p.Author, p.Comment, p.OperationID)
		if err != nil {
			return nil, err
		}
		return encode(version)
	case "rollback_config":
		var p struct {
			Author      string `json:"author"`
			Comment     string `json:"comment"`
			OperationID string `json:"operation_id"`
		}
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		version, err := s.Service.RollbackConfig(ctx, p.Author, p.Comment, p.OperationID)
		if err != nil {
			return nil, err
		}
		return encode(version)
	case "list_sessions":
		var p domain.SessionQuery
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		result, err := s.Service.ListSessions(ctx, p)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "get_session":
		var p struct {
			ID string `json:"id"`
		}
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		result, err := s.Service.GetSession(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "session_stats":
		result, err := s.Service.SessionStats(ctx)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "runtime_health":
		result, err := s.Service.RuntimeHealth(ctx)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "revoke_session":
		var p struct {
			ID     string `json:"id"`
			Reason string `json:"reason"`
		}
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		return nil, s.Service.RevokeSession(ctx, p.ID, p.Reason)
	case "add_temporary_block":
		var p domain.TemporaryBlock
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		return nil, s.Service.AddTemporaryBlock(ctx, p)
	case "remove_temporary_block":
		var p struct {
			Indicator string `json:"indicator"`
		}
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		return nil, s.Service.RemoveTemporaryBlock(ctx, p.Indicator)
	case "list_temporary_blocks":
		result, err := s.Service.ListTemporaryBlocks(ctx)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "read_runtime_events":
		var p struct {
			After uint64 `json:"after"`
			Max   int    `json:"max"`
		}
		if err := decodePayload(request, &p); err != nil {
			return nil, err
		}
		result, err := s.Service.ReadRuntimeEvents(ctx, p.After, p.Max)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "inspection_health":
		service, ok := s.Service.(InspectionRuntimeService)
		if !ok {
			return nil, errors.New("inspection runtime IPC is unavailable")
		}
		result, err := service.InspectionHealth(ctx)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "inspection_capabilities":
		service, ok := s.Service.(InspectionRuntimeService)
		if !ok {
			return nil, errors.New("inspection runtime IPC is unavailable")
		}
		result, err := service.InspectionCapabilities(ctx)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "list_security_events":
		service, ok := s.Service.(InspectionRuntimeService)
		if !ok {
			return nil, errors.New("inspection runtime IPC is unavailable")
		}
		var query domain.SecurityQuery
		if err := decodePayload(request, &query); err != nil {
			return nil, err
		}
		result, err := service.ListSecurityEvents(ctx, query)
		if err != nil {
			return nil, err
		}
		return encode(result)
	case "get_security_event":
		service, ok := s.Service.(InspectionRuntimeService)
		if !ok {
			return nil, errors.New("inspection runtime IPC is unavailable")
		}
		var payload struct {
			ID string `json:"id"`
		}
		if err := decodePayload(request, &payload); err != nil {
			return nil, err
		}
		result, err := service.GetSecurityEvent(ctx, payload.ID)
		if err != nil {
			return nil, err
		}
		return encode(result)
	default:
		return nil, fmt.Errorf("unsupported runtime operation %q", request.Operation)
	}
}
func writeRuntimeResponse(connection net.Conn, response runtimeResponse, limits ...int64) error {
	limit := int64(8 << 20)
	if len(limits) > 0 && limits[0] > 0 {
		limit = limits[0]
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if int64(len(encoded)+1) > limit {
		response.OK = false
		response.Data = nil
		response.Code = "IPC_RESPONSE_TOO_LARGE"
		response.Error = "runtime IPC response exceeds configured byte limit"
		encoded, err = json.Marshal(response)
		if err != nil {
			return err
		}
		if int64(len(encoded)+1) > limit {
			return errors.New("runtime IPC response limit is too small for an error envelope")
		}
	}
	encoded = append(encoded, '\n')
	_, err = connection.Write(encoded)
	return err
}
