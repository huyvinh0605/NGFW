package gateipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"
)

type Client struct {
	SocketPath    string
	Timeout       time.Duration
	MaxFrameBytes int
	// dialContext is replaceable by same-package tests only.
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func NewClient(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: 2 * time.Second, MaxFrameBytes: DefaultMaxFrameBytes}
}

func (client *Client) Call(ctx context.Context, operation Operation, payload any, out any) (ResponseMeta, error) {
	return client.CallAtGeneration(ctx, operation, payload, out, 0)
}

// CallAtGeneration rejects a response older than the connection/request state
// already held by the caller. A caller needing exact equality must also check
// the returned generation against its own current state before applying it.
func (client *Client) CallAtGeneration(ctx context.Context, operation Operation, payload any, out any, minimumGeneration uint64) (ResponseMeta, error) {
	if client == nil || client.SocketPath == "" || !operation.Valid() {
		return ResponseMeta{}, protocolError(CodeMalformed)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ResponseMeta{}, protocolError(CodeMalformed)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ResponseMeta{}, protocolError(CodeInternal)
	}
	correlationID := hex.EncodeToString(random[:])
	timeout := boundedTimeout(client.Timeout)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := client.dialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	connection, err := dial(callCtx, "unix", client.SocketPath)
	if err != nil {
		return ResponseMeta{}, transportError(callCtx, err)
	}
	defer connection.Close()
	deadline, _ := callCtx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return ResponseMeta{}, transportError(callCtx, err)
	}
	stop := context.AfterFunc(callCtx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err := writeFrame(connection, client.MaxFrameBytes, requestFrame{
		Version: ProtocolVersion, CorrelationID: correlationID, Operation: operation, Payload: encoded,
	}); err != nil {
		return ResponseMeta{}, transportError(callCtx, err)
	}
	var response responseFrame
	if err := readFrame(connection, client.MaxFrameBytes, &response); err != nil {
		return ResponseMeta{}, transportError(callCtx, err)
	}
	if response.Version != ProtocolVersion {
		return ResponseMeta{}, protocolError(CodeVersionMismatch)
	}
	if response.CorrelationID != "" && response.CorrelationID != correlationID {
		return ResponseMeta{}, protocolError(CodeCorrelation)
	}
	meta := ResponseMeta{ConfigGeneration: response.ConfigGeneration, DecisionID: response.DecisionID}
	if !response.OK {
		if response.Code == "" {
			return meta, protocolError(CodeMalformed)
		}
		return meta, protocolError(response.Code)
	}
	if response.CorrelationID != correlationID || response.DecisionID == "" || len(response.Data) == 0 {
		return ResponseMeta{}, protocolError(CodeMalformed)
	}
	if response.ConfigGeneration < minimumGeneration {
		return ResponseMeta{}, protocolError(CodeStaleGeneration)
	}
	if out != nil {
		if err := json.Unmarshal(response.Data, out); err != nil {
			return ResponseMeta{}, protocolError(CodeMalformed)
		}
	}
	return meta, nil
}

func boundedTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return 2 * time.Second
	}
	if value > 30*time.Second {
		return 30 * time.Second
	}
	return value
}

func transportError(ctx context.Context, err error) error {
	var protocol *ProtocolError
	if errors.As(err, &protocol) {
		return protocol
	}
	var netError net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) || errors.As(err, &netError) && netError.Timeout() {
		return protocolError(CodeDeadline)
	}
	return protocolError(CodeEngineDown)
}
