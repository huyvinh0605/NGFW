// Package suricata_socket implements Suricata's bounded JSON Unix command
// protocol for one synchronous request-inspection worker.
package suricata_socket

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion  = "0.1"
	maxResponseBytes = 64 << 10
	maxPathBytes     = 4096
	defaultTimeout   = 2 * time.Second
)

var (
	ErrUnavailable   = errors.New("SURICATA_SOCKET_UNAVAILABLE")
	ErrProtocol      = errors.New("SURICATA_SOCKET_PROTOCOL")
	ErrResponseLimit = errors.New("SURICATA_SOCKET_RESPONSE_LIMIT")
	ErrRejected      = errors.New("SURICATA_SOCKET_REJECTED")
	ErrInvalidPath   = errors.New("SURICATA_SOCKET_INVALID_PATH")
)

type Client struct {
	mu      sync.Mutex
	conn    net.Conn
	timeout time.Duration
	closed  bool
}

// Dial negotiates protocol 0.1 and checks all PCAP commands required by T21.
// A failed negotiation closes the connection; a caller must never infer that
// an unavailable socket produced a clean inspection result.
func Dial(ctx context.Context, socketPath string, timeout time.Duration) (*Client, error) {
	if ctx == nil || !validPath(socketPath) {
		return nil, ErrInvalidPath
	}
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = defaultTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(dialCtx, "unix", socketPath)
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	client := &Client{conn: connection, timeout: timeout}
	if _, err = client.exchange(ctx, map[string]any{"version": protocolVersion}); err != nil {
		_ = client.Close()
		return nil, err
	}
	commands, err := client.CommandList(ctx)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	available := make(map[string]bool, len(commands))
	for _, command := range commands {
		available[command] = true
	}
	for _, required := range []string{"pcap-file", "pcap-current", "pcap-file-list", "pcap-file-number"} {
		if !available[required] {
			_ = client.Close()
			return nil, ErrProtocol
		}
	}
	return client, nil
}

func (client *Client) Close() error {
	if client == nil {
		return nil
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil
	}
	client.closed = true
	return client.conn.Close()
}

func (client *Client) CommandList(ctx context.Context) ([]string, error) {
	message, err := client.exchange(ctx, map[string]any{"command": "command-list"})
	if err != nil {
		return nil, err
	}
	var commands []string
	if err := json.Unmarshal(message, &commands); err != nil || commands == nil {
		return nil, ErrProtocol
	}
	return commands, nil
}

// Submit queues a worker-owned PCAP path and isolated output directory.
// Both paths must be absolute and must be allocated by the worker, not from
// Host, URL, RequestID or other traffic-controlled strings.
func (client *Client) Submit(ctx context.Context, pcapPath, outputDirectory string) error {
	if !validPath(pcapPath) || !validPath(outputDirectory) {
		return ErrInvalidPath
	}
	_, err := client.exchange(ctx, map[string]any{
		"command":   "pcap-file",
		"arguments": map[string]string{"filename": pcapPath, "output-dir": outputDirectory},
	})
	return err
}

func (client *Client) Current(ctx context.Context) (string, error) {
	message, err := client.exchange(ctx, map[string]any{"command": "pcap-current"})
	if err != nil {
		return "", err
	}
	var current string
	if err := json.Unmarshal(message, &current); err != nil {
		return "", ErrProtocol
	}
	return current, nil
}

func (client *Client) Queued(ctx context.Context) ([]string, error) {
	message, err := client.exchange(ctx, map[string]any{"command": "pcap-file-list"})
	if err != nil {
		return nil, err
	}
	var result struct {
		Count *int     `json:"count"`
		Files []string `json:"files"`
	}
	if err := json.Unmarshal(message, &result); err != nil || result.Count == nil || *result.Count < 0 || *result.Count != len(result.Files) || *result.Count > 10000 {
		return nil, ErrProtocol
	}
	return result.Files, nil
}

func (client *Client) QueueDepth(ctx context.Context) (int, error) {
	message, err := client.exchange(ctx, map[string]any{"command": "pcap-file-number"})
	if err != nil {
		return 0, err
	}
	var depth int
	if len(message) == 0 || string(message) == "null" {
		return 0, ErrProtocol
	}
	if err := json.Unmarshal(message, &depth); err != nil || depth < 0 || depth > 10000 {
		return 0, ErrProtocol
	}
	return depth, nil
}

func (client *Client) exchange(ctx context.Context, command map[string]any) (json.RawMessage, error) {
	if client == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed {
		return nil, ErrUnavailable
	}
	callCtx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	deadline, _ := callCtx.Deadline()
	if err := client.conn.SetDeadline(deadline); err != nil {
		client.closeFailed()
		return nil, errors.Join(ErrUnavailable, err)
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(callCtx, func() {
		_ = client.conn.SetDeadline(time.Now())
		close(callbackDone)
	})
	defer func() {
		if !stop() {
			<-callbackDone
		}
		_ = client.conn.SetDeadline(time.Time{})
	}()
	encoded, err := json.Marshal(command)
	if err != nil || len(encoded)+1 > maxResponseBytes {
		return nil, ErrProtocol
	}
	encoded = append(encoded, '\n')
	for len(encoded) != 0 {
		written, writeErr := client.conn.Write(encoded)
		if writeErr != nil || written <= 0 {
			client.closeFailed()
			return nil, transportError(callCtx, writeErr)
		}
		encoded = encoded[written:]
	}
	limited := &io.LimitedReader{R: client.conn, N: maxResponseBytes + 1}
	var reply struct {
		Return  string          `json:"return"`
		Message json.RawMessage `json:"message"`
	}
	if err := json.NewDecoder(limited).Decode(&reply); err != nil {
		client.closeFailed()
		if limited.N == 0 {
			return nil, ErrResponseLimit
		}
		var syntax *json.SyntaxError
		var invalidType *json.UnmarshalTypeError
		if errors.As(err, &syntax) || errors.As(err, &invalidType) {
			return nil, ErrProtocol
		}
		return nil, transportError(callCtx, err)
	}
	if limited.N == 0 {
		client.closeFailed()
		return nil, ErrResponseLimit
	}
	if reply.Return == "NOK" {
		return nil, ErrRejected
	}
	if reply.Return != "OK" {
		client.closeFailed()
		return nil, ErrProtocol
	}
	return reply.Message, nil
}

// closeFailed runs with mu held. Once framing, I/O or cancellation fails the
// persistent connection cannot safely match a later command to a reply.
func (client *Client) closeFailed() {
	client.closed = true
	_ = client.conn.Close()
}

func transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return errors.Join(ErrUnavailable, ctx.Err())
	}
	if err == nil {
		return ErrUnavailable
	}
	return errors.Join(ErrUnavailable, err)
}

func validPath(path string) bool {
	return path != "" && len(path) <= maxPathBytes && filepath.IsAbs(path) && !strings.ContainsAny(path, "\x00\r\n")
}
