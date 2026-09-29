package gateipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func pipeClient(server *Server) (*Client, <-chan struct{}) {
	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.ServeConn(context.Background(), serverConn)
	}()
	client := NewClient("test.sock")
	client.dialContext = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	return client, done
}

func TestClientServerOpenConnectionAndGeneration(t *testing.T) {
	var calls atomic.Int32
	server := NewServer(HandlerFunc(func(_ context.Context, op Operation, payload json.RawMessage) (Result, error) {
		calls.Add(1)
		if op != OpenConnection {
			t.Fatalf("unexpected operation %q", op)
		}
		var open domain.ProxyConnectionOpen
		if err := json.Unmarshal(payload, &open); err != nil || open.ConnectionID != "c1" {
			t.Fatalf("incorrect domain payload %+v: %v", open, err)
		}
		return Result{Meta: ResponseMeta{ConfigGeneration: 9, DecisionID: "d9"}, Data: domain.ProxyConnectionDecision{DecisionID: "d9", ConfigGeneration: 9, Action: domain.TLSGateDecrypt, FailMode: domain.GateFailClose}}, nil
	}))
	for _, minimum := range []uint64{9, 10} {
		client, done := pipeClient(server)
		var decision domain.ProxyConnectionDecision
		meta, err := client.CallAtGeneration(context.Background(), OpenConnection, domain.ProxyConnectionOpen{ConnectionID: "c1"}, &decision, minimum)
		if minimum == 10 {
			requireCode(t, err, CodeStaleGeneration)
		} else if err != nil || meta.DecisionID != decision.DecisionID || meta.ConfigGeneration != decision.ConfigGeneration || decision.Action != domain.TLSGateDecrypt {
			t.Fatalf("wrong response/meta: %+v %+v %v", meta, decision, err)
		}
		<-done
	}
	if calls.Load() != 2 {
		t.Fatalf("handler call count %d", calls.Load())
	}
}

func TestServerRejectsVersionAndMalformedOperationBeforeHandler(t *testing.T) {
	var calls atomic.Int32
	server := NewServer(HandlerFunc(func(context.Context, Operation, json.RawMessage) (Result, error) {
		calls.Add(1)
		return Result{}, nil
	}))
	for _, tc := range []struct {
		request requestFrame
		code    string
	}{
		{requestFrame{Version: 2, CorrelationID: "old", Operation: OpenConnection, Payload: []byte(`{}`)}, CodeVersionMismatch},
		{requestFrame{Version: ProtocolVersion, CorrelationID: "unknown", Operation: "execute_shell", Payload: []byte(`{}`)}, CodeMalformed},
	} {
		left, right := net.Pipe()
		done := make(chan struct{})
		go func() { server.ServeConn(context.Background(), right); close(done) }()
		if err := writeFrame(left, DefaultMaxFrameBytes, tc.request); err != nil {
			t.Fatal(err)
		}
		var reply responseFrame
		if err := readFrame(left, DefaultMaxFrameBytes, &reply); err != nil {
			t.Fatal(err)
		}
		_ = left.Close()
		<-done
		if reply.OK || reply.Code != tc.code || reply.CorrelationID != tc.request.CorrelationID {
			t.Fatalf("wrong rejection: %+v", reply)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid wire message reached engine handler")
	}
}

func TestHandlerErrorDoesNotLeakDetails(t *testing.T) {
	server := NewServer(HandlerFunc(func(context.Context, Operation, json.RawMessage) (Result, error) {
		return Result{}, errors.New("Authorization: secret-token")
	}))
	client, done := pipeClient(server)
	_, err := client.Call(context.Background(), GateHealthPing, struct{}{}, nil)
	<-done
	requireCode(t, err, CodeInternal)
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatal("handler error leaked into IPC response")
	}
}

func TestClientRejectsWrongCorrelationAndMissingDecisionID(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*responseFrame)
		code string
	}{
		{"wrong identity", func(r *responseFrame) { r.CorrelationID = "another-request" }, CodeCorrelation},
		{"missing decision ID", func(r *responseFrame) { r.DecisionID = "" }, CodeMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			client := NewClient("test.sock")
			client.dialContext = func(context.Context, string, string) (net.Conn, error) { return left, nil }
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer right.Close()
				var request requestFrame
				if err := readFrame(right, DefaultMaxFrameBytes, &request); err != nil {
					return
				}
				reply := responseFrame{Version: ProtocolVersion, CorrelationID: request.CorrelationID, OK: true, ConfigGeneration: 9, DecisionID: "d1", Data: []byte(`{}`)}
				tc.edit(&reply)
				_ = writeFrame(right, DefaultMaxFrameBytes, reply)
			}()
			_, err := client.Call(context.Background(), GateHealthPing, struct{}{}, nil)
			<-done
			requireCode(t, err, tc.code)
		})
	}
}

func TestClientTimeoutIsBoundedAndNotSuccess(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	client := NewClient("test.sock")
	client.Timeout = 25 * time.Millisecond
	client.dialContext = func(context.Context, string, string) (net.Conn, error) { return left, nil }
	_, err := client.Call(context.Background(), GateHealthPing, struct{}{}, nil)
	requireCode(t, err, CodeDeadline)
}

func TestServerRejectsUnboundedWorkerConfiguration(t *testing.T) {
	server := NewServer(HandlerFunc(func(context.Context, Operation, json.RawMessage) (Result, error) { return Result{}, nil }))
	server.MaxConcurrent = 257
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requireCode(t, server.Serve(context.Background(), listener), CodeMalformed)
}

func TestServerRejectsOversizedFrameBeforeHandler(t *testing.T) {
	var calls atomic.Int32
	server := NewServer(HandlerFunc(func(context.Context, Operation, json.RawMessage) (Result, error) {
		calls.Add(1)
		return Result{}, nil
	}))
	left, right := net.Pipe()
	done := make(chan struct{})
	go func() { server.ServeConn(context.Background(), right); close(done) }()
	if _, err := left.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	var reply responseFrame
	if err := readFrame(left, DefaultMaxFrameBytes, &reply); err != nil {
		t.Fatal(err)
	}
	_ = left.Close()
	<-done
	if reply.Code != CodeFrameTooLarge || calls.Load() != 0 {
		t.Fatalf("oversized input reached handler or got wrong error: %+v", reply)
	}
}

func TestServeUnixRejectsExistingNonSocketWithoutDeletingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.sock")
	if err := os.WriteFile(path, []byte("do not delete"), 0600); err != nil {
		t.Fatal(err)
	}
	server := NewServer(HandlerFunc(func(context.Context, Operation, json.RawMessage) (Result, error) { return Result{}, nil }))
	if err := server.ServeUnix(context.Background(), path); err == nil {
		t.Fatal("non-socket path was accepted")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "do not delete" {
		t.Fatalf("existing file was changed: %q, %v", contents, err)
	}
}

func TestServeUnixRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.sock")
	server := NewServer(HandlerFunc(func(_ context.Context, operation Operation, _ json.RawMessage) (Result, error) {
		if operation != GateHealthPing {
			t.Fatalf("unexpected operation %q", operation)
		}
		return Result{Meta: ResponseMeta{ConfigGeneration: 5, DecisionID: "health-5"}, Data: domain.RequestGateHealth{Enabled: true, Generation: 5, Status: "healthy"}}, nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.ServeUnix(ctx, path) }()
	client := NewClient(path)
	readyDeadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Unix IPC listener failed: %v", err)
		default:
		}
		if time.Now().After(readyDeadline) {
			t.Fatal("Unix IPC listener did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var health domain.RequestGateHealth
	meta, err := client.Call(context.Background(), GateHealthPing, struct{}{}, &health)
	if err != nil || meta.ConfigGeneration != 5 || health.Generation != 5 || health.Status != "healthy" {
		t.Fatalf("Unix IPC round trip failed: %+v %+v %v", meta, health, err)
	}
	if runtime.GOOS != "windows" {
		stat, err := os.Stat(path)
		if err != nil || stat.Mode().Perm() != 0660 {
			t.Fatalf("Unix IPC socket has wrong permissions: %v %v", stat, err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Unix IPC shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Unix IPC did not stop on cancellation")
	}
}
