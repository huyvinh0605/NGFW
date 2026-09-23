package engineipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type fakeRuntimeService struct{}

func (fakeRuntimeService) GetRunningConfig(context.Context) (domain.Config, domain.ConfigVersion, error) {
	return domain.Config{}, domain.ConfigVersion{Version: 4}, nil
}

func TestRuntimeIPCResponseLimitReturnsBoundedErrorEnvelope(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		done <- writeRuntimeResponse(serverSide, runtimeResponse{Version: RuntimeProtocolVersion, RequestID: "r1", OK: true, Data: json.RawMessage(`{"value":"` + strings.Repeat("x", 1024) + `"}`)}, 256)
	}()
	var response runtimeResponse
	if err := json.NewDecoder(clientSide).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.OK || !strings.Contains(response.Error, "exceeds configured byte limit") || len(response.Data) != 0 {
		t.Fatalf("unexpected bounded response: %#v", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func (fakeRuntimeService) CommitConfig(context.Context, domain.Config, uint64, string, string, string) (domain.ConfigVersion, error) {
	return domain.ConfigVersion{Version: 5}, nil
}
func (fakeRuntimeService) RollbackConfig(context.Context, string, string, string) (domain.ConfigVersion, error) {
	return domain.ConfigVersion{Version: 6}, nil
}
func (fakeRuntimeService) ListSessions(context.Context, domain.SessionQuery) (domain.SessionPage, error) {
	return domain.SessionPage{Page: 1, PageSize: 1, Total: 1}, nil
}
func (fakeRuntimeService) GetSession(context.Context, string) (domain.RuntimeSession, error) {
	return domain.RuntimeSession{SessionID: "s1"}, nil
}
func (fakeRuntimeService) SessionStats(context.Context) (domain.RuntimeStats, error) {
	return domain.RuntimeStats{ActiveSessions: 1}, nil
}
func (fakeRuntimeService) RuntimeHealth(context.Context) (domain.RuntimeHealth, error) {
	return domain.RuntimeHealth{Status: "healthy"}, nil
}
func (fakeRuntimeService) RevokeSession(context.Context, string, string) error            { return nil }
func (fakeRuntimeService) AddTemporaryBlock(context.Context, domain.TemporaryBlock) error { return nil }
func (fakeRuntimeService) RemoveTemporaryBlock(context.Context, string) error             { return nil }
func (fakeRuntimeService) ListTemporaryBlocks(context.Context) ([]domain.TemporaryBlock, error) {
	return nil, nil
}
func (fakeRuntimeService) ReadRuntimeEvents(context.Context, uint64, int) (domain.RuntimeEventPage, error) {
	return domain.RuntimeEventPage{NextSequence: 1}, nil
}
func (fakeRuntimeService) InspectionHealth(context.Context) (domain.InspectionHealth, error) {
	return domain.InspectionHealth{Enabled: true, Status: "healthy", Generation: 4}, nil
}
func (fakeRuntimeService) InspectionCapabilities(context.Context) (domain.InspectionCapabilities, error) {
	return domain.InspectionCapabilities{Supported: true, Modes: []domain.InspectionMode{domain.InspectionModeIDS, domain.InspectionModeIPS}}, nil
}
func (fakeRuntimeService) ListSecurityEvents(context.Context, domain.SecurityQuery) (domain.SecurityEventPage, error) {
	return domain.SecurityEventPage{Items: []domain.ThreatEvent{{EventID: "evt-1"}}, NextSequence: 1}, nil
}
func (fakeRuntimeService) GetSecurityEvent(context.Context, string) (domain.ThreatEvent, error) {
	return domain.ThreatEvent{EventID: "evt-1", SuricataFlowID: "18446744073709551615"}, nil
}

func TestRuntimeIPCListAndTimeoutContract(t *testing.T) {
	socket := t.TempDir() + "/engine.sock"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := NewRuntimeServer(socket, fakeRuntimeService{})
	server.QueryTimeout = time.Second
	go func() { _ = server.Serve(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		connection, err := net.DialTimeout("unix", socket, 25*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("runtime server did not start")
		}
		time.Sleep(time.Millisecond)
	}
	client := NewRuntimeClient(socket)
	page, err := client.ListSessions(context.Background(), domain.SessionQuery{Page: 1, PageSize: 1})
	if err != nil || page.Total != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	session, err := client.GetSession(context.Background(), "s1")
	if err != nil || session.SessionID != "s1" {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	health, err := client.RuntimeHealth(context.Background())
	if err != nil || health.Status != "healthy" {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	inspectionHealth, err := client.InspectionHealth(context.Background())
	if err != nil || !inspectionHealth.Enabled || inspectionHealth.Generation != 4 {
		t.Fatalf("inspection health=%+v err=%v", inspectionHealth, err)
	}
	capabilities, err := client.InspectionCapabilities(context.Background())
	if err != nil || !capabilities.Supported || len(capabilities.Modes) != 2 {
		t.Fatalf("inspection capabilities=%+v err=%v", capabilities, err)
	}
	security, err := client.ListSecurityEvents(context.Background(), domain.SecurityQuery{Limit: 1})
	if err != nil || len(security.Items) != 1 || security.Items[0].EventID != "evt-1" {
		t.Fatalf("security page=%+v err=%v", security, err)
	}
	event, err := client.GetSecurityEvent(context.Background(), "evt-1")
	if err != nil || event.SuricataFlowID != "18446744073709551615" {
		t.Fatalf("security event=%+v err=%v", event, err)
	}
}

func startRuntimeTestServer(t *testing.T, service RuntimeService, configure func(*RuntimeServer)) (string, context.CancelFunc) {
	t.Helper()
	socket := t.TempDir() + "/engine.sock"
	ctx, cancel := context.WithCancel(context.Background())
	server := NewRuntimeServer(socket, service)
	if configure != nil {
		configure(server)
	}
	go func() { _ = server.Serve(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		connection, err := net.DialTimeout("unix", socket, 10*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return socket, cancel
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("runtime test server did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRuntimeIPCRejectsV2AndOversizedRequest(t *testing.T) {
	socket, cancel := startRuntimeTestServer(t, fakeRuntimeService{}, func(server *RuntimeServer) { server.MaxRequestBytes = 256 })
	defer cancel()
	for _, test := range []struct {
		name    string
		request any
		code    string
	}{
		{name: "version", request: runtimeRequest{Version: 2, RequestID: "v2", Operation: "runtime_health"}, code: "IPC_VERSION_MISMATCH"},
		{name: "oversized", request: map[string]any{"version": RuntimeProtocolVersion, "request_id": "large", "operation": "runtime_health", "payload": strings.Repeat("x", 1024)}, code: "INVALID_REQUEST"},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, err := net.Dial("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err := json.NewEncoder(connection).Encode(test.request); err != nil {
				t.Fatal(err)
			}
			var response runtimeResponse
			if err := json.NewDecoder(connection).Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.OK || response.Code != test.code {
				t.Fatalf("response=%#v", response)
			}
		})
	}
}

type blockingRuntimeService struct{ fakeRuntimeService }

func (blockingRuntimeService) RuntimeHealth(ctx context.Context) (domain.RuntimeHealth, error) {
	<-ctx.Done()
	return domain.RuntimeHealth{}, ctx.Err()
}

func TestRuntimeIPCQueryTimeoutKeepsTypedError(t *testing.T) {
	socket, cancel := startRuntimeTestServer(t, blockingRuntimeService{}, func(server *RuntimeServer) { server.QueryTimeout = 20 * time.Millisecond })
	defer cancel()
	client := NewRuntimeClient(socket)
	client.QueryTimeout = time.Second
	_, err := client.RuntimeHealth(context.Background())
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Code != "DEADLINE_EXCEEDED" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%#v", err)
	}
}

func TestRuntimeIPCClientRejectsOversizedPeerResponse(t *testing.T) {
	temporary, err := os.CreateTemp("", "ngfw-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	socket := temporary.Name()
	_ = temporary.Close()
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request runtimeRequest
		_ = json.NewDecoder(connection).Decode(&request)
		_, _ = connection.Write([]byte(`{"version":3,"request_id":"` + request.RequestID + `","ok":true,"data":{"padding":"` + strings.Repeat("x", 1024) + `"}}`))
	}()
	client := NewRuntimeClient(socket)
	client.MaxResponseBytes = 256
	_, err = client.RuntimeHealth(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds configured byte limit") {
		t.Fatalf("oversized peer response error=%v", err)
	}
	<-done
	_ = os.Remove(socket)
}
