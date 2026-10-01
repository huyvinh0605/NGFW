package engineipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type gateRuntimeFake struct{ fakeRuntimeService }

func (gateRuntimeFake) RequestGateHealth(context.Context) (domain.RequestGateHealth, error) {
	return domain.RequestGateHealth{Enabled: true, Status: "down", Generation: 7}, nil
}
func (gateRuntimeFake) RequestGateCapabilities(context.Context) (domain.RequestGateCapabilities, error) {
	return domain.RequestGateCapabilities{Supported: true, ProductionReady: false}, nil
}
func (gateRuntimeFake) ListRequestGateEvidence(_ context.Context, after uint64, limit int) (domain.RequestGateEvidencePage, error) {
	return domain.RequestGateEvidencePage{Items: []domain.RequestGateEvidence{{EventID: "m4-e1", Sequence: after + 1}}, NextSequence: after + 1, HasMore: limit == 1}, nil
}

func TestRequestGateRuntimeIPCRoundTripAndBoundedPage(t *testing.T) {
	// Keep the Unix socket path short on Windows, which has a tight AF_UNIX
	// path limit and appends the test name to t.TempDir().
	dir, err := os.MkdirTemp("", "m4ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "e.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := NewRuntimeServer(socket, gateRuntimeFake{})
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		connection, dialErr := net.DialTimeout("unix", socket, 10*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("runtime server: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime server did not start: %v", dialErr)
		}
		time.Sleep(time.Millisecond)
	}
	client := NewRuntimeClient(socket)
	health, err := client.RequestGateHealth(context.Background())
	if err != nil || health.Status != "down" || health.Generation != 7 {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	caps, err := client.RequestGateCapabilities(context.Background())
	if err != nil || !caps.Supported || caps.ProductionReady {
		t.Fatalf("caps=%+v err=%v", caps, err)
	}
	page, err := client.ListRequestGateEvidence(context.Background(), 9, 1)
	if err != nil || len(page.Items) != 1 || page.NextSequence != 10 || !page.HasMore {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if _, err := client.ListRequestGateEvidence(context.Background(), 0, 129); err == nil {
		t.Fatal("unbounded page accepted")
	}
}
