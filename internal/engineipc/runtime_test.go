package engineipc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type fakeRuntimeService struct{}

func (fakeRuntimeService) GetRunningConfig(context.Context) (domain.Config, domain.ConfigVersion, error) {
	return domain.Config{}, domain.ConfigVersion{Version: 4}, nil
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
}
