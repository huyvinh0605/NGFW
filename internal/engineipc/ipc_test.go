package engineipc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

func TestClientServerApplyRoundTrip(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "engine.sock")
	applier := &recordingApplier{applied: make(chan domain.Config, 1)}
	server := NewServer(socket, applier)
	ctx, cancel := context.WithCancel(context.Background())
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Serve(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client := NewClient(socket)
		client.Timeout = time.Second
		if err := client.Apply(context.Background(), config.Defaults()); err == nil {
			select {
			case applied := <-applier.applied:
				if applied.MaxSessions != config.Defaults().MaxSessions {
					t.Fatalf("wrong config reached engine: %#v", applied)
				}
			case <-time.After(time.Second):
				t.Fatal("engine did not record apply")
			}
			cancel()
			if err := <-serverResult; err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-serverResult
	t.Fatal("engine IPC server did not become ready")
}

type recordingApplier struct{ applied chan domain.Config }

func (r *recordingApplier) Apply(_ context.Context, value domain.Config) error {
	r.applied <- value
	return nil
}
