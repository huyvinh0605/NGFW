package engineipc

import (
	"context"
	"errors"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

type missingSessionService struct{ fakeRuntimeService }

func (missingSessionService) GetSession(context.Context, string) (domain.RuntimeSession, error) {
	return domain.RuntimeSession{}, session.ErrSessionMissing
}

func TestRuntimeIPCPreservesSessionNotFound(t *testing.T) {
	socket, cancel := startRuntimeTestServer(t, missingSessionService{}, nil)
	defer cancel()
	_, err := NewRuntimeClient(socket).GetSession(context.Background(), "missing-session")
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Code != "NOT_FOUND" || !errors.Is(err, domain.ErrRuntimeSessionNotFound) {
		t.Fatalf("lost typed session-not-found across IPC: %v", err)
	}
}
