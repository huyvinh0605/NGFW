package management

import (
	"context"

	"github.com/kltngfw/ngfw/internal/domain"
)

// RuntimeClient is the only management-plane dependency on M2 runtime state.
// The production implementation is an engine IPC client; tests may inject a
// bounded fake. It intentionally does not expose session.Store or dataplane.
type RuntimeClient interface {
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

type InspectionRuntimeClient interface {
	InspectionHealth(context.Context) (domain.InspectionHealth, error)
	InspectionCapabilities(context.Context) (domain.InspectionCapabilities, error)
	ListSecurityEvents(context.Context, domain.SecurityQuery) (domain.SecurityEventPage, error)
	GetSecurityEvent(context.Context, string) (domain.ThreatEvent, error)
}
