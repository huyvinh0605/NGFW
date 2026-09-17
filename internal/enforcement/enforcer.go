package enforcement

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type Interface interface {
	AllowSession(context.Context, string) error
	DropSession(context.Context, string) error
	RejectSession(context.Context, string) error
	ResetSession(context.Context, string) error
	RateLimit(context.Context, string, int, int) error
	TemporaryBlock(context.Context, domain.TemporaryBlock) error
	Health() domain.ComponentHealth
}

type Memory struct {
	mu        sync.Mutex
	decisions map[string]domain.Decision
	blocks    map[string]domain.TemporaryBlock
	fail      bool
}

func NewMemory() *Memory {
	return &Memory{decisions: map[string]domain.Decision{}, blocks: map[string]domain.TemporaryBlock{}}
}
func (m *Memory) set(id string, d domain.Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return fmt.Errorf("enforcement unavailable")
	}
	m.decisions[id] = d
	return nil
}
func (m *Memory) AllowSession(_ context.Context, id string) error {
	return m.set(id, domain.DecisionAllow)
}
func (m *Memory) DropSession(_ context.Context, id string) error {
	return m.set(id, domain.DecisionDrop)
}
func (m *Memory) RejectSession(_ context.Context, id string) error {
	return m.set(id, domain.DecisionReject)
}
func (m *Memory) ResetSession(_ context.Context, id string) error {
	return m.set(id, domain.DecisionReset)
}
func (m *Memory) RateLimit(_ context.Context, id string, _, _ int) error {
	return m.set(id, domain.DecisionRateLimit)
}
func (m *Memory) TemporaryBlock(_ context.Context, b domain.TemporaryBlock) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return fmt.Errorf("enforcement unavailable")
	}
	m.blocks[b.ID] = b
	return nil
}
func (m *Memory) Health() domain.ComponentHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := "ok"
	if m.fail {
		status = "down"
	}
	return domain.ComponentHealth{Name: "enforcement", Status: status, UpdatedAt: time.Now()}
}
func (m *Memory) SetFailure(fail bool) { m.mu.Lock(); m.fail = fail; m.mu.Unlock() }
func (m *Memory) Decision(id string) (domain.Decision, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.decisions[id]
	return v, ok
}
func (m *Memory) Blocks() []domain.TemporaryBlock {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]domain.TemporaryBlock, 0, len(m.blocks))
	for _, b := range m.blocks {
		if b.ExpiresAt.After(time.Now()) {
			out = append(out, b)
		}
	}
	return out
}
