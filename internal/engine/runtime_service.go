package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

// RuntimeServiceAdapter is the narrow management surface exposed by the
// privileged engine IPC server. It contains no HTTP or authentication logic.
// Apply is supplied by the engine command and is the only path that mutates
// Linux dataplane state.
type RuntimeServiceAdapter struct {
	Runtime  *Runtime
	Config   *config.Manager
	Apply    func(context.Context, domain.Config) error
	Rollback func(context.Context, domain.Config) error
	applyMu  sync.Mutex
	mu       sync.Mutex
	receipts map[string]domain.ConfigVersion
}

func NewRuntimeServiceAdapter(runtime *Runtime, manager *config.Manager, apply func(context.Context, domain.Config) error) *RuntimeServiceAdapter {
	return &RuntimeServiceAdapter{Runtime: runtime, Config: manager, Apply: apply, receipts: map[string]domain.ConfigVersion{}}
}

func (s *RuntimeServiceAdapter) GetRunningConfig(context.Context) (domain.Config, domain.ConfigVersion, error) {
	if s.Config == nil {
		return domain.Config{}, domain.ConfigVersion{}, errors.New("configuration manager unavailable")
	}
	return s.Config.Running(), s.Config.Version(), nil
}

func (s *RuntimeServiceAdapter) CommitConfig(ctx context.Context, desired domain.Config, expected uint64, author, comment, operationID string) (domain.ConfigVersion, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.Config == nil || s.Apply == nil {
		return domain.ConfigVersion{}, errors.New("privileged activation unavailable")
	}
	if operationID != "" {
		s.mu.Lock()
		if version, ok := s.receipts[operationID]; ok {
			s.mu.Unlock()
			return version, nil
		}
		s.mu.Unlock()
	}
	if errs := config.ExactDuplicatePolicyErrors(desired.Policies); len(errs) > 0 {
		return s.Config.Version(), errors.New(strings.Join(errs, "; "))
	}
	if errs := config.UnreachablePolicyErrors(desired.Policies); len(errs) > 0 {
		return s.Config.Version(), errors.New(strings.Join(errs, "; "))
	}
	if errs := (config.Validator{}).Validate(desired); len(errs) > 0 {
		return s.Config.Version(), errors.New("invalid candidate: " + strings.Join(errs, "; "))
	}
	if errs := s.Config.SetCandidate(desired); len(errs) > 0 {
		return s.Config.Version(), errors.New("invalid candidate")
	}
	var compiled connectivity.Program
	if s.Runtime != nil {
		if expected == ^uint64(0) {
			return s.Config.Version(), errors.New("policy generation exhausted")
		}
		var compileErr error
		compiled, compileErr = connectivity.CompileM2(desired, expected+1)
		if compileErr != nil {
			return s.Config.Version(), compileErr
		}
	}
	version, err := s.Config.CommitWithApply(ctx, author, comment, expected, s.Apply)
	if err != nil {
		return version, err
	}
	if s.Runtime != nil {
		compiled.Generation = version.Version
		if activateErr := s.Runtime.Activate(compiled, version.Version, "configuration generation changed"); activateErr != nil {
			// The dataplane was already activated by CommitWithApply. If the
			// runtime generation cannot be published, restore the previous
			// configuration and make that restoration a newer generation.
			restored, restoreErr := s.Config.RollbackWithApply(ctx, author, "restore after runtime activation failure", s.Apply)
			if restoreErr == nil {
				if restoredProgram, compileErr := connectivity.CompileM2(s.Config.Running(), restored.Version); compileErr == nil {
					_ = s.Runtime.Activate(restoredProgram, restored.Version, "restore after runtime activation failure")
				}
			}
			return version, errors.Join(activateErr, restoreErr)
		}
	}
	if operationID != "" {
		s.mu.Lock()
		if len(s.receipts) >= 1024 {
			for id := range s.receipts {
				delete(s.receipts, id)
				break
			}
		}
		s.receipts[operationID] = version
		s.mu.Unlock()
	}
	return version, nil
}

func (s *RuntimeServiceAdapter) RollbackConfig(ctx context.Context, author, comment, operationID string) (domain.ConfigVersion, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.Config == nil || s.Apply == nil {
		return domain.ConfigVersion{}, errors.New("privileged activation unavailable")
	}
	if operationID != "" {
		s.mu.Lock()
		if version, ok := s.receipts[operationID]; ok {
			s.mu.Unlock()
			return version, nil
		}
		s.mu.Unlock()
	}
	version, err := s.Config.RollbackWithApply(ctx, author, comment, s.Apply)
	if err != nil {
		return version, err
	}
	if s.Runtime != nil {
		program, compileErr := connectivity.CompileM2(s.Config.Running(), version.Version)
		if compileErr != nil {
			restored, restoreErr := s.Config.RollbackWithApply(ctx, author, "restore after rollback compile failure", s.Apply)
			if restoreErr == nil {
				if restoredProgram, secondErr := connectivity.CompileM2(s.Config.Running(), restored.Version); secondErr == nil {
					_ = s.Runtime.Activate(restoredProgram, restored.Version, "restore after rollback compile failure")
				}
			}
			return version, errors.Join(compileErr, restoreErr)
		}
		if activateErr := s.Runtime.Activate(program, version.Version, "configuration rollback"); activateErr != nil {
			// The dataplane is already on the rollback target. Restore the
			// previous running snapshot through a newer generation if the
			// runtime cannot publish the target generation.
			restored, restoreErr := s.Config.RollbackWithApply(ctx, author, "restore after rollback activation failure", s.Apply)
			if restoreErr == nil {
				if restoredProgram, compileErr := connectivity.CompileM2(s.Config.Running(), restored.Version); compileErr == nil {
					_ = s.Runtime.Activate(restoredProgram, restored.Version, "restore after rollback activation failure")
				}
			}
			return version, errors.Join(activateErr, restoreErr)
		}
	}
	if operationID != "" {
		s.mu.Lock()
		if len(s.receipts) >= 1024 {
			for id := range s.receipts {
				delete(s.receipts, id)
				break
			}
		}
		s.receipts[operationID] = version
		s.mu.Unlock()
	}
	return version, nil
}

func (s *RuntimeServiceAdapter) ListSessions(_ context.Context, query domain.SessionQuery) (domain.SessionPage, error) {
	if s.Runtime == nil {
		return domain.SessionPage{}, errors.New("runtime unavailable")
	}
	result := s.Runtime.Store.Query(session.SessionFilter{SourceIP: query.SourceIP, DestinationIP: query.DestinationIP, Protocol: query.Protocol, SourceZone: query.SourceZone, DestinationZone: query.DestinationZone, State: query.State, Decision: query.Decision, TupleView: query.TupleView}, session.Page{Number: query.Page, Size: query.PageSize})
	return domain.SessionPage{Items: result.Items, Page: result.Page, PageSize: result.PageSize, Total: result.Total, HasMore: result.HasMore, StoreRevision: result.StoreRevision, SnapshotTime: result.SnapshotTime}, nil
}
func (s *RuntimeServiceAdapter) GetSession(_ context.Context, id string) (domain.RuntimeSession, error) {
	if s.Runtime == nil {
		return domain.RuntimeSession{}, errors.New("runtime unavailable")
	}
	value, ok := s.Runtime.Store.Get(id)
	if !ok {
		return domain.RuntimeSession{}, session.ErrSessionMissing
	}
	return value, nil
}
func (s *RuntimeServiceAdapter) SessionStats(context.Context) (domain.RuntimeStats, error) {
	if s.Runtime == nil {
		return domain.RuntimeStats{}, errors.New("runtime unavailable")
	}
	v := s.Runtime.Stats()
	return domain.RuntimeStats{ActiveSessions: v.Active, Created: v.Created, Closed: v.Closed, Invalidated: v.Invalidated, TrackingDrops: v.TrackingDrops, CapacityDrops: v.CapacityDrops, EventDrops: v.EventDrops, Resyncs: v.Resyncs}, nil
}
func (s *RuntimeServiceAdapter) RuntimeHealth(context.Context) (domain.RuntimeHealth, error) {
	if s.Runtime == nil {
		return domain.RuntimeHealth{Status: "degraded", Message: "runtime unavailable", UpdatedAt: time.Now().UTC()}, nil
	}
	ready, message := s.Runtime.Health()
	status := "healthy"
	if !ready {
		status = "degraded"
	}
	return domain.RuntimeHealth{Status: status, Message: message, Generation: s.Runtime.CurrentGeneration(), UpdatedAt: time.Now().UTC()}, nil
}
func (s *RuntimeServiceAdapter) RevokeSession(ctx context.Context, id, reason string) error {
	if s.Runtime == nil {
		return errors.New("runtime unavailable")
	}
	return s.Runtime.RevokeContext(ctx, id, reason)
}
func (s *RuntimeServiceAdapter) AddTemporaryBlock(ctx context.Context, block domain.TemporaryBlock) error {
	if s.Runtime == nil {
		return errors.New("runtime unavailable")
	}
	return s.Runtime.AddTemporaryBlockContext(ctx, block)
}
func (s *RuntimeServiceAdapter) RemoveTemporaryBlock(ctx context.Context, indicator string) error {
	if s.Runtime == nil {
		return errors.New("runtime unavailable")
	}
	return s.Runtime.RemoveTemporaryBlockContext(ctx, indicator)
}
func (s *RuntimeServiceAdapter) ListTemporaryBlocks(_ context.Context) ([]domain.TemporaryBlock, error) {
	if s.Runtime == nil {
		return nil, errors.New("runtime unavailable")
	}
	return s.Runtime.Blocks(), nil
}
func (s *RuntimeServiceAdapter) ReadRuntimeEvents(_ context.Context, after uint64, max int) (domain.RuntimeEventPage, error) {
	if s.Runtime == nil {
		return domain.RuntimeEventPage{}, errors.New("runtime unavailable")
	}
	items, gap, next := s.Runtime.Events.Read(after, max)
	return domain.RuntimeEventPage{Items: items, GapFrom: gap, NextSequence: next}, nil
}
