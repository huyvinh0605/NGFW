package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/session"
)

// RuntimeServiceAdapter is the narrow management surface exposed by the
// privileged engine IPC server. It contains no HTTP or authentication logic.
// Apply is supplied by the engine command and is the only path that mutates
// Linux dataplane state.
type RuntimeServiceAdapter struct {
	Runtime *Runtime
	Config  *config.Manager
	Apply   func(context.Context, domain.Config) error
	// ApplyGeneration is the M3-aware privileged path.  The exact generation
	// is required so compensation cannot compile an old Config using a target
	// generation.  Apply remains for M1/M2 compatibility tests.
	ApplyGeneration func(context.Context, domain.Config, uint64) error
	Rollback        func(context.Context, domain.Config) error
	// BeforeActivate validates installed immutable sensor artifacts/capability
	// metadata before the dataplane is mutated.
	BeforeActivate func(context.Context, domain.Config, uint64) error
	// FinalizeActivation removes the outer dataplane journal only after Running,
	// the in-memory generation and inspection lifecycle all match.
	FinalizeActivation func(context.Context, domain.Config, uint64) error
	// AfterActivate owns process-local inspection lifecycle changes. Dataplane
	// activation and the Runtime generation are already committed when called.
	// Returning an error triggers the same newer-generation restoration path.
	AfterActivate func(context.Context, domain.Config, uint64) error
	// InspectionQueueStatus is supplied by the privileged process which owns
	// the nft lease manager. It must be a quick, read-only snapshot function.
	InspectionQueueStatus func() domain.InspectionQueueStatus
	applyMu               sync.Mutex
	mu                    sync.Mutex
	receipts              map[string]domain.ConfigVersion
}

func NewRuntimeServiceAdapter(runtime *Runtime, manager *config.Manager, apply func(context.Context, domain.Config) error) *RuntimeServiceAdapter {
	return &RuntimeServiceAdapter{Runtime: runtime, Config: manager, Apply: apply, receipts: map[string]domain.ConfigVersion{}}
}

func (s *RuntimeServiceAdapter) applyConfig(ctx context.Context, value domain.Config, generation uint64) error {
	if s.ApplyGeneration != nil {
		return s.ApplyGeneration(ctx, value, generation)
	}
	if s.Apply != nil {
		return s.Apply(ctx, value)
	}
	return errors.New("privileged activation unavailable")
}

func (s *RuntimeServiceAdapter) finalizeConfig(ctx context.Context, value domain.Config, generation uint64) error {
	if s.FinalizeActivation == nil {
		return nil
	}
	return s.FinalizeActivation(ctx, value, generation)
}

// pauseInspection serializes dynamic M3 set updates with the complete
// configuration activation. The returned runtime is the exact coordinator
// whose gate was acquired; callers must pass it to resumeInspection even when
// activation fails.
func (s *RuntimeServiceAdapter) pauseInspection() *InspectionRuntime {
	if s.Runtime == nil {
		return nil
	}
	current := s.Runtime.InspectionRuntime()
	if current != nil {
		current.BeginActivation()
	}
	return current
}

func (s *RuntimeServiceAdapter) resumeInspection(current *InspectionRuntime, changed []domain.RuntimeSession) {
	if current == nil {
		return
	}
	current.EndActivation()
	for _, value := range changed {
		current.OnSessionChanged(value)
	}
}

// restoreAfterActivationFailure returns the manager, Linux dataplane and
// in-memory runtime to the previous known-good configuration through a newer
// monotonic generation. The caller must already hold current's gate.
func (s *RuntimeServiceAdapter) restoreAfterActivationFailure(author, comment string) (domain.ConfigVersion, []domain.RuntimeSession, error) {
	restoreCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	restored, restoreErr := s.Config.RollbackWithGeneration(restoreCtx, author, comment, s.applyConfig)
	if restoreErr != nil || s.Runtime == nil {
		return restored, nil, restoreErr
	}
	program, compileErr := compileRuntimeProgram(s.Config.Running(), restored.Version)
	if compileErr != nil {
		return restored, nil, compileErr
	}
	changed, activateErr := s.Runtime.activateWhileInspectionPaused(program, restored.Version, comment)
	return restored, changed, activateErr
}

func (s *RuntimeServiceAdapter) finishRestoredActivation(restored domain.ConfigVersion, lifecycle bool) error {
	if lifecycle && s.AfterActivate != nil {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.AfterActivate(restoreCtx, s.Config.Running(), restored.Version)
		cancel()
		if err != nil {
			return fmt.Errorf("restore inspection runtime lifecycle: %w", err)
		}
	}
	finalizeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := s.finalizeConfig(finalizeCtx, s.Config.Running(), restored.Version)
	cancel()
	if err != nil {
		return fmt.Errorf("finalize restored activation: %w", err)
	}
	return nil
}

// recoverPublishedFailure is used after Running has already advanced.  The
// compensation is itself a normal rollback and therefore receives a newer
// monotonic generation and a fresh receipt/journal lifecycle.
func (s *RuntimeServiceAdapter) recoverPublishedFailure(author, comment string, cause error) (domain.ConfigVersion, error) {
	restoreInspection := s.pauseInspection()
	restored, restoredChanged, restoreErr := s.restoreAfterActivationFailure(author, comment)
	s.resumeInspection(restoreInspection, restoredChanged)
	if restoreErr == nil {
		restoreErr = s.finishRestoredActivation(restored, true)
	}
	return restored, errors.Join(cause, restoreErr)
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
	if s.Config == nil || (s.Apply == nil && s.ApplyGeneration == nil) {
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
	if errs := config.ExactDuplicatePolicyErrorsForConfig(desired); len(errs) > 0 {
		return s.Config.Version(), errors.New(strings.Join(errs, "; "))
	}
	if errs := config.UnreachablePolicyErrorsForConfig(desired); len(errs) > 0 {
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
		compiled, compileErr = compileRuntimeProgram(desired, expected+1)
		if compileErr != nil {
			return s.Config.Version(), compileErr
		}
	}
	if s.BeforeActivate != nil {
		if expected == ^uint64(0) {
			return s.Config.Version(), errors.New("policy generation exhausted")
		}
		if err := s.BeforeActivate(ctx, desired, expected+1); err != nil {
			return s.Config.Version(), fmt.Errorf("inspection activation preflight: %w", err)
		}
	}
	inspectionRuntime := s.pauseInspection()
	gateHeld := inspectionRuntime != nil
	defer func() {
		if gateHeld {
			s.resumeInspection(inspectionRuntime, nil)
		}
	}()
	version, err := s.Config.CommitWithGeneration(ctx, author, comment, expected, s.applyConfig)
	if err != nil {
		finalizeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		finalizeErr := s.finalizeConfig(finalizeCtx, s.Config.Running(), s.Config.Version().Version)
		cancel()
		return version, errors.Join(err, finalizeErr)
	}
	var changed []domain.RuntimeSession
	if s.Runtime != nil {
		compiled.Generation = version.Version
		var activateErr error
		changed, activateErr = s.Runtime.activateWhileInspectionPaused(compiled, version.Version, "configuration generation changed")
		if activateErr != nil {
			// The dataplane was already activated by CommitWithApply. If the
			// runtime generation cannot be published, restore the previous
			// configuration and make that restoration a newer generation.
			restored, restoredChanged, restoreErr := s.restoreAfterActivationFailure(author, "restore after runtime activation failure")
			if gateHeld {
				s.resumeInspection(inspectionRuntime, restoredChanged)
				gateHeld = false
			}
			if restoreErr == nil {
				restoreErr = s.finishRestoredActivation(restored, false)
			}
			if restoreErr == nil {
				return restored, activateErr
			}
			return version, errors.Join(activateErr, restoreErr)
		}
	}
	if gateHeld {
		s.resumeInspection(inspectionRuntime, changed)
		gateHeld = false
	}
	if s.AfterActivate != nil {
		if hookErr := s.AfterActivate(ctx, s.Config.Running(), version.Version); hookErr != nil {
			restored, recoveryErr := s.recoverPublishedFailure(author, "restore after inspection runtime activation failure", hookErr)
			return restored, recoveryErr
		}
	}
	if finalizeErr := s.finalizeConfig(ctx, s.Config.Running(), version.Version); finalizeErr != nil {
		restored, recoveryErr := s.recoverPublishedFailure(author, "restore after activation finalization failure", fmt.Errorf("finalize activation: %w", finalizeErr))
		return restored, recoveryErr
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
	if s.Config == nil || (s.Apply == nil && s.ApplyGeneration == nil) {
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
	inspectionRuntime := s.pauseInspection()
	gateHeld := inspectionRuntime != nil
	defer func() {
		if gateHeld {
			s.resumeInspection(inspectionRuntime, nil)
		}
	}()
	targetGeneration := s.Config.Version().Version + 1
	if s.BeforeActivate != nil {
		if targetGeneration == 0 {
			return s.Config.Version(), errors.New("policy generation exhausted")
		}
		target, ok := s.Config.RollbackTarget()
		if !ok {
			return s.Config.Version(), errors.New("no previous configuration")
		}
		if err := s.BeforeActivate(ctx, target, targetGeneration); err != nil {
			return s.Config.Version(), fmt.Errorf("inspection rollback preflight: %w", err)
		}
	}
	version, err := s.Config.RollbackWithGeneration(ctx, author, comment, s.applyConfig)
	if err != nil {
		finalizeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		finalizeErr := s.finalizeConfig(finalizeCtx, s.Config.Running(), s.Config.Version().Version)
		cancel()
		return version, errors.Join(err, finalizeErr)
	}
	var changed []domain.RuntimeSession
	if s.Runtime != nil {
		program, compileErr := compileRuntimeProgram(s.Config.Running(), version.Version)
		if compileErr != nil {
			restored, restoredChanged, restoreErr := s.restoreAfterActivationFailure(author, "restore after rollback compile failure")
			if gateHeld {
				s.resumeInspection(inspectionRuntime, restoredChanged)
				gateHeld = false
			}
			if restoreErr == nil {
				restoreErr = s.finishRestoredActivation(restored, false)
			}
			if restoreErr == nil {
				return restored, compileErr
			}
			return version, errors.Join(compileErr, restoreErr)
		}
		var activateErr error
		changed, activateErr = s.Runtime.activateWhileInspectionPaused(program, version.Version, "configuration rollback")
		if activateErr != nil {
			// The dataplane is already on the rollback target. Restore the
			// previous running snapshot through a newer generation if the
			// runtime cannot publish the target generation.
			restored, restoredChanged, restoreErr := s.restoreAfterActivationFailure(author, "restore after rollback activation failure")
			if gateHeld {
				s.resumeInspection(inspectionRuntime, restoredChanged)
				gateHeld = false
			}
			if restoreErr == nil {
				restoreErr = s.finishRestoredActivation(restored, false)
			}
			if restoreErr == nil {
				return restored, activateErr
			}
			return version, errors.Join(activateErr, restoreErr)
		}
	}
	if gateHeld {
		s.resumeInspection(inspectionRuntime, changed)
		gateHeld = false
	}
	if s.AfterActivate != nil {
		if hookErr := s.AfterActivate(ctx, s.Config.Running(), version.Version); hookErr != nil {
			restored, recoveryErr := s.recoverPublishedFailure(author, "restore after rollback inspection runtime failure", hookErr)
			return restored, recoveryErr
		}
	}
	if finalizeErr := s.finalizeConfig(ctx, s.Config.Running(), version.Version); finalizeErr != nil {
		restored, recoveryErr := s.recoverPublishedFailure(author, "restore after rollback finalization failure", fmt.Errorf("finalize rollback activation: %w", finalizeErr))
		return restored, recoveryErr
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

func compileRuntimeProgram(value domain.Config, generation uint64) (connectivity.Program, error) {
	if domain.UsesM3(value) {
		return connectivity.CompileM3(value, generation)
	}
	return connectivity.CompileM2(value, generation)
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
	return domain.RuntimeEventPage{Items: items, StreamID: s.Runtime.Events.StreamID(), GapFrom: gap, NextSequence: next}, nil
}

func (s *RuntimeServiceAdapter) InspectionHealth(context.Context) (domain.InspectionHealth, error) {
	health := domain.InspectionHealth{Status: "disabled", Sources: map[string]domain.InspectionSourceStatus{}, Stats: map[string]uint64{}, UpdatedAt: time.Now().UTC()}
	if s.Runtime == nil {
		return health, errors.New("runtime unavailable")
	}
	health.Generation = s.Runtime.CurrentGeneration()
	coordinator := s.Runtime.InspectionRuntime()
	if coordinator == nil {
		return health, nil
	}
	health.Enabled = true
	health.Status = "healthy"
	sources := coordinator.Health()
	if len(sources) == 0 {
		health.Status = "degraded"
		health.Reason = "no configured inspection sensor source"
	}
	for id, value := range sources {
		health.Sources[id] = domain.InspectionSourceStatus{SensorID: value.SensorID, Mode: value.Mode, State: value.State, Reason: value.Reason, LastRead: value.LastRead, LastHeartbeat: value.LastHeartbeat, Counters: sourceCounters(value.Counters), ReaderStats: cloneReaderStats(value.ReaderStats)}
		if value.State != "HEALTHY" && value.State != "DISABLED" {
			health.Status = "degraded"
		}
	}
	if s.InspectionQueueStatus != nil {
		health.IPSQueue = s.InspectionQueueStatus()
		if health.IPSQueue.Requested && (!health.IPSQueue.Configured || !health.IPSQueue.CaptureLive || !health.IPSQueue.LeaseActive) {
			health.Status = "degraded"
			if health.Reason == "" {
				health.Reason = "IPS requested but capture/lease readiness is incomplete"
			}
		}
	}
	health.Stats = coordinator.Stats()
	return health, nil
}

func sourceCounters(value inspection.SensorCounters) domain.SensorCounters {
	return domain.SensorCounters{UptimeSeconds: value.UptimeSeconds, CapturedPackets: value.CapturedPackets, CaptureDrops: value.CaptureDrops, NFQueueDrops: value.NFQueueDrops, SourceTimestamp: value.SourceTimestamp}
}

func cloneReaderStats(value map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(value))
	for key, count := range value {
		result[key] = count
	}
	return result
}
func (s *RuntimeServiceAdapter) InspectionCapabilities(context.Context) (domain.InspectionCapabilities, error) {
	return domain.InspectionCapabilities{Supported: true, Modes: []domain.InspectionMode{domain.InspectionModeIDS, domain.InspectionModeIPS}, Applications: []string{"HTTP", "TLS", "DNS", "SSH"}, FailModes: []string{"OPEN"}, Rulesets: []string{config.BuiltinM3RulesetID}, ApplicationMatchModes: []string{config.ApplicationMatchRestrictL3Allow}, Limitations: []string{"asynchronous application classification", "no TLS decryption", "no HTTP/3 inspection", "IPS fail-open only"}}, nil
}
func (s *RuntimeServiceAdapter) ListSecurityEvents(_ context.Context, query domain.SecurityQuery) (domain.SecurityEventPage, error) {
	if s.Runtime == nil || s.Runtime.InspectionRuntime() == nil {
		return domain.SecurityEventPage{}, errors.New("inspection runtime unavailable")
	}
	return s.Runtime.InspectionRuntime().SecurityEvents().Query(query), nil
}
func (s *RuntimeServiceAdapter) GetSecurityEvent(_ context.Context, id string) (domain.ThreatEvent, error) {
	if s.Runtime == nil || s.Runtime.InspectionRuntime() == nil {
		return domain.ThreatEvent{}, errors.New("inspection runtime unavailable")
	}
	value, ok := s.Runtime.InspectionRuntime().SecurityEvents().Get(id)
	if !ok {
		return domain.ThreatEvent{}, ErrSecurityEventNotFound
	}
	return value, nil
}
