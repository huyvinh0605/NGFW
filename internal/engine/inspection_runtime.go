package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/inspection/correlation"
	"github.com/kltngfw/ngfw/internal/inspection/eve"
	"github.com/kltngfw/ngfw/internal/session"
)

type InspectionIntentExecutor interface {
	ExecuteInspectionIntent(context.Context, domain.InspectionIntent) (domain.EnforcementResult, error)
}

type queuedObservation struct {
	value inspection.Observation
	bytes int
}

type sessionChange struct {
	sessionID string
	identity  domain.ConntrackIdentity
}

type InspectionRuntime struct {
	runtime       *Runtime
	sources       []inspection.EventSource
	security      *SecurityEventStore
	resolver      *correlation.Resolver
	pending       *correlation.PendingCorrelations
	deduper       *eve.Deduper
	queue         chan queuedObservation
	sessionQueue  chan sessionChange
	intentQueue   chan domain.InspectionIntent
	queueBytes    int64
	maxQueueBytes int64
	appTimeout    time.Duration
	drops         atomic.Uint64
	intentDrops   atomic.Uint64
	sessionDrops  atomic.Uint64
	processed     atomic.Uint64
	duplicates    atomic.Uint64
	stale         atomic.Uint64
	gate          sync.RWMutex
	mu            sync.RWMutex
	started       bool
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	executor      InspectionIntentExecutor
	health        map[string]inspection.SourceHealth
}

func NewInspectionRuntime(runtime *Runtime, limits domain.InspectionLimits, sources []inspection.EventSource) *InspectionRuntime {
	return NewInspectionRuntimeWithScope(runtime, limits, sources, flow.Scope{NetworkNamespace: runtimeNamespace(runtime)})
}

func NewInspectionRuntimeWithScope(runtime *Runtime, limits domain.InspectionLimits, sources []inspection.EventSource, scope flow.Scope) *InspectionRuntime {
	limits = limits.WithDefaults()
	queueItems := limits.ObservationQueueItems
	if queueItems <= 0 {
		queueItems = 4096
	}
	maxBytes := limits.ObservationQueueBytes
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	intentItems := queueItems / 4
	if intentItems < 64 {
		intentItems = 64
	}
	if intentItems > 1024 {
		intentItems = 1024
	}
	sessionItems := queueItems
	if runtime != nil && runtime.Store != nil && runtime.Store.Capacity() > sessionItems {
		sessionItems = runtime.Store.Capacity()
	}
	if sessionItems > 50000 {
		sessionItems = 50000
	}
	value := &InspectionRuntime{runtime: runtime, sources: append([]inspection.EventSource(nil), sources...), security: NewSecurityEventStore(limits.SecurityEvents, limits.SecurityEventBytes), queue: make(chan queuedObservation, queueItems), sessionQueue: make(chan sessionChange, sessionItems), intentQueue: make(chan domain.InspectionIntent, intentItems), maxQueueBytes: int64(maxBytes), appTimeout: time.Duration(limits.AppDetectionTimeoutMillis) * time.Millisecond, pending: correlation.NewPendingCorrelations(limits.CorrelationPending, time.Duration(limits.CorrelationWaitMillis)*time.Millisecond), deduper: eve.NewDeduper(20000, 4<<20, 10*time.Minute), health: map[string]inspection.SourceHealth{}}
	if runtime != nil {
		value.resolver = correlation.NewResolver(runtime.Store, scope, 10000)
	}
	return value
}

func runtimeNamespace(runtime *Runtime) string {
	if runtime == nil {
		return ""
	}
	sessions := runtime.Store.List()
	if len(sessions) > 0 {
		return sessions[0].Identity.NetworkNS
	}
	return ""
}
func (r *InspectionRuntime) SecurityEvents() *SecurityEventStore { return r.security }
func (r *InspectionRuntime) SetExecutor(executor InspectionIntentExecutor) {
	r.mu.Lock()
	r.executor = executor
	r.mu.Unlock()
}

func (r *InspectionRuntime) Start(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.started = true
	r.mu.Unlock()
	r.wg.Add(1)
	go r.loop(runCtx)
	// Enforcement performs kernel IO and therefore runs outside the single
	// observation reducer.  A fixed worker count and bounded channel prevent a
	// burst of alerts from creating one goroutine per event.
	for i := 0; i < 2; i++ {
		r.wg.Add(1)
		go r.intentWorker(runCtx)
	}
	for _, source := range r.sources {
		source := source
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			err := source.Run(runCtx, r)
			snapshot := source.Snapshot()
			if err != nil {
				snapshot.State = "UNAVAILABLE"
				snapshot.Reason = err.Error()
			}
			r.mu.Lock()
			r.health[snapshot.SensorID] = snapshot
			r.mu.Unlock()
		}()
	}
	return nil
}

func (r *InspectionRuntime) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	cancel := r.cancel
	r.cancel = nil
	r.started = false
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	r.wg.Wait()
}

func (r *InspectionRuntime) TrySubmit(obs inspection.Observation) bool {
	if r == nil {
		return false
	}
	encoded, _ := json.Marshal(obs)
	size := len(encoded)
	if size <= 0 {
		size = 1
	}
	for {
		current := atomic.LoadInt64(&r.queueBytes)
		if current+int64(size) > r.maxQueueBytes {
			r.drops.Add(1)
			return false
		}
		if atomic.CompareAndSwapInt64(&r.queueBytes, current, current+int64(size)) {
			break
		}
	}
	select {
	case r.queue <- queuedObservation{value: obs, bytes: size}:
		return true
	default:
		atomic.AddInt64(&r.queueBytes, -int64(size))
		r.drops.Add(1)
		return false
	}
}

func (r *InspectionRuntime) loop(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadlineTicker := time.NewTicker(time.Second)
	defer deadlineTicker.Stop()
	renewTicker := time.NewTicker(20 * time.Second)
	defer renewTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-r.queue:
			atomic.AddInt64(&r.queueBytes, -int64(item.bytes))
			r.HandleObservation(ctx, item.value)
		case change := <-r.sessionQueue:
			r.handleSessionChanged(change)
		case now := <-ticker.C:
			r.retryPending(ctx, now)
		case now := <-deadlineTicker.C:
			r.sweepAppDeadlines(now, 512)
		case now := <-renewTicker.C:
			r.renewAppGuards(now, 512)
		}
	}
}

func (r *InspectionRuntime) retryPending(ctx context.Context, now time.Time) {
	due, _ := r.pending.RetryDue(now, 128)
	for _, obs := range due {
		r.handleObservation(ctx, obs, true)
	}
}

func (r *InspectionRuntime) HandleObservation(ctx context.Context, obs inspection.Observation) {
	r.handleObservation(ctx, obs, false)
}

func (r *InspectionRuntime) handleObservation(ctx context.Context, obs inspection.Observation, pendingRetry bool) {
	if r == nil || r.runtime == nil {
		return
	}
	if !pendingRetry && r.deduper != nil && r.deduper.SeenOrAdd(obs.ID, time.Now().UTC()) {
		r.duplicates.Add(1)
		return
	}
	r.processed.Add(1)
	// Preserve every physical alert before attempting correlation. A replayed
	// source position may still complete a formerly pending correlation, but it
	// must not increment the session threat count or publish a second alert.
	attachThreat := false
	if obs.Alert != nil && !obs.Alert.InternalDiscovery {
		event := ThreatFromObservation(obs, domain.RuntimeSession{}, connectivity.InspectionSelection{Mode: obs.Source.Mode})
		event.CorrelationState = domain.CorrelationUncorrelated
		event.CorrelationReason = "correlation pending"
		stored, added, addErr := r.security.Add(event)
		if addErr == nil {
			attachThreat = added || stored.SessionID == ""
		}
	}
	resolution := r.resolver.Resolve(obs)
	if resolution.State != domain.CorrelationCorrelated || resolution.Session == nil {
		if obs.Alert != nil {
			_, _ = r.security.UpdateCorrelation(obs.ID, "", "", 0, resolution.State, resolution.Reason)
		}
		if resolution.State == domain.CorrelationUncorrelated {
			_ = r.pending.Add(obs, time.Now().UTC())
		}
		return
	}
	r.pending.Remove(obs.ID)
	value := resolution.Session.Clone()
	if obs.Alert != nil {
		_, _ = r.security.UpdateCorrelation(obs.ID, value.SessionID, value.MatchedPolicyID, value.PolicyGeneration, domain.CorrelationCorrelated, resolution.Reason)
	}
	if resolution.Recent {
		return
	}
	r.gate.RLock()
	defer r.gate.RUnlock()
	program := r.runtime.CurrentProgram()
	view := connectivity.ViewFromTuple(policyTupleForSession(value), value.SourceZone, value.DestinationZone)
	selection := connectivity.SelectInspection(program, view)
	if selection.Generation != r.runtime.CurrentGeneration() {
		r.stale.Add(1)
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		current, ok := r.runtime.Store.Get(value.SessionID)
		if !ok {
			return
		}
		expected := uint64(0)
		if current.Inspection != nil {
			expected = current.Inspection.Revision
		}
		reductionObservation := obs
		if reductionObservation.Alert != nil && !reductionObservation.Alert.InternalDiscovery && !attachThreat {
			reductionObservation.Alert = nil
		}
		reduction := ReduceInspection(current, selection, reductionObservation, time.Now().UTC())
		updated, err := r.runtime.Store.UpdateInspection(current.SessionID, current.Identity, selection.Generation, expected, reduction.Next)
		if errors.Is(err, session.ErrStaleInspection) {
			continue
		}
		if err != nil {
			return
		}
		for _, notification := range reduction.Notifications {
			notification.Revision = updated.Revision
			notification.InspectionRevision = updated.Inspection.Revision
			r.runtime.publish(notification)
		}
		for _, intent := range reduction.Intents {
			select {
			case r.intentQueue <- intent:
			case <-ctx.Done():
				return
			default:
				r.intentDrops.Add(1)
				r.completeIntent(intent, domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: intent.RequestedAction, Status: domain.EnforcementUnavailable, Reason: "inspection enforcement queue full", OperationID: intent.OperationID})
			}
		}
		return
	}
	r.stale.Add(1)
}

func (r *InspectionRuntime) intentWorker(ctx context.Context) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case intent := <-r.intentQueue:
			r.executeIntent(ctx, intent)
		}
	}
}

func (r *InspectionRuntime) executeIntent(parent context.Context, intent domain.InspectionIntent) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	// Serialize kernel guard IO with activation.  The preflight check binds the
	// intent to the exact session incarnation, inspection revision and current
	// policy generation before any nft mutation occurs.
	r.gate.RLock()
	current, ok := r.runtime.Store.Get(intent.SessionID)
	closedCleanup := intent.Kind == domain.IntentRemoveAppGuard && !ok
	if closedCleanup && r.runtime.Store.HasActiveKernelKey(intent.Identity) {
		// A newer incarnation now owns the same key visible to nftables. Its
		// guard must be allowed to expire or be managed by that live session.
		r.gate.RUnlock()
		r.stale.Add(1)
		return
	}
	if (!ok && !closedCleanup) || (ok && (!sameRuntimeIdentity(current.Identity, intent.Identity) || r.runtime.CurrentGeneration() != intent.Generation || current.Inspection == nil || current.Inspection.Revision != intent.ExpectedInspectionRevision)) {
		r.gate.RUnlock()
		r.stale.Add(1)
		return
	}
	if (intent.Kind == domain.IntentInstallAppGuard || intent.Kind == domain.IntentRenewAppGuard) && (current.Inspection.Mode != domain.InspectionModeIPS || current.Inspection.AppPolicyState != domain.AppPolicyMismatch) {
		r.gate.RUnlock()
		r.stale.Add(1)
		return
	}
	if !closedCleanup && (intent.Kind == domain.IntentInstallAppGuard || intent.Kind == domain.IntentRenewAppGuard) {
		if err := r.verifyKernelIdentity(ctx, intent.Identity); err != nil {
			r.gate.RUnlock()
			r.completeIntent(intent, domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: intent.RequestedAction, Status: domain.EnforcementUnavailable, Reason: "conntrack identity unavailable: " + err.Error(), OperationID: intent.OperationID})
			return
		}
	}
	r.mu.RLock()
	executor := r.executor
	r.mu.RUnlock()
	result := domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: intent.RequestedAction, Status: domain.EnforcementUnavailable, Reason: "inspection enforcement adapter unavailable", OperationID: intent.OperationID}
	if executor != nil {
		applied, err := executor.ExecuteInspectionIntent(ctx, intent)
		result = applied
		if err != nil && result.Reason == "" {
			result.Reason = err.Error()
			result.Status = domain.EnforcementFailed
		}
	}
	after, stillCurrent := r.runtime.Store.Get(intent.SessionID)
	validResult := closedCleanup || (stillCurrent && sameRuntimeIdentity(after.Identity, intent.Identity) && r.runtime.CurrentGeneration() == intent.Generation && after.Inspection != nil && after.Inspection.Revision == intent.ExpectedInspectionRevision)
	if !validResult && result.Status == domain.EnforcementApplied && (intent.Kind == domain.IntentInstallAppGuard || intent.Kind == domain.IntentRenewAppGuard) && executor != nil {
		cleanup := intent
		cleanup.Kind = domain.IntentRemoveAppGuard
		cleanup.RequestedAction = domain.DecisionAllow
		cleanup.OperationID += "-stale-cleanup"
		_, _ = executor.ExecuteInspectionIntent(ctx, cleanup)
	}
	r.gate.RUnlock()
	if !validResult {
		r.stale.Add(1)
		return
	}
	if closedCleanup {
		return
	}
	r.completeIntent(intent, result)
}

func (r *InspectionRuntime) completeIntent(intent domain.InspectionIntent, result domain.EnforcementResult) {
	r.gate.RLock()
	defer r.gate.RUnlock()
	current, ok := r.runtime.Store.Get(intent.SessionID)
	if !ok || !sameRuntimeIdentity(current.Identity, intent.Identity) || r.runtime.CurrentGeneration() != intent.Generation {
		return
	}
	if current.Inspection == nil {
		return
	}
	next := current.Inspection.Clone()
	next.Enforcement = result
	updated, err := r.runtime.Store.UpdateInspection(current.SessionID, current.Identity, intent.Generation, current.Inspection.Revision, next)
	if err != nil {
		return
	}
	if result.Status == domain.EnforcementApplied && intent.Kind != domain.IntentRenewAppGuard {
		reason := "application policy guard applied"
		if intent.Kind == domain.IntentRemoveAppGuard {
			reason = "application policy guard removed"
		}
		invalidated, _ := r.runtime.Store.Invalidate(current.SessionID, intent.Generation, reason, time.Now().UTC())
		if intent.Kind == domain.IntentRemoveAppGuard && invalidated.SessionID != "" {
			r.runtime.evaluateObserved(invalidated)
		}
	}
	r.runtime.publish(domain.RuntimeEvent{Kind: domain.EventInspectionStateChanged, Class: domain.EventClassInspection, SessionID: current.SessionID, Generation: intent.Generation, Revision: updated.Revision, InspectionRevision: updated.Inspection.Revision, Reason: result.Reason})
}

func (r *InspectionRuntime) verifyKernelIdentity(ctx context.Context, identity domain.ConntrackIdentity) error {
	if r == nil || r.runtime == nil || r.runtime.Source == nil {
		return errors.New("conntrack source unavailable")
	}
	_, err := r.runtime.Source.Get(ctx, conntrack.Identity{BootID: identity.BootID, NetworkNS: identity.NetworkNS, Zone: identity.Zone, Family: identity.Family, ID: identity.ID, KernelStart: identity.KernelStart, Original: identity.Original})
	return err
}

func sameRuntimeIdentity(a, b domain.ConntrackIdentity) bool {
	return a.BootID == b.BootID && a.NetworkNS == b.NetworkNS && a.Zone == b.Zone && a.Family == b.Family && a.ID == b.ID && a.KernelStart == b.KernelStart && a.Original == b.Original
}
func (r *InspectionRuntime) OnSessionChanged(value domain.RuntimeSession) {
	if r == nil || r.runtime == nil || value.SessionID == "" {
		return
	}
	change := sessionChange{sessionID: value.SessionID, identity: value.Identity}
	select {
	case r.sessionQueue <- change:
	default:
		r.sessionDrops.Add(1)
	}
}

func (r *InspectionRuntime) handleSessionChanged(change sessionChange) {
	if r == nil || r.runtime == nil || change.sessionID == "" {
		return
	}
	r.gate.RLock()
	defer r.gate.RUnlock()
	value, ok := r.runtime.Store.Get(change.sessionID)
	if !ok || !sameRuntimeIdentity(value.Identity, change.identity) {
		return
	}
	program := r.runtime.CurrentProgram()
	selection := connectivity.SelectInspection(program, connectivity.ViewFromTuple(policyTupleForSession(value), value.SourceZone, value.DestinationZone))
	if selection.Generation != r.runtime.CurrentGeneration() {
		return
	}
	current, ok := r.runtime.Store.Get(value.SessionID)
	if !ok || !sameRuntimeIdentity(current.Identity, value.Identity) {
		return
	}
	if current.Inspection != nil && current.Inspection.Generation == selection.Generation && current.Inspection.Mode == selection.Mode && current.Inspection.ProfileID == selection.ProfileID {
		return
	}
	expected := uint64(0)
	next := domain.DefaultSessionInspection()
	removeGuard := false
	installGuard := false
	if current.Inspection != nil {
		expected = current.Inspection.Revision
		next.Application = current.Inspection.Application.Clone()
		removeGuard = current.Inspection.Enforcement.Mechanism == domain.EnforcementNFTSessionGuard && current.Inspection.Enforcement.Status == domain.EnforcementApplied && current.Inspection.Enforcement.RequestedAction == domain.DecisionDrop
	}
	next.Generation, next.ProfileID, next.Mode = selection.Generation, selection.ProfileID, selection.Mode
	if selection.Mode == domain.InspectionModeOff {
		next.State, next.Coverage, next.AppPolicyState, next.Reason = domain.InspectionStateNotRequested, domain.CoverageNone, domain.AppPolicyNotApplicable, "policy does not select inspection"
	} else {
		next.State, next.Coverage = domain.InspectionStateQueued, domain.CoverageNone
		if len(selection.AllowedApps) == 0 {
			next.AppPolicyState, next.Reason = domain.AppPolicyNotApplicable, "policy has no application restriction"
		} else {
			deadline := time.Now().UTC().Add(r.appTimeout)
			next.AppDeadline = &deadline
			next.AppPolicyState, next.Reason = EvaluateAppRestriction(selection, next.Application, next.AppDeadline, time.Now().UTC())
			if next.AppPolicyState == domain.AppPolicyMismatch && selection.Mode == domain.InspectionModeIPS && strongApplication(next.Application) {
				removeGuard = false
				installGuard = current.Inspection == nil || current.Inspection.Enforcement.Mechanism != domain.EnforcementNFTSessionGuard || current.Inspection.Enforcement.Status != domain.EnforcementApplied
			}
		}
	}
	updated, err := r.runtime.Store.UpdateInspection(current.SessionID, current.Identity, selection.Generation, expected, next)
	if err != nil {
		return
	}
	r.runtime.publish(domain.RuntimeEvent{Kind: domain.EventInspectionStateChanged, Class: domain.EventClassInspection, SessionID: updated.SessionID, Generation: selection.Generation, Revision: updated.Revision, InspectionRevision: updated.Inspection.Revision, Reason: next.Reason})
	if removeGuard {
		intent := domain.InspectionIntent{Kind: domain.IntentRemoveAppGuard, OperationID: fmt.Sprintf("app-guard-remove-%s-%d", current.SessionID, updated.Inspection.Revision), SessionID: current.SessionID, Identity: current.Identity, Generation: selection.Generation, ExpectedInspectionRevision: updated.Inspection.Revision, RequestedAction: domain.DecisionAllow, Owner: "APP_POLICY", Reason: "application restriction no longer applies"}
		r.enqueueIntent(intent)
	}
	if installGuard {
		intent := domain.InspectionIntent{Kind: domain.IntentInstallAppGuard, OperationID: fmt.Sprintf("app-guard-install-%s-%d", current.SessionID, updated.Inspection.Revision), SessionID: current.SessionID, Identity: current.Identity, Generation: selection.Generation, ExpectedInspectionRevision: updated.Inspection.Revision, RequestedAction: domain.DecisionDrop, Owner: "APP_POLICY", Reason: "known application is outside policy allowlist"}
		r.enqueueIntent(intent)
	}
}

func (r *InspectionRuntime) OnSessionClosed(value domain.RuntimeSession) {
	if r == nil || value.Inspection == nil || value.Inspection.Enforcement.Mechanism != domain.EnforcementNFTSessionGuard || value.Inspection.Enforcement.Status != domain.EnforcementApplied {
		return
	}
	intent := domain.InspectionIntent{Kind: domain.IntentRemoveAppGuard, OperationID: "app-guard-close-" + value.SessionID, SessionID: value.SessionID, Identity: value.Identity, Generation: r.runtime.CurrentGeneration(), ExpectedInspectionRevision: value.Inspection.Revision, RequestedAction: domain.DecisionAllow, Owner: "APP_POLICY", Reason: "session closed"}
	// The worker recognizes REMOVE for an already-closed exact identity as a
	// cleanup operation. This keeps conntrack callbacks free of kernel IO.
	r.enqueueIntent(intent)
}

func (r *InspectionRuntime) enqueueIntent(intent domain.InspectionIntent) {
	select {
	case r.intentQueue <- intent:
	default:
		r.intentDrops.Add(1)
	}
}

func (r *InspectionRuntime) sweepAppDeadlines(now time.Time, budget int) {
	if r == nil || r.runtime == nil || budget <= 0 {
		return
	}
	values := r.runtime.Store.List()
	for _, current := range values {
		if budget == 0 {
			break
		}
		if current.Inspection == nil || current.Inspection.AppPolicyState != domain.AppPolicyPending || current.Inspection.AppDeadline == nil || now.Before(*current.Inspection.AppDeadline) {
			continue
		}
		budget--
		next := current.Inspection.Clone()
		next.AppPolicyState = domain.AppPolicyUnknownAllowed
		next.Reason = "application detection timeout; fail-open"
		updated, err := r.runtime.Store.UpdateInspection(current.SessionID, current.Identity, current.Inspection.Generation, current.Inspection.Revision, next)
		if err == nil {
			r.runtime.publish(domain.RuntimeEvent{Kind: domain.EventInspectionStateChanged, Class: domain.EventClassInspection, SessionID: updated.SessionID, Generation: next.Generation, Revision: updated.Revision, InspectionRevision: updated.Inspection.Revision, Reason: next.Reason})
		}
	}
}

func (r *InspectionRuntime) renewAppGuards(now time.Time, budget int) {
	if r == nil || r.runtime == nil || budget <= 0 {
		return
	}
	generation := r.runtime.CurrentGeneration()
	for _, current := range r.runtime.Store.List() {
		if budget == 0 {
			return
		}
		inspection := current.Inspection
		if inspection == nil || inspection.Generation != generation || inspection.Mode != domain.InspectionModeIPS || inspection.AppPolicyState != domain.AppPolicyMismatch || !strongApplication(inspection.Application) || inspection.Enforcement.Mechanism != domain.EnforcementNFTSessionGuard || inspection.Enforcement.Status != domain.EnforcementApplied {
			continue
		}
		budget--
		r.enqueueIntent(domain.InspectionIntent{Kind: domain.IntentRenewAppGuard, OperationID: fmt.Sprintf("app-guard-renew-%s-%d", current.SessionID, now.Unix()), SessionID: current.SessionID, Identity: current.Identity, Generation: generation, ExpectedInspectionRevision: inspection.Revision, RequestedAction: domain.DecisionDrop, Owner: "APP_POLICY", Reason: "renew active application policy guard"})
	}
}
func (r *InspectionRuntime) BeginActivation() {
	if r != nil {
		r.gate.Lock()
	}
}
func (r *InspectionRuntime) EndActivation() {
	if r != nil {
		r.gate.Unlock()
	}
}
func (r *InspectionRuntime) Health() map[string]inspection.SourceHealth {
	result := map[string]inspection.SourceHealth{}
	r.mu.RLock()
	for key, value := range r.health {
		result[key] = value
	}
	for _, source := range r.sources {
		snapshot := source.Snapshot()
		result[snapshot.SensorID] = snapshot
	}
	r.mu.RUnlock()
	return result
}

// CaptureLive asks the production sensor wrapper for current capture liveness.
// A plain file source deliberately cannot qualify an IPS lease: replaying EVE
// proves ingestion only, not that an NFQUEUE listener can return verdicts.
func (r *InspectionRuntime) CaptureLive(sensorID string, now time.Time) bool {
	if r == nil {
		return false
	}
	type captureLiveness interface{ CaptureLive(time.Time) bool }
	for _, source := range r.sources {
		snapshot := source.Snapshot()
		if snapshot.SensorID != sensorID {
			continue
		}
		live, ok := source.(captureLiveness)
		return ok && live.CaptureLive(now)
	}
	return false
}

// HasSource reports whether the configured coordinator owns the requested
// production sensor. It does not imply that the sensor is currently live.
func (r *InspectionRuntime) HasSource(sensorID string) bool {
	if r == nil {
		return false
	}
	for _, source := range r.sources {
		if source != nil && source.Snapshot().SensorID == sensorID {
			return true
		}
	}
	return false
}
func (r *InspectionRuntime) Stats() map[string]uint64 {
	result := map[string]uint64{"processed": r.processed.Load(), "duplicates": r.duplicates.Load(), "observation_drops": r.drops.Load(), "session_signal_drops": r.sessionDrops.Load(), "enforcement_drops": r.intentDrops.Load(), "stale_updates": r.stale.Load(), "queue_bytes": uint64(maxInt64(0, atomic.LoadInt64(&r.queueBytes))), "queue_items": uint64(len(r.queue)), "session_queue_items": uint64(len(r.sessionQueue)), "enforcement_queue_items": uint64(len(r.intentQueue))}
	for _, source := range r.Health() {
		for name, count := range source.ReaderStats {
			result[name] += count
		}
	}
	return result
}
func maxInt64(a, b int64) int64 {
	if b > a {
		return b
	}
	return a
}
func (r *InspectionRuntime) String() string {
	return fmt.Sprintf("inspection runtime processed=%d drops=%d", r.processed.Load(), r.drops.Load())
}
