package engine

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

type Runtime struct {
	Store             *session.RuntimeStore
	Source            conntrack.Source
	Events            *RuntimeEventRing
	mu                sync.RWMutex
	program           connectivity.Program
	generation        uint64
	started           bool
	degraded          bool
	eventSourceFailed bool
	lastError         string
	blocks            map[string]domain.TemporaryBlock
	revoked           map[string]domain.RuntimeSession
	maxRevoked        int
	queue             chan conntrack.Event
	refreshSlots      chan struct{}
	dumpMu            sync.Mutex
	applyMu           sync.Mutex
	guardMu           sync.Mutex
	resyncing         bool
	runCtx            context.Context
	queueDrops        atomic.Uint64
	lossVersion       atomic.Uint64
	trackingDrops     atomic.Uint64
	created           atomic.Uint64
	updated           atomic.Uint64
	closed            atomic.Uint64
	resyncs           atomic.Uint64
	dumpIncomplete    atomic.Uint64
	lastDumpBytes     atomic.Uint64
	lastDumpMillis    atomic.Uint64
	getChecks         atomic.Uint64
	getUnavailable    atomic.Uint64
	expiryBacklog     atomic.Uint64
	expiryOldest      atomic.Uint64
	cancel            context.CancelFunc
	guards            GuardEnforcer
	resyncInterval    time.Duration
	inspection        *InspectionRuntime
}

const defaultRuntimeResyncInterval = 30 * time.Second

const (
	maxQueryCounterRefresh     = 8
	queryCounterRefreshTimeout = 750 * time.Millisecond
)

type GuardEnforcer interface {
	AddSourceBlock(context.Context, string, time.Time) error
	RemoveSourceBlock(context.Context, string) error
	RevokeSession(context.Context, domain.RuntimeSession) error
	ReleaseSession(context.Context, domain.RuntimeSession) error
}

func NewRuntime(source conntrack.Source, program connectivity.Program, generation uint64, limits session.RuntimeLimits) *Runtime {
	if generation == 0 {
		generation = program.Generation
	}
	program.Generation = generation
	store := session.NewRuntimeStore(limits)
	queueSize := limits.MaxEventQueue
	if queueSize <= 0 {
		queueSize = session.DefaultRuntimeLimits().MaxEventQueue
	}
	return &Runtime{Store: store, Source: source, Events: NewRuntimeEventRing(queueSize), program: program, generation: generation, blocks: map[string]domain.TemporaryBlock{}, revoked: map[string]domain.RuntimeSession{}, maxRevoked: 10000, queue: make(chan conntrack.Event, queueSize), refreshSlots: make(chan struct{}, 4), resyncInterval: defaultRuntimeResyncInterval}
}

// RefreshSessionCounters reads one exact kernel flow for an API query. Kernel
// events may omit counters and a short flow can finish before the next bounded
// dump. A failed or ambiguous Get leaves the tracked session partial; it is
// never evidence that the kernel flow has disappeared.
func (r *Runtime) RefreshSessionCounters(ctx context.Context, candidate domain.RuntimeSession) {
	if r == nil || r.Source == nil || candidate.Identity.ID == 0 || !candidate.Identity.Original.Valid() {
		return
	}
	select {
	case r.refreshSlots <- struct{}{}:
		defer func() { <-r.refreshSlots }()
	default:
		return
	}
	identity := candidate.Identity
	record, err := r.Source.Get(ctx, conntrack.Identity{
		BootID: identity.BootID, NetworkNS: identity.NetworkNS,
		Zone: identity.Zone, Family: identity.Family, ID: identity.ID,
		KernelStart: identity.KernelStart, Original: identity.Original,
	})
	if err != nil || ctx.Err() != nil ||
		record.Identity.BootID != identity.BootID || record.Identity.NetworkNS != identity.NetworkNS ||
		record.Identity.Zone != identity.Zone || record.Identity.Family != identity.Family ||
		record.Identity.Original != identity.Original || !record.Presence.ID || record.Identity.ID != identity.ID ||
		identity.KernelStart != 0 && (!record.Presence.Timestamp || record.Identity.KernelStart != identity.KernelStart) {
		return
	}
	// Events and dump cutovers remain serialized with this merge. Recheck the
	// incarnation after I/O so a late Get cannot recreate or overwrite a flow.
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	current, ok := r.Store.Get(candidate.SessionID)
	if !ok || current.Identity != identity ||
		!record.ObservedAt.IsZero() && current.LastObservedAt.After(record.ObservedAt) {
		return
	}
	r.applyRecord(record, time.Now().UTC(), conntrack.EventUpdate, false)
}

// RefreshPageCounters bounds both the number of targeted Get calls and their
// total wait. Other page items retain their explicit quality metadata.
func (r *Runtime) RefreshPageCounters(ctx context.Context, items []domain.RuntimeSession) {
	if r == nil || r.Source == nil || len(items) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, queryCounterRefreshTimeout)
	defer cancel()
	for i, item := range items {
		if i >= maxQueryCounterRefresh || ctx.Err() != nil {
			return
		}
		r.RefreshSessionCounters(ctx, item)
	}
}

type runtimeSink struct{ r *Runtime }

func (s runtimeSink) TryEnqueue(ev conntrack.Event) bool {
	select {
	case s.r.queue <- ev:
		return true
	default:
		s.r.queueDrops.Add(1)
		s.r.lossVersion.Add(1)
		return false
	}
}
func (s runtimeSink) ReportLoss(loss conntrack.Loss) {
	s.r.lossVersion.Add(1)
	s.r.mu.Lock()
	s.r.degraded = true
	s.r.lastError = loss.Reason
	if loss.Fatal {
		s.r.eventSourceFailed = true
	}
	shouldResync := s.r.started && !s.r.resyncing && s.r.Source != nil
	if shouldResync {
		s.r.resyncing = true
	}
	runCtx := s.r.runCtx
	source := s.r.Source
	s.r.mu.Unlock()
	s.r.trackingDrops.Add(loss.Count)
	if shouldResync {
		go s.r.resync(source, runCtx)
	}
}

func (r *Runtime) Start(ctx context.Context) error {
	if r == nil || r.Source == nil {
		return errors.New("M2 runtime conntrack source is not configured")
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.started = true
	r.eventSourceFailed = false
	r.resyncing = true // initial snapshot is itself a resync cutover
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.runCtx = runCtx
	r.mu.Unlock()
	if err := r.Source.Subscribe(runCtx, runtimeSink{r: r}); err != nil {
		r.setDegraded(err)
		r.mu.Lock()
		r.started = false
		r.resyncing = false
		r.runCtx = nil
		r.cancel = nil
		r.mu.Unlock()
		cancel()
		return err
	}
	limits := r.dumpLimits()
	dumpStarted := time.Now().UTC()
	seen := make([]domain.ConntrackIdentity, 0)
	r.resyncs.Add(1)
	lossBefore := r.lossVersion.Load()
	// Serialize snapshot merge with queued event application. The bounded
	// source queue can report loss while this lock is held, but a complete dump
	// remains the cutover view and the queue is replayed immediately afterward.
	r.applyMu.Lock()
	r.dumpMu.Lock()
	dumpResult, dumpErr := r.Source.Dump(runCtx, limits, func(record conntrack.Record) error {
		seen = append(seen, record.Identity)
		r.applyRecord(record, time.Now().UTC(), conntrack.EventNew, true)
		return nil
	})
	r.dumpMu.Unlock()
	r.applyMu.Unlock()
	r.recordDump(dumpResult, dumpStarted)
	if dumpErr == nil && !dumpResult.Complete {
		dumpErr = conntrack.ErrDumpIncomplete
	}
	if dumpErr == nil && lossBefore != r.lossVersion.Load() {
		dumpErr = conntrack.ErrDumpIncomplete
		r.dumpIncomplete.Add(1)
	}
	if dumpErr != nil {
		r.setDegraded(dumpErr)
		// Keep the event subscription alive. A bounded/incomplete initial
		// dump degrades the session view but must not turn tracking into a
		// forwarding dependency; later events can still populate new flows and
		// a loss report will schedule another bounded resync.
		go r.consume(runCtx)
		go r.periodicResync(runCtx)
		go r.verifyExpiryLoop(runCtx)
		r.mu.Lock()
		r.resyncing = false
		r.mu.Unlock()
		return nil
	}
	r.reconcileMissing(seen, dumpStarted, time.Now().UTC(), "conntrack resync no longer contains flow")
	go r.consume(runCtx)
	go r.periodicResync(runCtx)
	go r.verifyExpiryLoop(runCtx)
	r.mu.Lock()
	r.resyncing = false
	r.mu.Unlock()
	return nil
}

// periodicResync refreshes fields which netlink UPDATE notifications are
// allowed to omit, especially packet/byte counters. The bounded kernel dump
// is advisory runtime telemetry and never becomes a forwarding dependency.
func (r *Runtime) periodicResync(ctx context.Context) {
	interval := r.resyncInterval
	if interval <= 0 {
		interval = defaultRuntimeResyncInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			if !r.started || r.resyncing || r.Source == nil {
				r.mu.Unlock()
				continue
			}
			r.resyncing = true
			source := r.Source
			parent := r.runCtx
			r.mu.Unlock()
			go r.resync(source, parent)
		}
	}
}

func (r *Runtime) resync(source conntrack.Source, parent context.Context) {
	if parent == nil {
		parent = context.Background()
	}
	defer func() {
		r.mu.Lock()
		r.resyncing = false
		r.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	dumpStarted := time.Now().UTC()
	seen := make([]domain.ConntrackIdentity, 0)
	r.resyncs.Add(1)
	lossBefore := r.lossVersion.Load()
	r.applyMu.Lock()
	r.dumpMu.Lock()
	result, err := source.Dump(ctx, r.dumpLimits(), func(record conntrack.Record) error {
		seen = append(seen, record.Identity)
		r.applyRecord(record, time.Now().UTC(), conntrack.EventUpdate, false)
		return nil
	})
	r.dumpMu.Unlock()
	r.recordDump(result, dumpStarted)
	if err == nil && !result.Complete {
		err = conntrack.ErrDumpIncomplete
	}
	if err == nil && lossBefore != r.lossVersion.Load() {
		err = conntrack.ErrDumpIncomplete
		r.dumpIncomplete.Add(1)
	}
	if err != nil {
		r.applyMu.Unlock()
		r.setDegraded(err)
		return
	}
	r.reconcileMissing(seen, dumpStarted, time.Now().UTC(), "conntrack resync no longer contains flow")
	r.applyMu.Unlock()
	r.mu.Lock()
	if !r.eventSourceFailed {
		r.degraded = false
		r.lastError = ""
	}
	r.mu.Unlock()
}

func (r *Runtime) recordDump(result conntrack.DumpResult, started time.Time) {
	r.lastDumpBytes.Store(uint64(result.Bytes))
	r.lastDumpMillis.Store(uint64(time.Since(started) / time.Millisecond))
	if !result.Complete {
		r.dumpIncomplete.Add(1)
	}
}

// verifyExpiryLoop probes only a bounded number of due flows at a bounded
// rate. Conntrack calls run outside the store and apply locks. An estimated
// timeout is never itself a reason to close a live session.
func (r *Runtime) verifyExpiryLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.Store.PruneClosed(now)
			candidates, backlog, oldest := r.Store.ExpiredCandidates(now, 32)
			r.expiryBacklog.Store(uint64(backlog))
			r.expiryOldest.Store(uint64(oldest / time.Second))
			if len(candidates) == 0 {
				continue
			}
			work := make(chan domain.RuntimeSession, len(candidates))
			for _, candidate := range candidates {
				work <- candidate
			}
			close(work)
			var workers sync.WaitGroup
			for i := 0; i < 4; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					for candidate := range work {
						if ctx.Err() != nil {
							return
						}
						r.verifyExpiredCandidate(ctx, candidate)
					}
				}()
			}
			workers.Wait()
		}
	}
}

func (r *Runtime) verifyExpiredCandidate(parent context.Context, candidate domain.RuntimeSession) {
	if r.Source == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 1500*time.Millisecond)
	defer cancel()
	r.getChecks.Add(1)
	record, err := r.Source.Get(ctx, conntrack.Identity{
		BootID: candidate.Identity.BootID, NetworkNS: candidate.Identity.NetworkNS,
		Zone: candidate.Identity.Zone, Family: candidate.Identity.Family,
		ID: candidate.Identity.ID, KernelStart: candidate.Identity.KernelStart,
		Original: candidate.Identity.Original,
	})
	if parent.Err() != nil {
		return
	}
	if err == nil && (record.Identity.Zone != candidate.Identity.Zone ||
		record.Identity.Family != candidate.Identity.Family ||
		record.Identity.Original != candidate.Identity.Original ||
		candidate.Identity.ID != 0 && record.Identity.ID != candidate.Identity.ID ||
		candidate.Identity.KernelStart != 0 && record.Identity.KernelStart != candidate.Identity.KernelStart ||
		candidate.Identity.BootID != "" && record.Identity.BootID != candidate.Identity.BootID ||
		candidate.Identity.NetworkNS != "" && record.Identity.NetworkNS != candidate.Identity.NetworkNS) {
		err = conntrack.ErrAmbiguousIdentity
	}
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	now := time.Now().UTC()
	if !r.Store.ExpiryCandidateCurrent(candidate, now) {
		return
	}
	switch {
	case err == nil && record.Presence.Timeout && record.Timeout > 0:
		r.applyRecord(record, now, conntrack.EventUpdate, false)
	case errors.Is(err, conntrack.ErrFlowNotFound):
		if closed, ok := r.Store.CloseVerifiedExpired(candidate, now); ok {
			r.releaseClosedSession(closed, "verified conntrack expiry")
		}
	default:
		r.getUnavailable.Add(1)
		reason := "conntrack expiry verification unavailable"
		if err == nil {
			reason = "conntrack Get omitted remaining timeout"
		}
		r.Store.DeferExpired(candidate, now, reason)
		r.setDegraded(errors.New(reason))
	}
}

func (r *Runtime) reconcileMissing(seen []domain.ConntrackIdentity, before, now time.Time, reason string) {
	removed := r.Store.ReconcileMissing(seen, before, now, reason)
	for _, value := range removed {
		r.releaseClosedSession(value, reason)
	}
}

func (r *Runtime) dumpLimits() conntrack.DumpLimits {
	maxRecords := r.Store.Capacity()
	if maxRecords <= 0 {
		maxRecords = 200000
	}
	maxBytes := int64(maxRecords) * 2048
	if maxBytes < 64<<20 {
		maxBytes = 64 << 20
	}
	return conntrack.DumpLimits{MaxRecords: maxRecords, MaxBytes: maxBytes, Deadline: 30 * time.Second}
}

func (r *Runtime) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-r.queue:
			r.applyEvent(ev)
		}
	}
}

func (r *Runtime) applyEvent(ev conntrack.Event) {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	if ev.Kind == conntrack.EventDestroy {
		if closed, ok := r.Store.Close(ev.Record.Identity, "conntrack destroy", eventTime(ev.Received)); ok {
			r.releaseClosedSession(closed, "conntrack destroy")
		}
		return
	}
	// LastObservedAt is a local cutover marker, not a kernel timestamp. An
	// event replayed after a dump must survive the missing-session sweep even
	// when its source-provided Received field is delayed or synthetic.
	r.applyRecord(ev.Record, time.Now().UTC(), ev.Kind, true)
}

func (r *Runtime) releaseClosedSession(value domain.RuntimeSession, reason string) {
	r.mu.RLock()
	guards := r.guards
	r.mu.RUnlock()
	r.mu.Lock()
	_, trackedRevoked := r.revoked[value.SessionID]
	delete(r.revoked, value.SessionID)
	r.mu.Unlock()
	if guards != nil && (value.Revoked || trackedRevoked) {
		r.guardMu.Lock()
		if !r.Store.HasActiveRevokedConntrackID(value.Identity.ID) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = guards.ReleaseSession(ctx, value)
			cancel()
		}
		r.guardMu.Unlock()
	}
	r.closed.Add(1)
	r.publish(domain.RuntimeEvent{Kind: domain.EventSessionClosed, SessionID: value.SessionID, Reason: reason})
	r.mu.RLock()
	inspectionRuntime := r.inspection
	r.mu.RUnlock()
	if inspectionRuntime != nil {
		inspectionRuntime.OnSessionClosed(value)
	}
}

func (r *Runtime) SetInspectionRuntime(value *InspectionRuntime) {
	r.mu.Lock()
	if value == nil {
		r.Store.SetInspectionHistoryLimits(0, 0)
	} else {
		r.Store.SetInspectionHistoryLimits(value.recentSessions, value.recentSessionTTL)
	}
	r.inspection = value
	r.mu.Unlock()
}
func (r *Runtime) InspectionRuntime() *InspectionRuntime {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.inspection
}

func (r *Runtime) SetGuardEnforcer(guards GuardEnforcer) {
	r.mu.Lock()
	r.guards = guards
	r.mu.Unlock()
}

func eventTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

func (r *Runtime) applyRecord(record conntrack.Record, now time.Time, kind conntrack.EventKind, publishUpdate bool) {
	v, created, changed, err := r.Store.ApplyObserved(record, now)
	if err != nil {
		if errors.Is(err, session.ErrStaleEvent) {
			r.trackingDrops.Add(1)
			return
		}
		if errors.Is(err, session.ErrRuntimeCapacity) {
			// RuntimeStore increments its bounded-capacity counter. Keep
			// this path out of the event-drop counter.
		}
		r.setDegraded(err)
		return
	}
	r.mu.RLock()
	program := r.program
	r.mu.RUnlock()
	if sourceZone, destinationZone := inferSessionZones(program, v); sourceZone != "" || destinationZone != "" {
		if enriched, enrichErr := r.Store.SetZones(v.SessionID, sourceZone, destinationZone); enrichErr == nil {
			changed = changed || enriched.Revision != v.Revision
			v = enriched
		}
	}
	if created {
		r.created.Add(1)
		r.publish(domain.RuntimeEvent{Kind: domain.EventSessionCreated, SessionID: v.SessionID, Revision: v.Revision})
	} else if publishUpdate && changed {
		r.updated.Add(1)
		r.publish(domain.RuntimeEvent{Kind: domain.EventSessionUpdated, SessionID: v.SessionID, Revision: v.Revision, Reason: string(kind)})
	}
	// A repeated snapshot is observation, not a retry trigger for an
	// invalidated or unavailable decision. A live event may retry it.
	if created || changed || v.PolicyGeneration != r.CurrentGeneration() ||
		publishUpdate && v.CacheState != domain.CacheCached {
		r.evaluateObserved(v)
	}
	r.mu.RLock()
	inspectionRuntime := r.inspection
	r.mu.RUnlock()
	if inspectionRuntime != nil && (created || changed) {
		inspectionRuntime.OnSessionChanged(v)
	}
}

// evaluateObserved records the connectivity decision associated with a
// kernel-observed session. Local INPUT/OUTPUT traffic is tracked for
// diagnostics but is outside the forward policy path, so it must remain
// explicitly unavailable instead of receiving the default forward verdict.
func (r *Runtime) evaluateObserved(value domain.RuntimeSession) {
	if value.SourceZone == connectivity.ZoneLocal || value.DestinationZone == connectivity.ZoneLocal {
		generation := r.CurrentGeneration()
		updated, err := r.Store.MarkEvaluationUnavailable(value.SessionID, generation, "local traffic is outside the M2 forward-policy path")
		if err == nil && updated.Revision != value.Revision {
			r.publish(domain.RuntimeEvent{Kind: domain.EventDecisionChanged, SessionID: value.SessionID, Generation: generation, Revision: updated.Revision, Reason: updated.DecisionReason})
		}
		return
	}
	if _, err := r.Evaluate(value.SessionID); err != nil && !errors.Is(err, session.ErrSessionMissing) && !errors.Is(err, session.ErrStaleDecision) {
		r.trackingDrops.Add(1)
		r.setDegraded(err)
	}
}

func (r *Runtime) setDegraded(err error) {
	r.mu.Lock()
	r.degraded = true
	r.lastError = err.Error()
	r.mu.Unlock()
}
func (r *Runtime) publish(ev domain.RuntimeEvent) { r.Events.Publish(ev) }
func (r *Runtime) CurrentProgram() connectivity.Program {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.program.Clone()
}
func (r *Runtime) CurrentGeneration() uint64 { r.mu.RLock(); defer r.mu.RUnlock(); return r.generation }

func (r *Runtime) Activate(program connectivity.Program, generation uint64, reason string) error {
	inspectionRuntime := r.InspectionRuntime()
	if inspectionRuntime != nil {
		inspectionRuntime.BeginActivation()
	}
	changed, err := r.activateWhileInspectionPaused(program, generation, reason)
	if inspectionRuntime != nil {
		inspectionRuntime.EndActivation()
		for _, value := range changed {
			inspectionRuntime.OnSessionChanged(value)
		}
	}
	return err
}

// activateWhileInspectionPaused publishes a new connectivity generation while
// the caller owns the current inspection runtime's activation gate. The
// management activation path uses this form so the same gate spans Linux
// network/nft mutation and the in-memory generation cutover. Conntrack event
// ingestion remains independent and may queue while the short cutover runs.
func (r *Runtime) activateWhileInspectionPaused(program connectivity.Program, generation uint64, reason string) ([]domain.RuntimeSession, error) {
	if generation == 0 {
		return nil, errors.New("policy generation must be non-zero")
	}
	r.mu.Lock()
	if generation <= r.generation {
		r.mu.Unlock()
		return nil, errors.New("policy generation must increase")
	}
	r.program = program
	r.program.Generation = generation
	r.generation = generation
	r.mu.Unlock()
	changed := make([]domain.RuntimeSession, 0)
	for _, current := range r.Store.List() {
		if current.Revoked {
			continue
		}
		sourceZone, destinationZone := inferSessionZones(program, current)
		if enriched, enrichErr := r.Store.SetZones(current.SessionID, sourceZone, destinationZone); enrichErr == nil {
			current = enriched
		}
		if v, err := r.Store.Invalidate(current.SessionID, generation, reason, time.Now().UTC()); err == nil {
			r.publish(domain.RuntimeEvent{Kind: domain.EventSessionInvalidated, SessionID: current.SessionID, Generation: generation, Revision: v.Revision, Reason: reason})
			if current.SourceZone == connectivity.ZoneLocal || current.DestinationZone == connectivity.ZoneLocal {
				r.evaluateObserved(v)
			}
			changed = append(changed, v)
		}
	}
	return changed, nil
}

func inferSessionZones(program connectivity.Program, value domain.RuntimeSession) (string, string) {
	policyTuple := policyTupleForSession(value)
	sourceZone, destinationZone := program.InferZones(policyTuple)
	// Conntrack reports the original direction and the reply direction, but it
	// does not reliably expose ingress/egress interface names. For DNAT, the
	// original destination is the public/VIP address while the post-translation
	// destination identifies the actual destination zone. Keep the source from
	// the original tuple and use the translated destination only when the
	// adapter has evidence that DNAT occurred.
	if value.NAT.DNAT && value.TranslatedTuple != nil {
		if inferred := program.InferAddressZone(value.TranslatedTuple.DstIP); inferred != "" {
			destinationZone = inferred
		}
	}
	if sourceZone == "" {
		sourceZone = connectivity.ZoneUnknown
	}
	if destinationZone == "" {
		destinationZone = connectivity.ZoneUnknown
	}
	return sourceZone, destinationZone
}

// policyTupleForSession mirrors the tuple seen by the nft forward filter:
// SNAT has not happened yet, while DNAT has already changed the destination.
// Keeping this normalization in the runtime evaluator prevents a DNAT rule
// from matching the public VIP/port while the kernel evaluates the DMZ
// address/port.
func policyTupleForSession(value domain.RuntimeSession) domain.Tuple {
	if !value.NAT.DNAT || value.TranslatedTuple == nil {
		return value.OriginalTuple
	}
	translated := *value.TranslatedTuple
	translated.SrcIP = value.OriginalTuple.SrcIP
	translated.SrcPort = value.OriginalTuple.SrcPort
	return translated
}

func (r *Runtime) Evaluate(sessionID string) (domain.PolicyDecision, error) {
	return r.evaluate(sessionID, 0)
}

func (r *Runtime) evaluate(sessionID string, retry int) (domain.PolicyDecision, error) {
	v, ok := r.Store.Get(sessionID)
	if !ok {
		return domain.PolicyDecision{}, session.ErrSessionMissing
	}
	r.mu.RLock()
	program, generation := r.program, r.generation
	_, blocked := r.blocks[v.OriginalTuple.SrcIP.String()]
	_, revoked := r.revoked[sessionID]
	degraded := r.degraded
	r.mu.RUnlock()
	if blocked {
		d := domain.PolicyDecision{Action: domain.DecisionDrop, Scope: "SOURCE", ConfigVersion: generation, Reason: "temporary block overrides cached allow"}
		updated, err := r.Store.SetDecision(sessionID, generation, d.Action, "", d.Reason)
		if err != nil {
			return d, err
		}
		r.publish(domain.RuntimeEvent{Kind: domain.EventDecisionChanged, SessionID: sessionID, Generation: generation, Revision: updated.Revision, Reason: d.Reason})
		return d, nil
	}
	if revoked {
		return domain.PolicyDecision{Action: domain.DecisionDrop, Scope: "SESSION", ConfigVersion: generation, Reason: "session revoked"}, nil
	}
	if v.CacheState == domain.CacheCached && v.PolicyGeneration == generation && !degraded && !v.Revoked {
		r.mu.RLock()
		generationStillCurrent := r.generation == generation
		r.mu.RUnlock()
		if !generationStillCurrent && retry < 2 {
			return r.evaluate(sessionID, retry+1)
		}
		return domain.PolicyDecision{Action: v.Decision, Scope: "SESSION", PolicyID: v.MatchedPolicyID, ConfigVersion: generation, Reason: "cached decision"}, nil
	}
	view := connectivity.ViewFromTuple(policyTupleForSession(v), v.SourceZone, v.DestinationZone)
	match := program.Evaluate(view)
	decision := domain.PolicyDecision{Action: match.Action, Scope: "SESSION", PolicyID: match.PolicyID, ConfigVersion: generation, Reason: match.Reason}
	updated, err := r.Store.SetDecisionIfCurrent(sessionID, v.Revision, generation, decision.Action, decision.PolicyID, decision.Reason)
	if err != nil {
		if errors.Is(err, session.ErrStaleDecision) && retry < 2 {
			return r.evaluate(sessionID, retry+1)
		}
		return decision, err
	}
	if updated.Revision > 0 {
		r.publish(domain.RuntimeEvent{Kind: domain.EventDecisionChanged, SessionID: sessionID, Generation: generation, Revision: updated.Revision, Reason: decision.Reason})
	}
	return decision, nil
}

func (r *Runtime) Invalidate(id, reason string) error {
	generation := r.CurrentGeneration()
	v, err := r.Store.Invalidate(id, generation, reason, time.Now().UTC())
	if err == nil {
		r.publish(domain.RuntimeEvent{Kind: domain.EventSessionInvalidated, SessionID: id, Generation: generation, Revision: v.Revision, Reason: reason})
	}
	return err
}

func (r *Runtime) InvalidateAll(reason string) error {
	var first error
	for _, current := range r.Store.List() {
		if err := r.Invalidate(current.SessionID, reason); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (r *Runtime) Revoke(id, reason string) error {
	return r.RevokeContext(context.Background(), id, reason)
}

func (r *Runtime) RevokeContext(ctx context.Context, id, reason string) error {
	v, ok := r.Store.Get(id)
	if !ok {
		return session.ErrSessionMissing
	}
	r.guardMu.Lock()
	defer r.guardMu.Unlock()
	r.mu.RLock()
	guards := r.guards
	r.mu.RUnlock()
	if guards != nil {
		if err := guards.RevokeSession(ctx, v); err != nil {
			return err
		}
	}
	r.mu.Lock()
	if r.maxRevoked <= 0 {
		r.maxRevoked = 10000
	}
	var evicted *domain.RuntimeSession
	if len(r.revoked) >= r.maxRevoked {
		for revokedID, old := range r.revoked {
			delete(r.revoked, revokedID)
			copy := old.Clone()
			evicted = &copy
			break
		}
	}
	r.revoked[id] = v
	guards = r.guards
	r.mu.Unlock()
	if evicted != nil && guards != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = guards.ReleaseSession(cleanupCtx, *evicted)
		cancel()
	}
	currentGeneration := r.CurrentGeneration()
	if _, err := r.Store.MarkRevoked(id, currentGeneration, reason); err != nil {
		r.mu.Lock()
		delete(r.revoked, id)
		r.mu.Unlock()
		if guards != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = guards.ReleaseSession(cleanupCtx, v)
			cancel()
		}
		return err
	}
	r.publish(domain.RuntimeEvent{Kind: domain.EventSessionInvalidated, SessionID: v.SessionID, Generation: currentGeneration, Reason: reason})
	r.publish(domain.RuntimeEvent{Kind: domain.EventDecisionChanged, SessionID: v.SessionID, Generation: currentGeneration, Reason: "revoked"})
	return nil
}
func (r *Runtime) AddTemporaryBlock(block domain.TemporaryBlock) error {
	return r.AddTemporaryBlockContext(context.Background(), block)
}

func (r *Runtime) AddTemporaryBlockContext(ctx context.Context, block domain.TemporaryBlock) error {
	if strings.TrimSpace(block.Indicator) == "" {
		return errors.New("block indicator is required")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(block.Indicator))
	if err != nil || !address.Is4() {
		return errors.New("temporary block indicator must be an IPv4 address")
	}
	block.Indicator = address.String()
	if block.ExpiresAt.IsZero() {
		block.ExpiresAt = time.Now().Add(5 * time.Minute)
	}
	if !block.ExpiresAt.After(time.Now()) {
		return errors.New("temporary block is already expired")
	}
	r.mu.Lock()
	if _, exists := r.blocks[block.Indicator]; !exists && len(r.blocks) >= 10000 {
		r.mu.Unlock()
		return errors.New("temporary block capacity reached")
	}
	r.blocks[block.Indicator] = block
	guards := r.guards
	r.mu.Unlock()
	if guards != nil {
		if err := guards.AddSourceBlock(ctx, block.Indicator, block.ExpiresAt); err != nil {
			r.mu.Lock()
			if current, exists := r.blocks[block.Indicator]; exists && current.ID == block.ID && current.ExpiresAt.Equal(block.ExpiresAt) {
				delete(r.blocks, block.Indicator)
			}
			r.mu.Unlock()
			return err
		}
	}
	for _, current := range r.Store.List() {
		if strings.EqualFold(current.OriginalTuple.SrcIP.String(), block.Indicator) {
			if err := r.Invalidate(current.SessionID, "temporary block"); err == nil {
				r.evaluateObserved(current)
			}
		}
	}
	return nil
}
func (r *Runtime) RemoveTemporaryBlock(indicator string) {
	_ = r.RemoveTemporaryBlockContext(context.Background(), indicator)
}

func (r *Runtime) RemoveTemporaryBlockContext(ctx context.Context, indicator string) error {
	if address, err := netip.ParseAddr(strings.TrimSpace(indicator)); err == nil && address.Is4() {
		indicator = address.String()
	}
	r.mu.RLock()
	guards := r.guards
	key := indicator
	if _, ok := r.blocks[indicator]; !ok {
		for candidate, value := range r.blocks {
			if value.ID == indicator {
				key = candidate
				break
			}
		}
	}
	r.mu.RUnlock()
	if guards != nil {
		if err := guards.RemoveSourceBlock(ctx, key); err != nil {
			return err
		}
	}
	r.mu.Lock()
	delete(r.blocks, key)
	r.mu.Unlock()
	r.reevaluateSource(key, "temporary block removed")
	return nil
}
func (r *Runtime) SweepBlocks(now time.Time) {
	r.mu.Lock()
	guards := r.guards
	expired := make([]string, 0)
	for k, v := range r.blocks {
		if !v.ExpiresAt.After(now) {
			delete(r.blocks, k)
			expired = append(expired, k)
		}
	}
	r.mu.Unlock()
	if guards != nil {
		for _, indicator := range expired {
			_ = guards.RemoveSourceBlock(context.Background(), indicator)
		}
	}
	for _, indicator := range expired {
		r.reevaluateSource(indicator, "temporary block expired")
	}
}

func (r *Runtime) reevaluateSource(indicator, reason string) {
	for _, current := range r.Store.List() {
		if current.Revoked {
			continue
		}
		if !strings.EqualFold(current.OriginalTuple.SrcIP.String(), indicator) {
			continue
		}
		if err := r.Invalidate(current.SessionID, reason); err == nil {
			r.evaluateObserved(current)
		}
	}
}
func (r *Runtime) Blocks() []domain.TemporaryBlock {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.TemporaryBlock, 0, len(r.blocks))
	now := time.Now()
	for _, block := range r.blocks {
		if block.ExpiresAt.After(now) {
			out = append(out, block)
		}
	}
	return out
}
func (r *Runtime) Stats() session.RuntimeStats {
	stats := r.Store.Stats()
	stats.EventDrops += r.Events.Dropped() + r.queueDrops.Load()
	stats.TrackingDrops += r.trackingDrops.Load()
	stats.Created = r.created.Load()
	stats.Closed = r.closed.Load()
	stats.Resyncs = r.resyncs.Load()
	stats.DumpIncomplete = r.dumpIncomplete.Load()
	stats.LastDumpBytes = r.lastDumpBytes.Load()
	stats.LastDumpMillis = r.lastDumpMillis.Load()
	stats.GetChecks = r.getChecks.Load()
	stats.GetUnavailable = r.getUnavailable.Load()
	stats.ExpiryBacklog = r.expiryBacklog.Load()
	stats.ExpiryOldestSeconds = r.expiryOldest.Load()
	return stats
}
func (r *Runtime) Health() (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.Source == nil {
		return false, "conntrack source unavailable"
	}
	if !r.started {
		return false, "conntrack runtime not started"
	}
	return !r.degraded, r.lastError
}
func (r *Runtime) Stop() error {
	r.mu.Lock()
	cancel := r.cancel
	r.cancel = nil
	r.started = false
	r.runCtx = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if r.Source != nil {
		return r.Source.Close()
	}
	return nil
}
