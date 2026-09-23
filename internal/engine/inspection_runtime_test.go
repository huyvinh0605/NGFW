package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/session"
)

type recordingInspectionExecutor struct {
	mu      sync.Mutex
	intents []domain.InspectionIntent
}

func (e *recordingInspectionExecutor) ExecuteInspectionIntent(_ context.Context, intent domain.InspectionIntent) (domain.EnforcementResult, error) {
	e.mu.Lock()
	e.intents = append(e.intents, intent)
	e.mu.Unlock()
	now := time.Now().UTC()
	return domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: intent.RequestedAction, Status: domain.EnforcementApplied, Reason: intent.Reason, OperationID: intent.OperationID, ObservedAt: &now}, nil
}

func m3RuntimeProgram(t *testing.T) connectivity.Program {
	t.Helper()
	value := domain.Config{
		DefaultDeny: true,
		Inspection:  &domain.InspectionConfig{Enabled: true, Limits: domain.DefaultInspectionLimits()},
		Profiles:    []domain.SecurityProfile{{ID: "ips", IDSIPSEnabled: true, TLSMode: domain.TLSMetadata, Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIPS, FailMode: configpkg.InspectionFailOpen, RulesetID: configpkg.BuiltinM3RulesetID}}},
		Policies:    []domain.SecurityPolicy{{ID: "allow-http", Priority: 10, Services: []string{"tcp:443"}, Applications: []string{"HTTP"}, ApplicationMatchMode: configpkg.ApplicationMatchRestrictL3Allow, SecurityProfileID: "ips", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}},
	}
	program, err := connectivity.CompileM3(value, 1)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestInspectionRuntimeCorrelatesIntoSoleM2SessionAndAppliesGuard(t *testing.T) {
	source := conntrack.NewFakeSource(32)
	runtime := NewRuntime(source, m3RuntimeProgram(t), 1, session.RuntimeLimits{MaxSessions: 8, MaxEventQueue: 32})
	coordinator := NewInspectionRuntimeWithScope(runtime, domain.DefaultInspectionLimits(), nil, flow.Scope{NetworkNamespace: "init", ConntrackZone: 1})
	executor := &recordingInspectionExecutor{}
	coordinator.SetExecutor(executor)
	runtime.SetInspectionRuntime(coordinator)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := coordinator.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer coordinator.Stop()

	record := runtimeRecord(71)
	source.SetSnapshot(record)
	runtime.applyRecord(record, time.Now().UTC(), conntrack.EventNew, true)
	var items []domain.RuntimeSession
	initializationDeadline := time.Now().Add(time.Second)
	for time.Now().Before(initializationDeadline) {
		items = runtime.Store.List()
		if len(items) == 1 && items[0].Inspection != nil && items[0].Inspection.AppPolicyState == domain.AppPolicyPending {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(items) != 1 || items[0].Inspection == nil || items[0].Inspection.AppPolicyState != domain.AppPolicyPending {
		t.Fatalf("session inspection was not initialized: %#v", items)
	}
	now := time.Now().UTC()
	severity := 2
	observation := inspection.Observation{
		ID: "event-71", Source: inspection.SourcePosition{SensorID: "ips", SensorEpoch: "epoch-1", Mode: domain.InspectionModeIPS},
		Kind: "alert", ObservedAt: &now, IngestedAt: now, HasFlowID: true, FlowID: 9007199254740993,
		Tuple: &record.OriginalTuple, FlowTuple: &record.OriginalTuple,
		App:   domain.ApplicationIdentity{Name: "TLS", Source: domain.ApplicationSourceSuricataAppProto, Confidence: domain.ApplicationConfidenceHigh},
		Alert: &inspection.AlertObservation{SignatureID: 9900100, HasSignatureID: true, Signature: "safe marker", Severity: &severity},
	}
	coordinator.HandleObservation(ctx, observation)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		current, ok := runtime.Store.Get(items[0].SessionID)
		if ok && current.Inspection != nil && current.Inspection.Enforcement.Status == domain.EnforcementApplied {
			if current.Inspection.Application.Name != "TLS" || current.Inspection.AppPolicyState != domain.AppPolicyMismatch || current.EffectiveDecision != domain.DecisionDrop {
				t.Fatalf("unexpected inspection state: %#v", current.Inspection)
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	current, _ := runtime.Store.Get(items[0].SessionID)
	if current.Inspection == nil || current.Inspection.Enforcement.Status != domain.EnforcementApplied {
		t.Fatalf("guard result was not committed: %#v", current.Inspection)
	}
	if len(runtime.Store.List()) != 1 {
		t.Fatal("inspection created a second session")
	}
	coordinator.HandleObservation(ctx, observation)
	time.Sleep(20 * time.Millisecond)
	replayed, _ := runtime.Store.Get(items[0].SessionID)
	if replayed.Inspection == nil || replayed.Inspection.ThreatCount != 1 {
		t.Fatalf("replayed EVE record changed threat count: %#v", replayed.Inspection)
	}
	if coordinator.Stats()["duplicates"] != 1 {
		t.Fatalf("replayed physical record was not counted as a duplicate: %#v", coordinator.Stats())
	}
	page := coordinator.SecurityEvents().Query(domain.SecurityQuery{Limit: 10})
	if len(page.Items) != 1 || page.Items[0].SessionID != current.SessionID || page.Items[0].CorrelationState != domain.CorrelationCorrelated {
		t.Fatalf("security event was not correlated to the runtime session: %#v", page)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if len(executor.intents) != 1 || executor.intents[0].Kind != domain.IntentInstallAppGuard {
		t.Fatalf("unexpected intents: %#v", executor.intents)
	}
}

func TestInspectionRuntimeQueueIsBounded(t *testing.T) {
	limits := domain.DefaultInspectionLimits()
	limits.ObservationQueueItems = 1
	limits.ObservationQueueBytes = 64
	coordinator := NewInspectionRuntime(nil, limits, nil)
	large := inspection.Observation{ID: string(make([]byte, 128))}
	if coordinator.TrySubmit(large) {
		t.Fatal("oversized observation entered bounded queue")
	}
	if coordinator.Stats()["observation_drops"] != 1 {
		t.Fatalf("drop counter not updated: %#v", coordinator.Stats())
	}
}

func TestInspectionSessionCallbackDoesNotBlockConntrackDuringActivation(t *testing.T) {
	runtime := NewRuntime(nil, m3RuntimeProgram(t), 1, session.RuntimeLimits{MaxSessions: 8, MaxEventQueue: 8})
	coordinator := NewInspectionRuntime(runtime, domain.DefaultInspectionLimits(), nil)
	coordinator.BeginActivation()
	done := make(chan struct{})
	go func() {
		coordinator.OnSessionChanged(domain.RuntimeSession{SessionID: "new-during-activation"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		coordinator.EndActivation()
		t.Fatal("conntrack session callback blocked on the inspection activation gate")
	}
	coordinator.EndActivation()
}
