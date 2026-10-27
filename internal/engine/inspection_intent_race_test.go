package engine

import (
	"context"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/session"
)

type inspectionExecutorFunc func(context.Context, domain.InspectionIntent) (domain.EnforcementResult, error)

func (f inspectionExecutorFunc) ExecuteInspectionIntent(ctx context.Context, intent domain.InspectionIntent) (domain.EnforcementResult, error) {
	return f(ctx, intent)
}

func TestAppGuardSurvivesMetadataBeforeAndDuringKernelIO(t *testing.T) {
	for _, phase := range []string{"queued", "in-flight", "superseded"} {
		t.Run(phase, func(t *testing.T) {
			source := conntrack.NewFakeSource(16)
			runtime := NewRuntime(source, m3RuntimeProgram(t), 1, session.RuntimeLimits{MaxSessions: 8})
			coordinator := NewInspectionRuntimeWithScope(runtime, domain.DefaultInspectionLimits(), nil, flow.Scope{NetworkNamespace: "init", ConntrackZone: 1})
			runtime.SetInspectionRuntime(coordinator)
			record := runtimeRecord(81)
			source.SetSnapshot(record)
			runtime.applyRecord(record, time.Now().UTC(), conntrack.EventNew, true)
			current := runtime.Store.List()[0]
			coordinator.handleSessionChanged(sessionChange{sessionID: current.SessionID, identity: current.Identity})
			now := time.Now().UTC()
			observation := inspection.Observation{ID: "ssh-discovery", Source: inspection.SourcePosition{SensorID: "ips", SensorEpoch: "epoch", Mode: domain.InspectionModeIPS}, Tuple: &record.OriginalTuple, ObservedAt: &now, IngestedAt: now, App: inspection.NormalizeApplication("SSH")}
			coordinator.HandleObservation(context.Background(), observation)
			var intent domain.InspectionIntent
			select {
			case intent = <-coordinator.intentQueue:
			default:
				t.Fatal("missing application guard intent")
			}
			metadata := func() {
				next := observation
				next.ID = "ssh-metadata"
				coordinator.HandleObservation(context.Background(), next)
			}
			if phase == "queued" {
				metadata()
			}
			calls := []domain.InspectionIntentKind{}
			coordinator.SetExecutor(inspectionExecutorFunc(func(_ context.Context, got domain.InspectionIntent) (domain.EnforcementResult, error) {
				calls = append(calls, got.Kind)
				if got.Kind == domain.IntentInstallAppGuard {
					if phase == "in-flight" {
						metadata()
					}
					if phase == "superseded" {
						value, _ := runtime.Store.Get(current.SessionID)
						next := value.Inspection.Clone()
						next.Application = inspection.NormalizeApplication("HTTP")
						next.AppPolicyState = domain.AppPolicyMatched
						next.Enforcement = domain.EnforcementResult{Mechanism: domain.EnforcementNone, Status: domain.EnforcementNotRequested}
						if _, err := runtime.Store.UpdateInspection(value.SessionID, value.Identity, 1, next.Revision, next); err != nil {
							t.Fatal(err)
						}
					}
				}
				return domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: got.RequestedAction, Status: domain.EnforcementApplied, OperationID: got.OperationID}, nil
			}))
			coordinator.executeIntent(context.Background(), intent)
			value, _ := runtime.Store.Get(current.SessionID)
			if phase == "superseded" {
				if len(calls) != 2 || calls[1] != domain.IntentRemoveAppGuard || value.EffectiveDecision == domain.DecisionDrop {
					t.Fatalf("superseded guard was not compensated: calls=%v inspection=%#v", calls, value.Inspection)
				}
				return
			}
			if len(calls) != 1 || value.Inspection.Enforcement.Status != domain.EnforcementApplied || value.EffectiveDecision != domain.DecisionDrop || value.Inspection.Enforcement.OperationID != intent.OperationID {
				t.Fatalf("metadata stranded a live guard: calls=%v inspection=%#v", calls, value.Inspection)
			}
			// A later packet alert must not erase an applied session guard.
			alert := observation
			alert.ID = "packet-alert"
			packetDrop := "drop"
			alert.Alert = &inspection.AlertObservation{SignatureAction: "blocked", PacketVerdict: &packetDrop}
			coordinator.HandleObservation(context.Background(), alert)
			value, _ = runtime.Store.Get(current.SessionID)
			if value.Inspection.Enforcement.Status != domain.EnforcementApplied || value.Inspection.Enforcement.OperationID != intent.OperationID || value.EffectiveDecision != domain.DecisionDrop {
				t.Fatalf("packet alert erased the session guard: %#v", value.Inspection)
			}
		})
	}
}
