package session

import (
	"errors"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
)

func TestUpdateInspectionUsesIndependentRevisionAndKeepsCounters(t *testing.T) {
	store := NewRuntimeStore(DefaultRuntimeLimits())
	record := testRecord()
	created, _, err := store.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	next := domain.DefaultSessionInspection()
	next.Generation = 0
	next.Mode = domain.InspectionModeIDS
	next.State = domain.InspectionStateInspecting
	updated, err := store.UpdateInspection(created.SessionID, created.Identity, 0, 0, next)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Inspection == nil || updated.Inspection.Revision != 1 || updated.PacketsOriginal != created.PacketsOriginal {
		t.Fatalf("bad update: %#v", updated)
	}
	// A conntrack counter revision must not invalidate the inspection CAS.
	record.PacketsOriginal++
	if _, _, err := store.Apply(record, time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	next = updated.Inspection.Clone()
	if _, err := store.UpdateInspection(created.SessionID, created.Identity, 0, 1, next); err != nil {
		t.Fatalf("counter update broke inspection CAS: %v", err)
	}
}

func TestHasActiveKernelKeyIgnoresKernelStartButScopesFullTuple(t *testing.T) {
	store := NewRuntimeStore(RuntimeLimits{MaxSessions: 8})
	record := testRecord()
	current, _, err := store.Apply(record, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reused := current.Identity
	reused.KernelStart++
	if !store.HasActiveKernelKey(reused) {
		t.Fatal("reused kernel-visible guard key was not detected")
	}
	reused.Original.SrcPort++
	if store.HasActiveKernelKey(reused) {
		t.Fatal("different original tuple must not collide")
	}
}

func TestUpdateInspectionRejectsWrongIncarnationAndRevision(t *testing.T) {
	store := NewRuntimeStore(DefaultRuntimeLimits())
	created, _, _ := store.Apply(testRecord(), time.Now().UTC())
	next := domain.DefaultSessionInspection()
	wrong := created.Identity
	wrong.KernelStart++
	if _, err := store.UpdateInspection(created.SessionID, wrong, 0, 0, next); !errors.Is(err, ErrStaleInspection) {
		t.Fatalf("wrong incarnation accepted: %v", err)
	}
	if _, err := store.UpdateInspection(created.SessionID, created.Identity, 0, 1, next); !errors.Is(err, ErrStaleInspection) {
		t.Fatalf("stale revision accepted: %v", err)
	}
}

func TestConnectivityReevaluationCannotOverwriteAppliedInspectionGuard(t *testing.T) {
	store := NewRuntimeStore(DefaultRuntimeLimits())
	created, _, err := store.Apply(testRecord(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetDecision(created.SessionID, 0, domain.DecisionAllow, "allow-web", "base allow"); err != nil {
		t.Fatal(err)
	}
	next := domain.DefaultSessionInspection()
	next.Generation = 0
	next.Mode = domain.InspectionModeIPS
	next.Enforcement = domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: domain.DecisionDrop, Status: domain.EnforcementApplied}
	guarded, err := store.UpdateInspection(created.SessionID, created.Identity, 0, 0, next)
	if err != nil {
		t.Fatal(err)
	}
	if guarded.EffectiveDecision != domain.DecisionDrop {
		t.Fatalf("guard was not reflected in effective decision: %#v", guarded)
	}
	reevaluated, err := store.SetDecision(created.SessionID, 0, domain.DecisionAllow, "allow-web", "reevaluated base allow")
	if err != nil {
		t.Fatal(err)
	}
	if reevaluated.Decision != domain.DecisionAllow || reevaluated.EffectiveDecision != domain.DecisionDrop {
		t.Fatalf("base reevaluation bypassed applied inspection guard: %#v", reevaluated)
	}
}

func TestResolveCandidatesIncludesNATAliasAndRecent(t *testing.T) {
	store := NewRuntimeStore(DefaultRuntimeLimits())
	createdAt := time.Now().UTC()
	created, _, err := store.Apply(testRecord(), createdAt)
	if err != nil {
		t.Fatal(err)
	}
	translated := *created.TranslatedTuple
	key := flow.Key{Scope: flow.Scope{NetworkNamespace: created.Identity.NetworkNS, ConntrackZone: created.Identity.Zone}, Tuple: translated}
	items, truncated := store.ResolveCandidates(key, createdAt, 8)
	if truncated || len(items) != 1 || items[0].SessionID != created.SessionID {
		t.Fatalf("active alias resolution failed: %#v %v", items, truncated)
	}
	_, _ = store.Close(created.Identity, "destroy", createdAt.Add(time.Second))
	items, truncated = store.ResolveRecent(key, createdAt.Add(500*time.Millisecond), 8)
	if truncated || len(items) != 1 {
		t.Fatalf("recent resolution failed: %#v %v", items, truncated)
	}
}
