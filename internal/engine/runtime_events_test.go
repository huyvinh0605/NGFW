package engine

import (
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestRuntimeEventRingIsBoundedAndReportsGap(t *testing.T) {
	ring := NewRuntimeEventRing(2)
	ring.Publish(domain.RuntimeEvent{Kind: domain.EventSessionCreated, SessionID: "s1"})
	ring.Publish(domain.RuntimeEvent{Kind: domain.EventSessionUpdated, SessionID: "s1"})
	ring.Publish(domain.RuntimeEvent{Kind: domain.EventSessionClosed, SessionID: "s1"})
	items, gap, next := ring.Read(0, 10)
	if len(items) != 2 || gap == 0 || next != 3 || ring.Dropped() != 1 {
		t.Fatalf("items=%d gap=%d next=%d dropped=%d", len(items), gap, next, ring.Dropped())
	}
}

func TestRuntimeEventRingClassifiesLifecycleAndPolicyEvents(t *testing.T) {
	ring := NewRuntimeEventRing(4)
	lifecycle := ring.Publish(domain.RuntimeEvent{Kind: domain.EventSessionCreated, SessionID: "s1"})
	policy := ring.Publish(domain.RuntimeEvent{Kind: domain.EventDecisionChanged, SessionID: "s1"})
	security := ring.Publish(domain.RuntimeEvent{Kind: domain.EventSessionUpdated, Class: domain.EventClassSecurity, SessionID: "s1"})
	if lifecycle.Class != domain.EventClassRuntime || policy.Class != domain.EventClassPolicy || security.Class != domain.EventClassSecurity {
		t.Fatalf("classes=%q,%q,%q", lifecycle.Class, policy.Class, security.Class)
	}
}
