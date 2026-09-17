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
