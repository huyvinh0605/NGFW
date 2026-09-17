package session

import (
	"context"
	"github.com/kltngfw/ngfw/internal/domain"
	"testing"
	"time"
)

func TestBidirectionalFlowMapsToOneSession(t *testing.T) {
	s := NewStore(2)
	now := time.Now()
	a := domain.FlowKey{SrcIP: "10.0.0.1", DstIP: "1.1.1.1", SrcPort: 1000, DstPort: 443, Protocol: "tcp"}
	x, created, err := s.GetOrCreate(context.Background(), a, "lan", "wan", now)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	y, created, err := s.GetOrCreate(context.Background(), a.Reverse(), "wan", "lan", now)
	if err != nil || created || x.ID != y.ID {
		t.Fatalf("reverse did not match: %v %v %v", created, x.ID, y.ID)
	}
}
