package engine

import (
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type RuntimeEventRing struct {
	mu       sync.Mutex
	items    []domain.RuntimeEvent
	capacity int
	next     uint64
	dropped  uint64
}

func NewRuntimeEventRing(capacity int) *RuntimeEventRing {
	if capacity <= 0 {
		capacity = 10000
	}
	return &RuntimeEventRing{capacity: capacity, items: make([]domain.RuntimeEvent, 0, capacity)}
}

func (r *RuntimeEventRing) Publish(ev domain.RuntimeEvent) domain.RuntimeEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	ev.Sequence = r.next
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if len(r.items) >= r.capacity {
		r.items = r.items[1:]
		r.dropped++
		ev.DroppedBefore = r.dropped
	}
	r.items = append(r.items, ev)
	return ev
}

func (r *RuntimeEventRing) Read(after uint64, max int) ([]domain.RuntimeEvent, uint64, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if max <= 0 {
		max = 200
	}
	if max > 200 {
		max = 200
	}
	items := make([]domain.RuntimeEvent, 0, max)
	var gap uint64
	for _, ev := range r.items {
		if ev.Sequence <= after {
			continue
		}
		if len(items) >= max {
			break
		}
		items = append(items, ev)
	}
	if len(r.items) > 0 && after+1 < r.items[0].Sequence {
		gap = r.items[0].Sequence
	}
	return items, gap, r.next
}

func (r *RuntimeEventRing) Dropped() uint64 { r.mu.Lock(); defer r.mu.Unlock(); return r.dropped }
