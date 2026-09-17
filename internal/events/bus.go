package events

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/kltngfw/ngfw/internal/domain"
)

// Bus is deliberately bounded. Security events are never allowed to wait on a
// slow dashboard or database writer.
type Bus struct {
	mu       sync.RWMutex
	subs     map[uint64]chan domain.SecurityEvent
	next     uint64
	capacity int
	dropped  atomic.Uint64
}

func NewBus(capacity int) *Bus {
	if capacity <= 0 {
		capacity = 10000
	}
	return &Bus{subs: make(map[uint64]chan domain.SecurityEvent), capacity: capacity}
}

func (b *Bus) Publish(event domain.SecurityEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- event:
		default:
			b.dropped.Add(1)
		}
	}
}

func (b *Bus) Subscribe(ctx context.Context) <-chan domain.SecurityEvent {
	b.mu.Lock()
	id := b.next
	b.next++
	ch := make(chan domain.SecurityEvent, b.capacity)
	b.subs[id] = ch
	b.mu.Unlock()
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
		b.mu.Unlock()
	}()
	return ch
}

func (b *Bus) Dropped() uint64 { return b.dropped.Load() }
