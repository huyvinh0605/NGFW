package correlation

import (
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

type pendingEntry struct {
	observation inspection.Observation
	expires     time.Time
	next        time.Time
	attempts    int
}

type PendingCorrelations struct {
	mu    sync.Mutex
	items map[string]pendingEntry
	max   int
	wait  time.Duration
}

func NewPendingCorrelations(max int, wait time.Duration) *PendingCorrelations {
	if max <= 0 {
		max = 2048
	}
	if wait <= 0 {
		wait = 2 * time.Second
	}
	return &PendingCorrelations{items: make(map[string]pendingEntry), max: max, wait: wait}
}

func (p *PendingCorrelations) Add(obs inspection.Observation, now time.Time) bool {
	if obs.ID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.items[obs.ID]; ok {
		return true
	}
	if len(p.items) >= p.max {
		return false
	}
	p.items[obs.ID] = pendingEntry{observation: obs, expires: now.Add(p.wait), next: now}
	return true
}

func (p *PendingCorrelations) RetryDue(now time.Time, budget int) (due, expired []inspection.Observation) {
	if budget <= 0 {
		budget = 128
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, entry := range p.items {
		if len(due)+len(expired) >= budget {
			break
		}
		if !entry.expires.After(now) {
			expired = append(expired, entry.observation)
			delete(p.items, id)
			continue
		}
		if entry.next.After(now) {
			continue
		}
		due = append(due, entry.observation)
		entry.attempts++
		entry.next = now.Add(100 * time.Millisecond * time.Duration(entry.attempts))
		p.items[id] = entry
	}
	return due, expired
}

func (p *PendingCorrelations) Remove(id string) { p.mu.Lock(); delete(p.items, id); p.mu.Unlock() }
func (p *PendingCorrelations) Len() int         { p.mu.Lock(); defer p.mu.Unlock(); return len(p.items) }
