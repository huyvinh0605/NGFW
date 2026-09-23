package engine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

var ErrSecurityEventTooLarge = errors.New("security event exceeds store byte limit")
var ErrSecurityEventNotFound = domain.ErrSecurityEventNotFound

type storedThreat struct {
	event domain.ThreatEvent
	size  int
}

// SecurityEventStore is an in-memory bounded ring. It owns event sequence and
// correlation revisions; callers only receive deep copies.
type SecurityEventStore struct {
	mu       sync.RWMutex
	items    []storedThreat
	index    map[string]int
	head     int
	count    int
	capacity int
	maxBytes int
	bytes    int
	next     uint64
	streamID string
	stats    domain.SecurityEventStats
}

func NewSecurityEventStore(capacity, maxBytes int) *SecurityEventStore {
	if capacity <= 0 {
		capacity = 5000
	}
	if maxBytes <= 0 {
		maxBytes = 16 << 20
	}
	var seed [12]byte
	_, _ = rand.Read(seed[:])
	return &SecurityEventStore{capacity: capacity, maxBytes: maxBytes, items: make([]storedThreat, capacity), index: make(map[string]int, capacity), streamID: hex.EncodeToString(seed[:])}
}

// Add is idempotent for an event ID. The bool is true only for a new record.
func (s *SecurityEventStore) Add(event domain.ThreatEvent) (domain.ThreatEvent, bool, error) {
	if strings.TrimSpace(event.EventID) == "" {
		return domain.ThreatEvent{}, false, errors.New("security event_id is required")
	}
	if event.EventClass == "" {
		event.EventClass = "security"
	}
	if event.Source == "" {
		event.Source = "SURICATA"
	}
	if event.IngestedAt.IsZero() {
		event.IngestedAt = time.Now().UTC()
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return domain.ThreatEvent{}, false, err
	}
	if len(encoded) > s.maxBytes {
		s.mu.Lock()
		s.stats.RejectedBytes++
		s.mu.Unlock()
		return domain.ThreatEvent{}, false, ErrSecurityEventTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot, exists := s.index[event.EventID]; exists {
		s.stats.Duplicates++
		return s.items[slot].event.Clone(), false, nil
	}
	s.next++
	event.Sequence = s.next
	encoded, err = json.Marshal(event)
	if err != nil {
		return domain.ThreatEvent{}, false, err
	}
	for s.count >= s.capacity || (s.count > 0 && s.bytes+len(encoded) > s.maxBytes) {
		s.evictOldestLocked()
	}
	if len(encoded) > s.maxBytes {
		s.stats.RejectedBytes++
		return domain.ThreatEvent{}, false, ErrSecurityEventTooLarge
	}
	slot := (s.head + s.count) % s.capacity
	s.items[slot] = storedThreat{event: event.Clone(), size: len(encoded)}
	s.index[event.EventID] = slot
	s.count++
	s.bytes += len(encoded)
	s.stats.Added++
	s.stats.CurrentEvents = uint64(s.count)
	s.stats.CurrentBytes = uint64(s.bytes)
	return event.Clone(), true, nil
}

func (s *SecurityEventStore) evictOldestLocked() {
	if s.count == 0 {
		return
	}
	old := s.items[s.head]
	delete(s.index, old.event.EventID)
	s.bytes -= old.size
	s.items[s.head] = storedThreat{}
	s.head = (s.head + 1) % s.capacity
	s.count--
	s.stats.Evicted++
}

func (s *SecurityEventStore) Get(id string) (domain.ThreatEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	position, ok := s.index[id]
	if !ok {
		return domain.ThreatEvent{}, false
	}
	return s.items[position].event.Clone(), true
}

func (s *SecurityEventStore) UpdateCorrelation(id, sessionID, policyID string, generation uint64, state domain.CorrelationState, reason string) (domain.ThreatEvent, error) {
	if !state.Valid() {
		return domain.ThreatEvent{}, errors.New("invalid correlation state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	position, ok := s.index[id]
	if !ok {
		return domain.ThreatEvent{}, ErrSecurityEventNotFound
	}
	record := &s.items[position]
	if record.event.SessionID == sessionID && record.event.PolicyID == policyID && record.event.PolicyGeneration == generation && record.event.CorrelationState == state && record.event.CorrelationReason == reason {
		return record.event.Clone(), nil
	}
	before := record.size
	updated := record.event.Clone()
	updated.SessionID = sessionID
	updated.PolicyID = policyID
	updated.PolicyGeneration = generation
	updated.CorrelationState = state
	updated.CorrelationReason = reason
	updated.CorrelationRevision++
	encoded, err := json.Marshal(updated)
	if err != nil {
		return domain.ThreatEvent{}, err
	}
	if len(encoded) > s.maxBytes {
		s.stats.RejectedBytes++
		return domain.ThreatEvent{}, ErrSecurityEventTooLarge
	}
	projected := s.bytes - before + len(encoded)
	if projected > s.maxBytes {
		reclaimable := 0
		for i := 0; i < s.count; i++ {
			candidate := s.items[(s.head+i)%s.capacity]
			if candidate.event.EventID == id {
				break
			}
			reclaimable += candidate.size
		}
		if projected-reclaimable > s.maxBytes {
			s.stats.RejectedBytes++
			return domain.ThreatEvent{}, ErrSecurityEventTooLarge
		}
	}
	for projected > s.maxBytes && s.count > 1 && s.items[s.head].event.EventID != id {
		s.evictOldestLocked()
		projected = s.bytes - before + len(encoded)
		position, ok = s.index[id]
		if !ok {
			return domain.ThreatEvent{}, ErrSecurityEventNotFound
		}
		record = &s.items[position]
		before = record.size
	}
	if projected > s.maxBytes {
		s.stats.RejectedBytes++
		return domain.ThreatEvent{}, ErrSecurityEventTooLarge
	}
	record.event = updated
	record.size = len(encoded)
	s.bytes = projected
	s.stats.CurrentEvents = uint64(s.count)
	s.stats.CurrentBytes = uint64(s.bytes)
	return record.event.Clone(), nil
}

func (s *SecurityEventStore) Query(query domain.SecurityQuery) domain.SecurityEventPage {
	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	s.mu.RLock()
	snapshot := make([]domain.ThreatEvent, s.count)
	for i := 0; i < s.count; i++ {
		snapshot[i] = s.items[(s.head+i)%s.capacity].event.Clone()
	}
	streamID, next, evicted := s.streamID, s.next, s.stats.Evicted
	var oldest uint64
	if len(snapshot) > 0 {
		oldest = snapshot[0].Sequence
	}
	s.mu.RUnlock()
	page := domain.SecurityEventPage{Items: make([]domain.ThreatEvent, 0, limit), StreamID: streamID, NextSequence: query.AfterSequence, OldestSequence: oldest, EvictedCount: evicted}
	if query.StreamID != "" && query.StreamID != streamID {
		page.Gap = true
		page.ResetRequired = true
		query.AfterSequence = 0
		page.NextSequence = 0
	}
	if oldest > 0 && oldest > query.AfterSequence+1 {
		page.GapFrom = oldest
		page.Gap = true
	}
	for _, event := range snapshot {
		if event.Sequence <= query.AfterSequence {
			continue
		}
		if len(page.Items) >= limit {
			page.HasMore = true
			break
		}
		// Advance through non-matching records too so a selective query cannot
		// become stuck rescanning the same bounded ring range forever.
		page.NextSequence = event.Sequence
		if matchesSecurityQuery(event, query) {
			page.Items = append(page.Items, event)
		}
	}
	if page.NextSequence > next {
		page.NextSequence = next
	}
	page.NextCursor = fmt.Sprintf("%s:%d", streamID, page.NextSequence)
	return page
}

func matchesSecurityQuery(event domain.ThreatEvent, query domain.SecurityQuery) bool {
	return (query.SessionID == "" || event.SessionID == query.SessionID) &&
		(query.SensorID == "" || event.SensorID == query.SensorID) &&
		(query.Mode == "" || event.CaptureMode == query.Mode) &&
		(query.Severity == "" || event.Severity == query.Severity) &&
		(query.Verdict == "" || event.Verdict == query.Verdict) &&
		(query.Correlation == "" || event.CorrelationState == query.Correlation) &&
		(query.Application == "" || strings.EqualFold(event.Application.Name, query.Application))
}

func (s *SecurityEventStore) Stats() domain.SecurityEventStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := s.stats
	result.CurrentEvents = uint64(s.count)
	result.CurrentBytes = uint64(s.bytes)
	return result
}
