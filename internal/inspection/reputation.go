package inspection

import (
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type ReputationStore struct {
	mu      sync.RWMutex
	entries map[string]domain.ReputationEntry
	max     int
}

func NewReputationStore(max int) *ReputationStore {
	if max <= 0 {
		max = 100000
	}
	return &ReputationStore{entries: map[string]domain.ReputationEntry{}, max: max}
}
func (s *ReputationStore) Upsert(e domain.ReputationEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[e.Indicator]; !ok && len(s.entries) >= s.max {
		return false
	}
	if e.LastUpdated == 0 {
		e.LastUpdated = time.Now().Unix()
	}
	s.entries[strings.ToLower(e.Indicator)] = e
	return true
}
func (s *ReputationStore) Lookup(indicator string) (domain.ReputationEntry, bool) {
	s.mu.RLock()
	e, ok := s.entries[strings.ToLower(indicator)]
	s.mu.RUnlock()
	if !ok || !e.Enabled || (e.ExpiresAt > 0 && e.ExpiresAt < time.Now().Unix()) {
		return domain.ReputationEntry{}, false
	}
	return e, true
}
func (s *ReputationStore) LookupContext(ip, domainName string) domain.ReputationContext {
	r := domain.ReputationContext{}
	if e, ok := s.Lookup(ip); ok {
		if strings.EqualFold(e.IndicatorType, "MALICIOUS_IP") {
			r.SrcIPScore = e.ReputationScore
		} else {
			r.DstIPScore = e.ReputationScore
		}
		r.MatchedLists = append(r.MatchedLists, e.Source)
	}
	if domainName != "" {
		if e, ok := s.Lookup(domainName); ok {
			r.DomainScore = e.ReputationScore
			r.MatchedLists = append(r.MatchedLists, e.Source)
		}
	}
	return r
}
func (s *ReputationStore) PurgeExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, e := range s.entries {
		if e.ExpiresAt > 0 && e.ExpiresAt < now.Unix() {
			delete(s.entries, k)
			removed++
		}
	}
	return removed
}
func (s *ReputationStore) List() []domain.ReputationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.ReputationEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		out = append(out, entry)
	}
	return out
}
func (s *ReputationStore) Delete(indicator string) {
	s.mu.Lock()
	delete(s.entries, strings.ToLower(indicator))
	s.mu.Unlock()
}
