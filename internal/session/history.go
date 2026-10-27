package session

import (
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

// SetInspectionHistoryLimits controls the existing canonical closed history.
// Zero restores the M2 limits supplied when the store was constructed. Active
// identities and kernel guards are unaffected by history eviction.
func (s *RuntimeStore) SetInspectionHistoryLimits(max int, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if max <= 0 {
		max = s.baseHistoryMax
	}
	if ttl <= 0 {
		ttl = s.baseHistoryTTL
	}
	previousMax := s.limits.MaxClosed
	s.limits.MaxClosed, s.limits.ClosedTTL = max, ttl
	s.pruneClosedLocked(time.Now().UTC())
	s.trimClosedLocked()
	// A smaller live limit must also release the formerly larger backing arrays.
	if max < previousMax {
		s.closed = append([]domain.RuntimeSession(nil), s.closed...)
		s.tombstones = append([]tombstone(nil), s.tombstones...)
	}
}

func (s *RuntimeStore) appendClosedLocked(value domain.RuntimeSession, tomb tombstone) {
	s.closed = append(s.closed, value)
	s.tombstones = append(s.tombstones, tomb)
	s.trimClosedLocked()
}

func (s *RuntimeStore) trimClosedLocked() {
	if excess := len(s.closed) - s.limits.MaxClosed; excess > 0 {
		clear(s.closed[:excess])
		s.closed = s.closed[excess:]
		s.stats.HistoryEvictions += uint64(excess)
	}
	if excess := len(s.tombstones) - s.limits.MaxClosed; excess > 0 {
		clear(s.tombstones[:excess])
		s.tombstones = s.tombstones[excess:]
	}
}
