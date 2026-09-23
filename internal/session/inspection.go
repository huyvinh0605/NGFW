package session

import (
	"errors"
	"math"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
)

var (
	ErrStaleInspection = errors.New("stale inspection update")
	ErrStaleGeneration = errors.New("stale inspection generation")
)

func (s *RuntimeStore) UpdateInspection(id string, identity domain.ConntrackIdentity, expectedGeneration, expectedInspectionRevision uint64, next domain.SessionInspection) (domain.RuntimeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byID[id]
	if !ok {
		return domain.RuntimeSession{}, ErrSessionMissing
	}
	if !tombstoneIdentityMatches(current.Identity, identity) || (identity.ID != 0 && current.Identity.ID != 0 && identity.ID != current.Identity.ID) {
		return domain.RuntimeSession{}, ErrStaleInspection
	}
	if current.PolicyGeneration > expectedGeneration || (current.Inspection != nil && current.Inspection.Generation > expectedGeneration) || next.Generation != expectedGeneration {
		return domain.RuntimeSession{}, ErrStaleGeneration
	}
	revision := uint64(0)
	if current.Inspection != nil {
		revision = current.Inspection.Revision
	}
	if revision != expectedInspectionRevision || revision == math.MaxUint64 {
		return domain.RuntimeSession{}, ErrStaleInspection
	}
	nextCopy := next.Clone()
	nextCopy.Revision = expectedInspectionRevision + 1
	current.Inspection = &nextCopy
	if current.Revoked {
		current.EffectiveDecision = domain.DecisionDrop
	} else if nextCopy.Enforcement.Status == domain.EnforcementApplied && nextCopy.Enforcement.Mechanism == domain.EnforcementNFTSessionGuard && nextCopy.Enforcement.RequestedAction == domain.DecisionDrop {
		current.EffectiveDecision = domain.DecisionDrop
	} else {
		current.EffectiveDecision = current.Decision
	}
	current.Revision++
	s.revision++
	return current.Clone(), nil
}

// ResolveCandidates returns active and recently closed sessions whose indexed
// aliases match a tuple at the observation time. Truncated is true when more
// candidates exist than the safe correlation limit.
func (s *RuntimeStore) ResolveCandidates(key flow.Key, observedAt time.Time, limit int) (items []domain.RuntimeSession, truncated bool) {
	if limit <= 0 || limit > 8 {
		limit = 8
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	for id := range s.byTuple[key] {
		current := s.byID[id]
		if current == nil || !sessionOverlaps(*current, observedAt) {
			continue
		}
		if len(items) >= limit {
			return items, true
		}
		items = append(items, current.Clone())
		seen[id] = struct{}{}
	}
	for i := len(s.closed) - 1; i >= 0; i-- {
		closed := s.closed[i]
		if _, ok := seen[closed.SessionID]; ok || !sessionOverlaps(closed, observedAt) || !sessionHasAlias(closed, key) {
			continue
		}
		if len(items) >= limit {
			return items, true
		}
		items = append(items, closed.Clone())
		seen[closed.SessionID] = struct{}{}
	}
	return items, false
}

func (s *RuntimeStore) ResolveRecent(key flow.Key, observedAt time.Time, limit int) (items []domain.RuntimeSession, truncated bool) {
	if limit <= 0 || limit > 8 {
		limit = 8
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.closed) - 1; i >= 0; i-- {
		closed := s.closed[i]
		if !sessionOverlaps(closed, observedAt) || !sessionHasAlias(closed, key) {
			continue
		}
		if len(items) >= limit {
			return items, true
		}
		items = append(items, closed.Clone())
	}
	return items, false
}

func sessionOverlaps(value domain.RuntimeSession, observedAt time.Time) bool {
	if observedAt.IsZero() {
		return true
	}
	if !value.CreatedAt.IsZero() && observedAt.Before(value.CreatedAt.Add(-2*time.Second)) {
		return false
	}
	if value.ClosedAt != nil && observedAt.After(value.ClosedAt.Add(2*time.Second)) {
		return false
	}
	return true
}

func sessionHasAlias(value domain.RuntimeSession, wanted flow.Key) bool {
	scope := flow.Scope{NetworkNamespace: value.Identity.NetworkNS, ConntrackZone: value.Identity.Zone}
	for _, candidate := range flow.Aliases(scope, value.OriginalTuple, value.ReplyTuple, value.TranslatedTuple) {
		if candidate == wanted {
			return true
		}
	}
	return false
}
