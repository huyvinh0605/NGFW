package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

var ErrCapacity = errors.New("session capacity reached")

type Store struct {
	mu       sync.RWMutex
	byID     map[string]*domain.Session
	byKey    map[string]string
	max      int
	contexts map[string]*domain.SecurityContext
}

func NewStore(max int) *Store {
	if max <= 0 {
		max = 50000
	}
	return &Store{byID: make(map[string]*domain.Session), byKey: make(map[string]string), contexts: make(map[string]*domain.SecurityContext), max: max}
}

func newID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-" + hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func canonicalKey(key domain.FlowKey) string {
	r := key.Reverse()
	a, b := key.String(), r.String()
	if b < a {
		return b + "|" + a
	}
	return a + "|" + b
}

func (s *Store) GetOrCreate(_ context.Context, key domain.FlowKey, sourceZone, destinationZone string, now time.Time) (*domain.Session, bool, error) {
	ck := canonicalKey(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byKey[ck]; ok {
		if existing := s.byID[id]; existing != nil {
			existing.LastSeen = now
			return cloneSession(existing), false, nil
		}
		delete(s.byKey, ck)
	}
	if len(s.byID) >= s.max {
		return nil, false, ErrCapacity
	}
	id := newID("sess")
	ctxID := newID("ctx")
	sess := &domain.Session{ID: id, ClientIP: key.SrcIP, ClientPort: key.SrcPort, ServerIP: key.DstIP, ServerPort: key.DstPort, Protocol: key.Protocol, SourceZone: sourceZone, DestinationZone: destinationZone, StartTime: now, LastSeen: now, Timeout: 5 * time.Minute, SecurityContextID: ctxID, Decision: domain.DecisionDrop}
	if key.Protocol == "tcp" || key.Protocol == "TCP" {
		sess.TCPState = "SYN_SENT"
	}
	s.byID[id] = sess
	s.byKey[ck] = id
	s.contexts[ctxID] = &domain.SecurityContext{FlowID: ck, SessionID: id, Network: domain.NetworkContext{SrcIP: key.SrcIP, DstIP: key.DstIP, SrcPort: key.SrcPort, DstPort: key.DstPort, Protocol: key.Protocol, SrcZone: sourceZone, DstZone: destinationZone}, UpdatedAt: now}
	return cloneSession(sess), true, nil
}

func (s *Store) Get(id string) (*domain.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return cloneSession(v), true
}

func (s *Store) FindByFlowID(flowID string) (*domain.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.byID {
		c := s.contexts[sess.SecurityContextID]
		if c != nil && c.FlowID == flowID {
			return cloneSession(sess), true
		}
	}
	return nil, false
}

func (s *Store) GetContext(id string) (*domain.SecurityContext, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.contexts[id]
	if !ok {
		return nil, false
	}
	return cloneContext(v), true
}

func (s *Store) Update(id string, fn func(*domain.Session) error) (*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	if err := fn(v); err != nil {
		return nil, err
	}
	return cloneSession(v), nil
}

func (s *Store) UpdateContext(id string, fn func(*domain.SecurityContext) error) (*domain.SecurityContext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.contexts[id]
	if !ok {
		return nil, errors.New("security context not found")
	}
	if err := fn(v); err != nil {
		return nil, err
	}
	v.UpdatedAt = time.Now()
	return cloneContext(v), nil
}

func (s *Store) Invalidate(id string, reason string) error {
	_, err := s.Update(id, func(v *domain.Session) error {
		v.Invalidated = true
		v.FastPathEligible = false
		v.FastPathReason = reason
		return nil
	})
	return err
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[id]
	if !ok {
		return errors.New("session not found")
	}
	delete(s.byID, id)
	delete(s.contexts, v.SecurityContextID)
	for k, sid := range s.byKey {
		if sid == id {
			delete(s.byKey, k)
		}
	}
	return nil
}

func (s *Store) List() []*domain.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*domain.Session, 0, len(s.byID))
	for _, v := range s.byID {
		result = append(result, cloneSession(v))
	}
	return result
}

func (s *Store) Cleanup(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, v := range s.byID {
		if v.LastSeen.Add(v.Timeout).Before(now) {
			delete(s.byID, id)
			delete(s.contexts, v.SecurityContextID)
			for k, sid := range s.byKey {
				if sid == id {
					delete(s.byKey, k)
				}
			}
			removed++
		}
	}
	return removed
}

func cloneSession(v *domain.Session) *domain.Session {
	c := *v
	if v.OriginalTuple != nil {
		x := *v.OriginalTuple
		c.OriginalTuple = &x
	}
	if v.ReplyTuple != nil {
		x := *v.ReplyTuple
		c.ReplyTuple = &x
	}
	return &c
}
func cloneContext(v *domain.SecurityContext) *domain.SecurityContext {
	c := *v
	c.IPS.Alerts = append([]domain.SecurityEvent(nil), v.IPS.Alerts...)
	c.Behavior.AnomalyEvents = append([]domain.SecurityEvent(nil), v.Behavior.AnomalyEvents...)
	c.Signals = append([]domain.SecurityEvent(nil), v.Signals...)
	c.Risk.Reasons = append([]string(nil), v.Risk.Reasons...)
	c.Risk.Contributions = append([]domain.RiskContribution(nil), v.Risk.Contributions...)
	if v.ML.Probabilities != nil {
		c.ML.Probabilities = map[string]float64{}
		for k, x := range v.ML.Probabilities {
			c.ML.Probabilities[k] = x
		}
	}
	return &c
}
