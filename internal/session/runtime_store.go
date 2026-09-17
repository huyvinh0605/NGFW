package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
)

var (
	ErrRuntimeCapacity = errors.New("runtime session capacity reached")
	ErrSessionMissing  = errors.New("runtime session not found")
	ErrIdentityMissing = errors.New("conntrack identity is incomplete")
	ErrAliasAmbiguous  = errors.New("tuple alias resolves to multiple sessions")
	ErrStaleEvent      = errors.New("stale conntrack event")
	ErrStaleDecision   = errors.New("stale policy decision")
)

type RuntimeLimits struct {
	MaxSessions   int
	MaxAliases    int
	MaxClosed     int
	ClosedTTL     time.Duration
	MaxAmbiguity  int
	MaxEventQueue int
}

func DefaultRuntimeLimits() RuntimeLimits {
	return RuntimeLimits{MaxSessions: 50000, MaxAliases: 8, MaxClosed: 5000, ClosedTTL: time.Minute, MaxAmbiguity: 4, MaxEventQueue: 10000}
}

type SessionFilter struct {
	SourceIP        string
	DestinationIP   string
	Protocol        uint8
	SourceZone      string
	DestinationZone string
	State           domain.SessionState
	Decision        domain.Decision
	TupleView       string
}

type Page struct {
	Number, Size int
	Cursor       string
}

type PageResult struct {
	Items         []domain.RuntimeSession `json:"items"`
	Page          int                     `json:"page"`
	PageSize      int                     `json:"page_size"`
	Total         int                     `json:"total"`
	HasMore       bool                    `json:"has_more"`
	StoreRevision uint64                  `json:"store_revision"`
	SnapshotTime  time.Time               `json:"snapshot_time"`
}

type RuntimeStats struct {
	Active, Created, Closed, Invalidated, TrackingDrops, CapacityDrops uint64
	EventDrops, Resyncs                                                uint64
}

type tombstone struct {
	ID       string
	Identity domain.ConntrackIdentity
	At       time.Time
}

type conntrackKey struct {
	BootID    string
	NetworkNS string
	Zone      uint16
	Family    domain.IPFamily
	ID        uint32
}

type RuntimeStore struct {
	mu                  sync.RWMutex
	byID                map[string]*domain.RuntimeSession
	byIdentity          map[domain.ConntrackIdentity]string
	byConntrack         map[conntrackKey]string
	byTuple             map[flow.Key]map[string]struct{}
	aliasesBySession    map[string][]flow.Key
	identitiesBySession map[string][]domain.ConntrackIdentity
	conntracksBySession map[string][]conntrackKey
	closed              []domain.RuntimeSession
	tombstones          []tombstone
	limits              RuntimeLimits
	revision            uint64
	stats               RuntimeStats
}

func NewRuntimeStore(limits RuntimeLimits) *RuntimeStore {
	defaults := DefaultRuntimeLimits()
	if limits.MaxSessions <= 0 {
		limits.MaxSessions = defaults.MaxSessions
	}
	if limits.MaxAliases <= 0 {
		limits.MaxAliases = defaults.MaxAliases
	}
	if limits.MaxClosed <= 0 {
		limits.MaxClosed = defaults.MaxClosed
	}
	if limits.ClosedTTL <= 0 {
		limits.ClosedTTL = defaults.ClosedTTL
	}
	if limits.MaxAmbiguity <= 0 {
		limits.MaxAmbiguity = defaults.MaxAmbiguity
	}
	if limits.MaxEventQueue <= 0 {
		limits.MaxEventQueue = defaults.MaxEventQueue
	}
	return &RuntimeStore{byID: map[string]*domain.RuntimeSession{}, byIdentity: map[domain.ConntrackIdentity]string{}, byConntrack: map[conntrackKey]string{}, byTuple: map[flow.Key]map[string]struct{}{}, aliasesBySession: map[string][]flow.Key{}, identitiesBySession: map[string][]domain.ConntrackIdentity{}, conntracksBySession: map[string][]conntrackKey{}, limits: limits}
}

func sessionID(identity domain.ConntrackIdentity) string {
	b := []byte(identity.BootID + "\x00" + identity.NetworkNS + "\x00" + identity.Original.String())
	b = append(b, byte(identity.Zone>>8), byte(identity.Zone), byte(identity.Family), byte(identity.ID>>24), byte(identity.ID>>16), byte(identity.ID>>8), byte(identity.ID))
	for shift := uint(56); ; shift -= 8 {
		b = append(b, byte(identity.KernelStart>>shift))
		if shift == 0 {
			break
		}
	}
	h := sha256.Sum256(b)
	return "sess-" + hex.EncodeToString(h[:16])
}

func (s *RuntimeStore) Apply(record conntrack.Record, now time.Time) (domain.RuntimeSession, bool, error) {
	// UPDATE messages can legitimately omit the original tuple when the
	// kernel only reports counters/timeout changes. The identity still carries
	// the canonical tuple when available; use it without erasing fields already
	// held by the live session.
	if !record.OriginalTuple.Valid() && record.Identity.Original.Valid() {
		record.OriginalTuple = record.Identity.Original
	}
	if !record.OriginalTuple.Valid() {
		return domain.RuntimeSession{}, false, ErrIdentityMissing
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	identity := record.Identity
	if identity.Original == (domain.Tuple{}) {
		identity.Original = record.OriginalTuple
	}
	record.Identity = identity
	s.mu.Lock()
	defer s.mu.Unlock()
	if id := s.resolveIdentityLocked(identity); id != "" {
		if existing := s.byID[id]; existing != nil {
			s.rememberIdentityLocked(id, identity)
			return s.mergeLocked(existing, record, now), false, nil
		}
	}
	for _, tombstone := range s.tombstones {
		if tombstoneIdentityMatches(tombstone.Identity, identity) {
			return domain.RuntimeSession{}, false, ErrStaleEvent
		}
	}
	key := flow.Key{Scope: flow.Scope{NetworkNamespace: identity.NetworkNS, ConntrackZone: identity.Zone}, Tuple: record.OriginalTuple}
	if id, status := s.resolveTupleLocked(key); status == "ok" {
		if existing := s.byID[id]; existing != nil {
			s.rememberIdentityLocked(id, identity)
			return s.mergeLocked(existing, record, now), false, nil
		}
	}
	if len(s.byID) >= s.limits.MaxSessions {
		s.stats.TrackingDrops++
		s.stats.CapacityDrops++
		return domain.RuntimeSession{}, false, ErrRuntimeCapacity
	}
	id := sessionID(identity)
	if _, exists := s.byID[id]; exists { // partial identity collision; never overwrite.
		id += "-" + hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	created := record.KernelStart
	createdFromKernel := !created.IsZero() && record.Presence.Timestamp
	if created.IsZero() {
		created = now
	}
	state := stateFor(record)
	sess := &domain.RuntimeSession{SessionID: id, Identity: identity, OriginalTuple: record.OriginalTuple, IPFamily: record.OriginalTuple.Family, Protocol: record.OriginalTuple.Protocol, State: state, CreatedAt: created, LastSeen: now, LastObservedAt: now, PacketsOriginal: record.PacketsOriginal, BytesOriginal: record.BytesOriginal, PacketsReply: record.PacketsReply, BytesReply: record.BytesReply, CacheState: domain.CacheNotEvaluated, Revision: 1, Quality: domain.SessionQuality{TrackingStatus: domain.TrackingComplete, IdentityConfidence: domain.IdentityComplete}}
	if !createdFromKernel {
		sess.Quality.IdentityConfidence = domain.IdentityPartial
		sess.Quality.MissingFields = append(sess.Quality.MissingFields, "kernel_start")
	}
	if !record.Presence.ID || identity.ID == 0 {
		sess.Quality.IdentityConfidence = domain.IdentityPartial
		sess.Quality.MissingFields = append(sess.Quality.MissingFields, "conntrack_id")
	}
	if !record.Presence.ReplyTuple {
		sess.Quality.TrackingStatus = domain.TrackingPartial
		sess.Quality.MissingFields = append(sess.Quality.MissingFields, "reply_tuple")
	}
	if !record.Presence.Counters {
		sess.Quality.TrackingStatus = domain.TrackingPartial
		sess.Quality.MissingFields = append(sess.Quality.MissingFields, "counters")
	}
	if !record.Presence.Timeout {
		sess.Quality.TrackingStatus = domain.TrackingPartial
		sess.Quality.MissingFields = append(sess.Quality.MissingFields, "timeout")
	}
	if !record.Presence.Mark {
		sess.Quality.TrackingStatus = domain.TrackingPartial
		sess.Quality.MissingFields = append(sess.Quality.MissingFields, "mark")
	}
	if record.ReplyTuple != nil {
		v := *record.ReplyTuple
		sess.ReplyTuple = &v
	}
	sess.NAT = makeNAT(record.OriginalTuple, record.ReplyTuple)
	if sess.NAT.TranslatedTuple != nil {
		translated := *sess.NAT.TranslatedTuple
		sess.TranslatedTuple = &translated
	}
	if record.Timeout > 0 {
		expiry := now.Add(record.Timeout)
		sess.ExpiresAt = &expiry
	}
	sess.KernelEpoch = uint16(record.Mark >> 20)
	sess.KernelMark = record.Mark
	if record.Mark != 0 {
		sess.KernelCacheVerified = false
	}
	s.byID[id] = sess
	s.rememberIdentityLocked(id, identity)
	s.indexLocked(sess)
	s.stats.Created++
	s.stats.Active = uint64(len(s.byID))
	s.revision++
	return sess.Clone(), true, nil
}

func tombstoneIdentityMatches(previous, current domain.ConntrackIdentity) bool {
	if previous.BootID != "" && current.BootID != "" && previous.BootID != current.BootID {
		return false
	}
	if previous.NetworkNS != "" && current.NetworkNS != "" && previous.NetworkNS != current.NetworkNS {
		return false
	}
	if previous.Zone != current.Zone || previous.Family != current.Family || previous.ID != current.ID || previous.Original != current.Original {
		return false
	}
	return previous.KernelStart == 0 || current.KernelStart == 0 || previous.KernelStart == current.KernelStart
}

func stateFor(r conntrack.Record) domain.SessionState {
	if strings.EqualFold(r.TCPState, "ESTABLISHED") || strings.EqualFold(r.TCPState, "FIN_WAIT") || strings.EqualFold(r.TCPState, "CLOSE_WAIT") || strings.EqualFold(r.TCPState, "LAST_ACK") || strings.EqualFold(r.TCPState, "TIME_WAIT") || strings.EqualFold(r.TCPState, "CLOSE") {
		if strings.EqualFold(r.TCPState, "ESTABLISHED") {
			return domain.SessionEstablished
		}
		return domain.SessionClosing
	}
	if r.SeenReply {
		return domain.SessionEstablished
	}
	return domain.SessionNew
}

func makeNAT(original domain.Tuple, reply *domain.Tuple) domain.NATInfo {
	n := domain.NATInfo{}
	o := original
	n.OriginalTuple = &o
	if reply == nil {
		return n
	}
	r := *reply
	n.ReplyTuple = &r
	t := reply.Reverse()
	n.TranslatedTuple = &t
	n.PreNATSource, n.PreNATDestination = original.SrcIP.String(), original.DstIP.String()
	n.PostNATSource, n.PostNATDestination = t.SrcIP.String(), t.DstIP.String()
	n.SNAT = original.SrcIP != t.SrcIP || original.SrcPort != t.SrcPort
	n.DNAT = original.DstIP != t.DstIP || original.DstPort != t.DstPort
	if n.SNAT {
		n.SourceTranslationMethod = "UNKNOWN"
	}
	return n
}

func (s *RuntimeStore) mergeLocked(existing *domain.RuntimeSession, r conntrack.Record, now time.Time) domain.RuntimeSession {
	if existing.Identity.KernelStart == 0 && r.Identity.KernelStart != 0 && r.Presence.Timestamp {
		existing.Identity.KernelStart = r.Identity.KernelStart
		existing.Quality.IdentityConfidence = domain.IdentityComplete
		existing.Quality.MissingFields = removeMissing(existing.Quality.MissingFields, "kernel_start")
	}
	if existing.Identity.ID == 0 && r.Identity.ID != 0 && r.Presence.ID {
		existing.Identity.ID = r.Identity.ID
		existing.Quality.MissingFields = removeMissing(existing.Quality.MissingFields, "conntrack_id")
		if existing.Quality.IdentityConfidence == domain.IdentityPartial && len(existing.Quality.MissingFields) == 0 {
			existing.Quality.IdentityConfidence = domain.IdentityComplete
		}
	}
	if r.Presence.ReplyTuple && r.ReplyTuple != nil {
		v := *r.ReplyTuple
		existing.ReplyTuple = &v
		existing.NAT = makeNAT(existing.OriginalTuple, r.ReplyTuple)
		if existing.NAT.TranslatedTuple != nil {
			translated := *existing.NAT.TranslatedTuple
			existing.TranslatedTuple = &translated
		} else {
			existing.TranslatedTuple = nil
		}
		existing.Quality.MissingFields = removeMissing(existing.Quality.MissingFields, "reply_tuple")
		s.reindexLocked(existing)
	}
	if r.Presence.Counters {
		existing.Quality.MissingFields = removeMissing(existing.Quality.MissingFields, "counters")
		if r.PacketsOriginal > existing.PacketsOriginal || r.BytesOriginal > existing.BytesOriginal || r.PacketsReply > existing.PacketsReply || r.BytesReply > existing.BytesReply {
			existing.LastSeen = now
		}
		existing.PacketsOriginal = maxUint64(existing.PacketsOriginal, r.PacketsOriginal)
		existing.BytesOriginal = maxUint64(existing.BytesOriginal, r.BytesOriginal)
		existing.PacketsReply = maxUint64(existing.PacketsReply, r.PacketsReply)
		existing.BytesReply = maxUint64(existing.BytesReply, r.BytesReply)
	}
	if r.Presence.Timeout && r.Timeout > 0 {
		existing.Quality.MissingFields = removeMissing(existing.Quality.MissingFields, "timeout")
		expiry := now.Add(r.Timeout)
		existing.ExpiresAt = &expiry
	}
	if r.TCPState != "" {
		existing.State = stateFor(r)
	}
	if r.SeenReply && existing.State == domain.SessionNew {
		existing.State = domain.SessionEstablished
	}
	existing.LastObservedAt = now
	if existing.State != domain.SessionClosed {
		existing.LastSeen = now
	}
	existing.KernelMark = r.Mark
	existing.KernelEpoch = uint16(r.Mark >> 20)
	if r.Presence.Mark {
		existing.Quality.MissingFields = removeMissing(existing.Quality.MissingFields, "mark")
	}
	if len(existing.Quality.MissingFields) == 0 {
		existing.Quality.TrackingStatus = domain.TrackingComplete
	}
	existing.Revision++
	s.rememberIdentityLocked(existing.SessionID, r.Identity)
	s.revision++
	return existing.Clone()
}

func removeMissing(values []string, target string) []string {
	filtered := values[:0]
	for _, value := range values {
		if value != target {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func maxUint64(a, b uint64) uint64 {
	if b > a {
		return b
	}
	return a
}

func (s *RuntimeStore) indexLocked(v *domain.RuntimeSession) {
	s.removeTupleIndexesLocked(v.SessionID)
	scope := flow.Scope{NetworkNamespace: v.Identity.NetworkNS, ConntrackZone: v.Identity.Zone}
	aliases := flow.Aliases(scope, v.OriginalTuple, v.ReplyTuple, v.TranslatedTuple)
	if len(aliases) > s.limits.MaxAliases {
		aliases = aliases[:s.limits.MaxAliases]
		v.Quality.TrackingStatus = domain.TrackingPartial
		v.Quality.Reason = "alias limit"
	}
	for _, alias := range aliases {
		if s.byTuple[alias] == nil {
			s.byTuple[alias] = map[string]struct{}{}
		}
		s.byTuple[alias][v.SessionID] = struct{}{}
	}
	s.aliasesBySession[v.SessionID] = aliases
}

func (s *RuntimeStore) reindexLocked(v *domain.RuntimeSession) { s.indexLocked(v); s.revision++ }

func (s *RuntimeStore) removeIndexesLocked(id string) {
	s.removeTupleIndexesLocked(id)
	for _, identity := range s.identitiesBySession[id] {
		if current, ok := s.byIdentity[identity]; ok && current == id {
			delete(s.byIdentity, identity)
		}
	}
	delete(s.identitiesBySession, id)
	for _, key := range s.conntracksBySession[id] {
		if current, ok := s.byConntrack[key]; ok && current == id {
			delete(s.byConntrack, key)
		}
	}
	delete(s.conntracksBySession, id)
}

func makeConntrackKey(identity domain.ConntrackIdentity) (conntrackKey, bool) {
	if identity.ID == 0 {
		return conntrackKey{}, false
	}
	return conntrackKey{BootID: identity.BootID, NetworkNS: identity.NetworkNS, Zone: identity.Zone, Family: identity.Family, ID: identity.ID}, true
}

func (s *RuntimeStore) rememberIdentityLocked(id string, identity domain.ConntrackIdentity) {
	if id == "" {
		return
	}
	if current, ok := s.byIdentity[identity]; !ok || current != id {
		s.byIdentity[identity] = id
		known := false
		for _, value := range s.identitiesBySession[id] {
			if value == identity {
				known = true
				break
			}
		}
		if !known {
			s.identitiesBySession[id] = append(s.identitiesBySession[id], identity)
			limit := s.limits.MaxAliases
			if limit <= 0 {
				limit = DefaultRuntimeLimits().MaxAliases
			}
			for len(s.identitiesBySession[id]) > limit {
				oldest := s.identitiesBySession[id][0]
				s.identitiesBySession[id] = s.identitiesBySession[id][1:]
				if current, exists := s.byIdentity[oldest]; exists && current == id {
					delete(s.byIdentity, oldest)
				}
			}
		}
	}
	if key, ok := makeConntrackKey(identity); ok {
		if current, exists := s.byConntrack[key]; !exists || current == id {
			s.byConntrack[key] = id
			known := false
			for _, value := range s.conntracksBySession[id] {
				if value == key {
					known = true
					break
				}
			}
			if !known {
				s.conntracksBySession[id] = append(s.conntracksBySession[id], key)
				limit := s.limits.MaxAliases
				if limit <= 0 {
					limit = DefaultRuntimeLimits().MaxAliases
				}
				for len(s.conntracksBySession[id]) > limit {
					oldest := s.conntracksBySession[id][0]
					s.conntracksBySession[id] = s.conntracksBySession[id][1:]
					if current, exists := s.byConntrack[oldest]; exists && current == id {
						delete(s.byConntrack, oldest)
					}
				}
			}
		}
	}
}

func (s *RuntimeStore) resolveIdentityLocked(identity domain.ConntrackIdentity) string {
	if id := s.byIdentity[identity]; id != "" {
		return id
	}
	if key, ok := makeConntrackKey(identity); ok {
		if id := s.byConntrack[key]; id != "" {
			if current := s.byID[id]; current != nil {
				if identity.Original.Valid() && current.OriginalTuple != identity.Original {
					return ""
				}
				if identity.KernelStart != 0 && current.Identity.KernelStart != 0 && identity.KernelStart != current.Identity.KernelStart {
					return ""
				}
				return id
			}
		}
	}
	if identity.Original.Valid() {
		key := flow.Key{Scope: flow.Scope{NetworkNamespace: identity.NetworkNS, ConntrackZone: identity.Zone}, Tuple: identity.Original}
		if id, status := s.resolveTupleLocked(key); status == "ok" {
			if current := s.byID[id]; current != nil {
				if identity.BootID != "" && current.Identity.BootID != "" && identity.BootID != current.Identity.BootID {
					return ""
				}
				if identity.NetworkNS != "" && current.Identity.NetworkNS != "" && identity.NetworkNS != current.Identity.NetworkNS {
					return ""
				}
				if identity.ID != 0 && current.Identity.ID != 0 && identity.ID != current.Identity.ID {
					return ""
				}
				if identity.KernelStart != 0 && current.Identity.KernelStart != 0 && identity.KernelStart != current.Identity.KernelStart {
					return ""
				}
				return id
			}
		}
	}
	return ""
}

func (s *RuntimeStore) removeTupleIndexesLocked(id string) {
	for _, alias := range s.aliasesBySession[id] {
		ids := s.byTuple[alias]
		delete(ids, id)
		if len(ids) == 0 {
			delete(s.byTuple, alias)
		}
	}
	delete(s.aliasesBySession, id)
}

func (s *RuntimeStore) resolveTupleLocked(k flow.Key) (string, string) {
	ids := s.byTuple[k]
	if len(ids) == 0 {
		return "", "missing"
	}
	if len(ids) > s.limits.MaxAmbiguity {
		return "", "ambiguous"
	}
	if len(ids) != 1 {
		return "", "ambiguous"
	}
	for id := range ids {
		return id, "ok"
	}
	return "", "missing"
}

func (s *RuntimeStore) Resolve(tuple flow.Key) (domain.RuntimeSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, status := s.resolveTupleLocked(tuple)
	if status == "ambiguous" {
		return domain.RuntimeSession{}, ErrAliasAmbiguous
	}
	if status != "ok" {
		return domain.RuntimeSession{}, ErrSessionMissing
	}
	v := s.byID[id]
	if v == nil {
		return domain.RuntimeSession{}, ErrSessionMissing
	}
	return v.Clone(), nil
}

func (s *RuntimeStore) Get(id string) (domain.RuntimeSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.byID[id]
	if !ok {
		return domain.RuntimeSession{}, false
	}
	return v.Clone(), true
}

func (s *RuntimeStore) Close(identity domain.ConntrackIdentity, reason string, now time.Time) (domain.RuntimeSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.resolveIdentityLocked(identity)
	if id == "" {
		if identity.ID != 0 {
			return domain.RuntimeSession{}, false
		}
		if identity.Original.Valid() {
			for _, tombstone := range s.tombstones {
				if tombstoneIdentityMatches(tombstone.Identity, identity) {
					return domain.RuntimeSession{}, false
				}
			}
		}
		key := flow.Key{Scope: flow.Scope{NetworkNamespace: identity.NetworkNS, ConntrackZone: identity.Zone}, Tuple: identity.Original}
		var status string
		id, status = s.resolveTupleLocked(key)
		if status != "ok" {
			return domain.RuntimeSession{}, false
		}
	}
	if id == "" {
		return domain.RuntimeSession{}, false
	}
	v := s.byID[id]
	if v == nil {
		delete(s.byIdentity, identity)
		return domain.RuntimeSession{}, false
	}
	if identity.KernelStart != 0 && v.Identity.KernelStart != 0 && identity.KernelStart != v.Identity.KernelStart {
		return domain.RuntimeSession{}, false
	}
	if identity.ID != 0 && v.Identity.ID != 0 && identity.ID != v.Identity.ID {
		return domain.RuntimeSession{}, false
	}
	if identity.BootID != "" && v.Identity.BootID != "" && identity.BootID != v.Identity.BootID {
		return domain.RuntimeSession{}, false
	}
	if identity.NetworkNS != "" && v.Identity.NetworkNS != "" && identity.NetworkNS != v.Identity.NetworkNS {
		return domain.RuntimeSession{}, false
	}
	if identity.Original.Valid() && v.OriginalTuple != identity.Original {
		return domain.RuntimeSession{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	v.State = domain.SessionClosed
	v.ClosedAt = &now
	v.Revision++
	if reason != "" {
		v.Quality.Reason = reason
	}
	closed := v.Clone()
	s.closed = append(s.closed, closed)
	if len(s.closed) > s.limits.MaxClosed {
		s.closed = s.closed[len(s.closed)-s.limits.MaxClosed:]
	}
	s.tombstones = append(s.tombstones, tombstone{ID: id, Identity: v.Identity, At: now})
	if len(s.tombstones) > s.limits.MaxClosed {
		s.tombstones = s.tombstones[len(s.tombstones)-s.limits.MaxClosed:]
	}
	s.removeIndexesLocked(id)
	delete(s.byID, id)
	s.stats.Closed++
	s.stats.Active = uint64(len(s.byID))
	s.revision++
	return closed, true
}

func (s *RuntimeStore) Delete(id string, reason string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[id]
	if !ok {
		return ErrSessionMissing
	}
	v.State = domain.SessionClosed
	if now.IsZero() {
		now = time.Now().UTC()
	}
	closedAt := now.UTC()
	v.ClosedAt = &closedAt
	v.Quality.Reason = reason
	closed := v.Clone()
	s.closed = append(s.closed, closed)
	if len(s.closed) > s.limits.MaxClosed {
		s.closed = s.closed[len(s.closed)-s.limits.MaxClosed:]
	}
	s.tombstones = append(s.tombstones, tombstone{ID: id, Identity: v.Identity, At: closedAt})
	if len(s.tombstones) > s.limits.MaxClosed {
		s.tombstones = s.tombstones[len(s.tombstones)-s.limits.MaxClosed:]
	}
	s.removeIndexesLocked(id)
	delete(s.byID, id)
	s.stats.Closed++
	s.stats.Active = uint64(len(s.byID))
	s.revision++
	return nil
}

func (s *RuntimeStore) Invalidate(id string, generation uint64, reason string, now time.Time) (domain.RuntimeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[id]
	if !ok {
		return domain.RuntimeSession{}, ErrSessionMissing
	}
	now = now.UTC()
	v.CacheState = domain.CacheInvalidated
	v.KernelCacheVerified = false
	v.InvalidatedAt = &now
	v.InvalidationReason = reason
	v.PolicyGeneration = generation
	v.DecisionGeneration++
	v.Revision++
	s.stats.Invalidated++
	s.revision++
	return v.Clone(), nil
}

func (s *RuntimeStore) SetDecision(id string, generation uint64, action domain.Decision, policyID, reason string) (domain.RuntimeSession, error) {
	return s.setDecision(id, 0, generation, action, policyID, reason)
}

// SetDecisionIfCurrent publishes an evaluator result only if the session has
// not changed since the evaluator took its snapshot. This prevents a slow
// policy evaluation from overwriting an invalidation, revoke, or destroy.
func (s *RuntimeStore) SetDecisionIfCurrent(id string, expectedRevision, generation uint64, action domain.Decision, policyID, reason string) (domain.RuntimeSession, error) {
	return s.setDecision(id, expectedRevision, generation, action, policyID, reason)
}

func (s *RuntimeStore) setDecision(id string, expectedRevision, generation uint64, action domain.Decision, policyID, reason string) (domain.RuntimeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[id]
	if !ok {
		return domain.RuntimeSession{}, ErrSessionMissing
	}
	if (expectedRevision != 0 && v.Revision != expectedRevision) || v.Revoked || v.PolicyGeneration > generation {
		return domain.RuntimeSession{}, ErrStaleDecision
	}
	v.MatchedPolicyID = policyID
	v.PolicyGeneration = generation
	v.DecisionGeneration++
	v.Decision = action
	v.EffectiveDecision = action
	v.DecisionReason = reason
	v.CacheState = domain.CacheCached
	v.InvalidatedAt = nil
	v.InvalidationReason = ""
	v.Revision++
	s.revision++
	return v.Clone(), nil
}

func (s *RuntimeStore) MarkRevoked(id string, generation uint64, reason string) (domain.RuntimeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[id]
	if !ok {
		return domain.RuntimeSession{}, ErrSessionMissing
	}
	v.Revoked = true
	v.CacheState = domain.CacheInvalidated
	v.KernelCacheVerified = false
	v.PolicyGeneration = generation
	v.InvalidationReason = reason
	v.InvalidatedAt = ptrTime(time.Now().UTC())
	v.Decision = domain.DecisionDrop
	v.EffectiveDecision = domain.DecisionDrop
	v.DecisionReason = reason
	v.DecisionGeneration++
	v.Revision++
	s.stats.Invalidated++
	s.revision++
	return v.Clone(), nil
}

func ptrTime(value time.Time) *time.Time { return &value }

// SetZones records the deterministic zone enrichment obtained from the
// current connectivity program. It is intentionally separate from Apply so a
// conntrack adapter never has to invent interface metadata.
func (s *RuntimeStore) SetZones(id, source, destination string) (domain.RuntimeSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.byID[id]
	if !ok {
		return domain.RuntimeSession{}, ErrSessionMissing
	}
	if v.SourceZone == source && v.DestinationZone == destination {
		return v.Clone(), nil
	}
	v.SourceZone, v.DestinationZone = source, destination
	v.Revision++
	s.revision++
	return v.Clone(), nil
}

func (s *RuntimeStore) List() []domain.RuntimeSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.RuntimeSession, 0, len(s.byID))
	for _, v := range s.byID {
		out = append(out, v.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].SessionID < out[j].SessionID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *RuntimeStore) Query(filter SessionFilter, page Page) PageResult {
	s.mu.RLock()
	all := make([]domain.RuntimeSession, 0, len(s.byID))
	for _, v := range s.byID {
		all = append(all, v.Clone())
	}
	revision := s.revision
	s.mu.RUnlock()
	filtered := all[:0]
	for _, v := range all {
		if matches(v, filter) {
			filtered = append(filtered, v)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].CreatedAt.Equal(filtered[j].CreatedAt) {
			return filtered[i].SessionID < filtered[j].SessionID
		}
		return filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
	})
	if page.Size <= 0 {
		page.Size = 100
	}
	if page.Size > 500 {
		page.Size = 500
	}
	if page.Number <= 0 {
		page.Number = 1
	}
	start := (page.Number - 1) * page.Size
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + page.Size
	if end > len(filtered) {
		end = len(filtered)
	}
	items := append([]domain.RuntimeSession(nil), filtered[start:end]...)
	return PageResult{Items: items, Page: page.Number, PageSize: page.Size, Total: len(filtered), HasMore: end < len(filtered), StoreRevision: revision, SnapshotTime: time.Now().UTC()}
}

func matches(v domain.RuntimeSession, f SessionFilter) bool {
	matchesTuple := func(o domain.Tuple) bool {
		if f.SourceIP != "" && !strings.EqualFold(o.SrcIP.String(), f.SourceIP) {
			return false
		}
		if f.DestinationIP != "" && !strings.EqualFold(o.DstIP.String(), f.DestinationIP) {
			return false
		}
		if f.Protocol != 0 && o.Protocol != f.Protocol {
			return false
		}
		return true
	}
	switch f.TupleView {
	case "translated":
		if v.TranslatedTuple == nil || !matchesTuple(*v.TranslatedTuple) {
			return false
		}
	case "any":
		if !matchesTuple(v.OriginalTuple) && (v.TranslatedTuple == nil || !matchesTuple(*v.TranslatedTuple)) {
			return false
		}
	default:
		if !matchesTuple(v.OriginalTuple) {
			return false
		}
	}
	if f.SourceZone != "" && !strings.EqualFold(v.SourceZone, f.SourceZone) {
		return false
	}
	if f.DestinationZone != "" && !strings.EqualFold(v.DestinationZone, f.DestinationZone) {
		return false
	}
	if f.State != "" && v.State != f.State {
		return false
	}
	if f.Decision != "" && v.EffectiveDecision != f.Decision && v.Decision != f.Decision {
		return false
	}
	return true
}

func (s *RuntimeStore) Cleanup(now time.Time, budget int) int {
	return len(s.CleanupExpired(now, budget))
}

func (s *RuntimeStore) CleanupExpired(now time.Time, budget int) []domain.RuntimeSession {
	if budget <= 0 {
		budget = 512
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	closedNow := make([]domain.RuntimeSession, 0)
	for id, v := range s.byID {
		if len(closedNow) >= budget {
			break
		}
		if v.ExpiresAt != nil && !v.ExpiresAt.After(now) {
			v.State = domain.SessionClosed
			closedAt := now.UTC()
			v.ClosedAt = &closedAt
			s.closed = append(s.closed, v.Clone())
			if len(s.closed) > s.limits.MaxClosed {
				s.closed = s.closed[len(s.closed)-s.limits.MaxClosed:]
			}
			s.tombstones = append(s.tombstones, tombstone{ID: id, Identity: v.Identity, At: now.UTC()})
			if len(s.tombstones) > s.limits.MaxClosed {
				s.tombstones = s.tombstones[len(s.tombstones)-s.limits.MaxClosed:]
			}
			s.removeIndexesLocked(id)
			delete(s.byID, id)
			closedNow = append(closedNow, v.Clone())
		}
	}
	cutoff := now.Add(-s.limits.ClosedTTL)
	kept := s.closed[:0]
	for _, v := range s.closed {
		if v.ClosedAt != nil && v.ClosedAt.After(cutoff) {
			kept = append(kept, v)
		}
	}
	s.closed = kept
	tombs := s.tombstones[:0]
	for _, t := range s.tombstones {
		if t.At.After(cutoff) {
			tombs = append(tombs, t)
		}
	}
	s.tombstones = tombs
	if len(closedNow) > 0 {
		s.stats.Closed += uint64(len(closedNow))
		s.stats.Active = uint64(len(s.byID))
		s.revision++
	}
	return closedNow
}

// ReconcileMissing removes active sessions which were not present in a
// complete conntrack dump. The caller supplies the identities observed by one
// bounded resync and the start time of that dump. Events observed after the
// dump began are left alone because they may describe a connection created or
// updated while the multipart dump was in flight.
//
// This operation is deliberately performed under the store lock so removal,
// index cleanup and tombstone creation are atomic with respect to NEW/UPDATE/
// DESTROY events. The returned snapshots let the engine release any kernel
// guards and publish lifecycle events without holding this lock.
func (s *RuntimeStore) ReconcileMissing(seen []domain.ConntrackIdentity, before time.Time, now time.Time, reason string) []domain.RuntimeSession {
	if before.IsZero() {
		before = time.Now().UTC()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	before = before.UTC()
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	seenIDs := make(map[string]struct{}, len(seen))
	for _, identity := range seen {
		if id := s.resolveIdentityLocked(identity); id != "" {
			seenIDs[id] = struct{}{}
		}
	}
	removed := make([]domain.RuntimeSession, 0)
	for id, value := range s.byID {
		if _, present := seenIDs[id]; present {
			continue
		}
		if value.LastObservedAt.After(before) {
			continue
		}
		value.State = domain.SessionClosed
		closedAt := now
		value.ClosedAt = &closedAt
		value.CacheState = domain.CacheInvalidated
		value.KernelCacheVerified = false
		if reason != "" {
			value.Quality.Reason = reason
		}
		value.Revision++
		closed := value.Clone()
		s.closed = append(s.closed, closed)
		if len(s.closed) > s.limits.MaxClosed {
			s.closed = s.closed[len(s.closed)-s.limits.MaxClosed:]
		}
		s.tombstones = append(s.tombstones, tombstone{ID: id, Identity: value.Identity, At: now})
		if len(s.tombstones) > s.limits.MaxClosed {
			s.tombstones = s.tombstones[len(s.tombstones)-s.limits.MaxClosed:]
		}
		s.removeIndexesLocked(id)
		delete(s.byID, id)
		removed = append(removed, closed)
	}
	if len(removed) > 0 {
		s.stats.Closed += uint64(len(removed))
		s.stats.Active = uint64(len(s.byID))
		s.revision++
	}
	return removed
}

func (s *RuntimeStore) Stats() RuntimeStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.stats
	out.Active = uint64(len(s.byID))
	return out
}
func (s *RuntimeStore) Revision() uint64 { s.mu.RLock(); defer s.mu.RUnlock(); return s.revision }
func (s *RuntimeStore) Capacity() int    { return s.limits.MaxSessions }
