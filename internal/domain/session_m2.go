package domain

import "time"

type SessionState string

const (
	SessionNew         SessionState = "NEW"
	SessionEstablished SessionState = "ESTABLISHED"
	SessionClosing     SessionState = "CLOSING"
	SessionClosed      SessionState = "CLOSED"
)

type CacheState string

const (
	CacheNotEvaluated CacheState = "NOT_EVALUATED"
	CacheCached       CacheState = "CACHED"
	CacheInvalidated  CacheState = "INVALIDATED"
)

type TrackingStatus string

const (
	TrackingComplete  TrackingStatus = "COMPLETE"
	TrackingPartial   TrackingStatus = "PARTIAL"
	TrackingStale     TrackingStatus = "STALE"
	TrackingAmbiguous TrackingStatus = "AMBIGUOUS"
)

type IdentityConfidence string

const (
	IdentityComplete  IdentityConfidence = "COMPLETE"
	IdentityPartial   IdentityConfidence = "PARTIAL"
	IdentityAmbiguous IdentityConfidence = "AMBIGUOUS"
)

// NATInfo keeps both kernel tuples and the derived forward view used by the
// L3/L4 policy evaluator. A method is UNKNOWN unless the adapter has direct
// evidence for the configured NAT rule.
type NATInfo struct {
	OriginalTuple           *Tuple `json:"original_tuple,omitempty"`
	ReplyTuple              *Tuple `json:"reply_tuple,omitempty"`
	TranslatedTuple         *Tuple `json:"translated_tuple,omitempty"`
	PreNATSource            string `json:"pre_nat_source,omitempty"`
	PreNATDestination       string `json:"pre_nat_destination,omitempty"`
	PostNATSource           string `json:"post_nat_source,omitempty"`
	PostNATDestination      string `json:"post_nat_destination,omitempty"`
	SNAT                    bool   `json:"snat"`
	DNAT                    bool   `json:"dnat"`
	SourceTranslationMethod string `json:"source_translation_method,omitempty"`
	MatchedRuleID           string `json:"matched_rule_id,omitempty"`
	EvidenceGeneration      uint64 `json:"evidence_generation,omitempty"`
}

type ConntrackIdentity struct {
	BootID      string   `json:"boot_id,omitempty"`
	NetworkNS   string   `json:"network_namespace,omitempty"`
	Zone        uint16   `json:"conntrack_zone,omitempty"`
	Family      IPFamily `json:"family"`
	ID          uint32   `json:"conntrack_id,omitempty"`
	KernelStart uint64   `json:"kernel_start,omitempty"`
	Original    Tuple    `json:"original_tuple"`
}

type SessionQuality struct {
	TrackingStatus     TrackingStatus     `json:"tracking_status"`
	IdentityConfidence IdentityConfidence `json:"identity_confidence"`
	MissingFields      []string           `json:"missing_fields,omitempty"`
	Reason             string             `json:"reason,omitempty"`
	LastResyncID       uint64             `json:"last_resync_id,omitempty"`
}

// RuntimeSession is the M2 canonical session representation. The legacy
// domain.Session remains as a compatibility DTO for M1 callers and is derived
// from this object at the API boundary.
type RuntimeSession struct {
	SessionID           string            `json:"session_id"`
	Identity            ConntrackIdentity `json:"identity"`
	OriginalTuple       Tuple             `json:"original_tuple"`
	ReplyTuple          *Tuple            `json:"reply_tuple,omitempty"`
	TranslatedTuple     *Tuple            `json:"translated_tuple,omitempty"`
	NAT                 NATInfo           `json:"nat"`
	IPFamily            IPFamily          `json:"ip_family"`
	Protocol            uint8             `json:"protocol"`
	SourceZone          string            `json:"source_zone,omitempty"`
	DestinationZone     string            `json:"destination_zone,omitempty"`
	State               SessionState      `json:"state"`
	CreatedAt           time.Time         `json:"created_at"`
	LastSeen            time.Time         `json:"last_seen"`
	LastObservedAt      time.Time         `json:"last_observed_at"`
	ExpiresAt           *time.Time        `json:"expires_at,omitempty"`
	ClosedAt            *time.Time        `json:"closed_at,omitempty"`
	PacketsOriginal     uint64            `json:"packets_original"`
	BytesOriginal       uint64            `json:"bytes_original"`
	PacketsReply        uint64            `json:"packets_reply"`
	BytesReply          uint64            `json:"bytes_reply"`
	MatchedPolicyID     string            `json:"matched_policy_id,omitempty"`
	PolicyGeneration    uint64            `json:"policy_generation"`
	Decision            Decision          `json:"decision,omitempty"`
	DecisionGeneration  uint64            `json:"decision_generation"`
	DecisionReason      string            `json:"decision_reason,omitempty"`
	CacheState          CacheState        `json:"cache_state"`
	InvalidatedAt       *time.Time        `json:"invalidated_at,omitempty"`
	InvalidationReason  string            `json:"invalidation_reason,omitempty"`
	KernelEpoch         uint16            `json:"kernel_epoch,omitempty"`
	KernelMark          uint32            `json:"kernel_mark,omitempty"`
	KernelCacheVerified bool              `json:"kernel_cache_verified"`
	EffectiveDecision   Decision          `json:"effective_decision,omitempty"`
	Revoked             bool              `json:"revoked"`
	Revision            uint64            `json:"revision"`
	Quality             SessionQuality    `json:"quality"`
}

func (s RuntimeSession) Clone() RuntimeSession {
	c := s
	if s.ReplyTuple != nil {
		v := *s.ReplyTuple
		c.ReplyTuple = &v
	}
	if s.TranslatedTuple != nil {
		v := *s.TranslatedTuple
		c.TranslatedTuple = &v
	}
	c.NAT = s.NAT
	if s.NAT.OriginalTuple != nil {
		v := *s.NAT.OriginalTuple
		c.NAT.OriginalTuple = &v
	}
	if s.NAT.ReplyTuple != nil {
		v := *s.NAT.ReplyTuple
		c.NAT.ReplyTuple = &v
	}
	if s.NAT.TranslatedTuple != nil {
		v := *s.NAT.TranslatedTuple
		c.NAT.TranslatedTuple = &v
	}
	c.Quality.MissingFields = append([]string(nil), s.Quality.MissingFields...)
	return c
}
