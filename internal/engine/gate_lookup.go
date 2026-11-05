package engine

import (
	"context"
	"time"

	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/session"
)

// A new SYN may reuse a tuple while the old CLOSING entry is still in RAM.
// Consult the live kernel identity before pinning a proxy connection to M2.
// Do not merge this read: an asynchronous lifecycle event remains the store
// owner, and a delayed lookup must not recreate a closed incarnation.
func (service *GateService) resolveProxySession(ctx context.Context, tuple domain.Tuple) (domain.RuntimeSession, error) {
	source, supported := service.Runtime.Source.(conntrack.ReplyLookupSource)
	if !supported {
		return service.Runtime.Store.Resolve(flow.Key{Scope: service.Scope, Tuple: tuple})
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	select {
	case service.Runtime.refreshSlots <- struct{}{}:
		defer func() { <-service.Runtime.refreshSlots }()
	case <-lookupCtx.Done():
		return domain.RuntimeSession{}, lookupCtx.Err()
	}
	reply := tuple.Reverse()
	record, err := source.LookupReply(lookupCtx, reply, service.Scope.ConntrackZone)
	if err != nil {
		return domain.RuntimeSession{}, err // unavailable/absent is not permission.
	}
	identity := record.Identity
	if !record.Presence.ID || identity.ID == 0 || !identity.Original.Valid() ||
		identity.NetworkNS != service.Scope.NetworkNamespace || identity.Zone != service.Scope.ConntrackZone ||
		identity.Family != tuple.Family || !record.Presence.ReplyTuple || record.ReplyTuple == nil || *record.ReplyTuple != reply {
		return domain.RuntimeSession{}, conntrack.ErrAmbiguousIdentity
	}
	value, err := service.Runtime.Store.ResolveIdentity(identity)
	if err != nil {
		return domain.RuntimeSession{}, err
	}
	if identity.KernelStart != 0 && value.Identity.KernelStart != 0 && identity.KernelStart != value.Identity.KernelStart {
		return domain.RuntimeSession{}, session.ErrSessionMissing
	}
	// ApplyObserved publishes the record before the event reducer sets zones.
	// Evaluating that interim record would cache a false default-deny result.
	// Keep the connection unbound and use OpenConnection's authoritative
	// first-match fallback until enrichment completes. An existing deny or
	// revoke must still be returned to the caller and enforced.
	if (value.SourceZone == "" || value.DestinationZone == "") &&
		value.Decision == "" && value.EffectiveDecision == "" && !value.Revoked && value.State != domain.SessionClosed {
		return domain.RuntimeSession{}, session.ErrSessionMissing
	}
	return value, nil
}
