package engine

import (
	"context"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

// Only a unique partial tuple match is eligible. Kernel Get remains the
// authority: missing identity never becomes permission to correlate/enforce.
func (r *InspectionRuntime) enqueueIdentityRefresh(candidate domain.RuntimeSession) {
	if r == nil || r.runtime == nil || candidate.Identity.ID == 0 || candidate.Identity.KernelStart != 0 {
		return
	}
	r.identityMu.Lock()
	defer r.identityMu.Unlock()
	if _, pending := r.identityPending[candidate.SessionID]; pending {
		return
	}
	select {
	case r.identityQueue <- sessionChange{sessionID: candidate.SessionID, identity: candidate.Identity}:
		r.identityPending[candidate.SessionID] = struct{}{}
	default:
		r.identityRefreshDrops.Add(1)
	}
}

// Two fixed workers and at most 128 queued identity keys keep netlink IO off
// the observation reducer. Runtime refresh also shares its four-slot kernel
// Get budget with API reads and rechecks incarnation before merging a reply.
func (r *InspectionRuntime) identityRefreshWorker(ctx context.Context) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-r.identityQueue:
			if r.runtime != nil {
				current, ok := r.runtime.Store.Get(request.sessionID)
				if ok && current.Identity == request.identity && current.Identity.KernelStart == 0 {
					refreshCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
					r.identityRefreshAttempts.Add(1)
					r.runtime.RefreshSessionCounters(refreshCtx, current)
					cancel()
				}
			}
			r.identityMu.Lock()
			delete(r.identityPending, request.sessionID)
			r.identityMu.Unlock()
		}
	}
}
