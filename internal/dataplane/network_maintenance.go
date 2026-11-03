package dataplane

import (
	"context"
	"errors"
	"fmt"
)

// MaintainNetwork repairs external loss of engine-owned network objects using
// only the last applied target. It does not recompile nft, advance epochs,
// publish Running, or touch an activation journal. The controller lock prevents
// a stale observation/repair from overwriting a concurrent commit or rollback.
func (c *Controller) MaintainNetwork(ctx context.Context) (bool, error) {
	if !c.mu.TryLock() {
		return false, nil
	}
	defer c.mu.Unlock()
	if !c.hasCurrent || c.prepared || c.recoveryPending {
		return false, nil
	}
	verifier, ok := c.network.(NetworkStateVerifier)
	if !ok {
		return false, errors.New("configured network adapter cannot verify kernel state")
	}
	err := verifier.Verify(ctx, c.current)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ErrNetworkDrift) {
		return false, err
	}
	c.m4Runtime.Store(nil)
	if repairErr := c.network.Reconcile(ctx, c.current, c.current); repairErr != nil {
		return false, errors.Join(err, fmt.Errorf("repair managed network: %w", repairErr))
	}
	if verifyErr := verifier.Verify(ctx, c.current); verifyErr != nil {
		return false, fmt.Errorf("verify repaired network: %w", verifyErr)
	}
	return true, nil
}
