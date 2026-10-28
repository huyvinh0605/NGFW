package dataplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/kltngfw/ngfw/internal/domain"
)

// NetworkStateRestorer applies a recovery target without compensating back to
// the failed/interrupted source. A controller owns the outer transaction and
// retains its journal if this directed recovery cannot finish.
type NetworkStateRestorer interface {
	Restore(context.Context, domain.Config, domain.Config) error
}

var ErrActivationRecoveryPending = errors.New("pending activation recovery must finish before applying an unrelated configuration")

// A retained journal describes exactly two possible configurations. Applying
// a third target before completing recovery would leave its new objects
// unrecorded if the engine crashed again before publishing Running.
func (c *Controller) validateRecoveryTarget(desired domain.Config) error {
	if !c.recoveryPending {
		return nil
	}
	wanted, err := configChecksum(desired)
	if err != nil {
		return err
	}
	for _, known := range []struct {
		value domain.Config
		valid bool
	}{{c.current, true}, {c.recoveryPrevious, c.recoveryPreviousKnown}} {
		if !known.valid {
			continue
		}
		hash, err := configChecksum(known.value)
		if err != nil {
			return err
		}
		if wanted == hash {
			return nil
		}
	}
	return ErrActivationRecoveryPending
}

func (c *Controller) reconcileActivationNetwork(ctx context.Context, source, desired, previous domain.Config, previousKnown bool) error {
	if err := c.reconcileNetwork(ctx, source, desired, c.recoveryPending); err != nil {
		return err
	}
	if c.recoveryPending && previousKnown {
		// An interrupted compensation may already have restored some or all
		// previous objects. Check both journaled sources when replaying target.
		if err := c.reconcileNetwork(ctx, previous, desired, true); err != nil {
			return fmt.Errorf("remove previous recovery leftovers: %w", err)
		}
	}
	return nil
}

func (r *NetworkReconciler) Restore(ctx context.Context, previous, desired domain.Config) error {
	if r == nil || r.Runner == nil {
		return errors.New("network reconciler has no ip command runner")
	}
	plan, err := PlanNetwork(previous, desired)
	if err != nil {
		return err
	}
	if err := r.applyPlan(ctx, plan); err != nil {
		return err
	}
	return r.VerifyTransition(ctx, previous, desired)
}

func (c *Controller) reconcileNetwork(ctx context.Context, previous, desired domain.Config, recovering bool) error {
	if recovering {
		if restorer, ok := c.network.(NetworkStateRestorer); ok {
			return restorer.Restore(ctx, previous, desired)
		}
	}
	// Legacy adapters still supply their original reconciliation interface.
	return c.network.Reconcile(ctx, previous, desired)
}
