package dataplane

import (
	"context"
	"errors"

	"github.com/kltngfw/ngfw/internal/domain"
)

// NetworkStateRestorer applies a recovery target without compensating back to
// the failed/interrupted source. A controller owns the outer transaction and
// retains its journal if this directed recovery cannot finish.
type NetworkStateRestorer interface {
	Restore(context.Context, domain.Config, domain.Config) error
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
