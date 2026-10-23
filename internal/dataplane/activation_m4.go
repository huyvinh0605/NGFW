package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type ProxyRoutingManager interface {
	Preflight(context.Context) error
	Ensure(context.Context) error
	Remove(context.Context) error
	Verify(context.Context) error
}

func snapshotUsesM4(snapshot *ActivationSnapshot) bool {
	return snapshot != nil && snapshot.ProxyPlan != nil && snapshot.ProxyPlan.Enabled
}

func withM4Bundle(bundle RulesetBundle, value domain.Config, plan ProxySelectionPlan) (RulesetBundle, error) {
	selector, err := RenderM4TPROXYSelection(value, plan)
	if err != nil {
		return RulesetBundle{}, err
	}
	bundle.ProxySchema = ProxySchemaScript()
	bundle.PolicyTransaction += "\n" + selector + renderM4RuntimeGuards(value, plan.Enabled)
	if len(bundle.ExpectedObjects) == 0 {
		bundle.ExpectedObjects = []string{"inet/ngfw", "inet/ngfw_runtime", "inet/ngfw_inspection"}
	}
	bundle.ExpectedObjects = append(bundle.ExpectedObjects, "inet/ngfw_proxy")
	return bundle, nil
}

// The sets stay in their original tables. Only the owned chains are replaced,
// preserving live timeout elements across commits and rollback. These guards
// precede TPROXY because intercepted packets no longer visit the forward hook.
func renderM4RuntimeGuards(value domain.Config, enabled bool) string {
	var out strings.Builder
	for _, table := range []string{"ngfw_runtime", "ngfw_inspection"} {
		fmt.Fprintf(&out, "add chain inet %s m4_guard { type filter hook prerouting priority -95; policy accept; }\nflush chain inet %s m4_guard\n", table, table)
		if !enabled {
			continue
		}
		prefix := "add rule inet " + table + " m4_guard "
		out.WriteString(prefix + "fib daddr type local return\n")
		out.WriteString(prefix + "iifname \"lo\" return\n")
		for _, iface := range value.Interfaces {
			if iface.Mode == domain.InterfaceManagement {
				out.WriteString(prefix + "iifname " + quoteSet([]string{iface.SystemName}) + " return\n")
				out.WriteString(prefix + "fib daddr oifname " + quoteSet([]string{iface.SystemName}) + " return\n")
			}
		}
		if table == "ngfw_runtime" {
			for _, rule := range []string{"ct state invalid drop", "ct id @revoked_ctids drop", "ip saddr @source_blocks drop", "ip daddr @source_blocks drop"} {
				out.WriteString(prefix + rule + "\n")
			}
		} else {
			out.WriteString(prefix + "meta l4proto { tcp, udp } ct zone . ct id . ct original ip saddr . ct original proto-src . ct original ip daddr . ct original proto-dst . meta l4proto @app_denied_v4 drop\n")
		}
	}
	return out.String()
}

func (c *Controller) prepareM4(ctx context.Context, target *ActivationSnapshot) error {
	if !snapshotUsesM4(target) {
		return nil
	}
	if c.ProxyRouting == nil || c.PrepareProxy == nil {
		return ErrM4ActivationUnavailable
	}
	// A restart recompiles with a new conntrack epoch, but must retain the
	// already accepted artifact identity for the same Running config/version.
	if target.ProxyArtifacts == nil {
		targetHash, _ := configChecksum(target.Config)
		for _, durable := range []*ActivationSnapshot{c.currentSnapshot, c.recoverySnapshot} {
			if durable == nil || durable.ProxyArtifacts == nil || durable.Generation != target.Generation {
				continue
			}
			durableHash, _ := configChecksum(durable.Config)
			if targetHash == durableHash {
				copy := *durable.ProxyArtifacts
				target.ProxyArtifacts = &copy
				break
			}
		}
	}
	if err := c.ProxyRouting.Preflight(ctx); err != nil {
		return fmt.Errorf("M4 policy routing preflight: %w", err)
	}
	artifacts, err := c.PrepareProxy(ctx, target.Config, target.Generation)
	if err != nil {
		return err
	}
	if target.ProxyArtifacts != nil && *target.ProxyArtifacts != artifacts {
		return errors.New("M4 installed artifacts differ from activation snapshot")
	}
	if artifacts.RulesetID != domain.EffectiveRequestGateConfig(target.Config).RulesetID || len(artifacts.RulesetHash) != 64 || len(artifacts.WorkerConfigHash) != 64 {
		return errors.New("M4 preflight returned incomplete artifact identity")
	}
	target.ProxyArtifacts = &artifacts
	target.ArtifactHash, err = activationArtifactHash(*target)
	return err
}

// Kernel observations are refreshed on a bounded monitor, never by forking
// ip/nft for each HTTP request. Every activation invalidates the observation
// immediately; only verification of the published snapshot can restore it.
type m4RuntimeIdentity struct {
	generation uint64
	artifacts  domain.RequestGateArtifacts
}

func (c *Controller) M4InterceptionReady(generation uint64) bool {
	state := c.m4Runtime.Load()
	return state != nil && generation != 0 && state.generation == generation
}

func (c *Controller) M4Artifacts(generation uint64) domain.RequestGateArtifacts {
	state := c.m4Runtime.Load()
	if state != nil && state.generation == generation {
		return state.artifacts
	}
	return domain.RequestGateArtifacts{}
}

func (c *Controller) refreshM4ReadinessLocked(parent context.Context) {
	if c.prepared || c.recoveryPending || !snapshotUsesM4(c.currentSnapshot) || c.currentSnapshot.ProxyArtifacts == nil || c.ProxyRouting == nil {
		c.m4Runtime.Store(nil)
		return
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if c.VerifyActivation(ctx, *c.currentSnapshot) != nil {
		c.m4Runtime.Store(nil)
		return
	}
	c.m4Runtime.Store(&m4RuntimeIdentity{generation: c.currentGeneration, artifacts: *c.currentSnapshot.ProxyArtifacts})
}

func (c *Controller) RefreshM4Readiness(ctx context.Context) {
	if !c.mu.TryLock() {
		return
	}
	defer c.mu.Unlock()
	c.refreshM4ReadinessLocked(ctx)
}

func (c *Controller) MonitorM4Readiness(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.m4Runtime.Store(nil)
			return
		case <-ticker.C:
			c.RefreshM4Readiness(ctx)
		}
	}
}
