package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

type maintainedNetwork struct {
	fakeNetworkReconciler
	drift      bool
	observeErr error
	repairErr  error
}

func (n *maintainedNetwork) Verify(context.Context, domain.Config) error {
	if n.observeErr != nil {
		return n.observeErr
	}
	if n.drift {
		return ErrNetworkDrift
	}
	return nil
}

func (n *maintainedNetwork) Reconcile(ctx context.Context, old, desired domain.Config) error {
	_ = n.fakeNetworkReconciler.Reconcile(ctx, old, desired)
	if n.repairErr != nil {
		return n.repairErr
	}
	n.drift = false
	return nil
}

func TestNetworkMaintenanceRepairsWithoutPolicyGenerationOrJournalChanges(t *testing.T) {
	network, rules := &maintainedNetwork{}, &fakeRulesetApplier{}
	path := filepath.Join(t.TempDir(), "applied.json")
	c, err := NewController(network, rules, &fakeForwarding{}, path)
	if err != nil {
		t.Fatal(err)
	}
	value := baseM1Config()
	options := M2CompileOptions{Epoch: 3, ZoneSlots: map[string]uint8{"wan": 1, "lan": 2}, CacheEnabled: true}
	if err := c.ApplyRuntime(context.Background(), value, options, 9); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	networkCalls, nftCalls := len(network.calls), len(rules.rulesets)
	if repaired, err := c.MaintainNetwork(context.Background()); err != nil || repaired || len(network.calls) != networkCalls {
		t.Fatalf("healthy network was reapplied: repaired=%t err=%v", repaired, err)
	}
	network.drift = true
	if repaired, err := c.MaintainNetwork(context.Background()); err != nil || !repaired {
		t.Fatalf("drift not repaired: repaired=%t err=%v", repaired, err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || len(rules.rulesets) != nftCalls || len(network.calls) != networkCalls+1 || c.currentGeneration != 9 || c.currentM2Options.Epoch != 3 {
		t.Fatal("network repair changed policy, generation, epoch, or durable applied identity")
	}
	if _, err := os.Stat(path + ".activation"); !os.IsNotExist(err) {
		t.Fatal("maintenance created an activation journal")
	}
	// A later activation replaces the repair target; maintenance must not use
	// a previously captured Running or network observation.
	value.Interfaces[1].IPv4Addresses = []string{"192.168.90.1/24"}
	if err := c.ApplyRuntime(context.Background(), value, options, 10); err != nil {
		t.Fatal(err)
	}
	network.drift = true
	if _, err := c.MaintainNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := network.calls[len(network.calls)-1]
	if last.desired.Interfaces[1].IPv4Addresses[0] != "192.168.90.1/24" || c.currentGeneration != 10 {
		t.Fatal("maintenance restored an obsolete configuration")
	}
}

func TestNetworkMaintenanceSkipsActivationAndFailedObservations(t *testing.T) {
	network := &maintainedNetwork{drift: true}
	c, err := NewController(network, &fakeRulesetApplier{}, &fakeForwarding{}, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	c.current = baseM1Config()
	for _, state := range []string{"empty", "prepared", "recovery", "locked"} {
		c.hasCurrent, c.prepared, c.recoveryPending = state != "empty", state == "prepared", state == "recovery"
		if state == "locked" {
			c.mu.Lock()
		}
		repaired, err := c.MaintainNetwork(context.Background())
		if state == "locked" {
			c.mu.Unlock()
		}
		if err != nil || repaired || len(network.calls) != 0 {
			t.Fatalf("maintenance mutated during %s: %t %v", state, repaired, err)
		}
	}
	c.hasCurrent, c.prepared, c.recoveryPending = true, false, false
	network.observeErr = errors.New("ip read failed")
	if repaired, err := c.MaintainNetwork(context.Background()); err == nil || repaired || len(network.calls) != 0 {
		t.Fatal("failed observation triggered a network repair")
	}
	network.observeErr, network.repairErr = nil, errors.New("ip apply failed")
	if repaired, err := c.MaintainNetwork(context.Background()); err == nil || repaired {
		t.Fatal("failed repair reported as success")
	}
}

func TestActivationVerificationRejectsNetworkDriftBeforeKernelReadiness(t *testing.T) {
	network := &maintainedNetwork{drift: true}
	c, err := NewController(network, &fakeRulesetApplier{}, &fakeForwarding{}, filepath.Join(t.TempDir(), "applied.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, _, err := PrepareM3Activation(baseM1Config(), 1, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyActivation(context.Background(), snapshot); !errors.Is(err, ErrNetworkDrift) {
		t.Fatalf("activation readiness ignored the missing network: %v", err)
	}
}
