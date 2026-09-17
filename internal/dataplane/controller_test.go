package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestControllerRestoresNetworkAndNftablesAfterNftFailure(t *testing.T) {
	network := &fakeNetworkReconciler{}
	rules := &fakeRulesetApplier{}
	forwarding := &fakeForwarding{}
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	controller, err := NewController(network, rules, forwarding, statePath)
	if err != nil {
		t.Fatal(err)
	}
	old := baseM1Config()
	old.Interfaces[1].IPv4Addresses = []string{"192.168.10.1/24"}
	if err := controller.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	desired := baseM1Config()
	desired.Interfaces[1].IPv4Addresses = []string{"192.168.20.1/24"}
	rules.failNext = true
	if err := controller.Apply(context.Background(), desired); err == nil {
		t.Fatal("expected injected nftables failure")
	}
	if len(network.calls) != 4 {
		t.Fatalf("network reconcile calls=%d, want initial/apply/two restore passes", len(network.calls))
	}
	restore := network.calls[2]
	if restore.previous.Interfaces[1].IPv4Addresses[0] != "192.168.20.1/24" || restore.desired.Interfaces[1].IPv4Addresses[0] != "192.168.10.1/24" {
		t.Fatalf("unexpected network restore transition: %#v", restore)
	}
	if cleanup := network.calls[3]; cleanup.desired.Interfaces[1].IPv4Addresses[0] != "192.168.10.1/24" {
		t.Fatalf("source cleanup did not target old config: %#v", cleanup)
	}
	if len(rules.rulesets) != 3 {
		t.Fatalf("nft calls=%d, want initial/failed new/restored old", len(rules.rulesets))
	}
	if controller.current.Interfaces[1].IPv4Addresses[0] != "192.168.10.1/24" {
		t.Fatal("controller published failed desired state")
	}
}

func TestControllerLoadsSnapshotAndReconcilesOnStartup(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dataplane-applied.json")
	first, err := NewController(&fakeNetworkReconciler{}, &fakeRulesetApplier{}, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	running := baseM1Config()
	if err := first.Apply(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	network := &fakeNetworkReconciler{}
	second, err := NewController(network, &fakeRulesetApplier{}, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !second.hasCurrent {
		t.Fatal("applied snapshot was not loaded")
	}
	if err := second.Apply(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	if len(network.calls) != 1 || len(network.calls[0].previous.Interfaces) != len(running.Interfaces) {
		t.Fatalf("startup did not reconcile from persisted snapshot: %#v", network.calls)
	}
}

func TestControllerUsesInterruptedTargetAsRecoverySource(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "dataplane-applied.json")
	previous := baseM1Config()
	attempted := baseM1Config()
	attempted.Interfaces[1].IPv4Addresses = []string{"192.168.99.1/24"}
	if err := saveAppliedState(statePath, previous); err != nil {
		t.Fatal(err)
	}
	if err := saveActivationState(statePath+".activation", activationState{Previous: previous, PreviousKnown: true, Desired: attempted}); err != nil {
		t.Fatal(err)
	}
	network := &fakeNetworkReconciler{}
	controller, err := NewController(network, &fakeRulesetApplier{}, &fakeForwarding{}, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !controller.RecoveryPending() {
		t.Fatal("interrupted activation was not detected")
	}
	if err := controller.Apply(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	if got := network.calls[0].previous.Interfaces[1].IPv4Addresses[0]; got != "192.168.99.1/24" {
		t.Fatalf("recovery source=%s, want interrupted target", got)
	}
}

type reconcileCall struct {
	previous domain.Config
	desired  domain.Config
}

type fakeNetworkReconciler struct{ calls []reconcileCall }

func (f *fakeNetworkReconciler) Reconcile(_ context.Context, previous, desired domain.Config) error {
	f.calls = append(f.calls, reconcileCall{previous: previous, desired: desired})
	return nil
}

type fakeRulesetApplier struct {
	rulesets []string
	failNext bool
}

func (f *fakeRulesetApplier) ApplyRuleset(_ context.Context, ruleset string) error {
	f.rulesets = append(f.rulesets, ruleset)
	if f.failNext {
		f.failNext = false
		return errors.New("injected nft failure")
	}
	return nil
}

type fakeForwarding struct{ calls int }

func (f *fakeForwarding) Ensure(context.Context) error {
	f.calls++
	return nil
}
