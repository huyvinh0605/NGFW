package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestRestoreFailureNeverReinstallsFailedSource(t *testing.T) {
	runner := &fakeIPRunner{failOnceContains: "addr replace 10.0.0.1/24"}
	previous := domain.Config{Interfaces: []domain.Interface{{ID: "lan", SystemName: "eth1", Mode: domain.InterfaceL3, IPv4Addresses: []string{"10.0.1.1/24"}}}}
	desired := domain.Config{Interfaces: []domain.Interface{{ID: "lan", SystemName: "eth1", Mode: domain.InterfaceL3, IPv4Addresses: []string{"10.0.0.1/24"}}}}
	if err := NewNetworkReconciler(runner).Restore(context.Background(), previous, desired); err == nil {
		t.Fatal("expected restoration failure")
	}
	if strings.Contains(strings.Join(runner.Commands(), "\n"), "addr replace 10.0.1.1/24") {
		t.Fatal("recovery attempted to reinstall the failed source")
	}
}

type networkRestorerSpy struct {
	fakeNetworkReconciler
	restored []reconcileCall
}

func (s *networkRestorerSpy) Restore(_ context.Context, previous, desired domain.Config) error {
	s.restored = append(s.restored, reconcileCall{previous: previous, desired: desired})
	return nil
}

func TestControllerCompensationAndStartupUseDirectedRestore(t *testing.T) {
	for _, m3 := range []bool{false, true} {
		network := &networkRestorerSpy{}
		rules := &fakeBundleApplier{}
		path := filepath.Join(t.TempDir(), "applied.json")
		controller, err := NewController(network, rules, &fakeForwarding{}, path)
		if err != nil {
			t.Fatal(err)
		}
		previous := baseM1Config()
		if m3 {
			previous = m3DataplaneConfig()
		}
		apply := func(c *Controller, value domain.Config, generation uint64) error {
			if m3 {
				return c.ApplyRuntime(context.Background(), value, M2CompileOptions{}, generation)
			}
			return c.Apply(context.Background(), value)
		}
		if err := apply(controller, previous, 1); err != nil {
			t.Fatal(err)
		}
		target := cloneNetworkTestConfig(t, previous)
		target.DefaultDeny = !previous.DefaultDeny
		rules.failNext, rules.fail = true, true
		if err := apply(controller, target, 2); err == nil {
			t.Fatal("expected nft failure")
		}
		if len(network.calls) != 2 || len(network.restored) != 2 || controller.RecoveryPending() {
			t.Fatalf("compensation called transactional forward reconcile: apply=%d restore=%d pending=%t", len(network.calls), len(network.restored), controller.RecoveryPending())
		}
		// A durable interrupted journal must select the same directed path.
		if err := saveActivationState(path+".activation", activationState{Previous: previous, PreviousKnown: true, Desired: target}); err != nil {
			t.Fatal(err)
		}
		restarted, err := NewController(network, &fakeBundleApplier{}, &fakeForwarding{}, path)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(restarted, previous, 1); err != nil {
			t.Fatal(err)
		}
		if len(network.calls) != 2 || len(network.restored) != 3 {
			t.Fatal("startup recovery used forward reconciliation")
		}
	}
}

func cloneNetworkTestConfig(t *testing.T, value domain.Config) domain.Config {
	t.Helper()
	copy, err := cloneActivationConfig(value)
	if err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestCancelledIPCommandRemainsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewExecIPCommandRunner(os.Args[0]).Run(ctx, "-test.run=TestNoSuchTest")
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrIPObjectNotFound) {
		t.Fatalf("cancellation classified as harmless absence: %v", err)
	}
}

type journalRemovalFailureRules struct {
	fakeBundleApplier
	journal      string
	breakOnApply bool
}

func (r *journalRemovalFailureRules) ApplyBundle(ctx context.Context, bundle RulesetBundle) error {
	if r.breakOnApply {
		r.breakOnApply = false
		if err := os.Remove(r.journal); err != nil {
			return err
		}
		if err := os.Mkdir(r.journal, 0700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(r.journal, "blocked"), []byte("injected removal failure"), 0600); err != nil {
			return err
		}
		return errors.New("injected nft failure")
	}
	return r.fakeBundleApplier.ApplyBundle(ctx, bundle)
}

func TestM3CompensationReportsJournalRemovalFailure(t *testing.T) {
	state := filepath.Join(t.TempDir(), "applied.json")
	rules := &journalRemovalFailureRules{journal: state + ".activation"}
	controller, err := NewController(&networkRestorerSpy{}, rules, &fakeForwarding{}, state)
	if err != nil {
		t.Fatal(err)
	}
	value := m3DataplaneConfig()
	if err := controller.ApplyRuntime(context.Background(), value, M2CompileOptions{}, 1); err != nil {
		t.Fatal(err)
	}
	rules.breakOnApply = true
	err = controller.ApplyRuntimePrepared(context.Background(), value, M2CompileOptions{}, 2)
	if err == nil || !strings.Contains(err.Error(), "remove rolled-back activation journal") || !controller.RecoveryPending() {
		t.Fatalf("journal removal failure was silently reported as a completed rollback: %v", err)
	}
}
