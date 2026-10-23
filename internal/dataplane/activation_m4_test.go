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

func m4ActivationConfig() domain.Config {
	value := baseM1Config()
	gate := m4SelectorConfig()
	value.RequestGate, value.Profiles = gate.RequestGate, gate.Profiles
	value.Policies = gate.Policies[1:]
	return value
}

type fakeProxyRouting struct {
	active     bool
	failEnsure bool
	failVerify bool
	calls      []string
}

func (f *fakeProxyRouting) Preflight(context.Context) error {
	f.calls = append(f.calls, "preflight")
	return nil
}
func (f *fakeProxyRouting) Ensure(context.Context) error {
	f.calls = append(f.calls, "ensure")
	if f.failEnsure {
		f.failEnsure = false
		return errors.New("route failure")
	}
	f.active = true
	return nil
}
func (f *fakeProxyRouting) Remove(context.Context) error {
	f.calls = append(f.calls, "remove")
	f.active = false
	return nil
}
func (f *fakeProxyRouting) Verify(context.Context) error {
	if !f.active || f.failVerify {
		return errors.New("route missing")
	}
	return nil
}

type verifiedM4Applier struct {
	fakeBundleApplier
	verifyFail bool
}

func (f *verifiedM4Applier) VerifyBundle(context.Context, RulesetBundle) error {
	if f.verifyFail {
		return errors.New("nft drift")
	}
	return nil
}

func fakeM4Artifacts(context.Context, domain.Config, uint64) (domain.RequestGateArtifacts, error) {
	return domain.RequestGateArtifacts{RulesetID: "m4-builtin-v1", RulesetHash: strings.Repeat("a", 64), WorkerConfigHash: strings.Repeat("b", 64), CAFingerprint: strings.Repeat("c", 64)}, nil
}

func TestM4ActivationLifecycleRollbackAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "applied.json")
	rules, routes := &verifiedM4Applier{}, &fakeProxyRouting{}
	controller, err := NewController(&fakeNetworkReconciler{}, rules, &fakeForwarding{}, path)
	if err != nil {
		t.Fatal(err)
	}
	controller.ProxyRouting, controller.PrepareProxy = routes, fakeM4Artifacts
	value := m4ActivationConfig()
	if err := controller.ApplyRuntimePrepared(ctx, value, M2CompileOptions{}, 2); err != nil {
		t.Fatal(err)
	}
	if controller.M4InterceptionReady(2) || !routes.active {
		t.Fatal("prepared generation was usable or route absent")
	}
	if err := controller.FinalizeActivation(ctx, value, 2); err != nil {
		t.Fatal(err)
	}
	if !controller.M4InterceptionReady(2) || controller.M4InterceptionReady(1) {
		t.Fatal("generation readiness incorrect")
	}
	state, _, err := loadAppliedSnapshot(path)
	if err != nil || state.Snapshot.ProxyArtifacts == nil || !state.Snapshot.ProxyPlan.Enabled {
		t.Fatalf("M4 identity not durable: %+v %v", state, err)
	}
	for _, text := range []string{"@revoked_ctids", "@source_blocks", "@app_denied_v4", "hook prerouting priority -95", "tproxy ip to"} {
		if !strings.Contains(rules.bundles[0].PolicyTransaction, text) {
			t.Fatalf("missing %s", text)
		}
	}
	rules.verifyFail = true
	controller.RefreshM4Readiness(ctx)
	if controller.M4InterceptionReady(2) {
		t.Fatal("kernel drift remained ready")
	}
	rules.verifyFail = false
	controller.RefreshM4Readiness(ctx)
	// A target nft failure restores the previous route and exact M4 artifact.
	target := m4ActivationConfig()
	target.Policies[1].Services = []string{"tcp:8443"}
	rules.fail = true
	if err := controller.ApplyRuntimePrepared(ctx, target, M2CompileOptions{}, 3); err == nil {
		t.Fatal("injection did not fail")
	}
	if !routes.active || !controller.M4InterceptionReady(2) {
		t.Fatal("failed target did not restore old M4 state")
	}
	// Leave a prepared attempt behind, reconstruct controller, recover from Running.
	if err := controller.ApplyRuntimePrepared(ctx, target, M2CompileOptions{}, 3); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewController(&fakeNetworkReconciler{}, rules, &fakeForwarding{}, path)
	if err != nil || !restarted.RecoveryPending() {
		t.Fatalf("missing interrupted activation: %v", err)
	}
	restarted.ProxyRouting, restarted.PrepareProxy = routes, fakeM4Artifacts
	if err := restarted.ApplyRuntimePrepared(ctx, value, M2CompileOptions{}, 2); err != nil {
		t.Fatal(err)
	}
	if err := restarted.FinalizeActivation(ctx, value, 2); err != nil {
		t.Fatal(err)
	}
	if !restarted.M4InterceptionReady(2) {
		t.Fatal("Running not recovered")
	}
	value.RequestGate.Enabled = false
	if err := restarted.ApplyRuntimePrepared(ctx, value, M2CompileOptions{}, 4); err != nil {
		t.Fatal(err)
	}
	if err := restarted.FinalizeActivation(ctx, value, 4); err != nil {
		t.Fatal(err)
	}
	last := rules.bundles[len(rules.bundles)-1].PolicyTransaction
	if routes.active || strings.Contains(last, "tproxy ip to") || strings.Contains(last, "m4_guard ct id") {
		t.Fatal("M4 downgrade left active interception or guards")
	}
	if _, err := os.Stat(path + ".activation"); !os.IsNotExist(err) {
		t.Fatal("journal remained after complete downgrade")
	}
}

func TestM4PreflightAndArtifactCorruptionAreNonMutating(t *testing.T) {
	network, rules, forwarding := &fakeNetworkReconciler{}, &verifiedM4Applier{}, &fakeForwarding{}
	c, _ := NewController(network, rules, forwarding, filepath.Join(t.TempDir(), "applied.json"))
	c.ProxyRouting = &fakeProxyRouting{}
	c.PrepareProxy = func(context.Context, domain.Config, uint64) (domain.RequestGateArtifacts, error) {
		return domain.RequestGateArtifacts{}, errors.New("CA unavailable")
	}
	if err := c.ApplyRuntimePrepared(context.Background(), m4ActivationConfig(), M2CompileOptions{}, 2); err == nil {
		t.Fatal("preflight failed open")
	}
	if forwarding.calls != 0 || len(network.calls) != 0 || len(rules.bundles) != 0 {
		t.Fatal("preflight mutated kernel")
	}
	snapshot, _, _, err := PrepareM3Activation(m4ActivationConfig(), 2, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, _ := fakeM4Artifacts(context.Background(), snapshot.Config, 2)
	snapshot.ProxyArtifacts = &artifacts
	snapshot.ArtifactHash, _ = activationArtifactHash(snapshot)
	snapshot.ProxyArtifacts.RulesetHash = strings.Repeat("f", 64)
	if _, err := CompileActivationSnapshot(snapshot); err == nil {
		t.Fatal("tampered ruleset fingerprint accepted")
	}
	snapshot, _, _, err = PrepareM3Activation(m4ActivationConfig(), 2, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ProxyRoute.Priority++
	// Even a forged, internally re-hashed snapshot cannot choose a different
	// policy-routing priority than the engine's fixed M4 route ownership.
	snapshot.ArtifactHash, _ = activationArtifactHash(snapshot)
	if _, err := CompileActivationSnapshot(snapshot); err == nil {
		t.Fatal("altered M4 policy-route specification accepted")
	}
}

func TestM4KernelStateNormalizationIgnoresCountersButDetectsRuleChanges(t *testing.T) {
	a := `{"nftables":[{"metainfo":{"version":"1"}},{"rule":{"handle":1,"expr":[{"counter":{"packets":3,"bytes":40}},{"drop":null}]}}]}`
	b := strings.ReplaceAll(strings.ReplaceAll(a, `"handle":1`, `"handle":9`), `"packets":3`, `"packets":99`)
	left, _ := normalizeM4JSON([]byte(a))
	right, _ := normalizeM4JSON([]byte(b))
	if left != right {
		t.Fatal("mutable kernel identity changed static state")
	}
	right, _ = normalizeM4JSON([]byte(strings.ReplaceAll(b, `"drop"`, `"accept"`)))
	if left == right {
		t.Fatal("rule mutation was normalized away")
	}
}

func TestM4RestartRejectsChangedAcceptedArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applied.json")
	c, _ := NewController(&fakeNetworkReconciler{}, &verifiedM4Applier{}, &fakeForwarding{}, path)
	c.ProxyRouting, c.PrepareProxy = &fakeProxyRouting{}, fakeM4Artifacts
	value := m4ActivationConfig()
	if err := c.ApplyRuntime(context.Background(), value, M2CompileOptions{}, 2); err != nil {
		t.Fatal(err)
	}
	network := &fakeNetworkReconciler{}
	restarted, err := NewController(network, &verifiedM4Applier{}, &fakeForwarding{}, path)
	if err != nil {
		t.Fatal(err)
	}
	restarted.ProxyRouting = &fakeProxyRouting{}
	restarted.PrepareProxy = func(ctx context.Context, value domain.Config, generation uint64) (domain.RequestGateArtifacts, error) {
		a, _ := fakeM4Artifacts(ctx, value, generation)
		a.RulesetHash = strings.Repeat("d", 64)
		return a, nil
	}
	if err := restarted.ApplyRuntime(context.Background(), value, M2CompileOptions{Epoch: 99}, 2); err == nil {
		t.Fatal("modified rules silently accepted on restart")
	}
	if len(network.calls) != 0 {
		t.Fatal("artifact mismatch mutated kernel")
	}
}

func TestLegacySnapshotStillVerifiesAfterM4Upgrade(t *testing.T) {
	value := m3DataplaneConfig()
	snapshot, _, _, err := PrepareM3Activation(value, 3, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Schema = 1
	snapshot.ProxyPlan = nil
	legacy, err := CompileM3Bundle(value, snapshot.M2Options, snapshot.InspectionPlan)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ArtifactHash, _ = activationArtifactHash(snapshot)
	snapshot.StaticRulesetHash, _ = rulesetBundleHash(legacy)
	if _, err := CompileActivationSnapshot(snapshot); err != nil {
		t.Fatalf("schema-1 upgrade broke persisted M3: %v", err)
	}
}
