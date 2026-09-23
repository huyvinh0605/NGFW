package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

func TestRuntimeServiceRejectsShadowedPolicyBeforeReplacingCandidate(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	desired := manager.Candidate()
	desired.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	desired.Interfaces = []domain.Interface{
		{ID: "lan0", SystemName: "eth1", ZoneID: "lan", Mode: domain.InterfaceL3},
		{ID: "wan0", SystemName: "eth0", ZoneID: "wan", Mode: domain.InterfaceL3},
	}
	desired.Policies = []domain.SecurityPolicy{
		{ID: "allow-web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
		{ID: "allow-https", Priority: 20, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
	}
	service := NewRuntimeServiceAdapter(nil, manager, func(context.Context, domain.Config) error { return nil })
	if _, err := service.CommitConfig(context.Background(), desired, 0, "test", "shadow", "op-shadow"); err == nil || !strings.Contains(err.Error(), "policy allow-https is unreachable") {
		t.Fatalf("expected shadowed-policy rejection, got %v", err)
	}
	if len(manager.Candidate().Policies) != 0 {
		t.Fatalf("rejected candidate replaced manager state: %#v", manager.Candidate().Policies)
	}
}

func TestRuntimeServiceM3ActivationStageOrderAndGeneration(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	desired := manager.Candidate()
	desired.DefaultDeny = !desired.DefaultDeny
	var stages []string
	service := NewRuntimeServiceAdapter(nil, manager, nil)
	service.BeforeActivate = func(_ context.Context, _ domain.Config, generation uint64) error {
		stages = append(stages, fmt.Sprintf("preflight:%d", generation))
		return nil
	}
	service.ApplyGeneration = func(_ context.Context, _ domain.Config, generation uint64) error {
		stages = append(stages, fmt.Sprintf("apply:%d", generation))
		return nil
	}
	service.AfterActivate = func(_ context.Context, _ domain.Config, generation uint64) error {
		stages = append(stages, fmt.Sprintf("lifecycle:%d", generation))
		return nil
	}
	service.FinalizeActivation = func(_ context.Context, _ domain.Config, generation uint64) error {
		stages = append(stages, fmt.Sprintf("finalize:%d", generation))
		return nil
	}
	version, err := service.CommitConfig(context.Background(), desired, 0, "test", "m3", "op-order")
	if err != nil {
		t.Fatal(err)
	}
	if version.Version != 1 {
		t.Fatalf("version=%d", version.Version)
	}
	want := []string{"preflight:1", "apply:1", "lifecycle:1", "finalize:1"}
	if strings.Join(stages, ",") != strings.Join(want, ",") {
		t.Fatalf("activation stages=%v want=%v", stages, want)
	}
}

func TestRuntimeServicePreflightFailureHasNoActivationSideEffect(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	applyCalls := 0
	service := NewRuntimeServiceAdapter(nil, manager, nil)
	service.ApplyGeneration = func(context.Context, domain.Config, uint64) error {
		applyCalls++
		return nil
	}
	service.BeforeActivate = func(context.Context, domain.Config, uint64) error { return errors.New("artifact hash mismatch") }
	if _, err := service.CommitConfig(context.Background(), manager.Candidate(), 0, "test", "m3", "op-preflight"); err == nil || !strings.Contains(err.Error(), "artifact hash mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
	if applyCalls != 0 || manager.Version().Version != 0 {
		t.Fatalf("preflight failure mutated activation: apply=%d version=%d", applyCalls, manager.Version().Version)
	}
}

func TestRuntimeServiceFailedApplyRestoresPreviousExactGenerationAndFinalizes(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	desired := manager.Candidate()
	desired.DefaultDeny = !desired.DefaultDeny
	var applied []uint64
	var finalized []uint64
	service := NewRuntimeServiceAdapter(nil, manager, nil)
	service.ApplyGeneration = func(_ context.Context, value domain.Config, generation uint64) error {
		applied = append(applied, generation)
		if value.DefaultDeny == desired.DefaultDeny {
			return errors.New("nft failed")
		}
		return nil
	}
	service.FinalizeActivation = func(_ context.Context, _ domain.Config, generation uint64) error {
		finalized = append(finalized, generation)
		return nil
	}
	if _, err := service.CommitConfig(context.Background(), desired, 0, "test", "m3", "op-fail"); err == nil {
		t.Fatal("expected activation failure")
	}
	if len(applied) != 2 || applied[0] != 1 || applied[1] != 0 {
		t.Fatalf("apply generations=%v, want target 1 then previous 0", applied)
	}
	if len(finalized) != 1 || finalized[0] != 0 || manager.Version().Version != 0 {
		t.Fatalf("restored activation was not finalized: finalized=%v version=%d", finalized, manager.Version().Version)
	}
}

func TestRuntimeServicePostPublishFailureRestoresThroughNewerGeneration(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	desired := manager.Candidate()
	desired.DefaultDeny = !desired.DefaultDeny
	var applied, finalized []uint64
	service := NewRuntimeServiceAdapter(nil, manager, nil)
	service.ApplyGeneration = func(_ context.Context, _ domain.Config, generation uint64) error {
		applied = append(applied, generation)
		return nil
	}
	firstLifecycle := true
	service.AfterActivate = func(_ context.Context, _ domain.Config, _ uint64) error {
		if firstLifecycle {
			firstLifecycle = false
			return errors.New("runtime lifecycle failed")
		}
		return nil
	}
	service.FinalizeActivation = func(_ context.Context, _ domain.Config, generation uint64) error {
		finalized = append(finalized, generation)
		return nil
	}
	version, err := service.CommitConfig(context.Background(), desired, 0, "test", "m3", "op-post-publish")
	if err == nil || !strings.Contains(err.Error(), "runtime lifecycle failed") {
		t.Fatalf("unexpected result version=%#v err=%v", version, err)
	}
	if version.Version != 2 || manager.Version().Version != 2 {
		t.Fatalf("restoration did not advance monotonically: result=%d running=%d", version.Version, manager.Version().Version)
	}
	if len(applied) != 2 || applied[0] != 1 || applied[1] != 2 {
		t.Fatalf("apply generations=%v, want target 1 and recovery 2", applied)
	}
	if len(finalized) != 1 || finalized[0] != 2 {
		t.Fatalf("recovery finalization=%v", finalized)
	}
}

func TestRuntimeServiceHoldsInspectionGateAcrossApplyAndReleasesBeforeLifecycleHook(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(nil, connectivity.Program{}, 0, session.DefaultRuntimeLimits())
	inspectionRuntime := NewInspectionRuntime(runtime, domain.InspectionLimits{}, nil)
	runtime.SetInspectionRuntime(inspectionRuntime)
	applyChecked := false
	service := NewRuntimeServiceAdapter(runtime, manager, func(context.Context, domain.Config) error {
		if inspectionRuntime.gate.TryRLock() {
			inspectionRuntime.gate.RUnlock()
			return errors.New("inspection activation gate was open during dataplane apply")
		}
		applyChecked = true
		return nil
	})
	hookChecked := false
	service.AfterActivate = func(context.Context, domain.Config, uint64) error {
		if !inspectionRuntime.gate.TryRLock() {
			return errors.New("inspection activation gate remained locked during lifecycle hook")
		}
		inspectionRuntime.gate.RUnlock()
		hookChecked = true
		return nil
	}
	version, err := service.CommitConfig(context.Background(), manager.Candidate(), 0, "test", "activation gate", "op-gate")
	if err != nil {
		t.Fatal(err)
	}
	if version.Version != 1 || runtime.CurrentGeneration() != 1 {
		t.Fatalf("unexpected generation: version=%d runtime=%d", version.Version, runtime.CurrentGeneration())
	}
	if !applyChecked || !hookChecked {
		t.Fatalf("activation phases were not exercised: apply=%v hook=%v", applyChecked, hookChecked)
	}
}
