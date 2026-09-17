package config

import (
	"context"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
	"testing"
)

func TestCommitAndVersionConflict(t *testing.T) {
	m, err := NewManager(t.TempDir(), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	c := m.Candidate()
	c.Zones = []domain.Zone{{ID: "lan"}}
	if errs := m.SetCandidate(c); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := m.Commit("test", "first", 99); err == nil {
		t.Fatal("expected version conflict")
	}
	v, err := m.Commit("test", "first", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != 1 {
		t.Fatalf("version=%d", v.Version)
	}
	if _, err := m.Rollback("test", "rollback"); err != nil {
		t.Fatal(err)
	}
}

func TestValidatorChecksInterfaceVLANAddressModeAndNATType(t *testing.T) {
	value := Defaults()
	value.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	value.Interfaces = []domain.Interface{
		{ID: "parent", SystemName: "eth1", Mode: domain.InterfaceVLANParent},
		{ID: "vlan10", SystemName: "eth1.10", Mode: domain.InterfaceVLANSub, ParentInterfaceID: "parent", VLANID: 10, ZoneID: "lan", IPv4Addresses: []string{"10.10.0.1/24"}, MTU: 1500},
		{ID: "wan0", SystemName: "eth0", Mode: domain.InterfaceL3, ZoneID: "wan"},
	}
	if errs := (Validator{}).Validate(value); len(errs) != 0 {
		t.Fatalf("valid VLAN config rejected: %v", errs)
	}
	value.Interfaces[1].VLANID = 4095
	value.Interfaces[1].IPv4Addresses = []string{"10.10.0.1"}
	value.NATRules = []domain.NATRule{{ID: "bad-nat", Type: "REDIRECT", SourceZone: "lan", DestinationZone: "wan", Enabled: true}}
	errors := strings.Join((Validator{}).Validate(value), "\n")
	for _, expected := range []string{"outside 1..4094", "invalid address prefix", "invalid type"} {
		if !strings.Contains(errors, expected) {
			t.Fatalf("missing validation error %q in:\n%s", expected, errors)
		}
	}
}

func TestRollbackWithApplySurvivesManagerRestart(t *testing.T) {
	directory := t.TempDir()
	manager, err := NewManager(directory, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Candidate()
	candidate.Zones = []domain.Zone{{ID: "lan"}}
	if errs := manager.SetCandidate(candidate); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := manager.CommitWithApply(context.Background(), "test", "commit", 0, func(context.Context, domain.Config) error { return nil }); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(directory, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	var applied domain.Config
	version, err := restarted.RollbackWithApply(context.Background(), "test", "rollback", func(_ context.Context, value domain.Config) error {
		applied = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if version.Version != 2 || len(applied.Zones) != 0 || len(restarted.Running().Zones) != 0 {
		t.Fatalf("previous config was not applied after restart: version=%d applied=%#v", version.Version, applied)
	}
}

func TestCommitApplyFailureRestoresOldConfigAndDoesNotPublish(t *testing.T) {
	manager, err := NewManager(t.TempDir(), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Candidate()
	candidate.Zones = []domain.Zone{{ID: "lan"}}
	manager.SetCandidate(candidate)
	var calls []domain.Config
	_, err = manager.CommitWithApply(context.Background(), "test", "failure", 0, func(_ context.Context, value domain.Config) error {
		calls = append(calls, value)
		if len(value.Zones) != 0 {
			return context.DeadlineExceeded
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected activation failure")
	}
	if len(calls) != 2 || len(calls[1].Zones) != 0 {
		t.Fatalf("old config was not restored: %#v", calls)
	}
	if manager.Version().Version != 0 || len(manager.Running().Zones) != 0 {
		t.Fatal("failed candidate was published")
	}
}
