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

func TestCommitWithGenerationNeverRestoresOldConfigUsingTargetGeneration(t *testing.T) {
	manager, err := NewManager(t.TempDir(), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Candidate()
	candidate.Zones = []domain.Zone{{ID: "lan"}}
	if errs := manager.SetCandidate(candidate); len(errs) != 0 {
		t.Fatal(errs)
	}
	type call struct {
		generation uint64
		zones      int
	}
	var calls []call
	_, err = manager.CommitWithGeneration(context.Background(), "test", "failure", 0, func(_ context.Context, value domain.Config, generation uint64) error {
		calls = append(calls, call{generation: generation, zones: len(value.Zones)})
		if len(value.Zones) != 0 {
			return context.DeadlineExceeded
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected activation failure")
	}
	if len(calls) != 2 || calls[0].generation != 1 || calls[0].zones != 1 || calls[1].generation != 0 || calls[1].zones != 0 {
		t.Fatalf("unexpected target/restore generations: %#v", calls)
	}
	if manager.Version().Version != 0 {
		t.Fatal("failed activation advanced running generation")
	}
}

func TestCandidateValidationIsBoundToCandidateChecksum(t *testing.T) {
	m, err := NewManager(t.TempDir(), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	state, _, _, valid := m.CandidateValidation()
	if state != "NOT_RUN" || valid {
		t.Fatalf("initial validation state=%s valid=%v", state, valid)
	}
	m.MarkCandidateValidation(true)
	state, _, _, valid = m.CandidateValidation()
	if state != "VALID" || !valid {
		t.Fatalf("marked validation state=%s valid=%v", state, valid)
	}
	candidate := m.Candidate()
	candidate.DefaultDeny = !candidate.DefaultDeny
	if errs := m.SetCandidate(candidate); len(errs) != 0 {
		t.Fatal(errs)
	}
	state, _, _, valid = m.CandidateValidation()
	if state != "NOT_RUN" || valid {
		t.Fatalf("edited candidate retained validation state=%s valid=%v", state, valid)
	}
}

func TestCandidateValidationForRejectsStaleSnapshot(t *testing.T) {
	m, err := NewManager(t.TempDir(), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := m.Candidate()
	changed := snapshot
	changed.DefaultDeny = !changed.DefaultDeny
	if errs := m.SetCandidate(changed); len(errs) != 0 {
		t.Fatal(errs)
	}
	if m.MarkCandidateValidationFor(snapshot, true) {
		t.Fatal("stale validation snapshot was accepted")
	}
	state, _, _, valid := m.CandidateValidation()
	if state != "NOT_RUN" || valid {
		t.Fatalf("stale validation changed state=%s valid=%v", state, valid)
	}
}

func TestValidatorServiceTable(t *testing.T) {
	cases := []struct {
		value string
		valid bool
	}{
		{"tcp:80", true}, {"tcp:443", true}, {"udp:53", true}, {"tcp:80-90", true}, {"icmp", true},
		{"80", false}, {"tcp", false}, {"tcp:", false}, {"tcp:0", false}, {"tcp:65536", false}, {"tcp:http", false}, {"icmp:80", false}, {"tcp:80,", false},
	}
	for _, tc := range cases {
		value := Defaults()
		value.Policies = []domain.SecurityPolicy{{ID: "p", Priority: 1, Services: []string{tc.value}, Action: domain.DecisionAllow, Enabled: true}}
		errs := (Validator{}).Validate(value)
		if (len(errs) == 0) != tc.valid {
			t.Errorf("service %q valid=%v errors=%v", tc.value, tc.valid, errs)
		}
	}
}

func TestCommitRevalidatesExactEffectiveDuplicates(t *testing.T) {
	m, err := NewManager(t.TempDir(), Defaults())
	if err != nil {
		t.Fatal(err)
	}
	candidate := m.Candidate()
	candidate.Policies = []domain.SecurityPolicy{
		{ID: "a", Priority: 10, Services: []string{"tcp:80", "tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
		{ID: "b", Priority: 20, Services: []string{"TCP:443", "tcp:80"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true},
	}
	if errs := m.SetCandidate(candidate); len(errs) != 0 {
		t.Fatal(errs)
	}
	if _, err := m.Commit("test", "duplicate", 0); err == nil || !strings.Contains(err.Error(), "exact duplicate") {
		t.Fatalf("commit accepted duplicate: %v", err)
	}
	if m.Version().Version != 0 {
		t.Fatal("duplicate commit changed running version")
	}
}

func TestValidatorPolicyIdentityAndPriorityRules(t *testing.T) {
	base := Defaults()
	base.Policies = []domain.SecurityPolicy{
		{ID: "ok", Priority: 10, Action: domain.DecisionAllow, Enabled: true},
		{ID: "ok", Priority: 10, Action: domain.DecisionDrop, Enabled: true},
	}
	errs := strings.Join((Validator{}).Validate(base), "\n")
	for _, expected := range []string{"duplicate object ok", "duplicate policy priority 10"} {
		if !strings.Contains(errs, expected) {
			t.Fatalf("missing %q in %s", expected, errs)
		}
	}
	for _, id := range []string{"", " whitespace", "<script>", "á"} {
		value := Defaults()
		value.Policies = []domain.SecurityPolicy{{ID: id, Priority: 1, Action: domain.DecisionAllow, Enabled: true}}
		if len((Validator{}).Validate(value)) == 0 {
			t.Errorf("invalid policy ID %q was accepted", id)
		}
	}
}
