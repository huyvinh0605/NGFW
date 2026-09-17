package dataplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestPlanNetworkRemovesStaleStateAndBuildsVLAN(t *testing.T) {
	previous := domain.Config{
		Interfaces: []domain.Interface{
			{ID: "parent", SystemName: "eth1", Mode: domain.InterfaceVLANParent, MTU: 1500, AdminState: true},
			{ID: "old-vlan", SystemName: "eth1.10", Mode: domain.InterfaceVLANSub, ParentInterfaceID: "parent", VLANID: 10, IPv4Addresses: []string{"10.10.0.1/24"}, MTU: 1500, AdminState: true},
		},
		Routes: []domain.Route{{ID: "old-route", DestinationCIDR: "10.30.0.0/24", Gateway: "10.10.0.2", InterfaceID: "old-vlan", Metric: 5, Enabled: true}},
	}
	desired := domain.Config{
		Interfaces: []domain.Interface{
			{ID: "parent", SystemName: "eth1", Mode: domain.InterfaceVLANParent, MTU: 9000, AdminState: true},
			{ID: "new-vlan", SystemName: "eth1.20", Mode: domain.InterfaceVLANSub, ParentInterfaceID: "parent", VLANID: 20, IPv4Addresses: []string{"10.20.0.1/24"}, MTU: 1400, AdminState: true},
		},
		Routes: []domain.Route{{ID: "new-route", DestinationCIDR: "10.40.0.0/24", Gateway: "10.20.0.2", InterfaceID: "new-vlan", Metric: 9, Enabled: true}},
	}
	plan, err := PlanNetwork(previous, desired)
	if err != nil {
		t.Fatal(err)
	}
	joined := renderOperations(plan)
	for _, expected := range []string{
		"-4 route del 10.30.0.0/24 via 10.10.0.2 dev eth1.10 metric 5",
		"-4 addr del 10.10.0.1/24 dev eth1.10",
		"link delete dev eth1.10",
		"ensure-vlan eth1.20 parent=eth1 id=20",
		"link set dev eth1 mtu 9000",
		"-4 addr replace 10.20.0.1/24 dev eth1.20",
		"-4 route replace 10.40.0.0/24 via 10.20.0.2 dev eth1.20 metric 9",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("plan missing %q:\n%s", expected, joined)
		}
	}
	if strings.Index(joined, "route del") > strings.Index(joined, "link delete") || strings.Index(joined, "addr del") > strings.Index(joined, "link delete") {
		t.Fatalf("stale state is removed in unsafe order:\n%s", joined)
	}
}

func TestPlanNetworkDoesNotDeleteUnchangedRoute(t *testing.T) {
	value := domain.Config{
		Interfaces: []domain.Interface{{ID: "wan", SystemName: "eth0", Mode: domain.InterfaceL3}},
		Routes:     []domain.Route{{ID: "default", DestinationCIDR: "0.0.0.0/0", Gateway: "192.0.2.1", InterfaceID: "wan", Metric: 100, Enabled: true}},
	}
	plan, err := PlanNetwork(value, value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(renderOperations(plan), "route del") {
		t.Fatalf("unchanged route was deleted:\n%s", renderOperations(plan))
	}
}

func TestReconcilerCreatesMissingVLAN(t *testing.T) {
	runner := &fakeIPRunner{missingVLAN: true}
	reconciler := NewNetworkReconciler(runner)
	desired := domain.Config{Interfaces: []domain.Interface{
		{ID: "parent", SystemName: "eth1", Mode: domain.InterfaceVLANParent, AdminState: true},
		{ID: "vlan", SystemName: "eth1.42", Mode: domain.InterfaceVLANSub, ParentInterfaceID: "parent", VLANID: 42, AdminState: true},
	}}
	if err := reconciler.Reconcile(context.Background(), domain.Config{}, desired); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(runner.Commands(), "\n"), "link add link eth1 name eth1.42 type vlan id 42") {
		t.Fatalf("VLAN create command not executed: %v", runner.Commands())
	}
}

func TestReconcilerRestoresPreviousSnapshotAfterCommandFailure(t *testing.T) {
	runner := &fakeIPRunner{failOnceContains: "addr replace 10.0.1.1/24"}
	reconciler := NewNetworkReconciler(runner)
	previous := domain.Config{Interfaces: []domain.Interface{{ID: "lan", SystemName: "eth1", Mode: domain.InterfaceL3, IPv4Addresses: []string{"10.0.0.1/24"}, MTU: 1500, AdminState: true}}}
	desired := domain.Config{Interfaces: []domain.Interface{{ID: "lan", SystemName: "eth1", Mode: domain.InterfaceL3, IPv4Addresses: []string{"10.0.1.1/24"}, MTU: 1400, AdminState: true}}}
	if err := reconciler.Reconcile(context.Background(), previous, desired); err == nil {
		t.Fatal("expected injected command failure")
	}
	commands := strings.Join(runner.Commands(), "\n")
	failed := strings.Index(commands, "addr replace 10.0.1.1/24")
	restored := strings.LastIndex(commands, "addr replace 10.0.0.1/24")
	if failed < 0 || restored < failed {
		t.Fatalf("old address was not restored after failure:\n%s", commands)
	}
}

type fakeIPRunner struct {
	mu               sync.Mutex
	commands         []string
	missingVLAN      bool
	failOnceContains string
	failed           bool
}

func (f *fakeIPRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	command := strings.Join(args, " ")
	f.commands = append(f.commands, command)
	if f.missingVLAN && strings.HasPrefix(command, "-details -json link show dev") {
		return nil, ErrIPObjectNotFound
	}
	if !f.failed && f.failOnceContains != "" && strings.Contains(command, f.failOnceContains) {
		f.failed = true
		return nil, errors.New("injected ip failure")
	}
	return []byte(`[{"ifindex":1,"ifname":"eth1"}]`), nil
}

func (f *fakeIPRunner) Commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

func renderOperations(operations []NetworkOperation) string {
	lines := make([]string, 0, len(operations))
	for _, operation := range operations {
		switch operation.Kind {
		case OperationEnsureLink:
			lines = append(lines, "ensure-link "+operation.InterfaceName)
		case OperationEnsureVLAN:
			lines = append(lines, "ensure-vlan "+operation.InterfaceName+" parent="+operation.ParentName+" id="+stringID(operation.VLANID))
		default:
			lines = append(lines, strings.Join(operation.Args, " "))
		}
	}
	return strings.Join(lines, "\n")
}

func stringID(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	result := ""
	for value > 0 {
		result = string(digits[value%10]) + result
		value /= 10
	}
	return result
}
