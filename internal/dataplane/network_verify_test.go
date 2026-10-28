package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

type observedIPRunner struct {
	responses map[string]string
	calls     []string
	err       error
}

func (r *observedIPRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	r.calls = append(r.calls, command)
	if r.err != nil {
		return nil, r.err
	}
	if response, ok := r.responses[command]; ok {
		return []byte(response), nil
	}
	return nil, errors.New("unexpected command: " + command)
}

func healthyNetworkObservation() (domain.Config, *observedIPRunner) {
	value := domain.Config{
		Interfaces: []domain.Interface{
			{ID: "wan", SystemName: "eth0", Mode: domain.InterfaceL3, MTU: 1500, AdminState: true, IPv4Addresses: []string{"192.0.2.2/24"}},
			{ID: "parent", SystemName: "eth1", Mode: domain.InterfaceVLANParent, MTU: 1500, AdminState: true},
			{ID: "vlan", SystemName: "eth1.42", Mode: domain.InterfaceVLANSub, ParentInterfaceID: "parent", VLANID: 42, MTU: 1400, AdminState: true, IPv4Addresses: []string{"10.42.0.1/24"}, IPv6Addresses: []string{"2001:0db8:42::1/64"}},
		},
		Routes: []domain.Route{
			{ID: "default", DestinationCIDR: "0.0.0.0/0", Gateway: "192.0.2.1", InterfaceID: "wan", Metric: 100, Enabled: true},
			{ID: "host", DestinationCIDR: "198.51.100.10/32", Gateway: "192.0.2.1", InterfaceID: "wan", Enabled: true},
			{ID: "v6", DestinationCIDR: "::/0", Gateway: "2001:db8:42::2", InterfaceID: "vlan", Enabled: true},
			{ID: "disabled", DestinationCIDR: "203.0.113.0/24", InterfaceID: "wan"},
		},
	}
	return value, &observedIPRunner{responses: map[string]string{
		"-details -json link show":       `[{"ifindex":2,"ifname":"eth0","mtu":1500,"flags":["UP"],"operstate":"DOWN"},{"ifindex":3,"ifname":"eth1","mtu":1500,"flags":["UP"]},{"ifindex":4,"ifname":"eth1.42","mtu":1400,"flags":["UP"],"link_index":3,"linkinfo":{"info_kind":"vlan","info_data":{"id":42}}}]`,
		"-json address show":             `[{"ifname":"eth0","addr_info":[{"local":"192.0.2.2","prefixlen":24},{"local":"fe80::1","prefixlen":64}]},{"ifname":"eth1.42","addr_info":[{"local":"10.42.0.1","prefixlen":24},{"local":"2001:db8:42::1","prefixlen":64}]}]`,
		"-4 -json route show table main": `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","metric":100},{"dst":"198.51.100.10","gateway":"192.0.2.1","dev":"eth0"},{"dst":"192.0.2.0/24","dev":"eth0","protocol":"kernel"}]`,
		"-6 -json route show table main": `[{"dst":"default","gateway":"2001:db8:42::2","dev":"eth1.42","metric":1024}]`,
	}}
}

func TestNetworkVerifierAcceptsCanonicalDualStackVLANAndUnmanagedState(t *testing.T) {
	value, runner := healthyNetworkObservation()
	if err := NewNetworkReconciler(runner).Verify(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("unexpected observations: %v", runner.calls)
	}
}

func TestNetworkVerifierDetectsLostAddressesAndRoutes(t *testing.T) {
	value, runner := healthyNetworkObservation()
	runner.responses["-json address show"] = `[]`
	runner.responses["-4 -json route show table main"] = `[]`
	err := NewNetworkReconciler(runner).Verify(context.Background(), value)
	if !errors.Is(err, ErrNetworkDrift) {
		t.Fatalf("missing network state reported as healthy: %v", err)
	}
	for _, expected := range []string{"192.0.2.2/24", "10.42.0.1/24", "2001:0db8:42::1/64", "route default", "route host"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("missing useful mismatch %q: %v", expected, err)
		}
	}
}

func TestNetworkVerifierChecksLinkVLANAndRouteAttributes(t *testing.T) {
	for _, tc := range []struct{ name, command, from, to, want string }{
		{"mtu", "-details -json link show", `"mtu":1400`, `"mtu":1500`, "MTU="},
		{"admin", "-details -json link show", `"flags":["UP"]`, `"flags":[]`, "admin UP="},
		{"vlan-id", "-details -json link show", `"id":42`, `"id":43`, "VLAN ID/parent"},
		{"vlan-parent", "-details -json link show", `"link_index":3`, `"link_index":2`, "VLAN ID/parent"},
		{"prefix", "-json address show", `"local":"10.42.0.1","prefixlen":24`, `"local":"10.42.0.1","prefixlen":25`, "missing address 10.42.0.1/24"},
		{"gateway", "-4 -json route show table main", `"gateway":"192.0.2.1"`, `"gateway":"192.0.2.3"`, "route default"},
		{"device", "-4 -json route show table main", `"dev":"eth0"`, `"dev":"eth1"`, "route default"},
		{"metric", "-4 -json route show table main", `"metric":100`, `"metric":101`, "route default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, runner := healthyNetworkObservation()
			runner.responses[tc.command] = strings.ReplaceAll(runner.responses[tc.command], tc.from, tc.to)
			err := NewNetworkReconciler(runner).Verify(context.Background(), value)
			if !errors.Is(err, ErrNetworkDrift) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong drift result: %v", err)
			}
		})
	}
}

func TestNetworkObservationFailuresAreNotEvidenceOfDrift(t *testing.T) {
	for _, response := range []string{"null", "{}", "[bad json]"} {
		value, runner := healthyNetworkObservation()
		runner.responses["-details -json link show"] = response
		err := NewNetworkReconciler(runner).Verify(context.Background(), value)
		if err == nil || errors.Is(err, ErrNetworkDrift) {
			t.Fatalf("malformed observation should fail without authorizing repair: %v", err)
		}
	}
	value, runner := healthyNetworkObservation()
	runner.err = errors.New("permission denied")
	if err := NewNetworkReconciler(runner).Verify(context.Background(), value); err == nil || errors.Is(err, ErrNetworkDrift) {
		t.Fatalf("read failure should not authorize repair: %v", err)
	}
}

func TestReconcileRejectsSuccessfulCommandsThatDidNotApplyAddress(t *testing.T) {
	runner := &fakeIPRunner{observations: map[string]string{"-json address show": `[]`}}
	desired := domain.Config{Interfaces: []domain.Interface{{ID: "lan", SystemName: "eth1", MTU: 1500, AdminState: true, IPv4Addresses: []string{"10.0.0.1/24"}}}}
	err := NewNetworkReconciler(runner).Reconcile(context.Background(), domain.Config{}, desired)
	if !errors.Is(err, ErrNetworkDrift) {
		t.Fatalf("ip exit 0 must not imply kernel state is correct: %v", err)
	}
	if !strings.Contains(strings.Join(runner.Commands(), "\n"), "addr del 10.0.0.1/24") {
		t.Fatal("post-apply verification failure did not compensate")
	}
}
