package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestNetworkTransitionRejectsStaleManagedObjects(t *testing.T) {
	for _, kind := range []string{"address", "route", "VLAN"} {
		t.Run(kind, func(t *testing.T) {
			desired, runner := healthyNetworkObservation()
			previous := cloneNetworkTestConfig(t, desired)
			switch kind {
			case "address":
				previous.Interfaces[0].IPv4Addresses = append(previous.Interfaces[0].IPv4Addresses, "192.0.2.3/24")
				runner.responses["-json address show"] = strings.Replace(runner.responses["-json address show"], `{"local":"192.0.2.2","prefixlen":24}`, `{"local":"192.0.2.2","prefixlen":24},{"local":"192.0.2.3","prefixlen":24}`, 1)
			case "route":
				previous.Routes = append(previous.Routes, domain.Route{ID: "removed", DestinationCIDR: "203.0.113.0/24", Gateway: "192.0.2.1", InterfaceID: "wan", Metric: 8, Enabled: true})
				runner.responses["-4 -json route show table main"] = strings.TrimSuffix(runner.responses["-4 -json route show table main"], "]") + `,{"dst":"203.0.113.0/24","gateway":"192.0.2.1","dev":"eth0","metric":8}]`
			case "VLAN":
				previous.Interfaces = append(previous.Interfaces, domain.Interface{ID: "removed", SystemName: "eth1.43", Mode: domain.InterfaceVLANSub, ParentInterfaceID: "parent", VLANID: 43})
				runner.responses["-details -json link show"] = strings.TrimSuffix(runner.responses["-details -json link show"], "]") + `,{"ifname":"eth1.43","link_index":3,"linkinfo":{"info_kind":"vlan","info_data":{"id":43}}}]`
			}
			err := NewNetworkReconciler(runner).VerifyTransition(context.Background(), previous, desired)
			if !errors.Is(err, ErrNetworkDrift) || !strings.Contains(err.Error(), "stale managed "+kind) {
				t.Fatalf("removed %s still exists but transition passed: %v", kind, err)
			}
		})
	}
}

func TestNetworkTransitionPreservesUnmanagedAndEquivalentState(t *testing.T) {
	desired, runner := healthyNetworkObservation()
	previous := cloneNetworkTestConfig(t, desired)
	previous.Interfaces[2].IPv6Addresses[0] = "2001:db8:42:0:0:0:0:1/64"
	previous.Routes[2].Gateway = "2001:0db8:42:0:0:0:0:2"
	previous.Routes[2].Metric = 1024
	if err := NewNetworkReconciler(runner).VerifyTransition(context.Background(), previous, desired); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanNetwork(previous, desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range plan {
		if strings.Contains(operation.Description, "remove") {
			t.Fatalf("equivalent IPv6 spelling/default metric caused removal: %+v", operation)
		}
	}
}
