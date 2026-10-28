package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// ErrNetworkDrift means a successful kernel observation differs from the
// applied configuration. A failed observation must never trigger a repair.
var ErrNetworkDrift = errors.New("managed network state differs from configuration")

type NetworkStateVerifier interface {
	Verify(context.Context, domain.Config) error
}

type observedNetworkLink struct {
	ipLinkDetails
	MTU   int      `json:"mtu"`
	Flags []string `json:"flags"`
}

type observedNetworkAddress struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type observedNetworkRoute struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gateway"`
	Device      string `json:"dev"`
	Metric      int    `json:"metric"`
	Type        string `json:"type"`
}

// Verify observes only. Extra OS-owned addresses/routes (including MGMT and
// IPv6 link-local state) are allowed; every configured object must be present.
// Carrier/operstate is deliberately not used as the administrative UP flag.
func (r *NetworkReconciler) Verify(ctx context.Context, desired domain.Config) error {
	if r == nil || r.Runner == nil {
		return errors.New("network verifier has no ip command runner")
	}
	var links []observedNetworkLink
	if err := r.observe(ctx, &links, "-details", "-json", "link", "show"); err != nil {
		return err
	}
	var addresses []observedNetworkAddress
	if err := r.observe(ctx, &addresses, "-json", "address", "show"); err != nil {
		return err
	}
	byName := make(map[string]observedNetworkLink, len(links))
	for _, link := range links {
		byName[link.IfName] = link
	}
	actualAddresses := make(map[string]map[netip.Prefix]bool, len(addresses))
	for _, link := range addresses {
		actualAddresses[link.IfName] = make(map[netip.Prefix]bool)
		for _, address := range link.AddrInfo {
			ip, err := netip.ParseAddr(address.Local)
			if err != nil || address.PrefixLen < 0 || address.PrefixLen > ip.BitLen() {
				return fmt.Errorf("invalid kernel address on %s", link.IfName)
			}
			actualAddresses[link.IfName][netip.PrefixFrom(ip, address.PrefixLen)] = true
		}
	}
	var drift []string
	interfaces := interfaceMap(desired)
	for _, iface := range desired.Interfaces {
		link, exists := byName[iface.SystemName]
		if !exists {
			drift = append(drift, "missing interface "+iface.SystemName)
			continue
		}
		up := false
		for _, flag := range link.Flags {
			up = up || flag == "UP"
		}
		if up != iface.AdminState {
			drift = append(drift, fmt.Sprintf("%s admin UP=%t, expected %t", iface.SystemName, up, iface.AdminState))
		}
		if iface.MTU > 0 && link.MTU != iface.MTU {
			drift = append(drift, fmt.Sprintf("%s MTU=%d, expected %d", iface.SystemName, link.MTU, iface.MTU))
		}
		if iface.Mode == domain.InterfaceVLANSub {
			parent, known := interfaces[iface.ParentInterfaceID]
			parentLink, present := byName[parent.SystemName]
			parentMatches := known && present && (link.Link == parent.SystemName || link.LinkIndex != 0 && link.LinkIndex == parentLink.IfIndex)
			if link.LinkInfo.Kind != "vlan" || link.LinkInfo.Data.ID != iface.VLANID || !parentMatches {
				drift = append(drift, fmt.Sprintf("%s VLAN ID/parent mismatch (expected %d on %s)", iface.SystemName, iface.VLANID, parent.SystemName))
			}
		}
		for _, address := range append(append([]string(nil), iface.IPv4Addresses...), iface.IPv6Addresses...) {
			prefix, err := netip.ParsePrefix(address)
			if err != nil {
				return fmt.Errorf("invalid configured address %s: %w", address, err)
			}
			if !actualAddresses[iface.SystemName][prefix] {
				drift = append(drift, "missing address "+address+" on "+iface.SystemName)
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		var expected []domain.Route
		for _, route := range desired.Routes {
			if !route.Enabled {
				continue
			}
			prefix, err := netip.ParsePrefix(route.DestinationCIDR)
			if err != nil {
				return fmt.Errorf("invalid configured route %s: %w", route.ID, err)
			}
			if (family == "-4") == prefix.Addr().Is4() {
				expected = append(expected, route)
			}
		}
		if len(expected) == 0 {
			continue
		}
		var routes []observedNetworkRoute
		if err := r.observe(ctx, &routes, family, "-json", "route", "show", "table", "main"); err != nil {
			return err
		}
		for _, route := range expected {
			found := false
			for _, actual := range routes {
				if networkRouteMatches(route, actual, interfaces, family) {
					found = true
					break
				}
			}
			if !found {
				drift = append(drift, fmt.Sprintf("missing/mismatched route %s (%s via %s, interface %s, metric %d)", route.ID, route.DestinationCIDR, route.Gateway, route.InterfaceID, route.Metric))
			}
		}
	}
	if len(drift) != 0 {
		return fmt.Errorf("%w: %s", ErrNetworkDrift, strings.Join(drift, "; "))
	}
	return nil
}

func (r *NetworkReconciler) observe(ctx context.Context, target any, args ...string) error {
	data, err := r.Runner.Run(ctx, args...)
	if err != nil {
		return fmt.Errorf("observe kernel network: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "[") {
		return errors.New("observe kernel network: expected an ip JSON array")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode kernel network: %w", err)
	}
	return nil
}

func networkRouteMatches(want domain.Route, actual observedNetworkRoute, interfaces map[string]domain.Interface, family string) bool {
	if actual.Type != "" && actual.Type != "unicast" {
		return false
	}
	destination := actual.Destination
	if destination == "default" {
		destination = "0.0.0.0/0"
		if family == "-6" {
			destination = "::/0"
		}
	} else if ip, err := netip.ParseAddr(destination); err == nil {
		destination = netip.PrefixFrom(ip, ip.BitLen()).String()
	}
	wantedPrefix, err := netip.ParsePrefix(want.DestinationCIDR)
	if err != nil {
		return false
	}
	actualPrefix, err := netip.ParsePrefix(destination)
	if err != nil || actualPrefix.Masked() != wantedPrefix.Masked() {
		return false
	}
	if want.Gateway != "" {
		gateway, err := netip.ParseAddr(actual.Gateway)
		wantedGateway, wantErr := netip.ParseAddr(want.Gateway)
		if err != nil || wantErr != nil || gateway != wantedGateway {
			return false
		}
	} else if actual.Gateway != "" {
		return false
	}
	if want.InterfaceID != "" {
		iface, ok := interfaces[want.InterfaceID]
		if !ok || iface.SystemName != actual.Device {
			return false
		}
	}
	metric := want.Metric
	if metric == 0 && family == "-6" {
		metric = 1024 // iproute2's implicit metric for a manually added IPv6 route.
	}
	return metric == actual.Metric
}
