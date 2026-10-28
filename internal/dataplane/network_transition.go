package dataplane

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// VerifyTransition checks the desired objects and the absence of objects
// explicitly removed by this transition. Unmanaged OS/MGMT state is allowed.
func (r *NetworkReconciler) VerifyTransition(ctx context.Context, previous, desired domain.Config) error {
	if err := r.Verify(ctx, desired); err != nil {
		return err
	}
	var drift []string
	wantedAddresses := addressSet(desired)
	staleAddresses := map[string]bool{}
	for _, iface := range previous.Interfaces {
		for _, family := range []struct {
			flag string
			list []string
		}{{"-4", iface.IPv4Addresses}, {"-6", iface.IPv6Addresses}} {
			for _, address := range family.list {
				key := addressKey(family.flag, iface.SystemName, address)
				if _, wanted := wantedAddresses[key]; !wanted {
					staleAddresses[key] = true
				}
			}
		}
	}
	if len(staleAddresses) > 0 {
		var addresses []observedNetworkAddress
		if err := r.observe(ctx, &addresses, "-json", "address", "show"); err != nil {
			return err
		}
		for _, link := range addresses {
			for _, address := range link.AddrInfo {
				ip, err := netip.ParseAddr(address.Local)
				if err != nil || address.PrefixLen < 0 || address.PrefixLen > ip.BitLen() {
					return fmt.Errorf("invalid kernel address on %s", link.IfName)
				}
				family := "-4"
				if ip.Is6() {
					family = "-6"
				}
				prefix := netip.PrefixFrom(ip, address.PrefixLen).String()
				if staleAddresses[addressKey(family, link.IfName, prefix)] {
					drift = append(drift, "stale managed address "+prefix+" on "+link.IfName)
				}
			}
		}
	}
	wantedLinks := map[string]bool{}
	for _, iface := range desired.Interfaces {
		wantedLinks[iface.SystemName] = true
	}
	staleVLANs := map[string]bool{}
	for _, iface := range previous.Interfaces {
		if iface.Mode == domain.InterfaceVLANSub && !wantedLinks[iface.SystemName] {
			staleVLANs[iface.SystemName] = true
		}
	}
	if len(staleVLANs) > 0 {
		var links []observedNetworkLink
		if err := r.observe(ctx, &links, "-details", "-json", "link", "show"); err != nil {
			return err
		}
		for _, link := range links {
			if staleVLANs[link.IfName] {
				drift = append(drift, "stale managed VLAN "+link.IfName)
			}
		}
	}
	wantedRoutes, err := routeSignatures(desired)
	if err != nil {
		return err
	}
	oldInterfaces := interfaceMap(previous)
	staleRoutes := map[string][]domain.Route{}
	for _, route := range previous.Routes {
		if !route.Enabled {
			continue
		}
		args, err := routeArgs("replace", route, oldInterfaces)
		if err != nil {
			return err
		}
		if _, wanted := wantedRoutes[routeSignature(args)]; !wanted {
			staleRoutes[args[0]] = append(staleRoutes[args[0]], route)
		}
	}
	for _, family := range []string{"-4", "-6"} {
		if len(staleRoutes[family]) == 0 {
			continue
		}
		var routes []observedNetworkRoute
		if err := r.observe(ctx, &routes, family, "-json", "route", "show", "table", "main"); err != nil {
			return err
		}
		for _, old := range staleRoutes[family] {
			for _, actual := range routes {
				if networkRouteMatches(old, actual, oldInterfaces, family) {
					drift = append(drift, "stale managed route "+old.ID)
					break
				}
			}
		}
	}
	if len(drift) > 0 {
		return fmt.Errorf("%w: %s", ErrNetworkDrift, strings.Join(drift, "; "))
	}
	return nil
}
