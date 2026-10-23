package dataplane

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

// The mark bit and route table belong to the checksummed activation plan.
// Rendering a selector alone never installs the policy route.
const M4TPROXYMark uint32 = 0x40000000
const M4TPROXYRouteTable = 140

// RenderM4TPROXYSelection renders the target-VM-probed IPv4 TPROXY path. It is
// a pure compiler; the controller owns resource preflight and activation.
func RenderM4TPROXYSelection(config domain.Config, plan ProxySelectionPlan) (string, error) {
	if err := plan.Validate(); err != nil {
		return "", err
	}
	expected, err := CompileM4ProxySelection(config, plan.Generation)
	if err != nil {
		return "", err
	}
	if !reflect.DeepEqual(plan, expected) {
		return "", fmt.Errorf("proxy selection plan differs from authoritative configuration")
	}
	if !plan.Enabled {
		return "delete table inet ngfw_proxy\n" + ProxySchemaScript(), nil
	}
	zones := make(map[string][]string)
	var management []string
	for _, iface := range config.Interfaces {
		zone := strings.ToLower(strings.TrimSpace(iface.ZoneID))
		if zone != "" {
			zones[zone] = append(zones[zone], iface.SystemName)
		}
		if iface.Mode == domain.InterfaceManagement {
			management = append(management, iface.SystemName)
		}
	}
	for zone, names := range zones {
		zones[zone] = uniqueSorted(names)
	}
	management = uniqueSorted(management)
	var output strings.Builder
	// A flush retains the old chain type and hook. Replace only the owned
	// table so ON/OFF and successive activations can change the chain shape
	// atomically with the policy transaction.
	output.WriteString("delete table inet ngfw_proxy\n")
	output.WriteString("table inet ngfw_proxy {\n")
	output.WriteString("  comment \"owner=ngfw-engine schema=1\"\n")
	output.WriteString("  chain select { type filter hook prerouting priority -90; policy accept;\n")
	output.WriteString("    iifname \"lo\" return\n")
	for _, nat := range config.NATRules {
		if !nat.Enabled || !strings.EqualFold(nat.Type, "DNAT") {
			continue
		}
		guard, err := m4TPROXYDNATZoneGuard(nat, zones)
		if err != nil {
			return "", err
		}
		output.WriteString("    " + guard + "\n")
	}
	output.WriteString("    fib daddr type local return\n")
	if len(management) > 0 {
		output.WriteString("    iifname " + quoteSet(management) + " return\n")
		output.WriteString("    fib daddr oifname " + quoteSet(management) + " return\n")
	}
	for _, entry := range plan.Rules {
		rule := entry.Match
		if err := domain.ValidateIdentifier(rule.ID); err != nil {
			return "", fmt.Errorf("unsafe M4 policy ID: %w", err)
		}
		base, err := m4TPROXYBase(rule, zones)
		if err != nil {
			return "", fmt.Errorf("policy %s: %w", rule.ID, err)
		}
		if entry.Gate {
			for _, ports := range entry.GatePorts {
				if ports.Contains(uint16(plan.ListenHTTPPort)) || ports.Contains(uint16(plan.ListenHTTPSPort)) {
					return "", fmt.Errorf("policy %s gate ports overlap a proxy listener; choose distinct listener ports", rule.ID)
				}
			}
			for _, port := range m4TransportPorts(entry.GatePorts) {
				listener := plan.ListenHTTPSPort
				if port.First == 80 && port.Last == 80 {
					listener = plan.ListenHTTPPort
				}
				portMatch := strconv.Itoa(int(port.First))
				if port.First != port.Last {
					portMatch += "-" + strconv.Itoa(int(port.Last))
				}
				match := strings.Join(append(append([]string{}, base...), "fib daddr type unicast", "tcp dport "+portMatch), " ")
				output.WriteString(fmt.Sprintf("    %s tproxy ip to :%d meta mark set meta mark | 0x%08x accept comment \"m4:%s\"\n", match, listener, M4TPROXYMark, rule.ID))
				// If the listener disappears, the packet must not fall through to
				// ordinary forwarding without its synchronous request gate.
				output.WriteString(fmt.Sprintf("    %s drop comment \"m4-no-listener:%s\"\n", match, rule.ID))
			}
			for _, profile := range config.Profiles {
				if profile.ID == entry.ProfileID && profile.RequestGate != nil && profile.RequestGate.BlockQUIC && m4AllowsQUIC(rule.Services) {
					output.WriteString("    " + strings.Join(base, " ") + " udp dport 443 drop comment \"m4-quic:" + rule.ID + "\"\n")
				}
			}
		}
		services, err := m4TPROXYServices(rule.Services)
		if err != nil {
			return "", fmt.Errorf("policy %s: %w", rule.ID, err)
		}
		for _, service := range services {
			match := append(append([]string{}, base...), service)
			output.WriteString("    " + strings.TrimSpace(strings.Join(match, " ")) + " return comment \"m4-first-match:" + rule.ID + "\"\n")
		}
	}
	output.WriteString("  }\n}\n")
	return output.String(), nil
}

// The contract reserves TCP/80 for plaintext HTTP. Explicit additional TCP
// services select TLS (including ranges); they are not guessed by sniffing.
func m4TransportPorts(ports []connectivity.PortRange) []connectivity.PortRange {
	var result []connectivity.PortRange
	for _, port := range ports {
		if port.First <= 80 && port.Last >= 80 {
			if port.First < 80 {
				result = append(result, connectivity.PortRange{First: port.First, Last: 79})
			}
			result = append(result, connectivity.PortRange{First: 80, Last: 80})
			if port.Last > 80 {
				result = append(result, connectivity.PortRange{First: 81, Last: port.Last})
			}
		} else {
			result = append(result, port)
		}
	}
	return result
}

func m4AllowsQUIC(services []connectivity.Service) bool {
	if len(services) == 0 {
		return true
	}
	for _, service := range services {
		if service.Protocol != 17 {
			continue
		}
		if len(service.Ports) == 0 {
			return true
		}
		for _, port := range service.Ports {
			if port.Contains(443) {
				return true
			}
		}
	}
	return false
}

// TPROXY bypasses the M1 forward-hook DNAT guard. Repeat that guard at the
// post-DNAT prerouting point before routing locally to the proxy.
func m4TPROXYDNATZoneGuard(rule domain.NATRule, zones map[string][]string) (string, error) {
	interfaces := zones[strings.ToLower(strings.TrimSpace(rule.DestinationZone))]
	if len(interfaces) == 0 {
		return "", fmt.Errorf("DNAT %s destination zone has no interface", rule.ID)
	}
	target := net.ParseIP(rule.TranslatedAddress).To4()
	if target == nil {
		return "", fmt.Errorf("DNAT %s has invalid translated address", rule.ID)
	}
	parts := []string{"ct status dnat"}
	if rule.SourceZone != "" {
		sources := zones[strings.ToLower(strings.TrimSpace(rule.SourceZone))]
		if len(sources) == 0 {
			return "", fmt.Errorf("DNAT %s source zone has no interface", rule.ID)
		}
		parts = append(parts, "iifname "+quoteSet(sources))
	}
	if rule.SourceNetwork != "" {
		source, err := canonicalIPv4(rule.SourceNetwork)
		if err != nil {
			return "", err
		}
		parts = append(parts, "ip saddr "+source)
	}
	parts = append(parts, "ip daddr "+target.String())
	port := rule.TranslatedPort
	if port == 0 {
		port = rule.OriginalPort
	}
	if port > 0 {
		parts = append(parts, strings.ToLower(rule.Protocol)+" dport "+strconv.Itoa(port))
	} else if rule.Protocol != "" {
		parts = append(parts, "meta l4proto "+strings.ToLower(rule.Protocol))
	}
	parts = append(parts, "fib daddr oifname != "+quoteSet(interfaces), "drop", `comment "m4-dnat-zone:`+rule.ID+`"`)
	return strings.Join(parts, " "), nil
}

func m4TPROXYBase(rule connectivity.Rule, zones map[string][]string) ([]string, error) {
	parts := make([]string, 0, 4)
	for _, group := range []struct {
		zones  map[string]struct{}
		prefix string
	}{{rule.SourceZones, "iifname"}, {rule.DestinationZones, "fib daddr oifname"}} {
		if len(group.zones) == 0 {
			continue
		}
		var names []string
		for zone := range group.zones {
			if len(zones[zone]) == 0 {
				return nil, fmt.Errorf("zone %s has no physical interface", zone)
			}
			names = append(names, zones[zone]...)
		}
		parts = append(parts, group.prefix+" "+quoteSet(names))
	}
	for _, group := range []struct {
		prefixes []netip.Prefix
		field    string
	}{{rule.SourceAddresses, "ip saddr"}, {rule.DestinationAddresses, "ip daddr"}} {
		if len(group.prefixes) == 0 {
			continue
		}
		addresses := make([]string, 0, len(group.prefixes))
		for _, prefix := range group.prefixes {
			if !prefix.IsValid() || !prefix.Addr().Is4() {
				return nil, fmt.Errorf("M4 TPROXY supports IPv4 policy addresses only")
			}
			addresses = append(addresses, prefix.Masked().String())
		}
		parts = append(parts, group.field+" "+valueOrSet(uniqueSorted(addresses), false))
	}
	return parts, nil
}

func m4TPROXYServices(services []connectivity.Service) ([]string, error) {
	if len(services) == 0 {
		return []string{""}, nil
	}
	var out []string
	for _, service := range services {
		var protocol string
		switch service.Protocol {
		case 1:
			protocol = "icmp"
		case 6:
			protocol = "tcp"
		case 17:
			protocol = "udp"
		default:
			return nil, fmt.Errorf("unsupported protocol %d", service.Protocol)
		}
		if len(service.Ports) == 0 {
			out = append(out, "meta l4proto "+protocol)
			continue
		}
		for _, port := range service.Ports {
			if protocol == "icmp" || port.First < 1 || port.First > port.Last {
				return nil, fmt.Errorf("invalid %s port range", protocol)
			}
			value := strconv.Itoa(int(port.First))
			if port.First != port.Last {
				value += "-" + strconv.Itoa(int(port.Last))
			}
			out = append(out, protocol+" dport "+value)
		}
	}
	sort.Strings(out)
	return out, nil
}
