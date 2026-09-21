package connectivity

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

type PortRange struct{ First, Last uint16 }

func (p PortRange) Contains(port uint16) bool { return port >= p.First && port <= p.Last }

type Service struct {
	Protocol uint8
	Ports    []PortRange
}

type Rule struct {
	ID, Name                              string
	Priority                              int
	SourceZones, DestinationZones         map[string]struct{}
	SourceAddresses, DestinationAddresses []netip.Prefix
	Services                              []Service
	Action                                domain.Decision
	Enabled                               bool
}

type Program struct {
	Rules          []Rule
	DefaultDeny    bool
	Generation     uint64
	zonePrefixes   map[string][]netip.Prefix
	localAddresses map[netip.Addr]struct{}
}

const (
	ZoneLocal   = "local"
	ZoneUnknown = "unknown"
)

type View struct {
	SourceIP, DestinationIP     netip.Addr
	SourcePort, DestinationPort uint16
	Protocol                    uint8
	SourceZone, DestinationZone string
}

type Decision struct {
	Action     domain.Decision
	PolicyID   string
	Generation uint64
	Reason     string
}

// CompileM2 applies the explicit milestone boundary before compiling the
// shared L3/L4 program. Inspection profiles, application names, risk
// predicates and request/source scopes require later security milestones and
// must be rejected rather than silently ignored by the connectivity runtime.
func CompileM2(config domain.Config, generation uint64) (Program, error) {
	for _, policy := range config.Policies {
		if !policy.Enabled {
			continue
		}
		if len(policy.Applications) > 0 {
			return Program{}, fmt.Errorf("policy %s uses application matching outside M2 L3/L4 scope", policy.ID)
		}
		if policy.SecurityProfileID != "" {
			return Program{}, fmt.Errorf("policy %s references security profile outside M2 L3/L4 scope", policy.ID)
		}
		if policy.MinimumRisk != nil || policy.MaximumRisk != nil {
			return Program{}, fmt.Errorf("policy %s uses risk matching outside M2 L3/L4 scope", policy.ID)
		}
		switch scope := strings.ToUpper(strings.TrimSpace(policy.Scope)); scope {
		case "", "SESSION":
		default:
			return Program{}, fmt.Errorf("policy %s scope %q is outside M2 session scope", policy.ID, policy.Scope)
		}
	}
	return Compile(config, generation)
}

func Compile(config domain.Config, generation uint64) (Program, error) {
	program := Program{DefaultDeny: config.DefaultDeny, Generation: generation, zonePrefixes: map[string][]netip.Prefix{}, localAddresses: map[netip.Addr]struct{}{}}
	interfacesByID := make(map[string]domain.Interface, len(config.Interfaces))
	for _, iface := range config.Interfaces {
		interfacesByID[iface.ID] = iface
		for _, raw := range append(append([]string{}, iface.IPv4Addresses...), iface.IPv6Addresses...) {
			prefix, err := parseInterfacePrefix(raw)
			if err == nil {
				if address, addressErr := parseInterfaceAddress(raw); addressErr == nil {
					program.localAddresses[address] = struct{}{}
				}
				if strings.TrimSpace(iface.ZoneID) != "" {
					program.zonePrefixes[iface.ZoneID] = append(program.zonePrefixes[iface.ZoneID], prefix)
				}
			}
		}
	}
	for _, route := range config.Routes {
		if !route.Enabled {
			continue
		}
		iface, ok := interfacesByID[route.InterfaceID]
		if !ok || strings.TrimSpace(iface.ZoneID) == "" {
			continue
		}
		if prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(route.DestinationCIDR)); parseErr == nil {
			program.zonePrefixes[iface.ZoneID] = append(program.zonePrefixes[iface.ZoneID], prefix.Masked())
		}
	}
	policies := append([]domain.SecurityPolicy(nil), config.Policies...)
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Priority < policies[j].Priority })
	seenPriority := map[int]struct{}{}
	for _, policy := range policies {
		if _, exists := seenPriority[policy.Priority]; exists {
			return Program{}, fmt.Errorf("duplicate policy priority %d", policy.Priority)
		}
		seenPriority[policy.Priority] = struct{}{}
		if !policy.Enabled {
			continue
		}
		if policy.Action != domain.DecisionAllow && policy.Action != domain.DecisionDrop && policy.Action != domain.DecisionReject {
			return Program{}, fmt.Errorf("policy %s action %q is not L3/L4", policy.ID, policy.Action)
		}
		rule := Rule{ID: policy.ID, Name: policy.Name, Priority: policy.Priority, Action: policy.Action, Enabled: true, SourceZones: stringSet(policy.SourceZones), DestinationZones: stringSet(policy.DestinationZones)}
		var err error
		if rule.SourceAddresses, err = prefixes(policy.SourceAddresses); err != nil {
			return Program{}, fmt.Errorf("policy %s source addresses: %w", policy.ID, err)
		}
		if rule.DestinationAddresses, err = prefixes(policy.DestinationAddresses); err != nil {
			return Program{}, fmt.Errorf("policy %s destination addresses: %w", policy.ID, err)
		}
		for _, raw := range policy.Services {
			service, parseErr := parseService(raw)
			if parseErr != nil {
				return Program{}, fmt.Errorf("policy %s service %q: %w", policy.ID, raw, parseErr)
			}
			rule.Services = append(rule.Services, service)
		}
		program.Rules = append(program.Rules, rule)
	}
	return program, nil
}

func parseInterfacePrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func parseInterfaceAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), nil
	}
	return netip.ParseAddr(value)
}

// InferZones maps an observed tuple to the configured interface networks.
// Conntrack does not expose ingress/egress interface names, so this is an
// explicit best-effort enrichment. An empty result remains observable and is
// evaluated according to the policy's zone matcher (usually default deny).
func (p Program) InferZones(tuple domain.Tuple) (string, string) {
	return p.InferAddressZone(tuple.SrcIP), p.InferAddressZone(tuple.DstIP)
}

// InferAddressZone applies the same longest-prefix/ambiguity rule used by
// InferZones to one address. It is exposed so the runtime can enrich a DNAT
// session's destination from its post-translation tuple while retaining the
// pre-NAT source zone.
func (p Program) InferAddressZone(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	if addr.IsLoopback() {
		return ZoneLocal
	}
	if _, local := p.localAddresses[addr]; local {
		return ZoneLocal
	}
	bestBits := -1
	bestZone := ""
	ambiguous := false
	for zone, prefixes := range p.zonePrefixes {
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				bits := prefix.Bits()
				if bits > bestBits {
					bestBits, bestZone, ambiguous = bits, zone, false
				} else if bits == bestBits && zone != bestZone {
					ambiguous = true
				}
			}
		}
	}
	if ambiguous || bestBits < 0 {
		return ""
	}
	return bestZone
}

func stringSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func prefixes(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if addr, err := netip.ParseAddr(value); err == nil {
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			out = append(out, netip.PrefixFrom(addr, bits))
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func parseService(value string) (Service, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) > 2 || parts[0] == "" {
		return Service{}, fmt.Errorf("invalid service")
	}
	proto, ok := domain.ParseProtocol(parts[0])
	if !ok {
		return Service{}, fmt.Errorf("invalid protocol")
	}
	service := Service{Protocol: proto}
	if len(parts) == 1 {
		return service, nil
	}
	if proto == 1 || proto == 58 {
		return Service{}, fmt.Errorf("ICMP does not use ports")
	}
	rangeParts := strings.Split(parts[1], "-")
	if len(rangeParts) > 2 {
		return Service{}, fmt.Errorf("invalid port range")
	}
	first, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
	if err != nil || first < 1 || first > 65535 {
		return Service{}, fmt.Errorf("invalid port")
	}
	last := first
	if len(rangeParts) == 2 {
		last, err = strconv.Atoi(strings.TrimSpace(rangeParts[1]))
		if err != nil || last < first || last > 65535 {
			return Service{}, fmt.Errorf("invalid port range")
		}
	}
	service.Ports = []PortRange{{First: uint16(first), Last: uint16(last)}}
	return service, nil
}

func (p Program) Evaluate(view View) Decision {
	for _, rule := range p.Rules {
		if rule.Enabled && ruleMatches(rule, view) {
			return Decision{Action: rule.Action, PolicyID: rule.ID, Generation: p.Generation, Reason: "policy " + rule.ID + " matched"}
		}
	}
	if p.DefaultDeny {
		return Decision{Action: domain.DecisionDrop, Generation: p.Generation, Reason: "default deny"}
	}
	return Decision{Action: domain.DecisionAllow, Generation: p.Generation, Reason: "default allow"}
}

func ruleMatches(rule Rule, view View) bool {
	if len(rule.SourceZones) > 0 {
		if _, ok := rule.SourceZones[strings.ToLower(strings.TrimSpace(view.SourceZone))]; !ok {
			return false
		}
	}
	if len(rule.DestinationZones) > 0 {
		if _, ok := rule.DestinationZones[strings.ToLower(strings.TrimSpace(view.DestinationZone))]; !ok {
			return false
		}
	}
	if !addressMatch(rule.SourceAddresses, view.SourceIP) || !addressMatch(rule.DestinationAddresses, view.DestinationIP) {
		return false
	}
	if len(rule.Services) == 0 {
		return true
	}
	for _, service := range rule.Services {
		if service.Protocol != view.Protocol {
			continue
		}
		if len(service.Ports) == 0 {
			return true
		}
		for _, ports := range service.Ports {
			if ports.Contains(view.DestinationPort) {
				return true
			}
		}
	}
	return false
}

func addressMatch(prefixes []netip.Prefix, addr netip.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (p Program) MatchBothDirections(original, reply View) Decision {
	return p.Evaluate(original)
}

func ViewFromTuple(t domain.Tuple, sourceZone, destinationZone string) View {
	return View{SourceIP: t.SrcIP, DestinationIP: t.DstIP, SourcePort: t.SrcPort, DestinationPort: t.DstPort, Protocol: t.Protocol, SourceZone: sourceZone, DestinationZone: destinationZone}
}
