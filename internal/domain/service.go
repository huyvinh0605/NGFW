package domain

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ServiceSelector is the canonical L3/L4 service matcher shared by the
// configuration validator, the runtime evaluator and the nft compiler.
// Empty Services on a policy still means any service; a selector itself must
// name a protocol and (for TCP/UDP) a destination port or range.
type ServiceSelector struct {
	Protocol string
	First    uint16
	Last     uint16
	AllPorts bool
}

func (s ServiceSelector) Canonical() string {
	protocol := strings.ToLower(strings.TrimSpace(s.Protocol))
	if s.AllPorts {
		return protocol
	}
	if s.First == s.Last {
		return fmt.Sprintf("%s:%d", protocol, s.First)
	}
	return fmt.Sprintf("%s:%d-%d", protocol, s.First, s.Last)
}

// ParseServiceSelector accepts the one canonical configuration grammar. TCP
// and UDP require a port/range; ICMP and ICMPv6 are protocol-only because
// they have no TCP/UDP destination port. Whitespace and protocol case are
// normalized so API, UI and runtime round-trip the same value.
func ParseServiceSelector(raw string) (ServiceSelector, error) {
	value := strings.TrimSpace(raw)
	invalid := func() (ServiceSelector, error) {
		return ServiceSelector{}, fmt.Errorf("invalid service %q; expected tcp:80, udp:53, tcp:1-65535, icmp, or icmpv6", raw)
	}
	if value == "" {
		return invalid()
	}
	parts := strings.Split(value, ":")
	if len(parts) > 2 || strings.TrimSpace(parts[0]) == "" {
		return invalid()
	}
	protocol := strings.ToLower(strings.TrimSpace(parts[0]))
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" && protocol != "icmpv6" {
		return invalid()
	}
	if len(parts) == 1 {
		if protocol == "tcp" || protocol == "udp" {
			return invalid()
		}
		return ServiceSelector{Protocol: protocol, AllPorts: true}, nil
	}
	if protocol == "icmp" || protocol == "icmpv6" {
		return invalid()
	}
	portParts := strings.Split(strings.TrimSpace(parts[1]), "-")
	if len(portParts) < 1 || len(portParts) > 2 || strings.TrimSpace(portParts[0]) == "" {
		return invalid()
	}
	first, err := strconv.Atoi(strings.TrimSpace(portParts[0]))
	if err != nil || first < 1 || first > 65535 {
		return invalid()
	}
	last := first
	if len(portParts) == 2 {
		if strings.TrimSpace(portParts[1]) == "" {
			return invalid()
		}
		last, err = strconv.Atoi(strings.TrimSpace(portParts[1]))
		if err != nil || last < first || last > 65535 {
			return invalid()
		}
	}
	return ServiceSelector{Protocol: protocol, First: uint16(first), Last: uint16(last)}, nil
}

// CanonicalServiceList validates, normalizes, de-duplicates and deterministically
// orders a policy's services. The caller may safely persist the returned slice.
func CanonicalServiceList(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	selectors := make([]ServiceSelector, 0, len(values))
	for _, raw := range values {
		if strings.TrimSpace(raw) == "" {
			return nil, fmt.Errorf("invalid empty service selector")
		}
		selector, err := ParseServiceSelector(raw)
		if err != nil {
			return nil, err
		}
		key := selector.Canonical()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		selectors = append(selectors, selector)
	}
	sort.Slice(selectors, func(i, j int) bool {
		if selectors[i].Protocol != selectors[j].Protocol {
			return selectors[i].Protocol < selectors[j].Protocol
		}
		if selectors[i].AllPorts != selectors[j].AllPorts {
			return !selectors[i].AllPorts
		}
		if selectors[i].First != selectors[j].First {
			return selectors[i].First < selectors[j].First
		}
		return selectors[i].Last < selectors[j].Last
	})
	out := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		out = append(out, selector.Canonical())
	}
	return out, nil
}
