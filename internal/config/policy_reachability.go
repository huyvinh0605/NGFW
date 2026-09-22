package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// policyServiceSelector uses the same protocol and destination-port semantics
// as the M1 nftables compiler and the M2 connectivity program. A selector
// without a port means every port for that protocol.
type policyServiceSelector struct {
	protocol string
	first    uint16
	last     uint16
	allPorts bool
}

func parseM1ServiceSelector(value string) (policyServiceSelector, error) {
	invalid := func() error {
		return fmt.Errorf("invalid service %q; expected tcp, udp, icmp, tcp:80, udp:53, or tcp:1000-2000", value)
	}
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) > 2 || len(parts) == 0 {
		return policyServiceSelector{}, invalid()
	}
	protocol := strings.ToLower(strings.TrimSpace(parts[0]))
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return policyServiceSelector{}, invalid()
	}
	selector := policyServiceSelector{protocol: protocol, allPorts: true}
	if len(parts) == 1 {
		return selector, nil
	}
	if protocol == "icmp" {
		return policyServiceSelector{}, invalid()
	}
	portParts := strings.Split(strings.TrimSpace(parts[1]), "-")
	if len(portParts) < 1 || len(portParts) > 2 {
		return policyServiceSelector{}, invalid()
	}
	first, err := strconv.Atoi(strings.TrimSpace(portParts[0]))
	if err != nil || first < 1 || first > 65535 {
		return policyServiceSelector{}, invalid()
	}
	last := first
	if len(portParts) == 2 {
		last, err = strconv.Atoi(strings.TrimSpace(portParts[1]))
		if err != nil || last < first || last > 65535 {
			return policyServiceSelector{}, invalid()
		}
	}
	selector.first, selector.last, selector.allPorts = uint16(first), uint16(last), false
	return selector, nil
}

// UnreachablePolicyErrors reports a policy only when one earlier M1/M2 L3/L4
// policy covers all of its traffic. It deliberately does not try to infer a
// union of multiple rules, which avoids rejecting a valid configuration when
// coverage cannot be proven from one first-match rule.
//
// This semantic check is separate from Validator so an appliance can still
// restart with a legacy running configuration that contains a redundant rule.
// Management and commit paths use it before accepting a new Candidate.
func UnreachablePolicyErrors(policies []domain.SecurityPolicy) []string {
	ordered := append([]domain.SecurityPolicy(nil), policies...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	var errs []string
	for laterIndex, later := range ordered {
		if !isL3L4FirstMatchPolicy(later) {
			continue
		}
		for earlierIndex := 0; earlierIndex < laterIndex; earlierIndex++ {
			earlier := ordered[earlierIndex]
			if earlier.Priority >= later.Priority || !isL3L4FirstMatchPolicy(earlier) {
				continue
			}
			if policyMatchCovers(earlier, later) {
				errs = append(errs, fmt.Sprintf("policy %s is unreachable: higher-priority policy %s (priority %d) already matches all of its traffic", later.ID, earlier.ID, earlier.Priority))
				break
			}
		}
	}
	return errs
}

func isL3L4FirstMatchPolicy(policy domain.SecurityPolicy) bool {
	if !policy.Enabled || len(policy.Applications) != 0 || policy.SecurityProfileID != "" || policy.MinimumRisk != nil || policy.MaximumRisk != nil {
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(policy.Scope)) {
	case "", "SESSION":
	default:
		return false
	}
	switch policy.Action {
	case domain.DecisionAllow, domain.DecisionDrop, domain.DecisionReject:
		return true
	default:
		return false
	}
}

func policyMatchCovers(earlier, later domain.SecurityPolicy) bool {
	return stringSelectorsCover(earlier.SourceZones, later.SourceZones) &&
		stringSelectorsCover(earlier.DestinationZones, later.DestinationZones) &&
		addressSelectorsCover(earlier.SourceAddresses, later.SourceAddresses) &&
		addressSelectorsCover(earlier.DestinationAddresses, later.DestinationAddresses) &&
		serviceSelectorsCover(earlier.Services, later.Services)
}

// An empty selector list means any value. Therefore it only fits inside an
// earlier list that is also empty; a concrete later list is covered when each
// member is accepted by the earlier selector list.
func stringSelectorsCover(earlier, later []string) bool {
	if len(later) == 0 {
		return len(earlier) == 0
	}
	if len(earlier) == 0 {
		return true
	}
	for _, wanted := range later {
		matched := false
		for _, candidate := range earlier {
			if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(wanted)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func addressSelectorsCover(earlier, later []string) bool {
	if len(later) == 0 {
		return len(earlier) == 0
	}
	if len(earlier) == 0 {
		return true
	}
	prior := make([]netip.Prefix, 0, len(earlier))
	for _, raw := range earlier {
		prefix, ok := selectorPrefix(raw)
		if !ok {
			return false
		}
		prior = append(prior, prefix)
	}
	for _, raw := range later {
		wanted, ok := selectorPrefix(raw)
		if !ok {
			return false
		}
		matched := false
		for _, candidate := range prior {
			if candidate.Addr().BitLen() == wanted.Addr().BitLen() && candidate.Bits() <= wanted.Bits() && candidate.Contains(wanted.Addr()) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func selectorPrefix(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix.Masked(), true
	}
	address, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, address.BitLen()), true
}

func serviceSelectorsCover(earlier, later []string) bool {
	if len(later) == 0 {
		return len(earlier) == 0
	}
	if len(earlier) == 0 {
		return true
	}
	prior := make([]policyServiceSelector, 0, len(earlier))
	for _, raw := range earlier {
		selector, err := parseM1ServiceSelector(raw)
		if err != nil {
			return false
		}
		prior = append(prior, selector)
	}
	for _, raw := range later {
		wanted, err := parseM1ServiceSelector(raw)
		if err != nil {
			return false
		}
		matched := false
		for _, candidate := range prior {
			if candidate.protocol != wanted.protocol {
				continue
			}
			if candidate.allPorts || (!wanted.allPorts && candidate.first <= wanted.first && candidate.last >= wanted.last) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
