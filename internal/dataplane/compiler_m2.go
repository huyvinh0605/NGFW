package dataplane

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// M2CompileOptions describes the immutable kernel cache metadata for one
// activation. Runtime guards live in a separate table so replacing the policy
// table cannot delete an active temporary block or revoke fence.
type M2CompileOptions struct {
	Epoch        uint16           `json:"epoch"`
	ZoneSlots    map[string]uint8 `json:"zone_slots,omitempty"`
	CacheEnabled bool             `json:"cache_enabled"`
}

func (o M2CompileOptions) Clone() M2CompileOptions {
	c := o
	c.ZoneSlots = make(map[string]uint8, len(o.ZoneSlots))
	for key, value := range o.ZoneSlots {
		c.ZoneSlots[key] = value
	}
	return c
}

func CompileM2Ruleset(config domain.Config, options M2CompileOptions) (string, error) {
	ruleset, err := CompileRuleset(config)
	if err != nil {
		return "", err
	}
	// M1's unconditional established accept is intentionally removed from the
	// M2 program. A packet without a current, provenance-bearing mark falls
	// through to the same current L3/L4 policy rules.
	old := "ct state established,related accept;"
	if !strings.Contains(ruleset, old) {
		return "", fmt.Errorf("M1 compiler did not expose established rule")
	}
	if !config.DefaultDeny {
		// Keep the base chain fail-closed. Default allow is represented by an
		// explicit final rule after all first-match policies and the same
		// runtime guard hook, so an unmarked packet cannot skip the M2 path.
		const acceptPolicy = "chain forward { type filter hook forward priority 0; policy accept;"
		const dropPolicy = "chain forward { type filter hook forward priority 0; policy drop;"
		if !strings.Contains(ruleset, acceptPolicy) {
			return "", fmt.Errorf("M1 compiler did not expose default-allow forward policy")
		}
		ruleset = strings.Replace(ruleset, acceptPolicy, dropPolicy, 1)
	}
	cacheRules := make([]string, 0)
	markByPolicy := map[string]uint32{}
	if options.CacheEnabled && options.Epoch > 0 && len(options.ZoneSlots) > 0 {
		slots := make([]int, 0, len(options.ZoneSlots))
		for _, slot := range options.ZoneSlots {
			if slot > 0 {
				slots = append(slots, int(slot))
			}
		}
		sort.Ints(slots)
		for _, src := range slots {
			for _, dst := range slots {
				value, _ := PackCacheMark(CacheMark{Epoch: options.Epoch, SourceZoneSlot: uint8(src), DestinationZoneSlot: uint8(dst)})
				cacheRules = append(cacheRules, fmt.Sprintf("ct state established ct mark & 0xffffff00 == 0x%08x accept", value))
			}
		}
		for _, policy := range config.Policies {
			if !policy.Enabled || policy.Action != domain.DecisionAllow || len(policy.SourceZones) != 1 || len(policy.DestinationZones) != 1 {
				continue
			}
			src, srcOK := options.ZoneSlots[policy.SourceZones[0]]
			dst, dstOK := options.ZoneSlots[policy.DestinationZones[0]]
			if !srcOK || !dstOK || src == 0 || dst == 0 {
				continue
			}
			value, markErr := PackCacheMark(CacheMark{Epoch: options.Epoch, SourceZoneSlot: src, DestinationZoneSlot: dst})
			if markErr == nil {
				markByPolicy[policy.ID] = value
			}
		}
	}
	// Even in safe no-cache mode invalid and block guards stay ahead of policy.
	replacement := "ct state invalid drop;"
	if len(cacheRules) > 0 {
		replacement += " " + strings.Join(cacheRules, "; ") + ";"
	}
	ruleset = strings.Replace(ruleset, "ct state invalid drop; ct state established,related accept;", replacement, 1)
	// Removing M1's blanket established accept must not break the reply
	// direction of a still-valid stateful connection. Add a constrained reverse
	// rule for each configured policy; it requires established/related state and
	// swaps zones, addresses and service direction. A reverse rule is therefore
	// not an unconditional state bypass and is re-evaluated after generation
	// changes just like the forward rule.
	reverseLines := make([]string, 0)
	zoneIfaces := buildZoneInterfaces(config)
	reversePolicies := append([]domain.SecurityPolicy(nil), config.Policies...)
	sort.SliceStable(reversePolicies, func(i, j int) bool { return reversePolicies[i].Priority < reversePolicies[j].Priority })
	for _, policy := range reversePolicies {
		if !policy.Enabled {
			continue
		}
		lines, reverseErr := renderReversePolicyRules(policy, zoneIfaces)
		if reverseErr != nil {
			return "", reverseErr
		}
		reverseLines = append(reverseLines, lines...)
	}
	forwardTail := make([]string, 0, len(reverseLines)+1)
	forwardTail = append(forwardTail, reverseLines...)
	if !config.DefaultDeny {
		forwardTail = append(forwardTail, `counter accept comment "default:allow"`)
	}
	if len(forwardTail) > 0 {
		var reverse strings.Builder
		for _, line := range forwardTail {
			reverse.WriteString("    ")
			reverse.WriteString(line)
			reverse.WriteByte('\n')
		}
		needle := "  }\n  chain nat_postrouting"
		ruleset = strings.Replace(ruleset, needle, reverse.String()+"  }\n\n  chain nat_postrouting", 1)
	}
	// A first-packet ALLOW records its policy generation and zone pair in the
	// conntrack mark. Preserve the low byte because M1 deployments may use it
	// for an independent mark. Policies with an ambiguous zone pair deliberately
	// remain on the evaluated path until a later activation can identify it.
	for policyID, value := range markByPolicy {
		for _, suffix := range []string{"", ":reverse"} {
			needle := ` counter accept comment "policy:` + policyID + suffix + `"`
			replacement := fmt.Sprintf(" ct mark set (ct mark & 0x000000ff) | 0x%08x counter accept comment \"policy:%s%s\"", value, policyID, suffix)
			ruleset = strings.ReplaceAll(ruleset, needle, replacement)
		}
	}
	// Conntrack IDs are an nftables expression-derived datatype.  A generic
	// `type integer` set is rejected by nft (and prevents the engine from
	// starting), so derive the set type from the expression used for lookup.
	runtimeTable := "table inet ngfw_runtime {\n  set source_blocks { type ipv4_addr; flags timeout; timeout 5m; }\n  set revoked_ctids { typeof ct id; }\n  chain forward_guard { type filter hook forward priority -20; policy accept; ct id @revoked_ctids drop; ip saddr @source_blocks drop; ip daddr @source_blocks drop; }\n}\n"
	return runtimeTable + ruleset, nil
}

func renderReversePolicyRules(policy domain.SecurityPolicy, zoneIfaces map[string][]string) ([]string, error) {
	base := []string{"ct state established,related"}
	if len(policy.DestinationZones) > 0 {
		base = append(base, "iifname "+quoteSet(zoneInterfaces(policy.DestinationZones, zoneIfaces)))
	}
	if len(policy.SourceZones) > 0 {
		base = append(base, "oifname "+quoteSet(zoneInterfaces(policy.SourceZones, zoneIfaces)))
	}
	if len(policy.DestinationAddresses) > 0 {
		values, err := canonicalIPv4List(policy.DestinationAddresses)
		if err != nil {
			return nil, fmt.Errorf("policy %s reverse destination addresses: %w", policy.ID, err)
		}
		base = append(base, "ip saddr "+valueOrSet(values, false))
	}
	if len(policy.SourceAddresses) > 0 {
		values, err := canonicalIPv4List(policy.SourceAddresses)
		if err != nil {
			return nil, fmt.Errorf("policy %s reverse source addresses: %w", policy.ID, err)
		}
		base = append(base, "ip daddr "+valueOrSet(values, false))
	}
	action, err := policyAction(policy.Action)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", policy.ID, err)
	}
	services := policy.Services
	if len(services) == 0 {
		services = []string{""}
	}
	lines := make([]string, 0, len(services))
	for _, service := range services {
		parts := append([]string(nil), base...)
		if service != "" {
			expression, expressionErr := reverseServiceExpression(service)
			if expressionErr != nil {
				return nil, fmt.Errorf("policy %s: %w", policy.ID, expressionErr)
			}
			parts = append(parts, expression)
		}
		parts = append(parts, "counter", action, `comment "policy:`+policy.ID+`:reverse"`)
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines, nil
}

func reverseServiceExpression(value string) (string, error) {
	selector, err := domain.ParseServiceSelector(value)
	if err != nil {
		return "", err
	}
	if selector.AllPorts {
		return "meta l4proto " + selector.Protocol, nil
	}
	port := strconv.Itoa(int(selector.First))
	if selector.First != selector.Last {
		port += "-" + strconv.Itoa(int(selector.Last))
	}
	return selector.Protocol + " sport " + port, nil
}
