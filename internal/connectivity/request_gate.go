package connectivity

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

// RequestGatePlan is a snapshot of the gate contract for one first-match
// connectivity ALLOW. It is never a second policy evaluator.
type RequestGatePlan struct {
	Enabled        bool                `json:"enabled"`
	PolicyID       string              `json:"policy_id,omitempty"`
	ProfileID      string              `json:"profile_id,omitempty"`
	Generation     uint64              `json:"generation"`
	TLSMode        domain.TLSMode      `json:"tls_mode,omitempty"`
	FailMode       domain.GateFailMode `json:"fail_mode,omitempty"`
	OversizeAction string              `json:"oversize_action,omitempty"`
	EncodingAction string              `json:"unsupported_encoding_action,omitempty"`
	BlockQUIC      bool                `json:"block_quic"`
	RulesetID      string              `json:"ruleset_id,omitempty"`
	exclusions     *compiledTLSExclusions
	tcpPorts       []PortRange
}

// A compiled set belongs to one immutable Program generation. Plans may
// share it without making a per-session copy of all exclusion selectors.
type compiledTLSExclusions struct{ rules []TLSExclusionRule }

// TLSExclusionRule keeps compiled selectors in configuration order. OR is
// used within each group, AND across nonempty groups.
type TLSExclusionRule struct {
	ID      string         `json:"id"`
	Reason  string         `json:"reason"`
	Domains []string       `json:"domains,omitempty"`
	CIDRs   []netip.Prefix `json:"destination_cidrs,omitempty"`
	Ports   []uint16       `json:"ports,omitempty"`
}

func (rule TLSExclusionRule) Clone() TLSExclusionRule {
	rule.Domains = append([]string(nil), rule.Domains...)
	rule.CIDRs = append([]netip.Prefix(nil), rule.CIDRs...)
	rule.Ports = append([]uint16(nil), rule.Ports...)
	return rule
}

func (plan RequestGatePlan) Clone() RequestGatePlan {
	plan.tcpPorts = append([]PortRange(nil), plan.tcpPorts...)
	return plan // the private compiled exclusion set is immutable
}

// TCPPorts returns a detached copy of the only destination ports that may be
// intercepted for this gate. A wildcard L3 policy does not imply all TCP ports.
func (plan RequestGatePlan) TCPPorts() []PortRange {
	return append([]PortRange(nil), plan.tcpPorts...)
}

// RequestGateTCPPorts is shared by runtime selection and the dataplane plan.
// Explicit TCP services retain their ranges; an empty service list gates only
// the standard HTTP/HTTPS ports even though the L3 policy matches all ports.
func RequestGateTCPPorts(rule Rule) []PortRange {
	if len(rule.Services) == 0 {
		return []PortRange{{First: 80, Last: 80}, {First: 443, Last: 443}}
	}
	ports := make([]PortRange, 0, len(rule.Services))
	for _, service := range rule.Services {
		if service.Protocol != 6 {
			continue
		}
		for _, port := range service.Ports {
			if port.First > 0 && port.First <= port.Last {
				ports = append(ports, port)
			}
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].First != ports[j].First {
			return ports[i].First < ports[j].First
		}
		return ports[i].Last < ports[j].Last
	})
	merged := ports[:0]
	for _, port := range ports {
		if len(merged) == 0 || uint32(port.First) > uint32(merged[len(merged)-1].Last)+1 {
			merged = append(merged, port)
			continue
		}
		if port.Last > merged[len(merged)-1].Last {
			merged[len(merged)-1].Last = port.Last
		}
	}
	return merged
}

// TLSExclusionRules returns a detached copy for diagnostics and tests.
func (plan RequestGatePlan) TLSExclusionRules() []TLSExclusionRule {
	if plan.exclusions == nil {
		return nil
	}
	rules := make([]TLSExclusionRule, len(plan.exclusions.rules))
	for i, rule := range plan.exclusions.rules {
		rules[i] = rule.Clone()
	}
	return rules
}

// CompiledRequestGateForPolicy exposes only a compiled annotation for the
// dataplane compiler. It is not a flow verdict: callers must retain every
// higher-priority connectivity rule before rendering an intercept rule.
func (p Program) CompiledRequestGateForPolicy(policyID string) (RequestGatePlan, bool) {
	plan, ok := p.requestGates[policyID]
	return plan.Clone(), ok
}

// MatchTLSExclusion uses the original destination as reconstructed after
// DNAT, never the public pre-DNAT address. Invalid/hidden SNI can match only
// an exclusion without a domain condition.
func (plan RequestGatePlan) MatchTLSExclusion(host string, originalDestination netip.AddrPort) (TLSExclusionRule, bool) {
	if !plan.Enabled || !originalDestination.IsValid() {
		return TLSExclusionRule{}, false
	}
	if plan.exclusions == nil {
		return TLSExclusionRule{}, false
	}
	for _, rule := range plan.exclusions.rules {
		if rule.matches(host, originalDestination) {
			return rule.Clone(), true
		}
	}
	return TLSExclusionRule{}, false
}

func (rule TLSExclusionRule) matches(host string, originalDestination netip.AddrPort) bool {
	if len(rule.Domains) > 0 {
		matched := false
		for _, pattern := range rule.Domains {
			if configpkg.TLSDomainMatchesCanonical(pattern, host) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(rule.CIDRs) > 0 {
		matched := false
		for _, prefix := range rule.CIDRs {
			if prefix.Contains(originalDestination.Addr()) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(rule.Ports) > 0 {
		for _, port := range rule.Ports {
			if port == originalDestination.Port() {
				return true
			}
		}
		return false
	}
	return true
}

func hasReferencedGateProfile(c domain.Config) bool {
	gateProfiles := make(map[string]bool)
	for _, profile := range c.Profiles {
		if profile.RequestGate != nil {
			gateProfiles[profile.ID] = true
		}
	}
	for _, policy := range c.Policies {
		if policy.Enabled && gateProfiles[policy.SecurityProfileID] {
			return true
		}
	}
	return false
}

// CompileM4 reuses the M3/M2 L3/L4 program and adds immutable gate plans.
// It deliberately has no dependency on REDIRECT versus TPROXY; that kernel
// choice remains blocked until the target Ubuntu capability probe passes.
func CompileM4(c domain.Config, generation uint64) (Program, error) {
	if domain.UsesM4(c) {
		if errs := configpkg.ValidateRequestGate(c); len(errs) != 0 {
			return Program{}, fmt.Errorf("invalid M4 request gate: %s", strings.Join(errs, "; "))
		}
	}
	for _, policy := range c.Policies {
		if !policy.Enabled {
			continue
		}
		if policy.MinimumRisk != nil || policy.MaximumRisk != nil {
			return Program{}, fmt.Errorf("policy %s risk matching is outside M4 connectivity scope", policy.ID)
		}
		if policy.Scope != "" && !strings.EqualFold(strings.TrimSpace(policy.Scope), "SESSION") {
			return Program{}, fmt.Errorf("policy %s scope %q is outside M4 session scope", policy.ID, policy.Scope)
		}
	}
	program, err := CompileM3(c, generation)
	if err != nil || !domain.UsesM4(c) {
		return program, err
	}
	gate := domain.EffectiveRequestGateConfig(c)
	compiledExclusions, err := compileTLSExclusions(c.TLSExclusions)
	if err != nil {
		return Program{}, err
	}
	sharedExclusions := &compiledTLSExclusions{rules: compiledExclusions}
	profiles := make(map[string]domain.SecurityProfile, len(c.Profiles))
	for _, profile := range c.Profiles {
		profiles[profile.ID] = profile
	}
	program.requestGates = make(map[string]RequestGatePlan)
	compiledRules := make(map[string]Rule, len(program.Rules))
	for _, rule := range program.Rules {
		compiledRules[rule.ID] = rule
	}
	for _, policy := range c.Policies {
		if !policy.Enabled || policy.Action != domain.DecisionAllow {
			continue
		}
		profile, ok := profiles[policy.SecurityProfileID]
		if !ok || profile.RequestGate == nil || !profile.RequestGate.Enabled {
			continue
		}
		program.requestGates[policy.ID] = RequestGatePlan{
			Enabled: true, PolicyID: policy.ID, ProfileID: profile.ID,
			Generation: generation, TLSMode: profile.TLSMode,
			FailMode:       profile.RequestGate.FailMode,
			OversizeAction: profile.RequestGate.OversizeAction,
			EncodingAction: profile.RequestGate.UnsupportedEncodingAction,
			BlockQUIC:      profile.RequestGate.BlockQUIC, RulesetID: gate.RulesetID,
			exclusions: sharedExclusions,
			tcpPorts:   RequestGateTCPPorts(compiledRules[policy.ID]),
		}
	}
	return program, nil
}

func compileTLSExclusions(exclusions []domain.TLSExclusion) ([]TLSExclusionRule, error) {
	compiled := make([]TLSExclusionRule, 0, len(exclusions))
	for _, item := range exclusions {
		if !item.Enabled {
			continue
		}
		rule := TLSExclusionRule{ID: item.ID, Reason: item.Reason}
		for _, raw := range item.Domains {
			domainName, err := configpkg.CanonicalTLSDomain(raw)
			if err != nil {
				return nil, fmt.Errorf("tls_exclusion %s domain: %w", item.ID, err)
			}
			rule.Domains = append(rule.Domains, domainName)
		}
		for _, raw := range item.DestinationCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("tls_exclusion %s CIDR: %w", item.ID, err)
			}
			rule.CIDRs = append(rule.CIDRs, prefix.Masked())
		}
		for _, port := range item.Ports {
			rule.Ports = append(rule.Ports, uint16(port))
		}
		compiled = append(compiled, rule)
	}
	return compiled, nil
}

// SelectRequestGate applies the same first-match policy decision as M2/M3.
// Default ALLOW and non-TCP traffic never acquire a gate implicitly. For a
// wildcard-service policy, only standard HTTP/TLS ports are selected;
// explicitly listed TCP services may select another TLS port.
func SelectRequestGate(program Program, view View) RequestGatePlan {
	decision := program.Evaluate(view)
	off := RequestGatePlan{PolicyID: decision.PolicyID, Generation: program.Generation}
	if decision.Action != domain.DecisionAllow || decision.PolicyID == "" || view.Protocol != 6 {
		return off
	}
	plan, ok := program.requestGates[decision.PolicyID]
	if !ok {
		return off
	}
	for _, ports := range plan.tcpPorts {
		if ports.Contains(view.DestinationPort) {
			return plan.Clone()
		}
	}
	return off
}
