package dataplane

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

// ProxySelectionSchema is a compiler input version. It is deliberately not an
// nftables table version: REDIRECT/TPROXY syntax is selected only after T01.
const ProxySelectionSchema = 1

// ProxySchemaScript defines only an inert, NGFW-owned table. T01 must select
// REDIRECT or TPROXY before a hooked prerouting chain can be rendered. Merely
// creating this table cannot change packet forwarding.
func ProxySchemaScript() string {
	return `table inet ngfw_proxy {
  comment "owner=ngfw-engine schema=1"
  chain select { }
}
`
}

// ProxySelectionPlan preserves *all* first-match connectivity rules. The
// eventual nft renderer must emit a terminal non-intercept path for earlier
// ungated ALLOW/DROP/REJECT rules before any later intercept rule.
type ProxySelectionPlan struct {
	SchemaVersion   int                  `json:"schema_version"`
	Generation      uint64               `json:"generation"`
	Enabled         bool                 `json:"enabled"`
	ListenHTTPPort  int                  `json:"listen_http_port,omitempty"`
	ListenHTTPSPort int                  `json:"listen_https_port,omitempty"`
	Rules           []ProxySelectionRule `json:"rules,omitempty"`
}

// Match is the same compiled matcher used by the M2/M3 connectivity program.
// Gate means the TCP submatch of this ALLOW is eligible for the M4 request
// gate. A policy may also include UDP services; those must never intercept.
// Gate is not an independent authorization decision.
type ProxySelectionRule struct {
	Match     connectivity.Rule        `json:"match"`
	Gate      bool                     `json:"gate"`
	ProfileID string                   `json:"profile_id,omitempty"`
	GatePorts []connectivity.PortRange `json:"gate_ports,omitempty"`
}

func (plan ProxySelectionPlan) Clone() ProxySelectionPlan {
	plan.Rules = append([]ProxySelectionRule(nil), plan.Rules...)
	for index := range plan.Rules {
		plan.Rules[index].Match = cloneProxyConnectivityRule(plan.Rules[index].Match)
		plan.Rules[index].GatePorts = append([]connectivity.PortRange(nil), plan.Rules[index].GatePorts...)
	}
	return plan
}

// Validate is called before a plan may enter a persisted activation snapshot
// or a kernel renderer. It cannot establish Linux interception capability.
func (plan ProxySelectionPlan) Validate() error {
	if plan.SchemaVersion != ProxySelectionSchema {
		return fmt.Errorf("unsupported proxy selection schema %d", plan.SchemaVersion)
	}
	if !plan.Enabled {
		if len(plan.Rules) != 0 || plan.ListenHTTPPort != 0 || plan.ListenHTTPSPort != 0 {
			return fmt.Errorf("disabled proxy selector contains active rules or listeners")
		}
		return nil
	}
	if plan.ListenHTTPPort < 1 || plan.ListenHTTPPort > 65535 || plan.ListenHTTPSPort < 1 || plan.ListenHTTPSPort > 65535 || plan.ListenHTTPPort == plan.ListenHTTPSPort {
		return fmt.Errorf("invalid proxy listener ports")
	}
	seenIDs := make(map[string]bool, len(plan.Rules))
	gateCount := 0
	lastPriority := -1
	for _, entry := range plan.Rules {
		rule := entry.Match
		if rule.ID == "" || seenIDs[rule.ID] || !rule.Enabled || rule.Priority <= lastPriority {
			return fmt.Errorf("proxy selector has duplicate, disabled or unordered policy %q", rule.ID)
		}
		seenIDs[rule.ID] = true
		lastPriority = rule.Priority
		if rule.Action != domain.DecisionAllow && rule.Action != domain.DecisionDrop && rule.Action != domain.DecisionReject {
			return fmt.Errorf("proxy selector policy %s has unsupported action", rule.ID)
		}
		if entry.Gate {
			if rule.Action != domain.DecisionAllow || entry.ProfileID == "" {
				return fmt.Errorf("proxy selector policy %s gates a non-ALLOW or lacks a profile", rule.ID)
			}
			if len(entry.GatePorts) == 0 || !slices.Equal(entry.GatePorts, connectivity.RequestGateTCPPorts(rule)) {
				return fmt.Errorf("proxy selector policy %s has invalid gate ports", rule.ID)
			}
			gateCount++
		} else if entry.ProfileID != "" || len(entry.GatePorts) != 0 {
			return fmt.Errorf("proxy selector policy %s has a profile or ports without a gate", rule.ID)
		}
	}
	if gateCount == 0 {
		return fmt.Errorf("enabled proxy selector has no gated policy")
	}
	return nil
}

func cloneProxyConnectivityRule(rule connectivity.Rule) connectivity.Rule {
	clone := rule
	clone.SourceZones = make(map[string]struct{}, len(rule.SourceZones))
	for zone := range rule.SourceZones {
		clone.SourceZones[zone] = struct{}{}
	}
	clone.DestinationZones = make(map[string]struct{}, len(rule.DestinationZones))
	for zone := range rule.DestinationZones {
		clone.DestinationZones[zone] = struct{}{}
	}
	clone.SourceAddresses = append([]netip.Prefix(nil), rule.SourceAddresses...)
	clone.DestinationAddresses = append([]netip.Prefix(nil), rule.DestinationAddresses...)
	clone.Services = append([]connectivity.Service(nil), rule.Services...)
	for index := range clone.Services {
		clone.Services[index].Ports = append([]connectivity.PortRange(nil), rule.Services[index].Ports...)
	}
	return clone
}
