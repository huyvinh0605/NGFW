package policy

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

type Evaluator struct{ DefaultDeny bool }

func NewEvaluator(defaultDeny bool) *Evaluator { return &Evaluator{DefaultDeny: defaultDeny} }

func (e *Evaluator) Evaluate(ctx *domain.SecurityContext, policies []domain.SecurityPolicy, profiles map[string]domain.SecurityProfile, version uint64) domain.PolicyDecision {
	ordered := append([]domain.SecurityPolicy(nil), policies...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	for _, p := range ordered {
		if !p.Enabled || !matches(p, ctx) {
			continue
		}
		d := domain.PolicyDecision{Action: p.Action, Scope: scope(p.Scope), PolicyID: p.ID, ConfigVersion: version, Reason: fmt.Sprintf("matched policy %s", p.Name)}
		if d.Scope == "" {
			d.Scope = "SESSION"
		}
		if p.Action == domain.DecisionAllow && p.MinimumRisk != nil && ctx.Risk.Score < *p.MinimumRisk {
			continue
		}
		if p.MaximumRisk != nil && ctx.Risk.Score > *p.MaximumRisk {
			continue
		}
		if profile, ok := profiles[p.SecurityProfileID]; ok {
			if p.Action == domain.DecisionAllow && ctx.Risk.Score >= profile.MinimumBlockRisk {
				d.Action = domain.DecisionDrop
				d.Reason = fmt.Sprintf("risk %d reached profile block threshold %d", ctx.Risk.Score, profile.MinimumBlockRisk)
			}
			if p.Action == domain.DecisionAllow && profile.URLFilteringEnabled && hasBlockedURL(ctx) {
				d.Action = domain.DecisionDrop
				d.Reason = "URL security profile blocked the request"
			}
		}
		return d
	}
	a := domain.DecisionAllow
	reason := "no policy matched"
	if e.DefaultDeny {
		a = domain.DecisionDrop
		reason = "default deny"
	}
	return domain.PolicyDecision{Action: a, Scope: "SESSION", ConfigVersion: version, Reason: reason}
}

func hasBlockedURL(ctx *domain.SecurityContext) bool {
	for _, ev := range ctx.Signals {
		if strings.EqualFold(ev.Detector, "URL") && (strings.EqualFold(ev.Category, "BLOCKED") || strings.EqualFold(ev.Category, "BLOCKED_URL")) {
			return true
		}
	}
	return false
}

func matches(p domain.SecurityPolicy, c *domain.SecurityContext) bool {
	if len(p.SourceZones) > 0 && !containsFold(p.SourceZones, c.Network.SrcZone) {
		return false
	}
	if len(p.DestinationZones) > 0 && !containsFold(p.DestinationZones, c.Network.DstZone) {
		return false
	}
	if len(p.SourceAddresses) > 0 && !addressMatches(p.SourceAddresses, c.Network.SrcIP) {
		return false
	}
	if len(p.DestinationAddresses) > 0 && !addressMatches(p.DestinationAddresses, c.Network.DstIP) {
		return false
	}
	if len(p.Applications) > 0 && !containsFold(p.Applications, c.App.Application) {
		return false
	}
	if len(p.Services) > 0 && !serviceMatches(p.Services, c) {
		return false
	}
	return true
}
func containsFold(values []string, v string) bool {
	for _, x := range values {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
func addressMatches(values []string, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, x := range values {
		if strings.EqualFold(x, ip) {
			return true
		}
		if _, n, err := net.ParseCIDR(x); err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}
func serviceMatches(values []string, c *domain.SecurityContext) bool {
	for _, v := range values {
		x := strings.ToUpper(v)
		if x == strings.ToUpper(c.Network.Protocol) {
			return true
		}
		if strings.Contains(x, ":") {
			parts := strings.SplitN(x, ":", 2)
			if strings.EqualFold(parts[0], c.Network.Protocol) && parts[1] == fmt.Sprint(c.Network.DstPort) {
				return true
			}
		}
	}
	return false
}
func scope(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	switch v {
	case "PACKET", "REQUEST", "SESSION", "SOURCE":
		return v
	default:
		return "SESSION"
	}
}
