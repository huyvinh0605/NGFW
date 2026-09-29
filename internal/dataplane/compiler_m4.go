package dataplane

import (
	"fmt"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

// CompileM4ProxySelection builds only the mechanism-neutral first-match
// selector. It cannot mutate nftables or mark REDIRECT/TPROXY as supported.
// The Linux T01 probe is required before rendering/applying this plan.
func CompileM4ProxySelection(config domain.Config, generation uint64) (ProxySelectionPlan, error) {
	plan := ProxySelectionPlan{SchemaVersion: ProxySelectionSchema, Generation: generation}
	if !domain.UsesM4(config) {
		return plan, nil // an OFF gate has no selector or side effect
	}
	program, err := connectivity.CompileM4(config, generation)
	if err != nil {
		return ProxySelectionPlan{}, err
	}
	limits := domain.EffectiveRequestGateConfig(config)
	plan.ListenHTTPPort = limits.ListenHTTPPort
	plan.ListenHTTPSPort = limits.ListenHTTPSPort
	plan.Rules = make([]ProxySelectionRule, 0, len(program.Rules))
	for _, compiledRule := range program.Rules {
		entry := ProxySelectionRule{Match: cloneProxyConnectivityRule(compiledRule)}
		if gate, present := program.CompiledRequestGateForPolicy(compiledRule.ID); present {
			if compiledRule.Action != domain.DecisionAllow || !gate.Enabled || gate.Generation != generation {
				return ProxySelectionPlan{}, fmt.Errorf("policy %s has inconsistent compiled M4 gate", compiledRule.ID)
			}
			entry.Gate = true
			entry.ProfileID = gate.ProfileID
			entry.GatePorts = gate.TCPPorts()
			plan.Enabled = true
		}
		plan.Rules = append(plan.Rules, entry)
	}
	if !plan.Enabled {
		plan.Rules = nil
		plan.ListenHTTPPort = 0
		plan.ListenHTTPSPort = 0
	}
	if err := plan.Validate(); err != nil {
		return ProxySelectionPlan{}, err
	}
	return plan, nil
}
