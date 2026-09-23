package connectivity

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

type Capabilities struct{ Inspection bool }

type InspectionSelection struct {
	PolicyID                  string                `json:"policy_id"`
	ProfileID                 string                `json:"profile_id,omitempty"`
	Mode                      domain.InspectionMode `json:"mode"`
	RulesetID                 string                `json:"ruleset_id,omitempty"`
	AllowedApps               []string              `json:"allowed_apps,omitempty"`
	AppDetectionTimeoutMillis int                   `json:"app_detection_timeout_ms,omitempty"`
	Generation                uint64                `json:"generation"`
}

func CompileForCapabilities(c domain.Config, generation uint64, caps Capabilities) (Program, error) {
	if !domain.UsesM3(c) {
		return CompileM2(c, generation)
	}
	if !caps.Inspection {
		return Program{}, fmt.Errorf("configuration requires M3 inspection capability")
	}
	return CompileM3(c, generation)
}

func CompileM3(c domain.Config, generation uint64) (Program, error) {
	if errs := configpkg.ValidateInspection(c); len(errs) > 0 {
		return Program{}, fmt.Errorf("invalid M3 inspection configuration: %s", strings.Join(errs, "; "))
	}
	if errs := configpkg.ExactDuplicatePolicyErrorsForConfig(c); len(errs) > 0 {
		return Program{}, fmt.Errorf("invalid M3 policy: %s", strings.Join(errs, "; "))
	}
	if errs := configpkg.M3UnreachablePolicyErrors(c); len(errs) > 0 {
		return Program{}, fmt.Errorf("invalid M3 policy: %s", strings.Join(errs, "; "))
	}
	program, err := Compile(c, generation)
	if err != nil {
		return Program{}, err
	}
	program.InspectionIncludeManagement = domain.EffectiveInspectionConfig(c).IncludeManagement
	appDetectionTimeout := domain.EffectiveInspectionConfig(c).Limits.AppDetectionTimeoutMillis
	program.Selections = make(map[string]InspectionSelection, len(program.Rules))
	profiles := make(map[string]domain.SecurityProfile, len(c.Profiles))
	for _, profile := range c.Profiles {
		profiles[profile.ID] = profile
	}
	policies := make(map[string]domain.SecurityPolicy, len(c.Policies))
	for _, policy := range c.Policies {
		policies[policy.ID] = policy
	}
	for _, rule := range program.Rules {
		policy := policies[rule.ID]
		selection := InspectionSelection{PolicyID: rule.ID, Mode: domain.InspectionModeOff, AppDetectionTimeoutMillis: appDetectionTimeout, Generation: generation}
		if profile, ok := profiles[policy.SecurityProfileID]; ok && profile.Inspection != nil {
			selection.ProfileID = profile.ID
			selection.Mode = profile.Inspection.Mode
			selection.RulesetID = profile.Inspection.RulesetID
		}
		seen := map[string]struct{}{}
		for _, raw := range policy.Applications {
			app := strings.ToUpper(strings.TrimSpace(raw))
			if app != "" {
				seen[app] = struct{}{}
			}
		}
		for app := range seen {
			selection.AllowedApps = append(selection.AllowedApps, app)
		}
		sort.Strings(selection.AllowedApps)
		program.Selections[rule.ID] = selection
	}
	return program, nil
}

func SelectInspection(program Program, view View) InspectionSelection {
	decision := program.Evaluate(view)
	if decision.PolicyID == "" || decision.Action != domain.DecisionAllow {
		return InspectionSelection{PolicyID: decision.PolicyID, Mode: domain.InspectionModeOff, Generation: program.Generation}
	}
	if !program.InspectionIncludeManagement {
		_, sourceManagement := program.ManagementZones[strings.ToLower(strings.TrimSpace(view.SourceZone))]
		_, destinationManagement := program.ManagementZones[strings.ToLower(strings.TrimSpace(view.DestinationZone))]
		if sourceManagement || destinationManagement {
			return InspectionSelection{PolicyID: decision.PolicyID, Mode: domain.InspectionModeOff, Generation: program.Generation}
		}
	}
	if selection, ok := program.Selections[decision.PolicyID]; ok {
		selection.AllowedApps = append([]string(nil), selection.AllowedApps...)
		return selection
	}
	return InspectionSelection{PolicyID: decision.PolicyID, Mode: domain.InspectionModeOff, Generation: program.Generation}
}

func (p Program) Clone() Program {
	c := p
	c.Rules = append([]Rule(nil), p.Rules...)
	for i := range c.Rules {
		c.Rules[i].SourceZones = cloneSet(p.Rules[i].SourceZones)
		c.Rules[i].DestinationZones = cloneSet(p.Rules[i].DestinationZones)
		c.Rules[i].SourceAddresses = append([]netip.Prefix(nil), p.Rules[i].SourceAddresses...)
		c.Rules[i].DestinationAddresses = append([]netip.Prefix(nil), p.Rules[i].DestinationAddresses...)
		c.Rules[i].Services = append([]Service(nil), p.Rules[i].Services...)
		for j := range c.Rules[i].Services {
			c.Rules[i].Services[j].Ports = append([]PortRange(nil), p.Rules[i].Services[j].Ports...)
		}
	}
	c.Selections = make(map[string]InspectionSelection, len(p.Selections))
	for key, value := range p.Selections {
		value.AllowedApps = append([]string(nil), value.AllowedApps...)
		c.Selections[key] = value
	}
	c.ManagementZones = cloneSet(p.ManagementZones)
	c.zonePrefixes = make(map[string][]netip.Prefix, len(p.zonePrefixes))
	for key, value := range p.zonePrefixes {
		c.zonePrefixes[key] = append([]netip.Prefix(nil), value...)
	}
	c.localAddresses = make(map[netip.Addr]struct{}, len(p.localAddresses))
	for key := range p.localAddresses {
		c.localAddresses[key] = struct{}{}
	}
	return c
}

func cloneSet(input map[string]struct{}) map[string]struct{} {
	output := make(map[string]struct{}, len(input))
	for value := range input {
		output[value] = struct{}{}
	}
	return output
}
