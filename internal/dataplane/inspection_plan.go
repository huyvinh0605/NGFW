package dataplane

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

type InspectionRule struct {
	Policy    domain.SecurityPolicy
	Selection connectivity.InspectionSelection
}
type InspectionPlan struct {
	Generation        uint64
	Enabled           bool
	IncludeManagement bool
	Rules             []InspectionRule
	RenderedRules     int
}

func CompileInspectionPlan(c domain.Config, program connectivity.Program) (InspectionPlan, error) {
	plan := InspectionPlan{Generation: program.Generation}
	effective := domain.EffectiveInspectionConfig(c)
	plan.Enabled = effective.Enabled
	plan.IncludeManagement = effective.IncludeManagement
	if !effective.Enabled {
		return plan, nil
	}
	policies := append([]domain.SecurityPolicy(nil), c.Policies...)
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Priority < policies[j].Priority })
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		selection, ok := program.Selections[policy.ID]
		if !ok {
			selection = connectivity.InspectionSelection{PolicyID: policy.ID, Mode: domain.InspectionModeOff, Generation: program.Generation}
		}
		plan.Rules = append(plan.Rules, InspectionRule{Policy: policy, Selection: selection})
		services := len(policy.Services)
		if services == 0 {
			services = 1
		}
		linesPerDirection := 1
		if selection.Mode == domain.InspectionModeIDS || selection.Mode == domain.InspectionModeIPS {
			linesPerDirection = 2
		}
		plan.RenderedRules += services * 2 * linesPerDirection
		if plan.RenderedRules > 10000 {
			return InspectionPlan{}, fmt.Errorf("inspection rule count exceeds 10000")
		}
	}
	return plan, nil
}

func RenderInspectionRules(plan InspectionPlan, c domain.Config) (string, error) {
	var builder strings.Builder
	builder.WriteString("flush chain inet ngfw_inspection inspect\n")
	if !plan.Enabled {
		return builder.String(), nil
	}
	zones := buildZoneInterfaces(c)
	managementInterfaces := make([]string, 0)
	if !plan.IncludeManagement {
		for _, iface := range c.Interfaces {
			if iface.Mode == domain.InterfaceManagement && iface.AdminState {
				managementInterfaces = append(managementInterfaces, iface.SystemName)
			}
		}
		sort.Strings(managementInterfaces)
	}
	for _, entry := range plan.Rules {
		forward, err := renderInspectionDirection(entry.Policy, entry.Selection, zones, managementInterfaces, false)
		if err != nil {
			return "", err
		}
		reverse, err := renderInspectionDirection(entry.Policy, entry.Selection, zones, managementInterfaces, true)
		if err != nil {
			return "", err
		}
		for _, line := range append(forward, reverse...) {
			builder.WriteString("add rule inet ngfw_inspection inspect " + line + "\n")
		}
	}
	return builder.String(), nil
}

func renderInspectionDirection(policy domain.SecurityPolicy, selection connectivity.InspectionSelection, zones map[string][]string, managementInterfaces []string, reverse bool) ([]string, error) {
	base := []string{}
	if len(managementInterfaces) > 0 {
		base = append(base, "iifname != "+quoteSet(managementInterfaces), "oifname != "+quoteSet(managementInterfaces))
	}
	sourceZones, destinationZones := policy.SourceZones, policy.DestinationZones
	sourceAddresses, destinationAddresses := policy.SourceAddresses, policy.DestinationAddresses
	if reverse {
		sourceZones, destinationZones = destinationZones, sourceZones
		sourceAddresses, destinationAddresses = destinationAddresses, sourceAddresses
		base = append(base, "ct state established,related")
	}
	if len(sourceZones) > 0 {
		base = append(base, "iifname "+quoteSet(zoneInterfaces(sourceZones, zones)))
	}
	if len(destinationZones) > 0 {
		base = append(base, "oifname "+quoteSet(zoneInterfaces(destinationZones, zones)))
	}
	if len(sourceAddresses) > 0 {
		values, err := canonicalIPv4List(sourceAddresses)
		if err != nil {
			return nil, err
		}
		base = append(base, "ip saddr "+valueOrSet(values, false))
	}
	if len(destinationAddresses) > 0 {
		values, err := canonicalIPv4List(destinationAddresses)
		if err != nil {
			return nil, err
		}
		base = append(base, "ip daddr "+valueOrSet(values, false))
	}
	services := policy.Services
	if len(services) == 0 {
		services = []string{""}
	}
	lines := make([]string, 0, len(services)*2)
	for _, service := range services {
		parts := append([]string(nil), base...)
		if service != "" {
			var expression string
			var err error
			if reverse {
				expression, err = reverseServiceExpression(service)
			} else {
				expression, err = serviceExpression(service)
			}
			if err != nil {
				return nil, err
			}
			parts = append(parts, expression)
		}
		comment := fmt.Sprintf(`comment "m3:%s:%s"`, policy.ID, map[bool]string{true: "reply", false: "original"}[reverse])
		switch selection.Mode {
		case domain.InspectionModeIDS:
			lines = append(lines, strings.Join(append(parts, "counter", "log group 100 snaplen 0 queue-threshold 1", comment), " "))
			lines = append(lines, strings.Join(append(parts, "counter", "accept", comment), " "))
		case domain.InspectionModeIPS:
			withLease := append(append([]string(nil), parts...), "meta nfproto . meta l4proto @ips_ready", "counter", "queue num 100 bypass", comment)
			lines = append(lines, strings.Join(withLease, " "))
			lines = append(lines, strings.Join(append(parts, "counter", "accept", comment), " "))
		default:
			lines = append(lines, strings.Join(append(parts, "counter", "accept", comment), " "))
		}
	}
	return lines, nil
}
