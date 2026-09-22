package dataplane

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// CompileRuleset renders the complete M1 nftables table. NftRunner validates
// and applies the returned script as one nftables transaction.
func CompileRuleset(config domain.Config) (string, error) {
	zoneIfaces := buildZoneInterfaces(config)
	if errs := validateForRender(config, zoneIfaces); len(errs) > 0 {
		return "", fmt.Errorf("cannot compile dataplane: %s", strings.Join(errs, "; "))
	}

	natRules := append([]domain.NATRule(nil), config.NATRules...)
	sort.SliceStable(natRules, func(i, j int) bool { return natRules[i].Priority < natRules[j].Priority })
	policies := append([]domain.SecurityPolicy(nil), config.Policies...)
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Priority < policies[j].Priority })

	var builder strings.Builder
	builder.WriteString("flush table inet ngfw\n")
	builder.WriteString("table inet ngfw {\n")
	builder.WriteString("  set temporary_blocks { type ipv4_addr; flags timeout; timeout 5m; }\n")
	builder.WriteString("  chain prerouting { type filter hook prerouting priority -150; policy accept; ip saddr @temporary_blocks drop; }\n")
	builder.WriteString("  chain nat_prerouting { type nat hook prerouting priority -100; policy accept;\n")
	for _, rule := range natRules {
		if !rule.Enabled || !strings.EqualFold(rule.Type, "DNAT") {
			continue
		}
		line, err := renderNATRule(rule, zoneIfaces, true)
		if err != nil {
			return "", err
		}
		builder.WriteString("    " + line + "\n")
	}
	builder.WriteString("  }\n")

	// DNAT destination-zone checks run before the stateful accept rule. This
	// prevents an established conntrack entry from bypassing a changed zone.
	builder.WriteString("  chain dnat_zone_guard { type filter hook forward priority -5; policy accept;\n")
	for _, rule := range natRules {
		if !rule.Enabled || !strings.EqualFold(rule.Type, "DNAT") {
			continue
		}
		line, err := renderDNATZoneGuard(rule, zoneIfaces)
		if err != nil {
			return "", err
		}
		builder.WriteString("    " + line + "\n")
	}
	builder.WriteString("  }\n")

	policy := "drop"
	if !config.DefaultDeny {
		policy = "accept"
	}
	builder.WriteString("  chain forward { type filter hook forward priority 0; policy " + policy + "; ct state invalid drop; ct state established,related accept;\n")
	for _, rule := range policies {
		if !rule.Enabled {
			continue
		}
		lines, err := renderPolicyRules(rule, zoneIfaces)
		if err != nil {
			return "", err
		}
		for _, line := range lines {
			builder.WriteString("    " + line + "\n")
		}
	}
	builder.WriteString("  }\n")

	builder.WriteString("  chain nat_postrouting { type nat hook postrouting priority 100; policy accept;\n")
	for _, rule := range natRules {
		if !rule.Enabled || strings.EqualFold(rule.Type, "DNAT") {
			continue
		}
		line, err := renderNATRule(rule, zoneIfaces, false)
		if err != nil {
			return "", err
		}
		builder.WriteString("    " + line + "\n")
	}
	builder.WriteString("  }\n")
	builder.WriteString("}\n")
	return builder.String(), nil
}

func renderPolicyRules(policy domain.SecurityPolicy, zoneIfaces map[string][]string) ([]string, error) {
	base := make([]string, 0, 6)
	if len(policy.SourceZones) > 0 {
		base = append(base, "iifname "+quoteSet(zoneInterfaces(policy.SourceZones, zoneIfaces)))
	}
	if len(policy.DestinationZones) > 0 {
		base = append(base, "oifname "+quoteSet(zoneInterfaces(policy.DestinationZones, zoneIfaces)))
	}
	if len(policy.SourceAddresses) > 0 {
		values, err := canonicalIPv4List(policy.SourceAddresses)
		if err != nil {
			return nil, fmt.Errorf("policy %s source addresses: %w", policy.ID, err)
		}
		base = append(base, "ip saddr "+valueOrSet(values, false))
	}
	if len(policy.DestinationAddresses) > 0 {
		values, err := canonicalIPv4List(policy.DestinationAddresses)
		if err != nil {
			return nil, fmt.Errorf("policy %s destination addresses: %w", policy.ID, err)
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
			expression, err := serviceExpression(service)
			if err != nil {
				return nil, fmt.Errorf("policy %s: %w", policy.ID, err)
			}
			parts = append(parts, expression)
		}
		parts = append(parts, "counter", action, `comment "policy:`+policy.ID+`"`)
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines, nil
}

func policyAction(action domain.Decision) (string, error) {
	switch action {
	case domain.DecisionAllow:
		return "accept", nil
	case domain.DecisionDrop:
		return "drop", nil
	case domain.DecisionReject:
		return "reject", nil
	default:
		return "", fmt.Errorf("action %q is not an M1 firewall action", action)
	}
}

func serviceExpression(value string) (string, error) {
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
	return selector.Protocol + " dport " + port, nil
}

func canonicalPort(value string) (string, error) {
	parts := strings.Split(strings.TrimSpace(value), "-")
	if len(parts) < 1 || len(parts) > 2 {
		return "", fmt.Errorf("invalid port or range")
	}
	ports := make([]int, len(parts))
	for index, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("port must be in 1..65535")
		}
		ports[index] = port
	}
	if len(ports) == 2 {
		if ports[0] > ports[1] {
			return "", fmt.Errorf("port range is reversed")
		}
		return fmt.Sprintf("%d-%d", ports[0], ports[1]), nil
	}
	return strconv.Itoa(ports[0]), nil
}

func renderNATRule(rule domain.NATRule, zoneIfaces map[string][]string, prerouting bool) (string, error) {
	parts := make([]string, 0, 10)
	if rule.SourceZone != "" {
		parts = append(parts, "iifname "+quoteSet(zoneInterfaces([]string{rule.SourceZone}, zoneIfaces)))
	}
	if !prerouting && rule.DestinationZone != "" {
		parts = append(parts, "oifname "+quoteSet(zoneInterfaces([]string{rule.DestinationZone}, zoneIfaces)))
	}
	if rule.SourceNetwork != "" {
		network, err := canonicalIPv4(rule.SourceNetwork)
		if err != nil {
			return "", fmt.Errorf("NAT %s source network: %w", rule.ID, err)
		}
		parts = append(parts, "ip saddr "+network)
	}
	if rule.DestinationNetwork != "" {
		network, err := canonicalIPv4(rule.DestinationNetwork)
		if err != nil {
			return "", fmt.Errorf("NAT %s destination network: %w", rule.ID, err)
		}
		parts = append(parts, "ip daddr "+network)
	}
	protocol := strings.ToLower(rule.Protocol)
	if rule.OriginalPort > 0 {
		parts = append(parts, fmt.Sprintf("%s dport %d", protocol, rule.OriginalPort))
	} else if protocol != "" {
		parts = append(parts, "meta l4proto "+protocol)
	}

	switch strings.ToUpper(rule.Type) {
	case "MASQUERADE":
		parts = append(parts, "masquerade")
	case "SNAT":
		target := net.ParseIP(rule.TranslatedAddress).To4().String()
		if rule.TranslatedPort > 0 {
			target += ":" + strconv.Itoa(rule.TranslatedPort)
		}
		parts = append(parts, "snat to "+target)
	case "DNAT":
		target := net.ParseIP(rule.TranslatedAddress).To4().String()
		if rule.TranslatedPort > 0 {
			target += ":" + strconv.Itoa(rule.TranslatedPort)
		}
		parts = append(parts, "dnat to "+target)
	default:
		return "", fmt.Errorf("NAT %s has unsupported type %q", rule.ID, rule.Type)
	}
	parts = append(parts, `comment "nat:`+rule.ID+`:priority=`+strconv.Itoa(rule.Priority)+`"`)
	return strings.Join(parts, " "), nil
}

func renderDNATZoneGuard(rule domain.NATRule, zoneIfaces map[string][]string) (string, error) {
	target := net.ParseIP(rule.TranslatedAddress)
	if target == nil || target.To4() == nil {
		return "", fmt.Errorf("DNAT %s has invalid IPv4 target", rule.ID)
	}
	interfaces := zoneInterfaces([]string{rule.DestinationZone}, zoneIfaces)
	parts := []string{"ct status dnat"}
	if rule.SourceZone != "" {
		parts = append(parts, "iifname "+quoteSet(zoneInterfaces([]string{rule.SourceZone}, zoneIfaces)))
	}
	if rule.SourceNetwork != "" {
		network, _ := canonicalIPv4(rule.SourceNetwork)
		parts = append(parts, "ip saddr "+network)
	}
	parts = append(parts, "ip daddr "+target.To4().String())
	guardPort := rule.TranslatedPort
	if guardPort == 0 {
		guardPort = rule.OriginalPort
	}
	if guardPort > 0 {
		parts = append(parts, fmt.Sprintf("%s dport %d", strings.ToLower(rule.Protocol), guardPort))
	} else if rule.Protocol != "" {
		parts = append(parts, "meta l4proto "+strings.ToLower(rule.Protocol))
	}
	parts = append(parts, "oifname != "+quoteSet(interfaces), "drop", `comment "dnat-zone:`+rule.ID+`"`)
	return strings.Join(parts, " "), nil
}

func buildZoneInterfaces(config domain.Config) map[string][]string {
	result := map[string][]string{}
	for _, iface := range config.Interfaces {
		if iface.ZoneID != "" && iface.SystemName != "" {
			result[iface.ZoneID] = append(result[iface.ZoneID], iface.SystemName)
		}
	}
	for zone, names := range result {
		result[zone] = uniqueSorted(names)
	}
	return result
}

func zoneInterfaces(zones []string, mapping map[string][]string) []string {
	var names []string
	for _, zone := range zones {
		names = append(names, mapping[zone]...)
	}
	return uniqueSorted(names)
}

func quoteSet(values []string) string {
	return valueOrSet(uniqueSorted(values), true)
}

func valueOrSet(values []string, quote bool) string {
	rendered := make([]string, len(values))
	for index, value := range values {
		if quote {
			rendered[index] = `"` + value + `"`
		} else {
			rendered[index] = value
		}
	}
	if len(rendered) == 1 {
		return rendered[0]
	}
	return "{ " + strings.Join(rendered, ", ") + " }"
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalIPv4List(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		canonical, err := canonicalIPv4(value)
		if err != nil {
			return nil, err
		}
		result = append(result, canonical)
	}
	return uniqueSorted(result), nil
}

func canonicalIPv4(value string) (string, error) {
	if strings.Contains(value, "/") {
		ip, network, err := net.ParseCIDR(value)
		if err != nil || ip.To4() == nil {
			return "", fmt.Errorf("%q is not an IPv4 CIDR", value)
		}
		return network.String(), nil
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("%q is not an IPv4 address", value)
	}
	return ip.To4().String(), nil
}

func validateForRender(config domain.Config, zoneIfaces map[string][]string) []string {
	var errs []string
	validInterfaceName := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
	for _, iface := range config.Interfaces {
		if !validInterfaceName.MatchString(iface.SystemName) {
			errs = append(errs, fmt.Sprintf("interface %s has unsafe system name %q", iface.ID, iface.SystemName))
		}
	}
	for _, policy := range config.Policies {
		if !policy.Enabled {
			continue
		}
		if _, err := policyAction(policy.Action); err != nil {
			errs = append(errs, "policy "+policy.ID+": "+err.Error())
		}
		if err := domain.ValidateIdentifier(policy.ID); err != nil {
			errs = append(errs, "policy "+err.Error())
		}
		for _, zone := range append(append([]string{}, policy.SourceZones...), policy.DestinationZones...) {
			if len(zoneIfaces[zone]) == 0 {
				errs = append(errs, fmt.Sprintf("policy %s zone %s has no interface", policy.ID, zone))
			}
		}
		if _, err := canonicalIPv4List(append(append([]string{}, policy.SourceAddresses...), policy.DestinationAddresses...)); err != nil {
			errs = append(errs, "policy "+policy.ID+": "+err.Error())
		}
		for _, service := range policy.Services {
			if _, err := serviceExpression(service); err != nil {
				errs = append(errs, "policy "+policy.ID+": "+err.Error())
			}
		}
	}
	for _, rule := range config.NATRules {
		if !rule.Enabled {
			continue
		}
		if err := domain.ValidateIdentifier(rule.ID); err != nil {
			errs = append(errs, "NAT "+err.Error())
		}
		typeName := strings.ToUpper(rule.Type)
		if typeName != "SNAT" && typeName != "MASQUERADE" && typeName != "DNAT" {
			errs = append(errs, fmt.Sprintf("NAT %s has unsupported type %q", rule.ID, rule.Type))
		}
		if len(zoneIfaces[rule.SourceZone]) == 0 {
			errs = append(errs, fmt.Sprintf("NAT %s source zone %s has no interface", rule.ID, rule.SourceZone))
		}
		if len(zoneIfaces[rule.DestinationZone]) == 0 {
			errs = append(errs, fmt.Sprintf("NAT %s destination zone %s has no interface", rule.ID, rule.DestinationZone))
		}
		protocol := strings.ToLower(rule.Protocol)
		if protocol != "" && protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
			errs = append(errs, fmt.Sprintf("NAT %s has invalid protocol %q", rule.ID, rule.Protocol))
		}
		if (rule.OriginalPort > 0 || rule.TranslatedPort > 0) && protocol != "tcp" && protocol != "udp" {
			errs = append(errs, "NAT "+rule.ID+" ports require tcp or udp")
		}
		for label, network := range map[string]string{"source": rule.SourceNetwork, "destination": rule.DestinationNetwork} {
			if network == "" {
				continue
			}
			if _, err := canonicalIPv4(network); err != nil || !strings.Contains(network, "/") {
				errs = append(errs, fmt.Sprintf("NAT %s %s network is not an IPv4 CIDR", rule.ID, label))
			}
		}
		if typeName == "SNAT" || typeName == "DNAT" {
			ip := net.ParseIP(rule.TranslatedAddress)
			if ip == nil || ip.To4() == nil {
				errs = append(errs, fmt.Sprintf("NAT %s requires an IPv4 translated address", rule.ID))
			}
		}
		if typeName == "DNAT" && !targetBelongsToZone(rule.TranslatedAddress, rule.DestinationZone, config) {
			errs = append(errs, fmt.Sprintf("DNAT %s target %s is not in an IPv4 subnet attached to destination zone %s", rule.ID, rule.TranslatedAddress, rule.DestinationZone))
		}
	}
	return errs
}

func targetBelongsToZone(address, zone string, config domain.Config) bool {
	target := net.ParseIP(address)
	if target == nil || target.To4() == nil {
		return false
	}
	interfaces := map[string]domain.Interface{}
	bestPrefix := -1
	bestZone := ""
	for _, iface := range config.Interfaces {
		interfaces[iface.ID] = iface
		for _, prefix := range iface.IPv4Addresses {
			_, network, err := net.ParseCIDR(prefix)
			if err == nil && network.Contains(target) {
				ones, _ := network.Mask.Size()
				if ones > bestPrefix {
					bestPrefix = ones
					bestZone = iface.ZoneID
				}
			}
		}
	}
	for _, route := range config.Routes {
		if !route.Enabled {
			continue
		}
		_, network, err := net.ParseCIDR(route.DestinationCIDR)
		if err != nil || network.IP.To4() == nil || !network.Contains(target) {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones > bestPrefix {
			bestPrefix = ones
			bestZone = interfaces[route.InterfaceID].ZoneID
		}
	}
	if bestPrefix >= 0 && bestZone == zone {
		return true
	}
	return false
}
