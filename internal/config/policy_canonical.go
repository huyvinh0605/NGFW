package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// PolicyEffectiveKey is a stable representation of the fields that affect an
// M1/M2 policy match and action. Identity, display name and priority are
// deliberately excluded: changing any of those must not hide an exact
// duplicate effective rule.
func PolicyEffectiveKey(policy domain.SecurityPolicy) (string, error) {
	return effectivePolicyKey(nil, policy)
}

// EffectivePolicyKey includes the resolved M3 profile semantics when a
// configuration is available. Profile IDs remain case-sensitive for lookup;
// only the serialized effective profile settings participate in the key.
func EffectivePolicyKey(c domain.Config, policy domain.SecurityPolicy) (string, error) {
	return effectivePolicyKey(&c, policy)
}

func effectivePolicyKey(c *domain.Config, policy domain.SecurityPolicy) (string, error) {
	services, err := domain.CanonicalServiceList(policy.Services)
	if err != nil {
		return "", fmt.Errorf("policy %s service: %w", policy.ID, err)
	}
	value := struct {
		Enabled              bool     `json:"enabled"`
		SourceZones          []string `json:"source_zones"`
		DestinationZones     []string `json:"destination_zones"`
		SourceAddresses      []string `json:"source_addresses"`
		DestinationAddresses []string `json:"destination_addresses"`
		Services             []string `json:"services"`
		Applications         []string `json:"applications"`
		ApplicationMatchMode string   `json:"application_match_mode"`
		SecurityProfileID    string   `json:"security_profile_id"`
		ProfileSemantics     string   `json:"profile_semantics,omitempty"`
		MinimumRisk          *int     `json:"minimum_risk,omitempty"`
		MaximumRisk          *int     `json:"maximum_risk,omitempty"`
		Action               string   `json:"action"`
		Scope                string   `json:"scope"`
	}{
		Enabled:              policy.Enabled,
		SourceZones:          canonicalStrings(policy.SourceZones),
		DestinationZones:     canonicalStrings(policy.DestinationZones),
		SourceAddresses:      canonicalAddresses(policy.SourceAddresses),
		DestinationAddresses: canonicalAddresses(policy.DestinationAddresses),
		Services:             services,
		Applications:         canonicalStrings(policy.Applications),
		ApplicationMatchMode: strings.ToUpper(strings.TrimSpace(policy.ApplicationMatchMode)),
		SecurityProfileID:    strings.TrimSpace(policy.SecurityProfileID),
		MinimumRisk:          cloneInt(policy.MinimumRisk),
		MaximumRisk:          cloneInt(policy.MaximumRisk),
		Action:               strings.ToUpper(strings.TrimSpace(string(policy.Action))),
		Scope:                canonicalScope(policy.Scope),
	}
	if c != nil && policy.SecurityProfileID != "" {
		for _, profile := range c.Profiles {
			if profile.ID == policy.SecurityProfileID {
				profileKey, err := ProfileEffectiveKey(profile)
				if err != nil {
					return "", err
				}
				value.ProfileSemantics = profileKey
				value.SecurityProfileID = ""
				break
			}
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// ProfileEffectiveKey contains only settings that can change M3 behavior.
func ProfileEffectiveKey(profile domain.SecurityProfile) (string, error) {
	value := struct {
		IDSIPSEnabled bool                      `json:"ids_ips_enabled"`
		TLSMode       domain.TLSMode            `json:"tls_mode"`
		Inspection    *domain.InspectionProfile `json:"inspection,omitempty"`
	}{IDSIPSEnabled: profile.IDSIPSEnabled, TLSMode: profile.TLSMode, Inspection: profile.Inspection}
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

// ExactDuplicatePolicyErrors rejects only policies with identical effective
// semantics. A subset/overlap is left to the explicit shadowing diagnostic so
// that a partially overlapping rule is not mislabeled as a duplicate.
func ExactDuplicatePolicyErrors(policies []domain.SecurityPolicy) []string {
	return exactDuplicatePolicyErrors(nil, policies)
}

func ExactDuplicatePolicyErrorsForConfig(c domain.Config) []string {
	return exactDuplicatePolicyErrors(&c, c.Policies)
}

func exactDuplicatePolicyErrors(c *domain.Config, policies []domain.SecurityPolicy) []string {
	type indexed struct {
		policy domain.SecurityPolicy
		key    string
	}
	ordered := append([]domain.SecurityPolicy(nil), policies...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].ID < ordered[j].ID
	})
	seen := map[string]indexed{}
	var errs []string
	for _, policy := range ordered {
		var key string
		var err error
		if c == nil {
			key, err = PolicyEffectiveKey(policy)
		} else {
			key, err = EffectivePolicyKey(*c, policy)
		}
		if err != nil {
			continue // structural validation reports the actionable syntax error
		}
		if prior, exists := seen[key]; exists {
			errs = append(errs, fmt.Sprintf("policy %s is an exact duplicate of effective policy %s (priority %d)", policy.ID, prior.policy.ID, prior.policy.Priority))
			continue
		}
		seen[key] = indexed{policy: policy, key: key}
	}
	return errs
}

func canonicalStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalAddresses(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if prefix, err := netip.ParsePrefix(value); err == nil {
			value = prefix.Masked().String()
		} else if address, err := netip.ParseAddr(value); err == nil {
			value = netip.PrefixFrom(address, address.BitLen()).String()
		}
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalScope(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "SESSION"
	}
	return value
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
