package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// tlsExclusionSelectors expresses OR within each group and AND across groups.
// Empty groups match all values of that dimension. The slice order is removed
// inside each group, but the order of exclusion entries is preserved.
type tlsExclusionSelectors struct {
	Domains []string `json:"domains"`
	CIDRs   []string `json:"cidrs"`
	Ports   []int    `json:"ports"`
}

func canonicalTLSExclusion(exclusion domain.TLSExclusion) (tlsExclusionSelectors, error) {
	var result tlsExclusionSelectors
	domains := make(map[string]bool, len(exclusion.Domains))
	for _, raw := range exclusion.Domains {
		value, err := canonicalTLSDomain(raw)
		if err != nil {
			return result, fmt.Errorf("domain %q: %w", raw, err)
		}
		domains[value] = true
	}
	for domain := range domains {
		result.Domains = append(result.Domains, domain)
	}
	sort.Strings(result.Domains)

	cidrs := make(map[string]bool, len(exclusion.DestinationCIDRs))
	for _, raw := range exclusion.DestinationCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return result, fmt.Errorf("CIDR %q: %w", raw, err)
		}
		cidrs[prefix.Masked().String()] = true
	}
	for cidr := range cidrs {
		result.CIDRs = append(result.CIDRs, cidr)
	}
	sort.Strings(result.CIDRs)

	ports := make(map[int]bool, len(exclusion.Ports))
	for _, port := range exclusion.Ports {
		if port < 1 || port > 65535 {
			return result, fmt.Errorf("invalid port %d", port)
		}
		ports[port] = true
	}
	for port := range ports {
		result.Ports = append(result.Ports, port)
	}
	sort.Ints(result.Ports)
	return result, nil
}

// TLSExclusionEffectiveKey is stable for equivalent selector spellings and
// captures the ordered exclusion behavior of the active M4 configuration.
func TLSExclusionEffectiveKey(c domain.Config) (string, error) {
	if !domain.UsesM4(c) {
		return "", nil
	}
	selectors := make([]tlsExclusionSelectors, 0, len(c.TLSExclusions))
	for _, exclusion := range c.TLSExclusions {
		if !exclusion.Enabled {
			continue
		}
		value, err := canonicalTLSExclusion(exclusion)
		if err != nil {
			return "", fmt.Errorf("tls_exclusion %s: %w", exclusion.ID, err)
		}
		selectors = append(selectors, value)
	}
	encoded, err := json.Marshal(selectors)
	return string(encoded), err
}

// TLSExclusionSemanticErrors rejects duplicate identities and any later rule
// fully covered by an earlier rule. Partial overlaps remain legal and use
// configuration order for deterministic first-match attribution.
func TLSExclusionSemanticErrors(c domain.Config) []string {
	if !domain.UsesM4(c) {
		return nil
	}
	type priorExclusion struct {
		id        string
		selectors tlsExclusionSelectors
	}
	var errs []string
	seenIDs := map[string]bool{}
	var earlier []priorExclusion
	for _, exclusion := range c.TLSExclusions {
		if seenIDs[exclusion.ID] {
			errs = append(errs, fmt.Sprintf("duplicate tls_exclusion ID %s", exclusion.ID))
		}
		seenIDs[exclusion.ID] = true
		if !exclusion.Enabled {
			continue
		}
		selector, err := canonicalTLSExclusion(exclusion)
		if err != nil {
			continue // syntax validation supplies the exact field error
		}
		for _, previous := range earlier {
			if !tlsExclusionCovers(previous.selectors, selector) {
				continue
			}
			kind := "shadowed by"
			if tlsExclusionEqual(previous.selectors, selector) {
				kind = "an exact duplicate of"
			}
			errs = append(errs, fmt.Sprintf("tls_exclusion %s is %s preceding tls_exclusion %s", exclusion.ID, kind, previous.id))
			break
		}
		earlier = append(earlier, priorExclusion{id: exclusion.ID, selectors: selector})
	}
	return errs
}

func tlsExclusionEqual(a, b tlsExclusionSelectors) bool {
	aBytes, _ := json.Marshal(a)
	bBytes, _ := json.Marshal(b)
	return string(aBytes) == string(bBytes)
}

func tlsExclusionCovers(earlier, later tlsExclusionSelectors) bool {
	return tlsDomainGroupCovers(earlier.Domains, later.Domains) &&
		tlsCIDRGroupCovers(earlier.CIDRs, later.CIDRs) &&
		tlsPortGroupCovers(earlier.Ports, later.Ports)
}

func tlsDomainGroupCovers(earlier, later []string) bool {
	if len(earlier) == 0 {
		return true
	}
	if len(later) == 0 {
		return false
	}
	for _, wanted := range later {
		matched := false
		for _, candidate := range earlier {
			if tlsDomainCovers(candidate, wanted) {
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

func tlsDomainCovers(earlier, later string) bool {
	if earlier == later {
		return true
	}
	if !strings.HasPrefix(earlier, "*.") {
		return false
	}
	apex := strings.TrimPrefix(earlier, "*.")
	if strings.HasPrefix(later, "*.") {
		later = strings.TrimPrefix(later, "*.")
	}
	return strings.HasSuffix(later, "."+apex)
}

// TLSDomainMatchesCanonical applies the same wildcard semantics used for
// exclusion shadow checks. The pattern must already be canonicalized.
func TLSDomainMatchesCanonical(pattern, host string) bool {
	canonical, err := canonicalTLSDomain(host)
	if err != nil || strings.HasPrefix(canonical, "*.") {
		return false
	}
	return tlsDomainCovers(pattern, canonical)
}

func tlsCIDRGroupCovers(earlier, later []string) bool {
	if len(earlier) == 0 {
		return true
	}
	if len(later) == 0 {
		return false
	}
	for _, wanted := range later {
		wantedPrefix, _ := netip.ParsePrefix(wanted)
		matched := false
		for _, raw := range earlier {
			candidate, _ := netip.ParsePrefix(raw)
			if candidate.Addr().BitLen() == wantedPrefix.Addr().BitLen() && candidate.Bits() <= wantedPrefix.Bits() && candidate.Contains(wantedPrefix.Addr()) {
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

func tlsPortGroupCovers(earlier, later []int) bool {
	if len(earlier) == 0 {
		return true
	}
	if len(later) == 0 {
		return false
	}
	allowed := make(map[int]bool, len(earlier))
	for _, port := range earlier {
		allowed[port] = true
	}
	for _, port := range later {
		if !allowed[port] {
			return false
		}
	}
	return true
}
