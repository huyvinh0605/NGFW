package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// ValidateRequestGate checks only active M4 configuration. M1/M2/M3
// candidates continue to have identical validation when the gate is off.
// CA files and kernel capabilities are checked during activation, not here.
func ValidateRequestGate(c domain.Config) []string {
	if !domain.UsesM4(c) {
		return nil
	}
	g := domain.EffectiveRequestGateConfig(c)
	var errs []string
	check := func(name string, value, minimum, maximum int) {
		if value < minimum || value > maximum {
			errs = append(errs, fmt.Sprintf("request_gate.%s must be in %d..%d", name, minimum, maximum))
		}
	}
	check("listen_http_port", g.ListenHTTPPort, 1, 65535)
	check("listen_https_port", g.ListenHTTPSPort, 1, 65535)
	if g.ListenHTTPPort == g.ListenHTTPSPort {
		errs = append(errs, "request_gate listen ports must differ")
	}
	if err := domain.ValidateIdentifier(g.RulesetID); err != nil {
		errs = append(errs, "request_gate.ruleset_id: "+err.Error())
	}
	check("worker_count", g.WorkerCount, 1, 4)
	check("queue_items", g.QueueItems, 1, 1024)
	check("queue_bytes", g.QueueBytes, 64<<10, 32<<20)
	check("max_concurrent_requests", g.MaxConcurrentRequests, 1, 1024)
	check("max_per_client_requests", g.MaxPerClientRequests, 1, 1024)
	if g.MaxPerClientRequests > g.MaxConcurrentRequests {
		errs = append(errs, "request_gate.max_per_client_requests exceeds max_concurrent_requests")
	}
	check("max_http2_streams", g.MaxHTTP2Streams, 1, 256)
	check("max_header_bytes", g.MaxHeaderBytes, 1024, 64<<10)
	check("max_header_count", g.MaxHeaderCount, 1, 256)
	check("max_url_bytes", g.MaxURLBytes, 256, 16<<10)
	check("max_raw_body_bytes", g.MaxRawBodyBytes, 1, 1<<20)
	check("max_decompressed_body_bytes", g.MaxDecompressedBodyBytes, 1, 4<<20)
	if g.MaxDecompressedBodyBytes < g.MaxRawBodyBytes {
		errs = append(errs, "request_gate.max_decompressed_body_bytes must be at least max_raw_body_bytes")
	}
	check("max_decompression_ratio", g.MaxDecompressionRatio, 1, 100)
	check("request_timeout_ms", g.RequestTimeoutMillis, 100, 30000)
	check("client_hello_bytes", g.ClientHelloBytes, 1024, 64<<10)
	check("client_hello_timeout_ms", g.ClientHelloTimeoutMillis, 100, 5000)
	check("leaf_cache_entries", g.LeafCacheEntries, 1, 4096)
	check("leaf_cache_ttl_seconds", g.LeafCacheTTLSeconds, 60, 24*60*60)

	profiles := make(map[string]domain.SecurityProfile, len(c.Profiles))
	for _, profile := range c.Profiles {
		profiles[profile.ID] = profile
		gate := profile.RequestGate
		if gate == nil || !gate.Enabled {
			continue
		}
		if !gate.FailMode.Valid() {
			errs = append(errs, fmt.Sprintf("profile %s request_gate.fail_mode must be OPEN or CLOSE", profile.ID))
		}
		if !validGatePartialAction(gate.OversizeAction) {
			errs = append(errs, fmt.Sprintf("profile %s request_gate.oversize_action must be BLOCK or ALLOW_PARTIAL", profile.ID))
		}
		if !validGatePartialAction(gate.UnsupportedEncodingAction) {
			errs = append(errs, fmt.Sprintf("profile %s request_gate.unsupported_encoding_action must be BLOCK or ALLOW_PARTIAL", profile.ID))
		}
		if gate.BlockQUIC && profile.TLSMode != domain.TLSDecrypt {
			errs = append(errs, fmt.Sprintf("profile %s block_quic requires TLS DECRYPT", profile.ID))
		}
	}
	for _, policy := range c.Policies {
		if policy.SecurityProfileID == "" {
			continue
		}
		profile, found := profiles[policy.SecurityProfileID]
		if !found || profile.RequestGate == nil || !profile.RequestGate.Enabled || !policy.Enabled {
			continue
		}
		if policy.Action != domain.DecisionAllow || canonicalScope(policy.Scope) != "SESSION" {
			errs = append(errs, fmt.Sprintf("policy %s request gate requires enabled ALLOW SESSION policy", policy.ID))
		}
		if !hasRequestGateTCPService(policy.Services) {
			errs = append(errs, fmt.Sprintf("policy %s request gate requires a TCP service or an empty service list", policy.ID))
		}
	}
	if len(c.TLSExclusions) > 1024 {
		errs = append(errs, "tls_exclusions exceeds 1024 entries")
	}
	for _, exclusion := range c.TLSExclusions {
		if !exclusion.Enabled {
			continue
		}
		if len(exclusion.Domains) > 64 || len(exclusion.DestinationCIDRs) > 64 || len(exclusion.Ports) > 64 {
			errs = append(errs, fmt.Sprintf("tls_exclusion %s exceeds 64 selectors per group", exclusion.ID))
		}
		if len(exclusion.Reason) > 512 || len(exclusion.Name) > 256 {
			errs = append(errs, fmt.Sprintf("tls_exclusion %s name or reason is too long", exclusion.ID))
		}
		if err := domain.ValidateIdentifier(exclusion.ID); err != nil {
			errs = append(errs, "tls_exclusion "+err.Error())
		}
		if strings.TrimSpace(exclusion.Reason) == "" {
			errs = append(errs, fmt.Sprintf("tls_exclusion %s requires reason", exclusion.ID))
		}
		if len(exclusion.Domains) == 0 && len(exclusion.DestinationCIDRs) == 0 && len(exclusion.Ports) == 0 {
			errs = append(errs, fmt.Sprintf("tls_exclusion %s cannot match all destinations", exclusion.ID))
		}
		for _, raw := range exclusion.Domains {
			if _, err := canonicalTLSDomain(raw); err != nil {
				errs = append(errs, fmt.Sprintf("tls_exclusion %s domain %q: %v", exclusion.ID, raw, err))
			}
		}
		for _, raw := range exclusion.DestinationCIDRs {
			if _, err := netip.ParsePrefix(raw); err != nil {
				errs = append(errs, fmt.Sprintf("tls_exclusion %s invalid CIDR %q", exclusion.ID, raw))
			}
		}
		for _, port := range exclusion.Ports {
			if port < 1 || port > 65535 {
				errs = append(errs, fmt.Sprintf("tls_exclusion %s invalid port %d", exclusion.ID, port))
			}
		}
	}
	errs = append(errs, TLSExclusionSemanticErrors(c)...)
	return errs
}

func validGatePartialAction(action string) bool {
	return action == "BLOCK" || action == "ALLOW_PARTIAL"
}

func hasRequestGateTCPService(services []string) bool {
	if len(services) == 0 {
		return true // wildcard policy: only standard HTTP/TLS ports are gated
	}
	for _, raw := range services {
		service, err := domain.ParseServiceSelector(raw)
		if err == nil && service.Protocol == "tcp" {
			return true
		}
	}
	return false
}

// canonicalTLSDomain accepts ASCII DNS names and a single leftmost wildcard.
// Unicode is rejected until an explicit IDNA contract and implementation exist.
func canonicalTLSDomain(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSuffix(raw, "."))
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	if len(value) == 0 || len(value) > 253 || !strings.Contains(value, ".") {
		return "", fmt.Errorf("invalid DNS name")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", fmt.Errorf("non-ASCII or invalid DNS character")
			}
		}
	}
	if wildcard {
		return "*." + value, nil
	}
	return value, nil
}

// CanonicalTLSDomain exposes the same normalization used at validation time
// to the immutable M4 selector. It does not perform IDNA conversion.
func CanonicalTLSDomain(raw string) (string, error) { return canonicalTLSDomain(raw) }
