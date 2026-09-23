package config

import (
	"fmt"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

const (
	ApplicationMatchRestrictL3Allow = "RESTRICT_L3_ALLOW"
	InspectionFailOpen              = "OPEN"
	BuiltinM3RulesetID              = "m3-builtin-v1"
)

var supportedM3Applications = map[string]struct{}{
	"HTTP": {}, "TLS": {}, "DNS": {}, "SSH": {},
}

// ValidateInspection validates the M3 portion of a candidate. A nil or
// disabled inspection block leaves M1/M2 behavior unchanged.
func ValidateInspection(c domain.Config) []string {
	var errs []string
	if c.Inspection != nil {
		l := c.Inspection.Limits
		if l.EVELineBytes < 0 {
			errs = append(errs, "inspection.limits.eve_line_bytes must be non-negative")
		}
		if l.NormalizedEventBytes < 0 {
			errs = append(errs, "inspection.limits.normalized_event_bytes must be non-negative")
		}
		if l.ObservationQueueItems < 0 {
			errs = append(errs, "inspection.limits.observation_queue_items must be non-negative")
		}
		if l.ObservationQueueBytes < 0 {
			errs = append(errs, "inspection.limits.observation_queue_bytes must be non-negative")
		}
		if l.SecurityEvents < 0 {
			errs = append(errs, "inspection.limits.security_events must be non-negative")
		}
		if l.SecurityEventBytes < 0 {
			errs = append(errs, "inspection.limits.security_event_bytes must be non-negative")
		}
		if l.CorrelationPending < 0 {
			errs = append(errs, "inspection.limits.correlation_pending must be non-negative")
		}
		if l.CorrelationWaitMillis < 0 {
			errs = append(errs, "inspection.limits.correlation_wait_ms must be non-negative")
		}
		if l.RecentSessions < 0 {
			errs = append(errs, "inspection.limits.recent_sessions must be non-negative")
		}
		if l.RecentSessionTTLSeconds < 0 {
			errs = append(errs, "inspection.limits.recent_session_ttl_seconds must be non-negative")
		}
		if l.AppDetectionTimeoutMillis < 0 {
			errs = append(errs, "inspection.limits.app_detection_timeout_ms must be non-negative")
		}
		if l.EVELineBytes > 4<<20 {
			errs = append(errs, "inspection.limits.eve_line_bytes exceeds 4194304")
		}
		if l.NormalizedEventBytes > 16<<10 {
			errs = append(errs, "inspection.limits.normalized_event_bytes exceeds 16384")
		}
		if l.ObservationQueueItems > 10000 {
			errs = append(errs, "inspection.limits.observation_queue_items exceeds 10000")
		}
		if l.ObservationQueueBytes > 32<<20 {
			errs = append(errs, "inspection.limits.observation_queue_bytes exceeds 33554432")
		}
		if l.SecurityEvents > 10000 {
			errs = append(errs, "inspection.limits.security_events exceeds 10000")
		}
		if l.SecurityEventBytes > 32<<20 {
			errs = append(errs, "inspection.limits.security_event_bytes exceeds 33554432")
		}
		if l.CorrelationPending > 4096 {
			errs = append(errs, "inspection.limits.correlation_pending exceeds 4096")
		}
		if l.CorrelationWaitMillis > 5000 {
			errs = append(errs, "inspection.limits.correlation_wait_ms exceeds 5000")
		}
		if l.RecentSessions > 5000 {
			errs = append(errs, "inspection.limits.recent_sessions exceeds 5000")
		}
		if l.RecentSessionTTLSeconds > 60 {
			errs = append(errs, "inspection.limits.recent_session_ttl_seconds exceeds 60")
		}
		if l.AppDetectionTimeoutMillis > 30000 {
			errs = append(errs, "inspection.limits.app_detection_timeout_ms exceeds 30000")
		}
		if l.AppDetectionTimeoutMillis > 0 && l.AppDetectionTimeoutMillis < 1000 {
			errs = append(errs, "inspection.limits.app_detection_timeout_ms must be at least 1000")
		}
		if l.NormalizedEventBytes > l.ObservationQueueBytes && l.ObservationQueueBytes > 0 {
			errs = append(errs, "inspection.limits.normalized_event_bytes must not exceed observation_queue_bytes")
		}
		if l.NormalizedEventBytes > l.SecurityEventBytes && l.SecurityEventBytes > 0 {
			errs = append(errs, "inspection.limits.normalized_event_bytes must not exceed security_event_bytes")
		}
	}

	profiles := make(map[string]domain.SecurityProfile, len(c.Profiles))
	for _, profile := range c.Profiles {
		profiles[profile.ID] = profile
	}
	for _, profile := range c.Profiles {
		if profile.Inspection == nil {
			continue
		}
		ip := profile.Inspection
		if !ip.Mode.Valid() {
			errs = append(errs, fmt.Sprintf("profile %s inspection.mode %q is invalid", profile.ID, ip.Mode))
		}
		if ip.Mode == domain.InspectionModeOff {
			errs = append(errs, fmt.Sprintf("profile %s inspection.mode must be IDS or IPS", profile.ID))
		}
		if !strings.EqualFold(strings.TrimSpace(ip.FailMode), InspectionFailOpen) {
			errs = append(errs, fmt.Sprintf("profile %s inspection.fail_mode must be OPEN (fail-open is the only M3 mode)", profile.ID))
		}
		if ip.RulesetID != BuiltinM3RulesetID {
			errs = append(errs, fmt.Sprintf("profile %s inspection.ruleset_id %q is not installed", profile.ID, ip.RulesetID))
		}
		if !profile.IDSIPSEnabled {
			errs = append(errs, fmt.Sprintf("profile %s must enable ids_ips_enabled for M3 inspection", profile.ID))
		}
		if profile.DPIEnabled {
			errs = append(errs, fmt.Sprintf("profile %s enables DPI, which is outside M3", profile.ID))
		}
		if profile.DNSSecurityEnabled || profile.URLFilteringEnabled || profile.ThreatIntelEnabled || profile.BehaviorEnabled || profile.MLDetectionEnabled {
			errs = append(errs, fmt.Sprintf("profile %s enables a feature outside M3", profile.ID))
		}
		if profile.TLSMode == domain.TLSDecrypt {
			errs = append(errs, fmt.Sprintf("profile %s TLS DECRYPT is unsupported in M3", profile.ID))
		}
		if profile.InspectionRequired || profile.InspectionFailureAction == domain.DecisionDrop || profile.InspectionFailureAction == domain.DecisionReject {
			errs = append(errs, fmt.Sprintf("profile %s uses legacy fail-closed inspection settings unsupported in M3", profile.ID))
		}
	}
	for _, policy := range c.Policies {
		if !policy.Enabled {
			continue
		}
		profileIsM3 := false
		if profile, ok := profiles[policy.SecurityProfileID]; ok && profile.Inspection != nil && profile.Inspection.Mode != domain.InspectionModeOff {
			profileIsM3 = true
		}
		m3Fields := len(policy.Applications) > 0 || policy.ApplicationMatchMode != "" || profileIsM3
		if !m3Fields {
			continue
		}
		if c.Inspection == nil || !c.Inspection.Enabled {
			errs = append(errs, fmt.Sprintf("policy %s uses M3 inspection but inspection.enabled is false", policy.ID))
			continue
		}
		if len(policy.Applications) > 0 {
			if policy.Action != domain.DecisionAllow {
				errs = append(errs, fmt.Sprintf("policy %s application restriction requires ALLOW", policy.ID))
			}
			if strings.ToUpper(strings.TrimSpace(policy.Scope)) != "SESSION" && strings.TrimSpace(policy.Scope) != "" {
				errs = append(errs, fmt.Sprintf("policy %s application restriction requires SESSION scope", policy.ID))
			}
			if strings.ToUpper(strings.TrimSpace(policy.ApplicationMatchMode)) != ApplicationMatchRestrictL3Allow {
				errs = append(errs, fmt.Sprintf("policy %s application_match_mode must be %s", policy.ID, ApplicationMatchRestrictL3Allow))
			}
		}
		if policy.ApplicationMatchMode != "" && strings.ToUpper(strings.TrimSpace(policy.ApplicationMatchMode)) != ApplicationMatchRestrictL3Allow {
			errs = append(errs, fmt.Sprintf("policy %s application_match_mode %q is unsupported", policy.ID, policy.ApplicationMatchMode))
		}
		for _, raw := range policy.Applications {
			app := strings.ToUpper(strings.TrimSpace(raw))
			if _, ok := supportedM3Applications[app]; !ok {
				errs = append(errs, fmt.Sprintf("policy %s application %q is unsupported in M3", policy.ID, raw))
			}
		}
		if policy.MinimumRisk != nil || policy.MaximumRisk != nil {
			errs = append(errs, fmt.Sprintf("policy %s risk thresholds are not available in M3", policy.ID))
		}
		if policy.SecurityProfileID == "" {
			errs = append(errs, fmt.Sprintf("policy %s application inspection requires security_profile_id", policy.ID))
			continue
		}
		profile, ok := profiles[policy.SecurityProfileID]
		if !ok || profile.Inspection == nil {
			errs = append(errs, fmt.Sprintf("policy %s references a profile without M3 inspection", policy.ID))
			continue
		}
		if len(policy.Applications) > 0 && profile.Inspection.Mode != domain.InspectionModeIPS {
			errs = append(errs, fmt.Sprintf("policy %s application restriction requires an IPS profile", policy.ID))
		}
	}
	return errs
}
