import type {
  ApplicationIdentity,
  EnforcementResult,
  InspectionCapabilities,
  InspectionHealth,
  SecurityEvent,
  SessionInspection,
} from "./types";

type RecordValue = Record<string, unknown>;

function record(value: unknown): RecordValue | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as RecordValue : null;
}
function text(value: unknown, fallback = ""): string { return typeof value === "string" ? value : fallback; }
function number(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) return Number(value);
  return fallback;
}
function bool(value: unknown, fallback = false): boolean { return typeof value === "boolean" ? value : fallback; }
function strings(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []; }
function timestamp(value: unknown): string {
  const candidate = text(value);
  return candidate && !Number.isNaN(Date.parse(candidate)) ? candidate : "";
}
function enumValue(value: unknown, allowed: string[], fallback: string): string {
  const candidate = text(value).trim().toUpperCase();
  return allowed.includes(candidate) ? candidate : fallback;
}

export function normalizeApplicationIdentity(value: unknown): ApplicationIdentity {
  const input = record(value);
  return {
    name: text(input?.name, "UNKNOWN").trim().toUpperCase() || "UNKNOWN",
    raw_name: text(input?.raw_name) || undefined,
    source: enumValue(input?.source, ["UNKNOWN", "SURICATA_APP_PROTO", "DPI_PARSER", "TLS_METADATA", "PORT_HEURISTIC"], "UNKNOWN"),
    confidence: enumValue(input?.confidence, ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "VERIFIED"], "UNKNOWN"),
    first_seen: timestamp(input?.first_seen) || undefined,
    last_seen: timestamp(input?.last_seen) || undefined,
    conflicted: bool(input?.conflicted),
  };
}

export function normalizeEnforcement(value: unknown): EnforcementResult {
  const input = record(value);
  return {
    mechanism: enumValue(input?.mechanism, ["NONE", "SURICATA_NFQUEUE", "NFT_SESSION_GUARD"], "NONE"),
    scope: enumValue(input?.scope, ["PACKET", "SESSION"], "PACKET"),
    requested_action: text(input?.requested_action).toUpperCase() || undefined,
    status: enumValue(input?.status, ["NOT_REQUESTED", "PENDING", "REPORTED", "APPLIED", "FAILED", "UNAVAILABLE"], "UNAVAILABLE"),
    reason: text(input?.reason) || undefined,
    observed_at: timestamp(input?.observed_at) || undefined,
    operation_id: text(input?.operation_id) || undefined,
  };
}

export function normalizeSessionInspection(value: unknown): SessionInspection | undefined {
  const input = record(value);
  if (!input) return undefined;
  return {
    generation: Math.max(0, number(input.generation)),
    revision: Math.max(0, number(input.revision)),
    profile_id: text(input.profile_id) || undefined,
    mode: enumValue(input.mode, ["OFF", "IDS", "IPS"], "OFF"),
    state: enumValue(input.state, ["NOT_REQUESTED", "QUEUED", "INSPECTING", "DEGRADED", "ERROR", "COMPLETE"], "ERROR"),
    reason: text(input.reason) || undefined,
    coverage: enumValue(input.coverage, ["NONE", "OBSERVED", "PARTIAL", "UNAVAILABLE"], "UNAVAILABLE"),
    application: normalizeApplicationIdentity(input.application),
    app_policy_state: enumValue(input.app_policy_state, ["NOT_APPLICABLE", "PENDING", "MATCHED", "MISMATCH", "UNKNOWN_ALLOWED"], "NOT_APPLICABLE"),
    app_deadline: timestamp(input.app_deadline) || undefined,
    threat_count: Math.max(0, number(input.threat_count)),
    last_event_id: text(input.last_event_id) || undefined,
    max_severity: enumValue(input.max_severity, ["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], "UNKNOWN"),
    latest_verdict: enumValue(input.latest_verdict, ["UNKNOWN", "ALERT", "DROP", "ERROR"], "UNKNOWN"),
    enforcement: normalizeEnforcement(input.enforcement),
    sources: strings(input.sources),
    missing_evidence: strings(input.missing_evidence),
  };
}

export function normalizeInspectionHealth(value: unknown): InspectionHealth | null {
  const input = record(value);
  if (!input) return null;
  const sources: InspectionHealth["sources"] = {};
  const rawSources = record(input.sources);
  for (const [key, raw] of Object.entries(rawSources ?? {})) {
    const source = record(raw);
    if (!source) continue;
    const rawCounters = record(source.counters);
    const counters: InspectionHealth["sources"][string]["counters"] = {};
    for (const [wire, field] of [["uptime_seconds", "uptime_seconds"], ["captured_packets", "captured_packets"], ["capture_drops", "capture_drops"], ["nfqueue_drops", "nfqueue_drops"]] as const) {
      const measured = number(rawCounters?.[wire], Number.NaN);
      if (Number.isFinite(measured)) counters[field] = Math.max(0, measured);
    }
    const sourceTimestamp = timestamp(rawCounters?.source_timestamp);
    if (sourceTimestamp) counters.source_timestamp = sourceTimestamp;
    const readerStats: Record<string, number> = {};
    for (const [name, raw] of Object.entries(record(source.reader_stats) ?? {})) {
      const measured = number(raw, Number.NaN);
      if (Number.isFinite(measured)) readerStats[name] = Math.max(0, measured);
    }
    sources[key] = {
      sensor_id: text(source.sensor_id, key),
      mode: enumValue(source.mode, ["IDS", "IPS"], "") || undefined,
      state: text(source.state, "UNKNOWN").toUpperCase(),
      reason: text(source.reason) || undefined,
      last_read: timestamp(source.last_read) || undefined,
      last_heartbeat: timestamp(source.last_heartbeat) || undefined,
      counters,
      reader_stats: readerStats,
    };
  }
  const stats: Record<string, number> = {};
  for (const [key, raw] of Object.entries(record(input.stats) ?? {})) {
    const value = number(raw, Number.NaN);
    if (Number.isFinite(value)) stats[key] = Math.max(0, value);
  }
  const rawQueue = record(input.ips_queue);
  return {
    enabled: bool(input.enabled),
    status: text(input.status, "unknown").toLowerCase(),
    reason: text(input.reason) || undefined,
    generation: Math.max(0, number(input.generation)),
    sources,
    ips_queue: {
      requested: bool(rawQueue?.requested),
      configured: bool(rawQueue?.configured),
      capture_live: bool(rawQueue?.capture_live),
      lease_active: bool(rawQueue?.lease_active),
      last_renewal: timestamp(rawQueue?.last_renewal) || undefined,
      last_error: text(rawQueue?.last_error) || undefined,
    },
    stats,
    updated_at: timestamp(input.updated_at),
  };
}

export function normalizeInspectionCapabilities(value: unknown): InspectionCapabilities | null {
  const input = record(value);
  if (!input) return null;
  return {
    supported: bool(input.supported),
    modes: strings(input.modes),
    applications: strings(input.applications),
    fail_modes: strings(input.fail_modes),
    rulesets: strings(input.rulesets),
    application_match_modes: strings(input.application_match_modes),
    limitations: strings(input.limitations),
  };
}

export function normalizeThreatEvent(value: unknown, index = 0): SecurityEvent | null {
  const input = record(value);
  if (!input) return null;
  const tuple = record(input.observed_tuple) ?? record(input.flow_tuple);
  const application = normalizeApplicationIdentity(input.application);
  const enforcement = normalizeEnforcement(input.enforcement);
  const eventID = text(input.event_id) || `security-${index}`;
  const severity = enumValue(input.severity, ["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], "UNKNOWN");
  const captureMode = enumValue(input.capture_mode, ["IDS", "IPS"], "");
  const correlation = enumValue(input.correlation_state, ["CORRELATED", "UNCORRELATED", "AMBIGUOUS"], "UNCORRELATED");
  const verdict = enumValue(input.verdict, ["UNKNOWN", "ALERT", "DROP", "ERROR"], "UNKNOWN");
  const observed = timestamp(input.observed_at) || timestamp(input.ingested_at);
  return {
    event_id: eventID,
    timestamp: observed,
    flow_id: text(input.suricata_flow_id) || undefined,
    session_id: text(input.session_id) || undefined,
    detector: text(input.source, "SURICATA"),
    event_class: "security",
    category: text(input.signature) || text(input.category) || "Suricata alert",
    signature_id: input.signature_id == null ? undefined : String(input.signature_id),
    severity,
    confidence: 0,
    confidence_available: false,
    source_ip: text(tuple?.src_ip) || undefined,
    destination_ip: text(tuple?.dst_ip) || undefined,
    application: application.name === "UNKNOWN" ? undefined : application.name,
    evidence: text(input.correlation_reason) || undefined,
    recommended_action: enforcement.requested_action,
    capture_mode: captureMode || undefined,
    correlation_state: correlation,
    verdict,
    packet_verdict: text(input.packet_verdict) || undefined,
    enforcement,
    metadata: {
      sensor_id: text(input.sensor_id) || undefined,
      sensor_epoch: text(input.sensor_epoch) || undefined,
      ruleset_id: text(input.ruleset_id) || undefined,
      capture_mode: captureMode || "UNKNOWN",
      correlation_state: correlation,
      verdict,
      packet_verdict: text(input.packet_verdict) || undefined,
      signature_action: text(input.signature_action) || undefined,
      application,
      enforcement,
    },
  };
}

export function normalizeThreatEventPage(value: unknown): SecurityEvent[] {
  const input = record(value);
  const items = Array.isArray(value) ? value : Array.isArray(input?.items) ? input.items : [];
  return items.map((item, index) => normalizeThreatEvent(item, index)).filter((item): item is SecurityEvent => item !== null);
}
