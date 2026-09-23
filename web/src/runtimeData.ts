import type {
  AuditEntry,
  ConfigExport,
  ComponentHealth,
  Health,
  InterfaceConfig,
  MLStatus,
  NATRule,
  NGFWConfig,
  ReputationEntry,
  Route,
  RiskContribution,
  SecurityEvent,
  SecurityPolicy,
  SecurityProfile,
  Session,
  SessionDetail,
  Stats,
  TemporaryBlock,
  User,
  Zone,
  FlowTuple,
} from "./types";
import { normalizeSessionInspection } from "./inspectionData";

type ObjectValue = Record<string, unknown>;

function objectValue(value: unknown): ObjectValue | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as ObjectValue : null;
}

function valueAt(value: ObjectValue | null, key: string): unknown {
  return value ? value[key] : undefined;
}

function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function boundedNumber(value: unknown, fallback: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, numberValue(value, fallback)));
}

function booleanValue(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function validTimestamp(value: unknown): string {
  const timestamp = stringValue(value);
  return timestamp && !Number.isNaN(Date.parse(timestamp)) ? timestamp : "";
}

const severityValues = new Set(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);

function eventSeverity(value: unknown): SecurityEvent["severity"] {
  const candidate = stringValue(value).toUpperCase();
  if (severityValues.has(candidate)) return candidate;
  // Runtime lifecycle events do not carry threat severity. Keep the display
  // value informational instead of inventing a security rating from `kind`.
  return "INFO";
}

function protocolName(value: unknown): string {
  if (typeof value === "string" && value.trim()) return value.toLowerCase();
  switch (numberValue(value)) {
    case 1:
      return "icmp";
    case 6:
      return "tcp";
    case 17:
      return "udp";
    case 58:
      return "icmpv6";
    default:
      return "unknown";
  }
}

function decisionValue(value: unknown): string {
  const decision = stringValue(value).toUpperCase();
  return ["ALLOW", "DROP", "REJECT", "RATE_LIMIT", "RESET_SESSION", "TEMP_BLOCK"].includes(decision) ? decision : "";
}

function sessionState(value: unknown): Session["tcp_state"] {
  const state = stringValue(value).toUpperCase();
  return ["NEW", "ESTABLISHED", "CLOSING", "CLOSED"].includes(state) ? state : "active";
}

function tupleValue(value: unknown): FlowTuple | null {
  const tuple = objectValue(value);
  if (!tuple) return null;
  return {
    src_ip: stringValue(tuple.src_ip, "unknown"),
    dst_ip: stringValue(tuple.dst_ip, "unknown"),
    src_port: boundedNumber(tuple.src_port, 0, 0, 65535),
    dst_port: boundedNumber(tuple.dst_port, 0, 0, 65535),
    protocol: protocolName(tuple.protocol),
    namespace: stringValue(tuple.namespace) || undefined,
  };
}

function normalizeRiskContributions(value: unknown): RiskContribution[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    const record = objectValue(item);
    if (!record) return null;
    return {
      source: stringValue(valueAt(record, "source"), "unknown"),
      value: boundedNumber(valueAt(record, "value"), 0, 0, 100),
      confidence: boundedNumber(valueAt(record, "confidence"), 0, 0, 1),
      reason: stringValue(valueAt(record, "reason")),
    } as RiskContribution;
  }).filter((item): item is RiskContribution => item !== null);
}

/**
 * The M2 API intentionally returns RuntimeEvent (kind/sequence/session_id),
 * while the original console was written for SecurityEvent (severity,
 * detector, category). Normalize both wire formats before React sees them.
 */
export function normalizeEvent(value: unknown, index = 0): SecurityEvent | null {
  const record = objectValue(value);
  if (!record) return null;
  const kind = stringValue(record.kind);
  const sequence = numberValue(record.sequence, 0);
  const eventID = stringValue(record.event_id) || (sequence > 0 ? String(sequence) : `runtime-${index}`);
  const category = stringValue(record.category) || kind || "Security signal";
  const detector = stringValue(record.detector) || (kind ? "SESSION_ENGINE" : "UNKNOWN");
  const metadata = objectValue(record.metadata);
  const eventClass = stringValue(record.event_class).toLowerCase()
    || (kind === "DecisionChanged" || kind === "SessionInvalidated" ? "policy" : kind ? "runtime" : "security");
  const runtimeMetadata = kind ? {
    ...(metadata ?? {}),
    kind,
    ...(sequence > 0 ? { sequence } : {}),
    ...(numberValue(record.generation, 0) > 0 ? { generation: numberValue(record.generation) } : {}),
    ...(numberValue(record.revision, 0) > 0 ? { revision: numberValue(record.revision) } : {}),
    ...(stringValue(record.reason) ? { reason: stringValue(record.reason) } : {}),
  } : metadata;
  return {
    event_id: eventID,
    timestamp: validTimestamp(record.timestamp),
    flow_id: stringValue(record.flow_id) || undefined,
    session_id: stringValue(record.session_id) || undefined,
    detector,
    event_class: eventClass,
    category,
    signature_id: stringValue(record.signature_id) || undefined,
    severity: eventSeverity(record.severity),
    confidence: boundedNumber(record.confidence, 0, 0, 1),
    source_ip: stringValue(record.source_ip) || undefined,
    destination_ip: stringValue(record.destination_ip) || undefined,
    application: stringValue(record.application) || undefined,
    evidence: stringValue(record.evidence) || (stringValue(record.reason) || undefined),
    recommended_action: stringValue(record.recommended_action) || undefined,
    metadata: runtimeMetadata ?? undefined,
  };
}

export function normalizeEventPage(value: unknown): SecurityEvent[] {
  const record = objectValue(value);
  const items = Array.isArray(value) ? value : Array.isArray(valueAt(record, "items")) ? valueAt(record, "items") as unknown[] : [];
  return items.map((item, index) => normalizeEvent(item, index)).filter((item): item is SecurityEvent => item !== null);
}

export function normalizeStats(value: unknown): Stats {
  const record = objectValue(value);
  const applications: Record<string, number> = {};
  const rawApplications = objectValue(valueAt(record, "applications"));
  for (const [name, count] of Object.entries(rawApplications ?? {})) {
    const normalized = numberValue(count, 0);
    if (name && normalized >= 0) applications[name] = normalized;
  }
  return {
    active_sessions: Math.max(0, numberValue(valueAt(record, "active_sessions"))),
    event_queue_dropped: Math.max(0, numberValue(valueAt(record, "event_queue_dropped") ?? valueAt(record, "event_drops"))),
    applications,
    blocked_sessions: Math.max(0, numberValue(valueAt(record, "blocked_sessions"))),
    timestamp: validTimestamp(valueAt(record, "timestamp")),
  };
}

function normalizeComponent(value: unknown, key: string): ComponentHealth {
  const record = objectValue(value);
  return {
    name: stringValue(valueAt(record, "name"), key),
    status: stringValue(valueAt(record, "status"), "unknown").toLowerCase(),
    message: stringValue(valueAt(record, "message")) || undefined,
    updated_at: validTimestamp(valueAt(record, "updated_at")) || undefined,
  };
}

export function normalizeHealth(value: unknown): Health | null {
  const record = objectValue(value);
  if (!record) return null;
  const components: Record<string, ComponentHealth> = {};
  const rawComponents = objectValue(valueAt(record, "components"));
  for (const [name, component] of Object.entries(rawComponents ?? {})) components[name] = normalizeComponent(component, name);
  return { status: stringValue(valueAt(record, "status"), "unknown").toLowerCase(), components };
}

export function normalizeSession(value: unknown, index = 0): Session | null {
  const record = objectValue(value);
  if (!record) return null;
  const identity = objectValue(valueAt(record, "identity"));
  const original = tupleValue(valueAt(record, "original_tuple")) ?? tupleValue(valueAt(identity, "original_tuple"));
  const reply = tupleValue(valueAt(record, "reply_tuple"));
  const id = stringValue(valueAt(record, "id")) || stringValue(valueAt(record, "session_id")) || `session-${index}`;
  const clientIP = stringValue(valueAt(record, "client_ip"), original?.src_ip ?? "unknown");
  const serverIP = stringValue(valueAt(record, "server_ip"), original?.dst_ip ?? "unknown");
  const clientPort = boundedNumber(valueAt(record, "client_port"), original?.src_port ?? 0, 0, 65535);
  const serverPort = boundedNumber(valueAt(record, "server_port"), original?.dst_port ?? 0, 0, 65535);
  const cacheState = stringValue(valueAt(record, "cache_state")).toUpperCase();
  const revoked = booleanValue(valueAt(record, "revoked"));
  const effectiveDecision = decisionValue(valueAt(record, "effective_decision"));
  const decision = cacheState === "INVALIDATED" && !revoked ? "" : decisionValue(valueAt(record, "decision")) || effectiveDecision;
  const quality = objectValue(valueAt(record, "quality"));
  const missingFields = stringArray(valueAt(quality, "missing_fields"));
  const hasCounterFields = ["packets_up", "packets_original", "packets_down", "packets_reply", "bytes_up", "bytes_original", "bytes_down", "bytes_reply"]
    .some((key) => Object.prototype.hasOwnProperty.call(record, key));
  const countersAvailable = booleanValue(valueAt(record, "counters_available"), hasCounterFields && !missingFields.includes("counters"));
  const kernelCacheVerified = booleanValue(valueAt(record, "kernel_cache_verified"));
  const declaredPath = stringValue(valueAt(record, "path_classification")).toUpperCase();
  const pathClassification: Session["path_classification"] = kernelCacheVerified && declaredPath !== "INSPECT"
    ? "FAST"
    : declaredPath === "INSPECT" ? "INSPECT" : "UNAVAILABLE";
  const riskAvailable = booleanValue(valueAt(record, "risk_available"), Object.prototype.hasOwnProperty.call(record, "risk_score"));
	const rawApplication = valueAt(record, "application");
	const applicationAvailable = booleanValue(valueAt(record, "application_available"), typeof rawApplication === "string" && rawApplication.trim() !== "");
	const inspection = normalizeSessionInspection(valueAt(record, "inspection"));
	const observedApplication = inspection?.application.name && inspection.application.name !== "UNKNOWN" ? inspection.application.name : "";
	const inspectionConfidence = inspection?.application.confidence === "VERIFIED" ? 1 : inspection?.application.confidence === "HIGH" ? 0.9 : inspection?.application.confidence === "MEDIUM" ? 0.6 : inspection?.application.confidence === "LOW" ? 0.3 : 0;
  const runtimeOriginal = original ? { ...original } : undefined;
  const runtimeReply = reply ? { ...reply } : undefined;
  return {
    id,
    client_ip: clientIP,
    client_port: clientPort,
    server_ip: serverIP,
    server_port: serverPort,
    protocol: protocolName(valueAt(record, "protocol") ?? original?.protocol),
    source_zone: stringValue(valueAt(record, "source_zone"), "unknown"),
    destination_zone: stringValue(valueAt(record, "destination_zone"), "unknown"),
    start_time: validTimestamp(valueAt(record, "start_time")) || validTimestamp(valueAt(record, "created_at")),
    last_seen: validTimestamp(valueAt(record, "last_seen")) || validTimestamp(valueAt(record, "last_observed_at")),
    tcp_state: sessionState(valueAt(record, "tcp_state") ?? valueAt(record, "state")),
    packets_up: Math.max(0, numberValue(valueAt(record, "packets_up") ?? valueAt(record, "packets_original"))),
    packets_down: Math.max(0, numberValue(valueAt(record, "packets_down") ?? valueAt(record, "packets_reply"))),
    bytes_up: Math.max(0, numberValue(valueAt(record, "bytes_up") ?? valueAt(record, "bytes_original"))),
    bytes_down: Math.max(0, numberValue(valueAt(record, "bytes_down") ?? valueAt(record, "bytes_reply"))),
		application: observedApplication || stringValue(valueAt(record, "application"), "Unavailable"),
		application_available: Boolean(observedApplication) || applicationAvailable,
		application_confidence: observedApplication ? inspectionConfidence : boundedNumber(valueAt(record, "application_confidence"), 0, 0, 1),
    security_context_id: stringValue(valueAt(record, "security_context_id"), id),
    policy_id: stringValue(valueAt(record, "policy_id")) || stringValue(valueAt(record, "matched_policy_id")),
    policy_version: Math.max(0, numberValue(valueAt(record, "policy_version") ?? valueAt(record, "policy_generation"))),
    decision_version: Math.max(0, numberValue(valueAt(record, "decision_version") ?? valueAt(record, "decision_generation"))),
    risk_score: boundedNumber(valueAt(record, "risk_score"), 0, 0, 100),
    risk_available: riskAvailable,
    decision,
    decision_status: decision ? "EVALUATED" : cacheState === "INVALIDATED" ? "INVALIDATED" : "UNAVAILABLE",
    decision_reason: stringValue(valueAt(record, "decision_reason")) || stringValue(valueAt(record, "invalidation_reason")) || undefined,
    cache_state: cacheState || "NOT_EVALUATED",
    counters_available: countersAvailable,
    fast_path_eligible: pathClassification === "FAST",
    path_classification: pathClassification,
    fast_path_reason: stringValue(valueAt(record, "fast_path_reason")) || (pathClassification === "UNAVAILABLE" ? "Kernel path provenance is not verified" : undefined),
    invalidated: booleanValue(valueAt(record, "invalidated"), cacheState === "INVALIDATED") || cacheState === "INVALIDATED",
    revoked,
    original_tuple: runtimeOriginal,
    reply_tuple: runtimeReply,
		translated_tuple: tupleValue(valueAt(record, "translated_tuple")) ?? undefined,
		inspection,
  };
}

export function normalizeSessionPage(value: unknown): Session[] {
  const record = objectValue(value);
  const items = Array.isArray(value) ? value : Array.isArray(valueAt(record, "items")) ? valueAt(record, "items") as unknown[] : [];
  return items.map((item, index) => normalizeSession(item, index)).filter((item): item is Session => item !== null);
}

function normalizeSecurityContext(value: unknown, session: Session): SessionDetail["security_context"] {
  const record = objectValue(value);
  const risk = objectValue(valueAt(record, "risk"));
  const policy = objectValue(valueAt(record, "policy"));
  const ml = objectValue(valueAt(record, "ml"));
	const tls = objectValue(valueAt(record, "tls"));
	const inspection = normalizeSessionInspection(valueAt(record, "inspection")) ?? session.inspection;
  return {
    flow_id: stringValue(valueAt(record, "flow_id"), session.id),
    session_id: stringValue(valueAt(record, "session_id"), session.id),
    network: objectValue(valueAt(record, "network")) ?? {},
    app: objectValue(valueAt(record, "app")) ?? {},
    tls: { ...(tls ?? {}), available: booleanValue(valueAt(tls, "available")) },
    dns: objectValue(valueAt(record, "dns")) ?? {},
    reputation: objectValue(valueAt(record, "reputation")) ?? {},
    ips: objectValue(valueAt(record, "ips")) as SessionDetail["security_context"]["ips"] ?? {},
    behavior: objectValue(valueAt(record, "behavior")) as SessionDetail["security_context"]["behavior"] ?? {},
    ml: {
      ...(ml ?? {}),
      confidence: boundedNumber(valueAt(ml, "confidence"), 0, 0, 1),
      available: booleanValue(valueAt(ml, "available")),
    },
    risk: {
      ...(risk ?? {}),
      score: boundedNumber(valueAt(risk, "score"), session.risk_score, 0, 100),
      level: stringValue(valueAt(risk, "level"), "Unavailable"),
      contributions: normalizeRiskContributions(valueAt(risk, "contributions")),
    },
    policy: {
      ...(policy ?? {}),
      action: decisionValue(valueAt(policy, "action")) || session.decision || "",
      matched_policy_id: stringValue(valueAt(policy, "matched_policy_id")) || session.policy_id || undefined,
      scope: stringValue(valueAt(policy, "scope")) || undefined,
      reason: stringValue(valueAt(policy, "reason")) || session.decision_reason || undefined,
    },
		signals: Array.isArray(valueAt(record, "signals")) ? valueAt(record, "signals") as SecurityEvent[] : [],
		inspection,
    updated_at: validTimestamp(valueAt(record, "updated_at")) || session.last_seen,
  };
}

export function normalizeSessionDetail(value: unknown): SessionDetail | null {
  const record = objectValue(value);
  const session = normalizeSession(valueAt(record, "session") ?? value, 0);
  if (!session) return null;
  return { session, security_context: normalizeSecurityContext(valueAt(record, "security_context"), session) };
}

function normalizeInterface(value: unknown, index: number): InterfaceConfig | null {
  const record = objectValue(value);
  if (!record) return null;
  return {
    id: stringValue(valueAt(record, "id"), `interface-${index}`),
    name: stringValue(valueAt(record, "name"), stringValue(valueAt(record, "id"), `Interface ${index + 1}`)),
    system_name: stringValue(valueAt(record, "system_name"), "unknown"),
    mac_address: stringValue(valueAt(record, "mac_address")) || undefined,
    zone_id: stringValue(valueAt(record, "zone_id"), "unknown"),
    mode: stringValue(valueAt(record, "mode"), "L3"),
    ipv4_addresses: stringArray(valueAt(record, "ipv4_addresses")),
    ipv6_addresses: stringArray(valueAt(record, "ipv6_addresses")),
    mtu: Math.max(0, numberValue(valueAt(record, "mtu"), 1500)),
    admin_state: booleanValue(valueAt(record, "admin_state"), true),
    link_state: stringValue(valueAt(record, "link_state")) || undefined,
    rx_packets: Math.max(0, numberValue(valueAt(record, "rx_packets"))),
    tx_packets: Math.max(0, numberValue(valueAt(record, "tx_packets"))),
    rx_bytes: Math.max(0, numberValue(valueAt(record, "rx_bytes"))),
    tx_bytes: Math.max(0, numberValue(valueAt(record, "tx_bytes"))),
  };
}

function normalizeZone(value: unknown, index: number): Zone | null {
  const record = objectValue(value);
  if (!record) return null;
  const id = stringValue(valueAt(record, "id"), `zone-${index}`);
  return { id, name: stringValue(valueAt(record, "name"), id), description: stringValue(valueAt(record, "description")) };
}

function normalizeRoute(value: unknown, index: number): Route | null {
  const record = objectValue(value);
  if (!record) return null;
  return {
    id: stringValue(valueAt(record, "id"), `route-${index}`),
    destination_cidr: stringValue(valueAt(record, "destination_cidr"), "unknown"),
    gateway: stringValue(valueAt(record, "gateway")),
    interface_id: stringValue(valueAt(record, "interface_id")),
    metric: Math.max(0, numberValue(valueAt(record, "metric"))),
    enabled: booleanValue(valueAt(record, "enabled"), true),
    description: stringValue(valueAt(record, "description")) || undefined,
  };
}

function normalizeNAT(value: unknown, index: number): NATRule | null {
  const record = objectValue(value);
  if (!record) return null;
  return {
    id: stringValue(valueAt(record, "id"), `nat-${index}`),
    name: stringValue(valueAt(record, "name"), stringValue(valueAt(record, "id"), `NAT ${index + 1}`)),
    type: stringValue(valueAt(record, "type"), "SNAT").toUpperCase(),
    source_zone: stringValue(valueAt(record, "source_zone")),
    destination_zone: stringValue(valueAt(record, "destination_zone")),
    source_network: stringValue(valueAt(record, "source_network")) || undefined,
    destination_network: stringValue(valueAt(record, "destination_network")) || undefined,
    protocol: stringValue(valueAt(record, "protocol")) || undefined,
    original_port: Math.max(0, numberValue(valueAt(record, "original_port"))),
    translated_address: stringValue(valueAt(record, "translated_address")) || undefined,
    translated_port: Math.max(0, numberValue(valueAt(record, "translated_port"))),
    enabled: booleanValue(valueAt(record, "enabled"), true),
    priority: Math.max(0, numberValue(valueAt(record, "priority"))),
  };
}

function normalizePolicy(value: unknown, index: number): SecurityPolicy | null {
  const record = objectValue(value);
  if (!record) return null;
  return {
    id: stringValue(valueAt(record, "id"), `policy-${index}`),
    name: stringValue(valueAt(record, "name"), stringValue(valueAt(record, "id"), `Policy ${index + 1}`)),
    priority: Math.max(0, numberValue(valueAt(record, "priority"))),
    source_zones: stringArray(valueAt(record, "source_zones")),
    destination_zones: stringArray(valueAt(record, "destination_zones")),
    source_addresses: stringArray(valueAt(record, "source_addresses")),
    destination_addresses: stringArray(valueAt(record, "destination_addresses")),
    services: stringArray(valueAt(record, "services")),
		applications: stringArray(valueAt(record, "applications")),
		application_match_mode: stringValue(valueAt(record, "application_match_mode")) || undefined,
    security_profile_id: stringValue(valueAt(record, "security_profile_id")) || undefined,
    minimum_risk: valueAt(record, "minimum_risk") == null ? undefined : boundedNumber(valueAt(record, "minimum_risk"), 0, 0, 100),
    maximum_risk: valueAt(record, "maximum_risk") == null ? undefined : boundedNumber(valueAt(record, "maximum_risk"), 100, 0, 100),
    action: decisionValue(valueAt(record, "action")) || "ALLOW",
    scope: stringValue(valueAt(record, "scope"), "SESSION"),
    log_start: booleanValue(valueAt(record, "log_start"), true),
    log_end: booleanValue(valueAt(record, "log_end"), true),
    enabled: booleanValue(valueAt(record, "enabled"), true),
  };
}

function normalizeProfile(value: unknown, index: number): SecurityProfile | null {
  const record = objectValue(value);
  if (!record) return null;
	const inspection = objectValue(valueAt(record, "inspection"));
	return {
    id: stringValue(valueAt(record, "id"), `profile-${index}`),
    name: stringValue(valueAt(record, "name"), stringValue(valueAt(record, "id"), `Profile ${index + 1}`)),
    ids_ips_enabled: booleanValue(valueAt(record, "ids_ips_enabled")),
    dpi_enabled: booleanValue(valueAt(record, "dpi_enabled")),
    dns_security_enabled: booleanValue(valueAt(record, "dns_security_enabled")),
    url_filtering_enabled: booleanValue(valueAt(record, "url_filtering_enabled")),
    threat_intel_enabled: booleanValue(valueAt(record, "threat_intel_enabled")),
    behavior_enabled: booleanValue(valueAt(record, "behavior_enabled")),
    ml_detection_enabled: booleanValue(valueAt(record, "ml_detection_enabled")),
    tls_mode: stringValue(valueAt(record, "tls_mode"), "BYPASS"),
    minimum_block_risk: boundedNumber(valueAt(record, "minimum_block_risk"), 80, 0, 100),
    logging_level: stringValue(valueAt(record, "logging_level"), "INFO"),
    inspection_required: booleanValue(valueAt(record, "inspection_required")),
		inspection_failure_action: stringValue(valueAt(record, "inspection_failure_action"), "ALLOW"),
		inspection: inspection ? {
			mode: stringValue(valueAt(inspection, "mode"), "OFF").toUpperCase(),
			fail_mode: stringValue(valueAt(inspection, "fail_mode"), "OPEN").toUpperCase(),
			ruleset_id: stringValue(valueAt(inspection, "ruleset_id")),
		} : undefined,
  };
}

function emptyConfig(): NGFWConfig {
  return {
    interfaces: [],
    zones: [],
    routes: [],
    nat_rules: [],
    policies: [],
    security_profiles: [],
    max_sessions: 0,
    max_events_queue: 0,
    max_http_body_inspection: 0,
    max_http_header_size: 0,
    max_url_length: 0,
    max_ml_input_length: 0,
    ml_timeout_millis: 0,
    request_inspection_timeout_millis: 0,
    default_deny: true,
  };
}

function normalizeConfig(value: unknown): NGFWConfig | null {
  const record = objectValue(value);
  if (!record) return null;
  const config = { ...emptyConfig(), ...record } as NGFWConfig;
  const interfaces = Array.isArray(valueAt(record, "interfaces")) ? valueAt(record, "interfaces") as unknown[] : [];
  const zones = Array.isArray(valueAt(record, "zones")) ? valueAt(record, "zones") as unknown[] : [];
  const routes = Array.isArray(valueAt(record, "routes")) ? valueAt(record, "routes") as unknown[] : [];
  const natRules = Array.isArray(valueAt(record, "nat_rules")) ? valueAt(record, "nat_rules") as unknown[] : [];
  const policies = Array.isArray(valueAt(record, "policies")) ? valueAt(record, "policies") as unknown[] : [];
  const profiles = Array.isArray(valueAt(record, "security_profiles")) ? valueAt(record, "security_profiles") as unknown[] : [];
  config.interfaces = interfaces.map(normalizeInterface).filter((item): item is InterfaceConfig => item !== null);
  config.zones = zones.map(normalizeZone).filter((item): item is Zone => item !== null);
  config.routes = routes.map(normalizeRoute).filter((item): item is Route => item !== null);
  config.nat_rules = natRules.map(normalizeNAT).filter((item): item is NATRule => item !== null);
  config.policies = policies.map(normalizePolicy).filter((item): item is SecurityPolicy => item !== null);
	config.security_profiles = profiles.map(normalizeProfile).filter((item): item is SecurityProfile => item !== null);
	const inspection = objectValue(valueAt(record, "inspection"));
	if (inspection) {
		const limits = objectValue(valueAt(inspection, "limits"));
		config.inspection = {
			enabled: booleanValue(valueAt(inspection, "enabled")),
			include_management: booleanValue(valueAt(inspection, "include_management")),
			limits: {
				eve_line_bytes: Math.max(0, numberValue(valueAt(limits, "eve_line_bytes"))),
				normalized_event_bytes: Math.max(0, numberValue(valueAt(limits, "normalized_event_bytes"))),
				observation_queue_items: Math.max(0, numberValue(valueAt(limits, "observation_queue_items"))),
				observation_queue_bytes: Math.max(0, numberValue(valueAt(limits, "observation_queue_bytes"))),
				security_events: Math.max(0, numberValue(valueAt(limits, "security_events"))),
				security_event_bytes: Math.max(0, numberValue(valueAt(limits, "security_event_bytes"))),
				correlation_pending: Math.max(0, numberValue(valueAt(limits, "correlation_pending"))),
				correlation_wait_ms: Math.max(0, numberValue(valueAt(limits, "correlation_wait_ms"))),
				recent_sessions: Math.max(0, numberValue(valueAt(limits, "recent_sessions"))),
				recent_session_ttl_seconds: Math.max(0, numberValue(valueAt(limits, "recent_session_ttl_seconds"))),
				app_detection_timeout_ms: Math.max(0, numberValue(valueAt(limits, "app_detection_timeout_ms"))),
			},
		};
	} else {
		delete config.inspection;
	}
  config.max_sessions = Math.max(0, numberValue(valueAt(record, "max_sessions")));
  config.max_events_queue = Math.max(0, numberValue(valueAt(record, "max_events_queue")));
  config.max_http_body_inspection = Math.max(0, numberValue(valueAt(record, "max_http_body_inspection")));
  config.max_http_header_size = Math.max(0, numberValue(valueAt(record, "max_http_header_size")));
  config.max_url_length = Math.max(0, numberValue(valueAt(record, "max_url_length")));
  config.max_ml_input_length = Math.max(0, numberValue(valueAt(record, "max_ml_input_length")));
  config.ml_timeout_millis = Math.max(0, numberValue(valueAt(record, "ml_timeout_millis")));
  config.request_inspection_timeout_millis = Math.max(0, numberValue(valueAt(record, "request_inspection_timeout_millis")));
  config.default_deny = booleanValue(valueAt(record, "default_deny"), true);
  return config;
}

export function normalizeConfigExport(value: unknown): ConfigExport | null {
  const record = objectValue(value);
  if (!record) return null;
  const running = normalizeConfig(valueAt(record, "running"));
  if (!running) return null;
  const candidate = normalizeConfig(valueAt(record, "candidate")) ?? normalizeConfig(running) ?? running;
  const versionRecord = objectValue(valueAt(record, "version"));
  const validationRecord = objectValue(valueAt(record, "candidate_validation"));
  return {
    running,
    candidate,
    version: {
      version: Math.max(0, numberValue(valueAt(versionRecord, "version"))),
      author: stringValue(valueAt(versionRecord, "author")),
      timestamp: validTimestamp(valueAt(versionRecord, "timestamp")),
      comment: stringValue(valueAt(versionRecord, "comment")),
      checksum: stringValue(valueAt(versionRecord, "checksum")),
    },
    candidate_valid: booleanValue(valueAt(record, "candidate_valid"), true),
    candidate_validation_state: stringValue(valueAt(validationRecord, "state")) || undefined,
    candidate_checksum: stringValue(valueAt(validationRecord, "candidate_checksum")) || undefined,
    checked_candidate_checksum: stringValue(valueAt(validationRecord, "checked_checksum")) || undefined,
  };
}

export function normalizeBlocks(value: unknown): TemporaryBlock[] {
  const items = Array.isArray(value) ? value : [];
  return items.map((item, index) => {
    const record = objectValue(item);
    if (!record) return null;
    return {
      id: stringValue(valueAt(record, "id"), `block-${index}`),
      indicator: stringValue(valueAt(record, "indicator"), "unknown"),
      reason: stringValue(valueAt(record, "reason"), "Temporary block"),
      created_at: validTimestamp(valueAt(record, "created_at")),
      expires_at: validTimestamp(valueAt(record, "expires_at")),
      source_event: stringValue(valueAt(record, "source_event")) || undefined,
    } as TemporaryBlock;
  }).filter((item): item is TemporaryBlock => item !== null);
}

export function normalizeReputation(value: unknown): ReputationEntry[] {
  const items = Array.isArray(value) ? value : [];
  return items.map((item, index) => {
    const record = objectValue(item);
    if (!record) return null;
    return {
      indicator: stringValue(valueAt(record, "indicator"), `indicator-${index}`),
      indicator_type: stringValue(valueAt(record, "indicator_type"), "UNKNOWN"),
      reputation_score: boundedNumber(valueAt(record, "reputation_score"), 0, 0, 100),
      category: stringValue(valueAt(record, "category")) || undefined,
      source: stringValue(valueAt(record, "source")) || undefined,
      first_seen: Math.max(0, numberValue(valueAt(record, "first_seen"))),
      last_updated: Math.max(0, numberValue(valueAt(record, "last_updated"))),
      expires_at: Math.max(0, numberValue(valueAt(record, "expires_at"))),
      enabled: booleanValue(valueAt(record, "enabled"), true),
    } as ReputationEntry;
  }).filter((item): item is ReputationEntry => item !== null);
}

export function normalizeAuditPage(value: unknown): AuditEntry[] {
  const record = objectValue(value);
  const items = Array.isArray(value) ? value : Array.isArray(valueAt(record, "items")) ? valueAt(record, "items") as unknown[] : [];
  return items.map((item, index) => {
    const entry = objectValue(item);
    if (!entry) return null;
    return {
      id: stringValue(valueAt(entry, "id"), `audit-${index}`),
      timestamp: validTimestamp(valueAt(entry, "timestamp")),
      actor: stringValue(valueAt(entry, "actor"), "unknown"),
      role: stringValue(valueAt(entry, "role")) || undefined,
      action: stringValue(valueAt(entry, "action"), "UNKNOWN"),
      resource: stringValue(valueAt(entry, "resource"), "unknown"),
      resource_id: stringValue(valueAt(entry, "resource_id")) || undefined,
      result: stringValue(valueAt(entry, "result"), "UNKNOWN"),
      message: stringValue(valueAt(entry, "message")) || undefined,
    } as AuditEntry;
  }).filter((item): item is AuditEntry => item !== null);
}

export function normalizeMLStatus(value: unknown): MLStatus | null {
  const record = objectValue(value);
  if (!record) return null;
  return { status: stringValue(valueAt(record, "status"), "unavailable"), configured: booleanValue(valueAt(record, "configured")) };
}

export function normalizeUser(value: unknown): User | null {
  const record = objectValue(value);
  if (!record) return null;
  return {
    id: stringValue(valueAt(record, "id")),
    username: stringValue(valueAt(record, "username"), "unknown"),
    role: stringValue(valueAt(record, "role"), "VIEWER"),
    enabled: booleanValue(valueAt(record, "enabled"), true),
  };
}
