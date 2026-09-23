export type Page = "overview" | "sessions" | "threats" | "policy" | "network" | "configuration" | "system";

export type ComponentHealth = {
  name: string;
  status: "ok" | "healthy" | "degraded" | "down" | string;
  message?: string;
  updated_at?: string;
};

export type Health = {
  status: "healthy" | "degraded" | string;
  components: Record<string, ComponentHealth>;
};

export type Stats = {
  active_sessions: number;
  event_queue_dropped: number;
  applications: Record<string, number>;
  blocked_sessions: number;
  timestamp: string;
};

export type Session = {
  id: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  protocol: string;
  source_zone: string;
  destination_zone: string;
  start_time: string;
  last_seen: string;
  tcp_state: string;
  packets_up: number;
  packets_down: number;
  bytes_up: number;
  bytes_down: number;
  application: string;
  application_available: boolean;
  application_confidence: number;
  security_context_id: string;
  policy_id: string;
  policy_version: number;
  decision_version: number;
  risk_score: number;
  risk_available: boolean;
  decision: string;
  decision_status: "EVALUATED" | "INVALIDATED" | "UNAVAILABLE";
  decision_reason?: string;
  cache_state: string;
  counters_available: boolean;
  fast_path_eligible: boolean;
  path_classification: "FAST" | "INSPECT" | "UNAVAILABLE";
  fast_path_reason?: string;
  invalidated: boolean;
  revoked: boolean;
  /** Runtime M2 tuple data. Legacy API responses may omit these fields. */
  original_tuple?: FlowTuple;
  reply_tuple?: FlowTuple;
  translated_tuple?: FlowTuple;
  inspection?: SessionInspection;
};

export type FlowTuple = {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  namespace?: string;
};

export type SecurityContext = {
  flow_id: string;
  session_id: string;
  network: Record<string, unknown>;
  app: Record<string, unknown>;
  tls: Record<string, unknown>;
  dns: Record<string, unknown>;
  reputation: Record<string, unknown>;
  ips: { alerts?: SecurityEvent[]; max_severity?: string };
  behavior: { anomaly_events?: SecurityEvent[] };
  ml: { predicted_class?: string; confidence: number; model_version?: string; available: boolean };
  risk: { score: number; level: string; reasons?: string[]; contributions?: RiskContribution[] };
  policy: { matched_policy_id?: string; action: string; scope?: string; reason?: string };
  signals?: SecurityEvent[];
  inspection?: SessionInspection;
  updated_at: string;
};

export type RiskContribution = {
  source: string;
  value: number;
  confidence: number;
  reason: string;
};

export type SessionDetail = {
  session: Session;
  security_context: SecurityContext;
};

export type SecurityEvent = {
  event_id: string;
  timestamp: string;
  flow_id?: string;
  session_id?: string;
  detector: string;
  event_class: "runtime" | "policy" | "security" | string;
  category: string;
  signature_id?: string;
  severity: "UNKNOWN" | "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  confidence: number;
  confidence_available?: boolean;
  source_ip?: string;
  destination_ip?: string;
  application?: string;
  evidence?: string;
  recommended_action?: string;
  metadata?: Record<string, unknown>;
  capture_mode?: "IDS" | "IPS" | string;
  correlation_state?: "CORRELATED" | "UNCORRELATED" | "AMBIGUOUS" | string;
  verdict?: "UNKNOWN" | "ALERT" | "DROP" | "ERROR" | string;
  packet_verdict?: string;
  enforcement?: EnforcementResult;
};

export type ApplicationIdentity = {
  name: string;
  raw_name?: string;
  source: string;
  confidence: string;
  first_seen?: string;
  last_seen?: string;
  conflicted: boolean;
};

export type EnforcementResult = {
  mechanism: string;
  scope: string;
  requested_action?: string;
  status: string;
  reason?: string;
  observed_at?: string;
  operation_id?: string;
};

export type SessionInspection = {
  generation: number;
  revision: number;
  profile_id?: string;
  mode: "OFF" | "IDS" | "IPS" | string;
  state: string;
  reason?: string;
  coverage: string;
  application: ApplicationIdentity;
  app_policy_state: string;
  app_deadline?: string;
  threat_count: number;
  last_event_id?: string;
  max_severity: string;
  latest_verdict: string;
  enforcement: EnforcementResult;
  sources: string[];
  missing_evidence: string[];
};

export type InspectionHealth = {
  enabled: boolean;
  status: string;
  reason?: string;
  generation: number;
  sources: Record<string, {
    sensor_id: string;
    mode?: string;
    state: string;
    reason?: string;
    last_read?: string;
    last_heartbeat?: string;
    counters: { uptime_seconds?: number; captured_packets?: number; capture_drops?: number; nfqueue_drops?: number; source_timestamp?: string };
    reader_stats: Record<string, number>;
  }>;
  ips_queue: { requested: boolean; configured: boolean; capture_live: boolean; lease_active: boolean; last_renewal?: string; last_error?: string };
  stats: Record<string, number>;
  updated_at: string;
};

export type InspectionCapabilities = {
  supported: boolean;
  modes: string[];
  applications: string[];
  fail_modes: string[];
  rulesets: string[];
  application_match_modes: string[];
  limitations: string[];
};

export type TemporaryBlock = {
  id: string;
  indicator: string;
  reason: string;
  created_at: string;
  expires_at: string;
  source_event?: string;
};

export type ReputationEntry = {
  indicator: string;
  indicator_type: string;
  reputation_score: number;
  category?: string;
  source?: string;
  first_seen: number;
  last_updated: number;
  expires_at: number;
  enabled: boolean;
};

export type AuditEntry = {
  id: string;
  timestamp: string;
  actor: string;
  role?: string;
  action: string;
  resource: string;
  resource_id?: string;
  result: string;
  message?: string;
};

export type InterfaceConfig = {
  id: string;
  name: string;
  system_name: string;
  mac_address?: string;
  zone_id: string;
  mode: string;
  ipv4_addresses: string[];
  ipv6_addresses?: string[];
  mtu: number;
  admin_state: boolean;
  link_state?: string;
  rx_packets?: number;
  tx_packets?: number;
  rx_bytes?: number;
  tx_bytes?: number;
};

export type Zone = { id: string; name: string; description: string };

export type Route = {
  id: string;
  destination_cidr: string;
  gateway: string;
  interface_id: string;
  metric: number;
  enabled: boolean;
  description?: string;
};

export type NATRule = {
  id: string;
  name: string;
  type: string;
  source_zone: string;
  destination_zone: string;
  source_network?: string;
  destination_network?: string;
  protocol?: string;
  original_port?: number;
  translated_address?: string;
  translated_port?: number;
  enabled: boolean;
  priority: number;
};

export type SecurityPolicy = {
  id: string;
  name: string;
  priority: number;
  source_zones?: string[];
  destination_zones?: string[];
  source_addresses?: string[];
  destination_addresses?: string[];
  services?: string[];
  applications?: string[];
  application_match_mode?: string;
  security_profile_id?: string;
  minimum_risk?: number;
  maximum_risk?: number;
  action: string;
  scope?: string;
  log_start: boolean;
  log_end: boolean;
  enabled: boolean;
};

export type SecurityProfile = {
  id: string;
  name: string;
  ids_ips_enabled: boolean;
  dpi_enabled: boolean;
  dns_security_enabled: boolean;
  url_filtering_enabled: boolean;
  threat_intel_enabled: boolean;
  behavior_enabled: boolean;
  ml_detection_enabled: boolean;
  tls_mode: string;
  minimum_block_risk: number;
  logging_level: string;
  inspection_required: boolean;
  inspection_failure_action: string;
  inspection?: InspectionProfile;
};

export type InspectionProfile = {
  mode: "IDS" | "IPS" | string;
  fail_mode: "OPEN" | string;
  ruleset_id: string;
};

export type InspectionLimits = {
  eve_line_bytes: number;
  normalized_event_bytes: number;
  observation_queue_items: number;
  observation_queue_bytes: number;
  security_events: number;
  security_event_bytes: number;
  correlation_pending: number;
  correlation_wait_ms: number;
  recent_sessions: number;
  recent_session_ttl_seconds: number;
  app_detection_timeout_ms: number;
};

export type InspectionConfig = {
  enabled: boolean;
  include_management: boolean;
  limits: InspectionLimits;
};

export type NGFWConfig = {
  interfaces: InterfaceConfig[];
  zones: Zone[];
  routes: Route[];
  nat_rules: NATRule[];
  policies: SecurityPolicy[];
  security_profiles: SecurityProfile[];
  inspection?: InspectionConfig;
  max_sessions: number;
  max_events_queue: number;
  max_http_body_inspection: number;
  max_http_header_size: number;
  max_url_length: number;
  max_ml_input_length: number;
  ml_timeout_millis: number;
  request_inspection_timeout_millis: number;
  default_deny: boolean;
};

export type ConfigVersion = {
  version: number;
  author: string;
  timestamp: string;
  comment: string;
  checksum: string;
};

export type ConfigExport = {
  running: NGFWConfig;
  candidate: NGFWConfig;
  version: ConfigVersion;
  candidate_valid: boolean;
  candidate_validation_state?: "VALID" | "INVALID" | "STALE" | "NOT_RUN" | string;
  candidate_checksum?: string;
  checked_candidate_checksum?: string;
};

export type User = {
  id: string;
  username: string;
  role: "ADMIN" | "OPERATOR" | "VIEWER" | string;
  enabled: boolean;
};

export type MLStatus = { status: string; configured: boolean };
