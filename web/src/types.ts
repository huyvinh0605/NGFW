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
  application_confidence: number;
  security_context_id: string;
  policy_id: string;
  policy_version: number;
  decision_version: number;
  risk_score: number;
  decision: string;
  fast_path_eligible: boolean;
  fast_path_reason?: string;
  invalidated: boolean;
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
  category: string;
  signature_id?: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  confidence: number;
  source_ip?: string;
  destination_ip?: string;
  application?: string;
  evidence?: string;
  recommended_action?: string;
  metadata?: Record<string, unknown>;
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
};

export type NGFWConfig = {
  interfaces: InterfaceConfig[];
  zones: Zone[];
  routes: Route[];
  nat_rules: NATRule[];
  policies: SecurityPolicy[];
  security_profiles: SecurityProfile[];
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
};

export type User = {
  id: string;
  username: string;
  role: "ADMIN" | "OPERATOR" | "VIEWER" | string;
  enabled: boolean;
};

export type MLStatus = { status: string; configured: boolean };
