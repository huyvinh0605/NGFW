import type { SecurityEvent } from "./types";
import { normalizeEventPage } from "./runtimeData";

export type EventFeed = "runtime" | "security" | "request";
export const FEED_LIMIT = 1000;
export const IMPORTANT_RUNTIME_LIMIT = 100;
export const EVENT_PAGE_SIZE = 100;
export type FeedStatus = { updated?: string; error?: string; stream?: string; hasMore?: boolean; gap?: boolean; evicted?: number };
export const feedNames: Record<EventFeed, string> = { runtime: "Runtime / policy", security: "Suricata M3", request: "Request M4" };

export function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
export function text(value: unknown): string { return typeof value === "string" ? value : ""; }
export function formatEndpoint(ip?: string, port?: number): string {
  if (!ip) return "—";
  const address = ip.includes(":") && !ip.startsWith("[") ? `[${ip}]` : ip;
  return port == null ? address : `${address}:${port}`;
}
export function safeEventText(value: string): string {
  return value.replace(/\bBearer\s+[\w.+/=-]+/gi, "Bearer [đã ẩn]").replace(/\b(authorization|cookie|password|token)\s*[:=]\s*[^\s;,]+/gi, "$1=[đã ẩn]");
}
export function sequence(value: unknown): string {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return value.replace(/^0+(?=\d)/, "");
  throw new Error("Sequence không hợp lệ hoặc vượt độ chính xác của response JSON");
}
export function sourceOf(event: SecurityEvent): EventFeed { return event.feed ?? (event.event_class === "security" ? "security" : "runtime"); }
export function eventKey(event: SecurityEvent): string { return `${sourceOf(event)}:${event.stream_id ?? ""}:${event.event_id}`; }
export function eventTitle(event: SecurityEvent): string {
  if (sourceOf(event) !== "runtime") return event.category;
  const names: Record<string, string> = {
    SessionCreated: "Phiên mới được theo dõi", SessionUpdated: "Cập nhật trạng thái phiên", SessionClosed: "Bản ghi phiên đã đóng",
    SessionInvalidated: "Quyết định phiên hết hiệu lực", DecisionChanged: "Quyết định policy thay đổi", ApplicationIdentified: "Đã nhận diện ứng dụng",
    InspectionStateChanged: "Trạng thái kiểm tra phiên thay đổi", InspectionHealthChanged: "Trạng thái nguồn kiểm tra thay đổi",
    SecurityAlert: "Có cảnh báo bảo mật (tham chiếu)", SecurityEventUpdated: "Cảnh báo bảo mật được bổ sung",
    RequestGateDecision: "M4 quyết định request (tham chiếu)", RequestGateResult: "M4 cập nhật kết quả forward (tham chiếu)",
  };
  return names[text(event.metadata?.kind) || event.category] || event.category;
}

/** Separate bounded caches: a busy runtime stream cannot evict security evidence. */
export function mergeEvents(previous: SecurityEvent[], incoming: SecurityEvent[], reset?: EventFeed): SecurityEvent[] {
  const index = new Map<string, SecurityEvent>();
  for (const event of [...previous.filter(e => sourceOf(e) !== reset), ...incoming]) {
    const key = eventKey(event), prior = index.get(key);
    if (prior && ((prior.revision ?? 0) > (event.revision ?? 0) ||
      (prior.sequence && event.sequence && BigInt(prior.sequence) > BigInt(event.sequence)))) continue;
    index.set(key, event);
  }
  const ordered = [...index.values()].sort((a, b) => {
    const time = (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0);
    if (time) return time;
    if (sourceOf(a) === sourceOf(b) && a.sequence && b.sequence) {
      return BigInt(a.sequence) === BigInt(b.sequence) ? 0 : BigInt(a.sequence) > BigInt(b.sequence) ? -1 : 1;
    }
    return eventKey(a).localeCompare(eventKey(b));
  });
  // Retain a small, bounded set of protection transitions even when routine
  // SessionUpdated notifications fill the runtime cache. Their timestamps stay unchanged.
  const important = new Set(ordered.filter(e => sourceOf(e) === "runtime" && needsAttention(e)).slice(0, IMPORTANT_RUNTIME_LIMIT).map(eventKey));
  const counts = { runtime: important.size, security: 0, request: 0 };
  return ordered.filter(e => important.has(eventKey(e)) || ++counts[sourceOf(e)] <= FEED_LIMIT);
}

export function runtimePage(value: unknown) {
  const input = record(value);
  if (!Array.isArray(input.items) && !Array.isArray(value)) throw new Error("Runtime trả danh sách không hợp lệ");
  const stream = text(input.stream_id);
  const items = normalizeEventPage(value).map(event => ({ ...event, feed: "runtime" as const, stream_id: stream }));
  const raw = (Array.isArray(value) ? value : input.items) as unknown[];
  const last = raw.length ? sequence(record(raw[raw.length - 1]).sequence) : undefined;
  const head = input.next_sequence == null ? last ?? "0" : sequence(input.next_sequence);
  // Runtime next_sequence is the stream HEAD, not the last record delivered.
  return { items, stream, last, hasMore: Boolean(last && BigInt(head) > BigInt(last)), gap: Number(input.gap_from) > 0 };
}

/** Allowlist only; raw request headers, query, body and credentials are never retained by this adapter. */
export function requestPage(value: unknown) {
  const input = record(value);
  if (!Array.isArray(input.items)) throw new Error("M4 trả danh sách không hợp lệ");
  const items: SecurityEvent[] = input.items.flatMap(raw => {
    const item = record(raw), context = record(item.context), decision = record(item.decision), inspection = record(item.inspection);
    if (!text(item.event_id) || !text(context.request_id)) return [];
    const forward = item.forward ? record(item.forward) : undefined;
    const path = text(context.path).split(/[?#]/)[0].slice(0, 2048);
    const alerts = Array.isArray(inspection.alerts) ? inspection.alerts.map(record) : [];
    const severities = ["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const severity = alerts.reduce((a, b) => severities.indexOf(text(b.severity)) > severities.indexOf(a) ? text(b.severity) : a, "UNKNOWN");
    return [{
      event_id: text(item.event_id), feed: "request", sequence: sequence(item.sequence), timestamp: text(item.observed_at),
      detector: "REQUEST_GATE", event_class: "inspection", category: `${text(context.method)} ${path || "/"}`,
      session_id: text(context.session_id) || text(decision.session_id) || undefined, policy_id: text(decision.policy_id) || undefined,
      severity, confidence: 0, confidence_available: false, verdict: text(decision.verdict) || "UNKNOWN",
      evidence: text(decision.reason_code), signature_id: alerts.map(a => text(a.signature_id)).filter(Boolean).join(", ") || undefined,
      request: { id: text(context.request_id), connection_id: text(context.connection_id), method: text(context.method), scheme: text(context.scheme), path,
        coverage: text(inspection.coverage) || text(decision.coverage) || "UNAVAILABLE", completed: inspection.completed === true,
        error_code: text(inspection.error_code), reason_code: text(decision.reason_code), http_status: Number(decision.http_status) || undefined,
        forward: forward ? { http_status: Number(forward.http_status) || undefined, reason_code: text(forward.reason_code), observed_at: text(forward.observed_at) } : undefined },
    }];
  });
  return { items, next: sequence(input.next_sequence ?? 0), hasMore: input.has_more === true };
}

export type EventView = "alerts" | "security" | "request" | "runtime" | "all";
export function needsAttention(e: SecurityEvent): boolean {
  if (sourceOf(e) === "security") return true;
  if (e.request) return Boolean(e.signature_id) || e.verdict !== "ALLOW" || !e.request.completed || Boolean(e.request.error_code) ||
    e.request.coverage !== "COMPLETE" || Boolean(e.request.forward && !["UPSTREAM_RESPONSE_RECEIVED"].includes(e.request.forward.reason_code));
  // Match actual kinds/statuses, never turn every lifecycle transition into an incident.
  return e.category === "InspectionHealthChanged" || e.enforcement?.status === "FAILED" ||
    ["ERROR", "FAILED", "DEGRADED", "UNAVAILABLE"].includes(text(e.metadata?.state).toUpperCase());
}
export type FilterField = "source_ip" | "destination_ip" | "session_id" | "signature_id" | "capture_mode" | "verdict" | "policy_id" | "detector";
export const fieldNames: Record<FilterField, string> = { source_ip: "IP nguồn", destination_ip: "IP đích", session_id: "Session ID", signature_id: "Signature ID", capture_mode: "IDS / IPS", verdict: "Verdict", policy_id: "Policy ID", detector: "Nguồn phát" };
export type EventFilter = { field: FilterField; value: string; exclude: boolean };
export type ViewerQuery = { view: EventView; query: string; severity: string; minutes: string; filters: EventFilter[] };
export const defaultQuery: ViewerQuery = { view: "alerts", query: "", severity: "ALL", minutes: "ALL", filters: [] };
export function filterEvents(events: SecurityEvent[], query: ViewerQuery, now: number): SecurityEvent[] {
  return events.filter(e => {
    const feed = sourceOf(e);
    if (query.view === "alerts" ? !needsAttention(e) : query.view !== "all" && feed !== query.view) return false;
    if (query.severity !== "ALL" && (feed === "runtime" || e.severity !== query.severity)) return false;
    if (query.minutes !== "ALL" && (!Number.isFinite(Date.parse(e.timestamp)) || Date.parse(e.timestamp) < now - Number(query.minutes) * 60000)) return false;
    const haystack = [e.category, e.detector, e.session_id, e.request?.id, e.source_ip, e.destination_ip, e.signature_id, e.policy_id, e.evidence].join(" ").toLowerCase();
    if (!haystack.includes(query.query.toLowerCase())) return false;
    return (Object.keys(fieldNames) as FilterField[]).every(field => {
      const value = String(e[field] ?? "").toLowerCase(), choices = query.filters.filter(f => f.field === field);
      const includes = choices.filter(f => !f.exclude), excludes = choices.filter(f => f.exclude);
      // Exclusion requires an actual value: missing data must not silently match NOT IP.
      return (!choices.length || Boolean(value)) && (!includes.length || includes.some(f => f.value.toLowerCase() === value)) && !excludes.some(f => f.value.toLowerCase() === value);
    });
  });
}

export function eventOutcome(e: SecurityEvent): string {
  if (e.request) return `${e.verdict || "UNKNOWN"} · request`;
  if (sourceOf(e) === "runtime") return "Thông báo trạng thái";
  if (e.enforcement?.status === "APPLIED") return `${e.verdict || "UNKNOWN"} · ${e.enforcement.scope} / APPLIED`;
  return `${e.verdict || "UNKNOWN"}${e.enforcement ? ` · ${e.enforcement.scope} / ${e.enforcement.status}` : " · chưa có enforcement evidence"}`;
}

export function eventCSV(events: SecurityEvent[]): string {
  const cell = (v: unknown) => `"${safeEventText(String(v ?? "")).replace(/^[\s]*[=+\-@\t\r]/, "'$&").replace(/"/g, '""')}"`;
  const rows = [["timestamp_utc", "source", "type", "event_id", "summary", "source_ip", "source_port", "destination_ip", "destination_port", "session_id", "request_id", "signature_id", "severity", "outcome", "policy_id"],
    ...events.map(e => [e.timestamp, sourceOf(e), e.event_class, e.event_id, e.category, e.source_ip, e.source_port, e.destination_ip, e.destination_port, e.session_id, e.request?.id, e.signature_id, sourceOf(e) === "runtime" ? "" : e.severity, eventOutcome(e), e.policy_id])];
  return "\uFEFF" + rows.map(r => r.map(cell).join(",")).join("\r\n");
}
