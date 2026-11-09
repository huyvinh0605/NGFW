import type { SecurityEvent } from "./types";
import { eventOutcome, eventTitle, eventTypeNames, eventTypeOf, formatEndpoint, sourceOf, type FilterField } from "./eventData";

export const columnDefinitions = {
  time: { label: "Thời gian · UTC+7", width: 148, source: "Mọi nguồn" },
  type: { label: "Loại / nguồn", width: 110, source: "Mọi nguồn" },
  summary: { label: "Sự kiện", width: 260, source: "Mọi nguồn" },
  tuple: { label: "IP / cổng", width: 180, source: "Suricata M3" },
  source: { label: "IP nguồn", width: 160, source: "Suricata M3" },
  destination: { label: "IP đích", width: 160, source: "Suricata M3" },
  source_port: { label: "Cổng nguồn", width: 96, source: "Suricata M3" },
  destination_port: { label: "Cổng đích", width: 96, source: "Suricata M3" },
  session: { label: "Session / request", width: 190, source: "Khi nguồn có ID liên kết" },
  severity: { label: "Mức độ", width: 86, source: "Suricata M3 / request M4" },
  outcome: { label: "Kết quả", width: 180, source: "Verdict và phạm vi được nguồn báo cáo" },
  policy: { label: "Policy", width: 150, source: "Khi nguồn có Policy ID" },
  signature: { label: "Signature ID", width: 110, source: "Suricata M3 / request M4" },
  application: { label: "Ứng dụng", width: 110, source: "Suricata M3" },
  capture: { label: "IDS / IPS", width: 90, source: "Suricata M3" },
  coverage: { label: "Coverage", width: 110, source: "Request M4" },
  forward: { label: "Kết quả upstream", width: 200, source: "Request M4 có forward result" },
} as const;
export type Column = keyof typeof columnDefinitions;
export type ColumnSetting = { id: Column; width: number; pin: "left" | "right" | "none" };
export const defaultColumns: ColumnSetting[] = (["time", "type", "summary", "tuple", "capture", "severity", "outcome", "policy"] as Column[])
  .map(id => ({ id, width: columnDefinitions[id].width, pin: id === "time" ? "left" : "none" }));
export function isColumn(value: unknown): value is Column { return typeof value === "string" && Object.prototype.hasOwnProperty.call(columnDefinitions, value); }
export function validColumns(value: unknown): value is ColumnSetting[] {
  return Array.isArray(value) && value.length > 0 && value.length <= Object.keys(columnDefinitions).length &&
    value.every(c => c && isColumn(c.id) && Number.isFinite(c.width) && c.width >= 80 && c.width <= 600 && ["left", "right", "none"].includes(c.pin)) &&
    new Set(value.map(c => c.id)).size === value.length;
}
export function orderedColumns(columns: ColumnSetting[]): ColumnSetting[] {
  return ["left", "none", "right"].flatMap(pin => columns.filter(c => c.pin === pin));
}
export function moveColumn(columns: ColumnSetting[], from: Column, to: Column): ColumnSetting[] {
  const source = columns.find(c => c.id === from), target = columns.find(c => c.id === to);
  if (!source || !target || from === to) return columns;
  const next = columns.filter(c => c.id !== from), index = columns.findIndex(c => c.id === to);
  next.splice(index, 0, { ...source, pin: target.pin });
  return orderedColumns(next);
}
export function columnFilter(e: SecurityEvent, id: Column): { field: FilterField; value: string } | undefined {
  const fields: Partial<Record<Column, FilterField>> = { source: "source_ip", destination: "destination_ip", source_port: "source_port", destination_port: "destination_port", policy: "policy_id", signature: "signature_id", application: "application", capture: "capture_mode", type: "event_type" };
  const field = fields[id];
  if (field) {
    const value = field === "event_type" ? eventTypeOf(e) : String(e[field as keyof SecurityEvent] ?? "");
    if (value) return { field, value };
  }
  if (id === "outcome" && e.verdict) return { field: "verdict", value: e.verdict };
  if (id === "session") {
    if (e.request?.id) return { field: "request_id", value: e.request.id };
    if (e.session_id) return { field: "session_id", value: e.session_id };
  }
}
export function columnText(e: SecurityEvent, id: Column): string {
  switch (id) {
    case "time": return e.timestamp;
    case "type": return eventTypeNames[eventTypeOf(e)];
    case "summary": return eventTitle(e);
    case "tuple": return `${formatEndpoint(e.source_ip, e.source_port)} → ${formatEndpoint(e.destination_ip, e.destination_port)}`;
    case "source": return e.source_ip || "—";
    case "destination": return e.destination_ip || "—";
    case "session": return e.request?.id || e.session_id || "—";
    case "source_port": return e.source_port == null ? "—" : String(e.source_port);
    case "destination_port": return e.destination_port == null ? "—" : String(e.destination_port);
    case "severity": return sourceOf(e) === "runtime" ? "Không áp dụng" : e.severity;
    case "outcome": return eventOutcome(e);
    case "policy": return e.policy_id || "—";
    case "signature": return e.signature_id || "—";
    case "application": return e.application || "—";
    case "capture": return e.capture_mode || "—";
    case "coverage": return e.request?.coverage || "—";
    case "forward": return e.request?.forward ? `${e.request.forward.http_status ?? "—"} · ${e.request.forward.reason_code}` : "—";
  }
}
