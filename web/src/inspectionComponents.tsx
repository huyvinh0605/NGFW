import type { InspectionHealth, SecurityEvent, SessionInspection } from "./types";

function tone(value: string): string {
  switch (value.toUpperCase()) {
    case "HEALTHY": case "OBSERVED": case "MATCHED": case "APPLIED": return "low";
    case "DEGRADED": case "PARTIAL": case "PENDING": case "UNKNOWN_ALLOWED": return "medium";
    case "DROP": case "MISMATCH": case "FAILED": case "ERROR": return "critical";
    default: return "neutral";
  }
}

export function ApplicationBadge({ inspection }: { inspection?: SessionInspection }) {
  const app = inspection?.application;
  const name = app?.name && app.name !== "UNKNOWN" ? app.name : "UNKNOWN";
  const details = app ? `${app.source} · ${app.confidence}${app.conflicted ? " · conflicting evidence" : ""}` : "No application evidence";
  return <span className={`badge badge-${name === "UNKNOWN" ? "neutral" : "blue"}`} title={details}>{name}</span>;
}

export function InspectionBadge({ inspection }: { inspection?: SessionInspection }) {
  if (!inspection || inspection.mode === "OFF") return <span className="badge badge-neutral">OFF</span>;
  return <span className={`badge badge-${tone(inspection.state)}`} title={inspection.reason}>{inspection.mode} · {inspection.state}</span>;
}

export function InspectionHealthPanel({ health }: { health: InspectionHealth | null }) {
  if (!health) return <section className="panel inspection-health"><div className="panel-heading"><div><h2>M3 inspection</h2><p>Không lấy được trạng thái từ engine.</p></div><span className="badge badge-critical">UNAVAILABLE</span></div></section>;
  return <section className="panel inspection-health">
    <div className="panel-heading"><div><h2>M3 inspection</h2><p>Generation {health.generation}; các sensor chạy độc lập với API/UI.</p></div><span className={`badge badge-${tone(health.status)}`}>{health.enabled ? health.status.toUpperCase() : "DISABLED"}</span></div>
    {health.reason && <p className="muted">{health.reason}</p>}
    <div className="setting-list">
      <div><span>IPS requested / configured</span><strong>{health.ips_queue.requested ? "YES" : "NO"} / {health.ips_queue.configured ? "YES" : "NO"}</strong></div>
      <div><span>Capture live / kernel lease</span><strong>{health.ips_queue.capture_live ? "LIVE" : "UNAVAILABLE"} / {health.ips_queue.lease_active ? "ACTIVE" : "INACTIVE"}</strong></div>
      {health.ips_queue.last_error && <div><span>IPS lease error</span><strong>{health.ips_queue.last_error}</strong></div>}
    </div>
    <div className="component-list">{Object.entries(health.sources).map(([id, source]) => <div className="component-row" key={id}><span className={`component-dot ${source.state.toLowerCase()}`}/><div><strong>{source.sensor_id.toUpperCase()} {source.mode ?? ""}</strong><small>{source.reason || `Heartbeat ${source.last_heartbeat || "unavailable"}`}</small></div><span>{source.state}</span></div>)}</div>
    {!Object.keys(health.sources).length && <p className="muted">Chưa có sensor source được cấu hình. L3/L4 forwarding vẫn hoạt động theo fail-open.</p>}
  </section>;
}

export function SessionInspectionDetails({ inspection }: { inspection?: SessionInspection }) {
  if (!inspection) return <p className="muted">Inspection context unavailable.</p>;
  return <div className="setting-list">
    <div><span>Mode / state</span><InspectionBadge inspection={inspection}/></div>
    <div><span>Application</span><ApplicationBadge inspection={inspection}/></div>
    <div><span>App policy</span><span className={`badge badge-${tone(inspection.app_policy_state)}`}>{inspection.app_policy_state}</span></div>
    <div><span>Coverage</span><strong>{inspection.coverage}</strong></div>
    <div><span>Threat events</span><strong>{inspection.threat_count}</strong></div>
    <div><span>Latest verdict</span><strong>{inspection.latest_verdict}</strong></div>
    <div><span>Enforcement</span><strong>{inspection.enforcement.mechanism} · {inspection.enforcement.status}</strong></div>
    {inspection.reason && <div><span>Reason</span><strong>{inspection.reason}</strong></div>}
  </div>;
}

export function ThreatEventTable({ events, onSelect }: { events: SecurityEvent[]; onSelect?: (event: SecurityEvent) => void }) {
  return <div className="table-scroll"><table><thead><tr><th>Mode</th><th>Alert</th><th>Correlation</th><th>Verdict</th><th>Enforcement</th></tr></thead><tbody>
    {events.map((event) => <tr key={event.event_id} className={onSelect ? "clickable-row" : ""} onClick={() => onSelect?.(event)}><td>{event.capture_mode || "—"}</td><td><strong>{event.category}</strong><small>{event.signature_id || "no signature"}</small></td><td>{event.correlation_state || "UNAVAILABLE"}</td><td>{event.verdict || "UNKNOWN"}{event.packet_verdict ? ` / packet ${event.packet_verdict}` : ""}</td><td>{event.enforcement ? `${event.enforcement.scope} · ${event.enforcement.status}` : "NOT_REQUESTED"}</td></tr>)}
  </tbody></table></div>;
}
