import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, APIError, errorMessage } from "./api";
import { normalizeSessionDetail } from "./runtimeData";
import { defaultQuery, EVENT_PAGE_SIZE, eventCSV, eventKey, eventOutcome, FEED_LIMIT, feedNames, fieldNames, filterEvents, safeEventText as safeText, sourceOf, text,
  type EventFeed, type EventFilter, type FilterField, type ViewerQuery } from "./eventData";
import type { EventMonitor } from "./useEventFeed";
import type { SecurityEvent, SessionDetail } from "./types";

type Column = "tuple" | "session" | "severity" | "outcome" | "policy";
const columnNames: Record<Column, string> = { tuple: "IP / cổng", session: "Session / request", severity: "Mức độ", outcome: "Kết quả", policy: "Policy" };
const defaultColumns: Column[] = ["tuple", "session", "severity", "outcome"];
const preferenceKey = "ngfw.events.views.v1";
type SavedView = { name: string; query: ViewerQuery; columns: Column[] };
function readViews(): SavedView[] {
  try {
    const raw: unknown = JSON.parse(window.localStorage.getItem(preferenceKey) ?? "[]");
    if (!Array.isArray(raw)) return [];
    return raw.filter(v => v && typeof v.name === "string" && v.name.length <= 64 && v.query &&
      ["alerts", "security", "request", "runtime", "all"].includes(v.query.view) && typeof v.query.query === "string" && v.query.query.length <= 256 &&
      ["ALL", "5", "15", "60"].includes(v.query.minutes) && ["ALL", "UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(v.query.severity) &&
      Array.isArray(v.query.filters) && v.query.filters.length <= 20 && v.query.filters.every((f: EventFilter) => f && Object.prototype.hasOwnProperty.call(fieldNames, f.field) && typeof f.value === "string" && f.value.length <= 256 && typeof f.exclude === "boolean") &&
      Array.isArray(v.columns) && v.columns.every((c: Column) => Object.prototype.hasOwnProperty.call(columnNames, c))).slice(0, 10);
  } catch { return []; }
}
export function eventTime(value: string): string {
  const time = Date.parse(value);
  return Number.isNaN(time) ? "Chưa có thời gian nguồn" : new Intl.DateTimeFormat("vi-VN", { dateStyle: "short", timeStyle: "medium", timeZone: "Asia/Bangkok" }).format(time) + " UTC+7";
}
function Tag({ children, tone = "blue" }: { children: ReactNode; tone?: string }) { return <span className={`badge badge-${tone}`}>{children}</span>; }
function Pair({ label, value }: { label: string; value?: string | number }) { return value !== undefined && value !== "" ? <div className="detail-pair"><span>{label}</span><strong>{safeText(String(value))}</strong></div> : null; }
function Section({ title, children }: { title: string; children: ReactNode }) { return <section className="detail-section"><h3>{title}</h3>{children}</section>; }
function fingerprint(e: SecurityEvent): string { return [e.sequence, e.revision, e.session_id, e.evidence, e.verdict, e.enforcement?.status, e.request?.forward?.reason_code, e.request?.forward?.http_status].join("|"); }

export function EventsPanel({ monitor, onBlock }: { monitor: EventMonitor; onBlock: (event: SecurityEvent) => Promise<boolean> }) {
  const [query, setQuery] = useState<ViewerQuery>({ ...defaultQuery, filters: [] });
  const [frozen, setFrozen] = useState<{ events: SecurityEvent[]; at: number } | null>(null);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [columns, setColumns] = useState<Column[]>(defaultColumns);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState<EventFilter>({ field: "source_ip", value: "", exclude: false });
  const [views, setViews] = useState(readViews);
  const [viewName, setViewName] = useState("");
  const [message, setMessage] = useState("");
  const [context, setContext] = useState<number | null>(null);
  const table = useRef<HTMLDivElement>(null);
  const frozenIndex = useMemo(() => new Map(frozen?.events.map(e => [eventKey(e), fingerprint(e)])), [frozen]);
  const pending = frozen ? monitor.events.filter(e => frozenIndex.get(eventKey(e)) !== fingerprint(e)).length : 0;
  const filtered = useMemo(() => filterEvents(frozen?.events ?? monitor.events, query, frozen?.at ?? Date.now())
    .filter(e => context === null || Math.abs(Date.parse(e.timestamp) - context) <= 60000), [monitor.events, frozen, query, context]);
  const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / EVENT_PAGE_SIZE) - 1));
  const rows = filtered.slice(currentPage * EVENT_PAGE_SIZE, (currentPage + 1) * EVENT_PAGE_SIZE);
  const pause = () => setFrozen(s => s ?? { events: monitor.events, at: Date.now() });
  const changeQuery = (patch: Partial<ViewerQuery>) => { pause(); setQuery(q => ({ ...q, ...patch })); setPage(0); };
  const addFilter = (entry: EventFilter) => {
    if (!entry.value.trim() || query.filters.length >= 20) return;
    const next = { ...entry, value: entry.value.trim().slice(0, 256) };
    if (!query.filters.some(f => f.field === next.field && f.value === next.value && f.exclude === next.exclude)) changeQuery({ filters: [...query.filters, next] });
  };
  const openEvent = (event: SecurityEvent) => { pause(); setSelected(event); };
  const resume = () => { setFrozen(null); setPage(0); if (table.current) table.current.scrollTop = 0; };
  const saveView = () => {
    const name = viewName.trim().slice(0, 64);
    if (!name) return;
    const next = [...views.filter(v => v.name !== name), { name, query, columns }].slice(-10);
    try { window.localStorage.setItem(preferenceKey, JSON.stringify(next)); setViews(next); setViewName(""); setMessage("Đã lưu bộ lọc và cột trên browser này; không lưu bản ghi sự kiện."); }
    catch { setMessage("Browser không cho lưu lựa chọn này."); }
  };
  const exportPage = () => {
    pause();
    const url = URL.createObjectURL(new Blob([eventCSV(rows)], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a"); link.href = url; link.download = `ngfw-events-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`; link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    setMessage(`Đã xuất ${rows.length} bản ghi của trang đang xem; timestamp trong CSV là UTC.`);
  };
  return <div className="page-stack events-viewer">
    <section className="panel compact event-source-status" aria-label="Trạng thái nguồn sự kiện">
      {(Object.keys(feedNames) as EventFeed[]).map(feed => {
        const status = monitor.sources[feed];
        return <div key={feed}><strong>{feedNames[feed]}</strong><span>{status.error ? `Lỗi đọc: ${status.error}` : status.updated ? `Đọc lúc ${eventTime(status.updated)}` : "Đang chờ dữ liệu"}</span>
          {status.gap && <span className="event-warning">Có khoảng trống / nguồn đã reset; lịch sử không đầy đủ.</span>}
          {Boolean(status.evicted) && <span>Nguồn đã loại {status.evicted} bản ghi cũ.</span>}
          {status.hasMore && <span>Đang đọc các trang còn giữ; chưa đến cuối nguồn.</span>}</div>;
      })}
    </section>
    <section className="toolbar panel compact event-toolbar">
      <select aria-label="Chế độ sự kiện" value={query.view} onChange={e => changeQuery({ view: e.target.value as ViewerQuery["view"] })}>
        <option value="alerts">Cảnh báo & trạng thái bảo vệ</option><option value="security">Cảnh báo Suricata</option><option value="request">Request M4</option><option value="runtime">Runtime / policy (chẩn đoán)</option><option value="all">Tất cả nguồn đã tải</option>
      </select>
      <div className="search-box"><input aria-label="Tìm trong sự kiện đã tải" placeholder="Tìm IP, session, request hoặc signature…" maxLength={256} value={query.query} onChange={e => changeQuery({ query: e.target.value })}/></div>
      <select aria-label="Mức độ cảnh báo" value={query.severity} onChange={e => changeQuery({ severity: e.target.value })}><option value="ALL">Mọi mức độ</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].map(s => <option key={s}>{s}</option>)}</select>
      <select aria-label="Khoảng thời gian đã tải" value={query.minutes} onChange={e => { setContext(null); changeQuery({ minutes: e.target.value }); }}><option value="ALL">Mọi thời điểm đã tải</option><option value="5">5 phút gần nhất</option><option value="15">15 phút gần nhất</option><option value="60">1 giờ gần nhất</option></select>
    </section>
    <section className="panel compact event-controls">
      <div className="event-actions">
        {frozen ? <button className="button button-primary" disabled={Boolean(selected)} onClick={resume}>Tiếp tục cập nhật{pending ? ` · ${pending} mới / thay đổi trong cửa sổ` : ""}</button> : <button className="button button-secondary" onClick={pause}>Tạm dừng bảng</button>}
        <Tag tone={frozen ? "medium" : "low"}>{frozen ? "ĐANG TẠM DỪNG HIỂN THỊ" : "ĐANG THEO DÕI"}</Tag>
        <button className="button button-ghost" disabled={monitor.loading} onClick={() => void monitor.refresh()}>{monitor.loading ? "Đang đọc…" : "Đọc trang nguồn tiếp theo"}</button>
        <button className="button button-ghost" disabled={!rows.length} onClick={exportPage}>Xuất CSV trang này</button>
        <details onToggle={e => { if (e.currentTarget.open) pause(); }}><summary>Cột hiển thị</summary><div className="event-options">{(Object.keys(columnNames) as Column[]).map(c => <label key={c}><input type="checkbox" checked={columns.includes(c)} onChange={e => setColumns(v => e.target.checked ? [...v, c] : v.filter(x => x !== c))}/>{columnNames[c]}</label>)}</div></details>
      </div>
      <p className="muted">Lọc trong cửa sổ đã tải, tối đa {FEED_LIMIT} bản ghi mỗi nguồn. Mỗi trang {EVENT_PAGE_SIZE} dòng; không phải truy vấn toàn bộ lịch sử. Tạm dừng bảng vẫn tiếp nhận dữ liệu, không dừng NGFW.</p>
      <details className="event-filter-options"><summary>Bộ lọc theo trường & chế độ xem đã lưu</summary>
        <div className="event-actions"><select aria-label="Trường lọc" value={filter.field} onChange={e => setFilter(f => ({ ...f, field: e.target.value as FilterField }))}>{Object.entries(fieldNames).map(([v, label]) => <option key={v} value={v}>{label}</option>)}</select>
          <select aria-label="Kiểu lọc" value={filter.exclude ? "exclude" : "include"} onChange={e => setFilter(f => ({ ...f, exclude: e.target.value === "exclude" }))}><option value="include">Bao gồm</option><option value="exclude">Loại trừ</option></select>
          <input aria-label="Giá trị lọc" value={filter.value} maxLength={256} onChange={e => setFilter(f => ({ ...f, value: e.target.value }))}/><button className="button button-secondary" disabled={!filter.value.trim() || query.filters.length >= 20} onClick={() => addFilter(filter)}>Thêm điều kiện</button></div>
        <p className="muted">Các giá trị bao gồm cùng trường dùng OR; khác trường dùng AND. Loại trừ bỏ từng giá trị. Bản ghi thiếu trường không khớp điều kiện đó.</p>
        <div className="event-actions"><input aria-label="Tên chế độ xem" placeholder="Tên bộ lọc và cột" maxLength={64} value={viewName} onChange={e => setViewName(e.target.value)}/><button className="button button-ghost" disabled={!viewName.trim()} onClick={saveView}>Lưu chế độ xem</button>
          <select aria-label="Chế độ xem đã lưu" value="" onChange={e => { const view = views.find(v => v.name === e.target.value); if (view) { pause(); setQuery(view.query); setColumns(view.columns); setContext(null); setPage(0); } }}><option value="">Nạp bộ lọc và cột…</option>{views.map(v => <option key={v.name}>{v.name}</option>)}</select>
          <button className="button button-ghost" disabled={!views.length} onClick={() => { try { window.localStorage.removeItem(preferenceKey); setViews([]); } catch { setMessage("Không xóa được lựa chọn trong browser."); } }}>Xóa chế độ xem đã lưu</button></div>
      </details>
      {(query.filters.length > 0 || context !== null) && <div className="event-actions event-filter-chips">{query.filters.map((f, i) => <button className="button button-ghost" key={`${f.field}:${f.value}:${f.exclude}`} onClick={() => changeQuery({ filters: query.filters.filter((_, index) => index !== i) })}>{f.exclude ? "Loại" : "Gồm"} {fieldNames[f.field]}: {f.value} ×</button>)}{context !== null && <button className="button button-ghost" onClick={() => setContext(null)}>±1 phút quanh sự kiện ×</button>}</div>}
      {message && <p role="status" className="muted">{message}</p>}
    </section>
    <section className="panel table-panel"><div className="table-scroll event-table-scroll" ref={table} onScroll={e => { if (e.currentTarget.scrollTop > 0) pause(); }} onWheel={e => { if (e.deltaY > 0) pause(); }}>
      <table className="event-table"><thead><tr><th>Thời gian · UTC+7</th><th>Loại / nguồn</th><th>Sự kiện</th>{columns.map(c => <th key={c}>{columnNames[c]}</th>)}</tr></thead><tbody>
        {rows.map(e => <tr className="clickable-row" key={eventKey(e)} onClick={() => openEvent(e)} onKeyDown={key => { if (key.target === key.currentTarget && ["Enter", " "].includes(key.key)) { key.preventDefault(); openEvent(e); } }} tabIndex={0} aria-label={`Chi tiết ${e.category}`}>
          <td><time dateTime={e.timestamp}>{eventTime(e.timestamp)}</time></td><td><Tag tone={sourceOf(e) === "security" ? "critical" : "blue"}>{e.request ? "request M4" : e.event_class}</Tag><small>{feedNames[sourceOf(e)]}</small></td>
          <td><strong>{safeText(e.category)}</strong><small>{e.detector}{e.signature_id ? ` · SID ${e.signature_id}` : ""}</small></td>
          {columns.map(c => <td key={c}>{c === "tuple" ? <><span>{e.source_ip ? `${e.source_ip}${e.source_port != null ? `:${e.source_port}` : ""}` : "—"}</span><small>→ {e.destination_ip ? `${e.destination_ip}${e.destination_port != null ? `:${e.destination_port}` : ""}` : "—"}</small></> :
            c === "session" ? <span className="mono">{e.request?.id || e.session_id || "—"}</span> : c === "severity" ? sourceOf(e) === "runtime" ? "Không áp dụng" : <Tag tone={e.severity.toLowerCase()}>{e.severity}</Tag> : c === "outcome" ? eventOutcome(e) : e.policy_id || "—"}</td>)}
        </tr>)}
        {!rows.length && <tr><td colSpan={3 + columns.length}><div className="empty-state"><strong>Không có bản ghi phù hợp trong dữ liệu đã tải</strong><p>Xem trạng thái từng nguồn và bộ lọc. Danh sách rỗng không chứng minh mọi lưu lượng an toàn.</p></div></td></tr>}
      </tbody></table>
    </div><div className="event-pagination"><span>{filtered.length ? `${currentPage * EVENT_PAGE_SIZE + 1}–${currentPage * EVENT_PAGE_SIZE + rows.length}` : "0"} / {filtered.length} phù hợp · {monitor.events.length} bản ghi đang giữ trong browser</span><div className="event-actions"><button className="button button-ghost" disabled={currentPage === 0} onClick={() => { pause(); setPage(currentPage - 1); }}>Trang trước</button><button className="button button-ghost" disabled={(currentPage + 1) * EVENT_PAGE_SIZE >= filtered.length} onClick={() => { pause(); setPage(currentPage + 1); }}>Trang sau</button></div></div></section>
    <p className="muted event-retention">Runtime và cảnh báo M3 được giữ theo dung lượng RAM, không có thời hạn cố định. Evidence M4 hiện có TTL tối đa 10 phút và giới hạn dung lượng; có thể bị loại sớm hơn. API M4 chưa báo gap/reset. EVE trên đĩa không phải lịch sử đầy đủ mà web có thể truy vấn.</p>
    {selected && <EventDetails event={selected} onClose={() => setSelected(null)} onFilter={addFilter} onContext={() => { setContext(Date.parse(selected.timestamp)); setQuery(q => ({ ...q, view: "all", minutes: "ALL" })); setPage(0); setSelected(null); }} onBlock={() => onBlock(selected)}/>}
  </div>;
}

export function EventDetails({ event: e, onClose, onFilter, onContext, onBlock }: { event: SecurityEvent; onClose: () => void; onFilter: (filter: EventFilter) => void; onContext: () => void; onBlock: () => Promise<boolean> }) {
  const [busy, setBusy] = useState(false), [session, setSession] = useState<SessionDetail | null>(null), [sessionError, setSessionError] = useState("");
  const controller = useRef<AbortController>();
  const closeButton = useRef<HTMLButtonElement>(null);
  const dialog = useRef<HTMLElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    closeButton.current?.focus();
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape") close.current();
      if (event.key === "Tab") {
        const controls = [...(dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input, select, summary, [tabindex="0"]') ?? [])];
        const first = controls[0], last = controls[controls.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    document.addEventListener("keydown", key);
    return () => { document.removeEventListener("keydown", key); controller.current?.abort(); previous?.focus(); };
  }, []);
  const loadSession = async () => {
    if (!e.session_id || busy) return;
    controller.current?.abort(); controller.current = new AbortController(); setBusy(true); setSessionError("");
    try { setSession(normalizeSessionDetail(await api(`/api/v1/sessions/${encodeURIComponent(e.session_id)}`, { signal: controller.current.signal }))); }
    catch (error) { setSessionError(error instanceof APIError && error.status === 404 ? "Session đã kết thúc hoặc không còn trong bộ nhớ. Sự kiện lịch sử vẫn xem được." : errorMessage(error)); }
    finally { setBusy(false); }
  };
  const block = async () => {
    if (busy || !window.confirm(`Chặn IP nguồn ${e.source_ip} trong 1 giờ? Đây là chặn IP, có thể ảnh hưởng mọi kết nối từ địa chỉ này. Không chỉ chặn packet của sự kiện.`)) return;
    setBusy(true);
    try { if (await onBlock()) onClose(); } finally { setBusy(false); }
  };
  const filterButtons = (field: FilterField, value?: string) => value ? <div className="event-actions"><button className="button button-ghost" onClick={() => onFilter({ field, value, exclude: false })}>Gồm {fieldNames[field]}: {value}</button><button className="button button-ghost" onClick={() => onFilter({ field, value, exclude: true })}>Loại {fieldNames[field]}: {value}</button></div> : null;
  const security = sourceOf(e) === "security";
  return <div className="drawer-layer"><button className="drawer-scrim" aria-label="Đóng chi tiết sự kiện" onClick={onClose}/><aside ref={dialog} className="drawer event-detail-drawer" role="dialog" aria-modal="true" aria-label="Chi tiết sự kiện"><div className="drawer-header"><div><span className="eyebrow">{feedNames[sourceOf(e)]}</span><h2>{safeText(e.category)}</h2></div><button ref={closeButton} className="icon-button" aria-label="Đóng" onClick={onClose}>×</button></div>
    <div className="drawer-body"><p className="muted">Bản ghi đang xem được giữ cố định. Đóng chi tiết rồi bấm Tiếp tục cập nhật để nhận thay đổi.</p>
      <Section title="Nguồn sự kiện"><Pair label="Thời gian" value={eventTime(e.timestamp)}/><Pair label="Loại" value={e.event_class}/><Pair label="Producer" value={e.detector}/><Pair label="Event ID" value={e.event_id}/><Pair label="Session ID" value={e.session_id}/><Pair label="Policy" value={e.policy_id}/></Section>
      {security && <><Section title="Phát hiện Suricata"><Pair label="Capture mode" value={e.capture_mode || "Chưa có dữ liệu nguồn"}/><Pair label="Signature ID" value={e.signature_id}/><Pair label="Severity" value={e.severity}/><Pair label="Correlation" value={e.correlation_state}/><Pair label="App được nhận diện" value={e.application}/></Section>
        <Section title="Verdict và phạm vi enforcement"><Pair label="Alert verdict" value={e.verdict || "UNKNOWN"}/><Pair label="Packet verdict" value={e.packet_verdict || "Chưa được nguồn báo cáo"}/><Pair label="Mechanism" value={e.enforcement?.mechanism}/><Pair label="Scope" value={e.enforcement?.scope}/><Pair label="Status" value={e.enforcement?.status || "Chưa có enforcement evidence"}/><p className="muted">IDS cảnh báo không tự chặn. DROP / PACKET / REPORTED là sensor báo drop packet; không chứng minh cả session hoặc IP đã bị chặn. UI không thay thế PCAP và origin log.</p></Section></>}
      {e.request && <><Section title="Request M4"><Pair label="Request ID" value={e.request.id}/><Pair label="Connection ID" value={e.request.connection_id}/><Pair label="Scheme" value={e.request.scheme}/><Pair label="Method" value={e.request.method}/><Pair label="Path (đã bỏ query)" value={e.request.path}/><Pair label="Coverage" value={e.request.coverage}/><Pair label="Inspection completed" value={e.request.completed ? "Có" : "Chưa hoàn tất"}/><Pair label="Inspection error" value={e.request.error_code}/><Pair label="Signature ID" value={e.signature_id}/></Section>
        <Section title="Quyết định và kết quả forward"><Pair label="Decision" value={e.verdict}/><Pair label="Reason code" value={e.request.reason_code}/><Pair label="HTTP status của decision" value={e.request.http_status}/><Pair label="Forward result" value={e.request.forward?.reason_code || "Chưa có kết quả forward trong evidence"}/><Pair label="HTTP status upstream" value={e.request.forward?.http_status}/><Pair label="Forward observed" value={e.request.forward?.observed_at ? eventTime(e.request.forward.observed_at) : undefined}/><p className="muted">ALLOW là quyết định cho phép request, không đồng nghĩa origin đã nhận hoặc trả 200. BLOCK có phạm vi request. Evidence này không cung cấp TLS mode/chứng chỉ để tự kết luận DECRYPT hay BYPASS.</p></Section></>}
      {sourceOf(e) === "runtime" && <Section title="Thông báo runtime / policy"><Pair label="Kind" value={text(e.metadata?.kind) || e.category}/><Pair label="Reason" value={e.evidence}/><p className="muted">Đây là thông báo trạng thái của engine. SessionUpdated không phải một cuộc tấn công hoặc một kết nối mới. Một notification SecurityAlert/RequestGateDecision dẫn tới evidence ở nguồn M3/M4 tương ứng.</p></Section>}
      {(e.source_ip || e.destination_ip) && <Section title="Tuple được nguồn ghi nhận"><Pair label="Source" value={e.source_ip ? `${e.source_ip}${e.source_port != null ? `:${e.source_port}` : ""}` : undefined}/><Pair label="Destination" value={e.destination_ip ? `${e.destination_ip}${e.destination_port != null ? `:${e.destination_port}` : ""}` : undefined}/>{filterButtons("source_ip", e.source_ip)}{filterButtons("destination_ip", e.destination_ip)}</Section>}
      {e.evidence && sourceOf(e) !== "runtime" && <Section title="Lý do"><p className="evidence">{safeText(e.evidence)}</p></Section>}
      <Section title="Điều tra liên quan">{filterButtons("session_id", e.session_id)}{filterButtons("signature_id", e.signature_id)}<div className="event-actions"><button className="button button-ghost" disabled={!e.timestamp || Number.isNaN(Date.parse(e.timestamp))} onClick={onContext}>Xem dữ liệu đã tải ±1 phút</button>{e.session_id && <button className="button button-ghost" disabled={busy} onClick={() => void loadSession()}>Đọc session hiện tại</button>}</div>
        {sessionError && <p role="status">{sessionError}</p>}{session && <><p className="muted">Đây là trạng thái hiện tại; không phải snapshot tại thời điểm event.</p><Pair label="Client" value={`${session.session.client_ip}:${session.session.client_port}`}/><Pair label="Server" value={`${session.session.server_ip}:${session.session.server_port}`}/><Pair label="State hiện tại" value={session.session.tcp_state}/><Pair label="Zones" value={`${session.session.source_zone} → ${session.session.destination_zone}`}/></>}
      </Section>
      <details><summary>Metadata chẩn đoán</summary><Pair label="Sequence" value={e.sequence}/><Pair label="Stream" value={e.stream_id}/><Pair label="Revision" value={e.revision}/><Pair label="Generation" value={text(String(e.metadata?.generation ?? ""))}/><Pair label="Sensor" value={text(e.metadata?.sensor_id)}/><Pair label="Ruleset" value={text(e.metadata?.ruleset_id)}/><Pair label="Suricata flow ID" value={e.flow_id}/></details>
    </div>
    {security && e.source_ip && <div className="drawer-footer"><button className="button button-danger" disabled={busy} onClick={() => void block()}>Chặn IP nguồn trong 1 giờ</button></div>}
  </aside></div>;
}
