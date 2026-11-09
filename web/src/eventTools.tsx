import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { columnDefinitions, defaultColumns, moveColumn, orderedColumns, type Column, type ColumnSetting } from "./eventColumns";
import { fieldNames, validTimeWindow, type EventFilter, type EventTimeWindow } from "./eventData";

export function ColumnPicker({ columns, onChange }: { columns: ColumnSetting[]; onChange: (columns: ColumnSetting[]) => void }) {
  const [search, setSearch] = useState("");
  const visible = orderedColumns(columns);
  return <div className="event-column-picker">
    <input aria-label="Tìm cột hiển thị" placeholder="Tìm cột: IP, policy, IDS…" maxLength={64} value={search} onChange={e => setSearch(e.target.value)}/>
    <div className="event-column-list">{(Object.keys(columnDefinitions) as Column[]).filter(id => `${columnDefinitions[id].label} ${columnDefinitions[id].source}`.toLocaleLowerCase("vi").includes(search.toLocaleLowerCase("vi"))).map(id => {
      const def = columnDefinitions[id], current = columns.find(c => c.id === id), index = visible.findIndex(c => c.id === id);
      return <div className="event-column-option" key={id}>
        <label><input type="checkbox" checked={Boolean(current)} disabled={Boolean(current && columns.length === 1)} onChange={e => onChange(e.target.checked ? [...columns, { id, width: def.width, pin: "none" }] : columns.filter(c => c.id !== id))}/><span>{def.label}<small>{def.source}</small></span></label>
        {current && <div className="event-column-adjust"><button type="button" className="icon-button" aria-label={`Đưa ${def.label} sang trái`} disabled={index === 0} onClick={() => onChange(moveColumn(visible, id, visible[index - 1].id))}>←</button><button type="button" className="icon-button" aria-label={`Đưa ${def.label} sang phải`} disabled={index === visible.length - 1} onClick={() => onChange(moveColumn(visible, id, visible[index + 1].id))}>→</button>
          <select aria-label={`Ghim ${def.label}`} value={current.pin} onChange={e => onChange(columns.map(c => c.id === id ? { ...c, pin: e.target.value as ColumnSetting["pin"] } : c))}><option value="none">Không ghim</option><option value="left">Ghim trái</option><option value="right">Ghim phải</option></select></div>}
      </div>;
    })}</div>
    <button className="button button-ghost" onClick={() => onChange(defaultColumns)}>Cột mặc định</button>
  </div>;
}

export function ColumnHeader({ column, style, onResize, onMove }: { column: ColumnSetting; style: CSSProperties; onResize: (width: number) => void; onMove: (from: Column, to: Column) => void }) {
  const resizing = useRef<{ x: number; width: number } | null>(null);
  return <th style={style} data-column={column.id} className={column.pin !== "none" ? "event-pinned" : undefined} draggable
    onDragStart={e => { if (resizing.current) { e.preventDefault(); return; } e.dataTransfer.setData("text/ngfw-event-column", column.id); e.dataTransfer.effectAllowed = "move"; }}
    onDragOver={e => { if (e.dataTransfer.types.includes("text/ngfw-event-column")) e.preventDefault(); }}
    onDrop={e => { e.preventDefault(); onMove(e.dataTransfer.getData("text/ngfw-event-column") as Column, column.id); }}>
    {columnDefinitions[column.id].label}
    <span role="separator" aria-label={`Độ rộng ${columnDefinitions[column.id].label}`} aria-orientation="vertical" aria-valuenow={column.width} aria-valuemin={80} aria-valuemax={600} tabIndex={0} className="event-column-resize"
      onPointerDown={e => { if (e.button !== 0) return; e.preventDefault(); e.stopPropagation(); resizing.current = { x: e.clientX, width: column.width }; e.currentTarget.setPointerCapture(e.pointerId); }}
      onPointerMove={e => { if (resizing.current) onResize(Math.max(80, Math.min(600, resizing.current.width + e.clientX - resizing.current.x))); }}
      onPointerUp={e => { resizing.current = null; if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId); }}
      onLostPointerCapture={() => { resizing.current = null; }}
      onKeyDown={e => { if (["ArrowLeft", "ArrowRight"].includes(e.key)) { e.preventDefault(); onResize(Math.max(80, Math.min(600, column.width + (e.key === "ArrowLeft" ? -10 : 10)))); } }}/>
  </th>;
}

export function toTimeInput(iso: string): string { const n = Date.parse(iso); return Number.isFinite(n) ? new Date(n + 7 * 3600000).toISOString().slice(0, 19) : ""; }
export function fromTimeInput(value: string): string { const n = Date.parse(`${value}+07:00`); return Number.isFinite(n) ? new Date(n).toISOString() : ""; }
export function TimeWindowPicker({ value, onApply }: { value?: EventTimeWindow; onApply: (value: EventTimeWindow | undefined) => void }) {
  const [mode, setMode] = useState<EventTimeWindow["mode"]>(value?.mode ?? "fixed");
  const [start, setStart] = useState(toTimeInput(value?.start ?? new Date(Date.now() - 3600000).toISOString()));
  const [end, setEnd] = useState(toTimeInput(value?.end ?? new Date().toISOString()));
  const [error, setError] = useState("");
  useEffect(() => { if (value) { setMode(value.mode); setStart(toTimeInput(value.start)); if (value.end) setEnd(toTimeInput(value.end)); } }, [value]);
  const apply = () => {
    const next: EventTimeWindow = { mode, start: fromTimeInput(start), ...(mode === "fixed" ? { end: fromTimeInput(end) } : {}) };
    if (!validTimeWindow(next)) { setError("Chọn thời gian hợp lệ; mốc kết thúc phải từ mốc bắt đầu trở đi."); return; }
    setError(""); onApply(next);
  };
  return <div className="event-time-picker"><div className="event-actions">
    <label>Kiểu khoảng thời gian<select aria-label="Kiểu khoảng thời gian" value={mode} onChange={e => setMode(e.target.value as EventTimeWindow["mode"])}><option value="fixed">Cố định từ / đến</option><option value="expanding">Từ mốc chọn đến hiện tại</option></select></label>
    <label>Từ · UTC+7<input type="datetime-local" step="1" aria-label="Thời gian bắt đầu UTC+7" value={start} onChange={e => setStart(e.target.value)}/></label>
    {mode === "fixed" && <label>Đến · UTC+7<input type="datetime-local" step="1" aria-label="Thời gian kết thúc UTC+7" value={end} onChange={e => setEnd(e.target.value)}/></label>}
    <button className="button button-secondary" onClick={apply}>Áp dụng thời gian</button><button className="button button-ghost" disabled={!value} onClick={() => { setError(""); onApply(undefined); }}>Bỏ khoảng tùy chọn</button>
  </div>{error && <p role="alert" className="field-error">{error}</p>}</div>;
}

export type CellMenuState = { filters: { field: EventFilter["field"]; value: string }[]; timestamp?: string; left: number; top: number; trigger: HTMLElement };
export function CellMenu({ menu, onClose, onFilter, onContext }: { menu: CellMenuState; onClose: () => void; onFilter: (filter: EventFilter) => void; onContext: (seconds: number) => void }) {
  const root = useRef<HTMLDivElement>(null);
  const close = useRef(onClose); close.current = onClose;
  useEffect(() => {
    root.current?.querySelector<HTMLButtonElement>("button")?.focus();
    const dismiss = (e: Event) => { if (!root.current?.contains(e.target as Node) && !menu.trigger.contains(e.target as Node)) close.current(); };
    const escape = (e: KeyboardEvent) => { if (e.key === "Escape") { close.current(); menu.trigger.focus(); } };
    const resize = () => close.current();
    document.addEventListener("pointerdown", dismiss); document.addEventListener("keydown", escape); window.addEventListener("resize", resize);
    return () => { document.removeEventListener("pointerdown", dismiss); document.removeEventListener("keydown", escape); window.removeEventListener("resize", resize); };
  }, [menu]);
  return createPortal(<div className="event-cell-menu" role="menu" aria-label="Thao tác ô sự kiện" ref={root}
    style={{ left: Math.max(8, Math.min(menu.left, window.innerWidth - 258)), top: Math.max(8, Math.min(menu.top, window.innerHeight - (menu.filters.length * 64 + 95))) }}
    onKeyDown={e => { const buttons = Array.from(root.current?.querySelectorAll<HTMLButtonElement>("button") ?? []), at = buttons.indexOf(document.activeElement as HTMLButtonElement); if (["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) { e.preventDefault(); buttons[e.key === "Home" ? 0 : e.key === "End" ? buttons.length - 1 : (at + (e.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length]?.focus(); } }}>
    {menu.filters.map(f => <div key={f.field}><span>{fieldNames[f.field]}: {f.value}</span><button role="menuitem" onClick={() => { onFilter({ ...f, exclude: false }); onClose(); }}>Bao gồm giá trị này</button><button role="menuitem" onClick={() => { onFilter({ ...f, exclude: true }); onClose(); }}>Loại trừ giá trị này</button></div>)}
    {menu.timestamp && <div><span>Bối cảnh quanh sự kiện</span><button role="menuitem" onClick={() => { onContext(5); onClose(); }}>Xem trước / sau 5 giây</button><button role="menuitem" onClick={() => { onContext(60); onClose(); }}>Xem trước / sau 1 phút</button></div>}
  </div>, document.body);
}

export function EventCell({ children, label, onMenu }: { children: ReactNode; label: string; onMenu?: (anchor: HTMLElement) => void }) {
  return <div className="event-cell"><div className="event-cell-value">{children}</div>{onMenu && <button className="event-cell-more" aria-label={`Thao tác ${label}`} aria-haspopup="menu" onClick={e => { e.stopPropagation(); onMenu(e.currentTarget); }}>⋯</button>}</div>;
}
