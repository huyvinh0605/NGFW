import { useId } from "react";
import { normalizeService, parseService } from "./policy";

export type ServiceEntry = {
  key: number;
  protocol: "tcp" | "udp" | "icmp" | "icmpv6";
  kind: "port" | "range" | "all";
  first: string;
  last: string;
  original?: string;
  opaque?: boolean;
};

export function serviceEntries(values: string[]): ServiceEntry[] {
  return values.map((original, key) => {
    try {
      const parsed = parseService(original);
      return { key, original, protocol: parsed.protocol,
        kind: parsed.first === 1 && parsed.last === 65535 ? "all" : parsed.first !== parsed.last ? "range" : "port",
        first: parsed.first == null ? "" : String(parsed.first), last: parsed.last == null ? "" : String(parsed.last) };
    } catch {
      return { key, original, opaque: true, protocol: "tcp", kind: "port", first: "", last: "" };
    }
  });
}

export function serializeServices(entries: ServiceEntry[]): string[] {
  return entries.map((entry, index) => {
    // Keep untouched legacy/future selectors byte-for-byte. The backend still
    // validates them; opening another field must not broaden an existing rule.
    if (entry.original !== undefined) return entry.original;
    if (entry.protocol === "icmp" || entry.protocol === "icmpv6") return entry.protocol;
    if (entry.kind === "all") return `${entry.protocol}:1-65535`;
    const first = Number(entry.first), last = Number(entry.last);
    if (!/^\d+$/.test(entry.first) || first < 1 || first > 65535) {
      throw new Error(`Dịch vụ ${index + 1}: nhập cổng đích từ 1 đến 65535.`);
    }
    if (entry.kind === "range" && (!/^\d+$/.test(entry.last) || last < first || last > 65535)) {
      throw new Error(`Dịch vụ ${index + 1}: cổng cuối phải từ ${first} đến 65535.`);
    }
    return normalizeService(`${entry.protocol}:${entry.first}${entry.kind === "range" ? `-${entry.last}` : ""}`);
  });
}

export function ZonePicker({ title, field, zones, selected, multiple, onMultiple, onChange }: {
  title: string; field: "source" | "destination"; zones: string[]; selected: string[];
  multiple: boolean; onMultiple: (value: boolean) => void; onChange: (value: string[]) => void;
}) {
  const id = useId();
  const label = field === "source" ? "nguồn" : "đích";
  const options = [...new Set([...zones, ...selected])];
  const awaitingSingle = !multiple && selected.length > 1;
  return <fieldset className="zone-picker">
    <legend>{title}</legend>
    <div className="choice-grid zone-options" role="group" aria-label={title} aria-describedby={id}>
      {options.map((zone) => <label className="choice" key={zone}>
        <input type={multiple ? "checkbox" : "radio"} name={id} aria-label={`Vùng ${label} ${zone.toUpperCase()}`} checked={!awaitingSingle && selected.includes(zone)} disabled={!zones.includes(zone)} onChange={() => onChange(multiple ? selected.includes(zone) ? selected.filter((item) => item !== zone) : [...selected, zone] : [zone])}/>
        <span>{zone}{!zones.includes(zone) ? " (đang giữ)" : ""}</span>
      </label>)}
    </div>
    <small className="zone-options-help" id={id}>
      <label className="zone-any"><input type={multiple ? "checkbox" : "radio"} name={id} checked={!selected.length} aria-label={`Bất kỳ vùng ${label}`} onChange={() => onChange([])}/><span>Không chọn = any zone</span></label>
      <label className="zone-multiple"><input type="checkbox" aria-label={`Chọn nhiều vùng ${label}`} checked={multiple} onChange={(event) => onMultiple(event.target.checked)}/><span>Chọn nhiều vùng</span></label>
    </small>
    {awaitingSingle && <small>Đang giữ {selected.join(", ")}. Chọn một vùng hoặc Bất kỳ để thay thế.</small>}
  </fieldset>;
}

const presets = [
  { name: "HTTP", service: "tcp:80" }, { name: "HTTPS", service: "tcp:443" },
  { name: "DNS (UDP)", service: "udp:53" }, { name: "DNS (TCP)", service: "tcp:53" },
  { name: "SSH", service: "tcp:22" },
];

export function ServicePicker({ entries, onChange, nextKey, error }: {
  entries: ServiceEntry[]; onChange: (value: ServiceEntry[]) => void; nextKey: () => number; error: string;
}) {
  const id = useId();
  function update(key: number, patch: Partial<ServiceEntry>) {
    onChange(entries.map((entry) => entry.key === key ? { ...entry, ...patch, original: undefined } : entry));
  }
  function addPreset(service: string) {
    if (entries.some((entry) => {
      try { return normalizeService(serializeServices([entry])[0]) === service; } catch { return false; }
    })) return;
    onChange([...entries, { ...serviceEntries([service])[0], key: nextKey() }]);
  }
  return <div className="policy-input-group service-picker" aria-describedby={id}>
    <span>Services</span><small id={id}>Chọn giao thức và cổng đích. Có thể thêm nhiều dịch vụ.</small>
    <div className="service-toolbar"><div className="service-presets" role="group" aria-label="Dịch vụ thường dùng">{presets.map((item) => <button type="button" key={item.service} onClick={() => addPreset(item.service)}>{item.name}</button>)}</div><button type="button" className="service-add" onClick={() => onChange([...entries, { key: nextKey(), protocol: "tcp", kind: "port", first: "", last: "" }])}>+ Thêm dịch vụ</button></div>
    {!entries.length && <p className="selection-summary">Không giới hạn dịch vụ — mọi giao thức và cổng.</p>}
    <div className="service-entries">{entries.map((entry, index) => <div className="service-entry" key={entry.key}>
      {entry.opaque ? <div className="service-legacy"><code>{entry.original}</code><small>Giữ nguyên dịch vụ đã có; dùng JSON nếu cần sửa giá trị này.</small></div> : <>
        <label className="service-protocol">Giao thức<select aria-label={`Giao thức dịch vụ ${index + 1}`} value={entry.protocol} onChange={(event) => update(entry.key, { protocol: event.target.value as ServiceEntry["protocol"] })}><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option></select></label>
        {entry.protocol === "tcp" || entry.protocol === "udp" ? <>
          <label className="service-kind">Loại cổng<select aria-label={`Loại cổng dịch vụ ${index + 1}`} value={entry.kind} onChange={(event) => update(entry.key, { kind: event.target.value as ServiceEntry["kind"] })}><option value="port">Một cổng</option><option value="range">Khoảng cổng</option><option value="all">Mọi cổng</option></select></label>
          {entry.kind !== "all" && <label className="service-port">{entry.kind === "range" ? "Từ cổng" : "Cổng đích"}<input aria-label={`Cổng đích dịch vụ ${index + 1}`} type="number" inputMode="numeric" min="1" max="65535" step="1" required value={entry.first} onChange={(event) => update(entry.key, { first: event.target.value })}/></label>}
          {entry.kind === "range" && <label className="service-end">Đến cổng<input aria-label={`Cổng cuối dịch vụ ${index + 1}`} type="number" inputMode="numeric" min={Number(entry.first) || 1} max="65535" step="1" required value={entry.last} onChange={(event) => update(entry.key, { last: event.target.value })}/></label>}
        </> : <span className="service-no-port">Giao thức này không dùng cổng.</span>}
      </>}
      <button type="button" className="service-remove" aria-label={`Xóa dịch vụ ${index + 1}`} onClick={() => onChange(entries.filter((item) => item.key !== entry.key))}>Xóa</button>
    </div>)}</div>
    {error && <small className="field-error" role="alert">{error}</small>}
  </div>;
}

export function ApplicationPicker({ applications, supported, available, canRestrict, onChange, error }: {
  applications: string[]; supported: string[]; available: boolean; canRestrict: boolean;
  onChange: (value: string[]) => void; error: string;
}) {
  const id = useId();
  const options = [...new Set([...supported, ...applications])];
  return <div className="policy-input-group application-picker" aria-describedby={id}>
    <div className="policy-field-heading"><span>Applications</span><button type="button" className="selection-any" aria-pressed={!applications.length} onClick={() => onChange([])}>Không giới hạn ứng dụng</button></div>
    <small id={id}>{!available ? "Chưa đọc được danh sách ứng dụng hỗ trợ. Các lựa chọn đã có được giữ nguyên." : !canRestrict ? "Chọn Action ALLOW và security profile IPS để giới hạn ứng dụng." : "Cho phép các ứng dụng đã chọn sau khi nhận diện. UNKNOWN vẫn theo cơ chế fail-open của M3."}</small>
    <div className="choice-grid application-options" role="group" aria-label="Ứng dụng được phép">{options.map((app) => <label className="choice" key={app}>
      <input type="checkbox" aria-label={`Ứng dụng ${app}`} checked={applications.includes(app)} disabled={!available || !canRestrict || !supported.includes(app)} onChange={() => onChange(applications.includes(app) ? applications.filter((item) => item !== app) : [...applications, app])}/>
      <span>{app}{!supported.includes(app) ? " (đang giữ)" : ""}</span>
    </label>)}</div>
    {error && <small className="field-error" role="alert">{error}</small>}
  </div>;
}
