import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { act, create, type ReactTestInstance } from "react-test-renderer";
import { defaultQuery, eventKey, eventTypeOf, filterEvents, relatedEvents, type ViewerQuery } from "../src/eventData.ts";
import { columnFilter, columnText, defaultColumns, moveColumn, orderedColumns, validColumns } from "../src/eventColumns.ts";
import { EventsPanel } from "../src/eventViewer.tsx";
import { fromTimeInput, toTimeInput } from "../src/eventTools.tsx";
import type { SecurityEvent } from "../src/types.ts";
import type { EventMonitor } from "../src/useEventFeed.ts";

const at = "2026-11-09T08:00:00Z";
const e = (id: string, patch: Partial<SecurityEvent> = {}): SecurityEvent => ({ event_id: id, timestamp: at, event_class: "security", feed: "security", detector: "SURICATA", severity: "HIGH", confidence: 0, category: "Alert", ...patch });
const content = (node: ReactTestInstance): string => node.children.map(c => typeof c === "string" ? c : content(c)).join("");

test("fixed, sliding and expanding windows use inclusive boundaries and pause-time cutoffs", () => {
  const events = [-60001, -60000, 0, 5000, 5001].map((offset, i) => e(String(i), { timestamp: new Date(Date.parse(at) + offset).toISOString() }));
  const q: ViewerQuery = { ...defaultQuery, time: { mode: "fixed", start: events[1].timestamp, end: events[3].timestamp } };
  assert.deepEqual(filterEvents(events, q, Date.parse(at)).map(x => x.event_id), ["1", "2", "3"]);
  assert.deepEqual(filterEvents(events, { ...q, time: { mode: "expanding", start: events[1].timestamp } }, Date.parse(at)).map(x => x.event_id), ["1", "2"]);
  assert.deepEqual(filterEvents(events, { ...defaultQuery, minutes: "5" }, Date.parse(at)).map(x => x.event_id), ["0", "1", "2"]);
  assert.equal(filterEvents(events, { ...q, time: { mode: "fixed", start: at, end: events[0].timestamp } }, Date.parse(at)).length, 0);
  assert.equal(fromTimeInput("2026-11-09T15:00:00"), at.replace("00Z", "00.000Z"));
  assert.equal(toTimeInput(at), "2026-11-09T15:00:00");
  assert.equal(fromTimeInput(""), "");
});

test("associations use explicit session, request or event references, never tuple coincidence", () => {
  const alert = e("alert", { session_id: "sess-A", source_ip: "192.0.2.1" });
  const rows = [alert, e("lifecycle", { feed: "runtime", session_id: "sess-A", category: "SessionClosed" }),
    e("reference", { feed: "runtime", metadata: { related_event_id: "alert" } }),
    e("unrelated", { session_id: "sess-B", source_ip: "192.0.2.1" }), e("other-feed-same-id", { metadata: { related_event_id: "alert" } })];
  assert.deepEqual(relatedEvents(alert, rows).map(x => x.event_id), ["lifecycle", "reference"]);
  const first = e("first", { feed: "request", request: { id: "r1", connection_id: "c1", method: "GET", scheme: "https", path: "/", coverage: "COMPLETE", completed: true, error_code: "", reason_code: "" } });
  assert.equal(relatedEvents(first, [first, { ...first, event_id: "second" }, { ...first, event_id: "third", request: { ...first.request!, id: "r2" } }]).length, 1);
  assert.equal(eventTypeOf(e("runtime", { feed: "runtime", event_class: "runtime", category: "SessionUpdated" })), "connection");
  assert.equal(eventTypeOf(e("policy", { feed: "runtime", event_class: "policy" })), "policy");
});

test("numeric ports, application and event types participate in typed filters with existing OR/AND rules", () => {
  const events = [e("a", { destination_port: 443, source_port: 0, application: "TLS" }), e("b", { destination_port: 80, application: "HTTP" }), e("missing")];
  assert.deepEqual(filterEvents(events, { ...defaultQuery, filters: [{ field: "destination_port", value: "443", exclude: false }, { field: "application", value: "TLS", exclude: false }] }, Date.parse(at)).map(x => x.event_id), ["a"]);
  assert.deepEqual(columnFilter(events[0], "source_port"), { field: "source_port", value: "0" });
  assert.equal(columnText(events[0], "source_port"), "0");
  assert.equal(columnText(events[2], "application"), "—");
  assert.equal(columnFilter(events[2], "capture"), undefined);
});

test("column order, pinning and persisted width constraints reject duplicate or malformed layouts", () => {
  assert.equal(validColumns(defaultColumns), true);
  assert.equal(validColumns([...defaultColumns, defaultColumns[0]]), false);
  assert.equal(validColumns([{ ...defaultColumns[0], width: 100000 }]), false);
  const moved = moveColumn(defaultColumns, "tuple", "summary");
  assert.deepEqual(moved.map(c => c.id), ["time", "type", "tuple", "summary", "capture", "severity", "outcome", "policy"]);
  assert.deepEqual(orderedColumns([{ id: "summary", width: 200, pin: "right" }, { id: "time", width: 150, pin: "left" }]).map(c => c.id), ["time", "summary"]);
});

test("legacy saved views migrate, new column sets and time windows reload without losing named searches", async () => {
  const oldWindow = globalThis.window;
  const store = new Map<string, string>();
  store.set("ngfw.events.views.v1", JSON.stringify([{ name: "Legacy", query: defaultQuery, columns: ["tuple", "session"] }]));
  globalThis.window = { localStorage: { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v), removeItem: (k: string) => store.delete(k) } } as unknown as Window & typeof globalThis;
  const monitor: EventMonitor = { events: [e("one")], sources: { runtime: {}, security: {}, request: {} }, loading: false, refresh: async () => {} };
  let panel!: ReturnType<typeof create>;
  try {
    await act(async () => { panel = create(<EventsPanel monitor={monitor} onBlock={async () => true}/>); });
    const select = (label: string) => panel.root.findByProps({ "aria-label": label });
    const button = (label: string) => panel.root.findAllByType("button").find(b => content(b) === label)!;
    await act(async () => select("Chế độ xem đã lưu").props.onChange({ target: { value: "Legacy" } }));
    assert.deepEqual(panel.root.findAllByType("th").map(th => th.props["data-column"]), ["time", "type", "summary", "tuple", "session"]);
    await act(async () => select("Tên bộ cột").props.onChange({ target: { value: "Forensics" } }));
    await act(async () => button("Lưu bộ cột").props.onClick());
    assert.equal(JSON.parse(store.get("ngfw.events.columns.v1")!)[0].name, "Forensics");
    assert.ok(store.get("ngfw.events.views.v1")?.includes("Legacy"));
    assert.ok(panel.root.findAllByType("tr").some(row => row.props["aria-label"] === "Chi tiết Alert"));
    assert.equal(eventKey(monitor.events[0]), "security::one");
  } finally { if (panel) panel.unmount(); globalThis.window = oldWindow; }
});
