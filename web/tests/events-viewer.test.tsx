import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { act, create, type ReactTestInstance } from "react-test-renderer";
import { renderToStaticMarkup } from "react-dom/server";
import { defaultQuery, eventCSV, eventKey, eventOutcome, FEED_LIMIT, filterEvents, mergeEvents, needsAttention, requestPage, runtimePage, sequence } from "../src/eventData.ts";
import { EventDetails, EventsPanel } from "../src/eventViewer.tsx";
import { normalizeThreatEvent } from "../src/inspectionData.ts";
import type { SecurityEvent } from "../src/types.ts";
import type { EventMonitor } from "../src/useEventFeed.ts";

const at = "2026-11-07T04:00:00Z";
function event(id: string, patch: Partial<SecurityEvent> = {}): SecurityEvent {
  return { event_id: id, timestamp: at, event_class: "security", feed: "security", detector: "SURICATA", severity: "LOW", confidence: 0, category: "Test alert", ...patch };
}
function content(node: ReactTestInstance): string { return node.children.map(c => typeof c === "string" ? c : content(c)).join(""); }

test("runtime pagination advances only to the delivered row, retaining exact decimal identifiers", () => {
  const page = runtimePage({ stream_id: "A", next_sequence: "18446744073709551615", items: [
    { kind: "SecurityAlert", sequence: "9007199254740993", event_id: "same-reference", timestamp: at },
    { kind: "SecurityEventUpdated", sequence: "9007199254740994", event_id: "same-reference", timestamp: at },
  ] });
  assert.equal(page.last, "9007199254740994"); assert.equal(page.hasMore, true);
  assert.notEqual(eventKey(page.items[0]), eventKey(page.items[1]));
  assert.equal(page.items[0].metadata?.related_event_id, "same-reference");
  assert.throws(() => sequence(9007199254740993), /độ chính xác/);
});

test("upsert keeps newer correlation evidence, isolates sources and bounds each cache", () => {
  const old = event("same", { revision: 1 }), updated = event("same", { revision: 2, session_id: "correlated" });
  const runtime = event("same", { feed: "runtime", sequence: "1", event_class: "runtime" });
  let merged = mergeEvents([old, runtime], [updated]);
  merged = mergeEvents(merged, [old]);
  assert.equal(merged.length, 2); assert.equal(merged.find(e => e.feed === "security")?.session_id, "correlated");
  merged = mergeEvents(merged, Array.from({ length: 1200 }, (_, i) => event(String(i), { feed: "runtime", sequence: String(i), event_class: "runtime" })));
  assert.equal(merged.filter(e => e.feed === "runtime").length, FEED_LIMIT);
  assert.equal(merged.filter(e => e.feed === "security").length, 1);
  assert.equal(mergeEvents(merged, [], "runtime").length, 1);
});

test("M4 decision and later forward annotation upsert one request without copying payload or query", () => {
  const input = { event_id: "decision-1", sequence: 1, observed_at: at, context: { request_id: "req-1", method: "GET", scheme: "https", path: "/search?token=SECRET", body: "PRIVATE", headers: { Authorization: "Bearer PRIVATE" } },
    inspection: { coverage: "COMPLETE", completed: true }, decision: { verdict: "ALLOW", reason_code: "INSPECTION_ALLOW" } };
  const first = requestPage({ items: [input], next_sequence: 1 }).items[0];
  const second = requestPage({ items: [{ ...input, sequence: 2, forward: { http_status: 502, reason_code: "TLS_UPSTREAM_VERIFY_FAILED", observed_at: at } }], next_sequence: 2 }).items[0];
  assert.equal(first.request?.forward, undefined); assert.equal(needsAttention(first), false);
  assert.equal(needsAttention(second), true); assert.equal(second.verdict, "ALLOW");
  const merged = mergeEvents([second], [first]); assert.equal(merged.length, 1);
  assert.equal(merged[0].request?.forward?.http_status, 502);
  assert.doesNotMatch(JSON.stringify(merged), /SECRET|PRIVATE|Authorization|headers/);
});

test("default view retains LOW detections and protection changes, excludes routine lifecycle noise", () => {
  const rows = [event("low"), event("life", { feed: "runtime", event_class: "runtime", category: "SessionUpdated" }),
    event("health", { feed: "runtime", event_class: "inspection", category: "InspectionHealthChanged" })];
  assert.deepEqual(filterEvents(rows, defaultQuery, Date.parse(at)).map(e => e.event_id), ["low", "health"]);
});

test("typed include/exclude filters implement OR within a field and AND across fields, with explicit missing values", () => {
  const rows = [event("a", { source_ip: "10.0.0.1", destination_ip: "10.1.0.1" }), event("b", { source_ip: "10.0.0.2", destination_ip: "10.1.0.1" }),
    event("c", { source_ip: "10.0.0.3", destination_ip: "10.1.0.1" }), event("unknown"), event("bad-time", { timestamp: "invalid" })];
  const query = { ...defaultQuery, filters: [
    { field: "source_ip" as const, value: "10.0.0.1", exclude: false }, { field: "source_ip" as const, value: "10.0.0.2", exclude: false },
    { field: "destination_ip" as const, value: "10.1.0.1", exclude: false }, { field: "source_ip" as const, value: "10.0.0.2", exclude: true },
  ] };
  assert.deepEqual(filterEvents(rows, query, Date.parse(at)).map(e => e.event_id), ["a"]);
  assert.deepEqual(filterEvents(rows, { ...defaultQuery, minutes: "5" }, Date.parse(at)).map(e => e.event_id), ["a", "b", "c", "unknown"]);
  assert.equal(filterEvents([event("missing")], { ...defaultQuery, filters: [{ field: "source_ip", value: "10.0.0.1", exclude: true }] }, Date.parse(at)).length, 0);
});

test("CSV contains the selected records only, escapes formulas and quotes, and excludes metadata credentials", () => {
  const csv = eventCSV([event("a", { category: '=HYPERLINK("evil")', evidence: "Bearer DO-NOT-EXPORT", metadata: { password: "PRIVATE" } }), event("b", { category: "Bearer SECRET" })]);
  assert.match(csv, /'\=HYPERLINK\(""evil""\)/);
  assert.doesNotMatch(csv, /PRIVATE|SECRET|DO-NOT-EXPORT/);
  assert.match(csv, /đã ẩn/);
});

test("drawer content follows its source; packet DROP never advertises a session/IP block", () => {
  const props = { onClose() {}, onFilter() {}, onContext() {}, onBlock: async () => true };
  const runtime = renderToStaticMarkup(<EventDetails event={event("1", { feed: "runtime", event_class: "runtime", category: "SessionUpdated" })} {...props}/>);
  assert.doesNotMatch(runtime, /Capture mode|Packet verdict|Signature ID|NOT_REQUESTED/);
  const missing = normalizeThreatEvent({ event_id: "missing" })!;
  assert.equal(missing.enforcement, undefined);
  const drop = event("drop", { verdict: "DROP", capture_mode: "IPS", enforcement: { mechanism: "SURICATA_NFQUEUE", scope: "PACKET", status: "REPORTED" } });
  assert.equal(eventOutcome(drop), "DROP · PACKET / REPORTED");
  const markup = renderToStaticMarkup(<EventDetails event={drop} {...props}/>);
  assert.match(markup, /không chứng minh cả session/);
});

test("pausing freezes visible records while ingestion continues, then resumes with the updated row", async () => {
  const base: EventMonitor = { events: [event("a")], sources: { runtime: {}, security: {}, request: {} }, loading: false, refresh: async () => {} };
  let view!: ReturnType<typeof create>;
  await act(async () => { view = create(<EventsPanel monitor={base} onBlock={async () => true}/>); });
  const button = (label: string) => view.root.findAllByType("button").find(b => content(b).startsWith(label))!;
  await act(async () => button("Tạm dừng bảng").props.onClick());
  const next = { ...base, events: [event("b", { category: "New alert" }), event("a", { category: "Updated alert", revision: 1 })] };
  await act(async () => view.update(<EventsPanel monitor={next} onBlock={async () => true}/>));
  assert.match(content(view.root), /Test alert/); assert.doesNotMatch(content(view.root), /Updated alert|New alert/);
  await act(async () => button("Tiếp tục cập nhật").props.onClick());
  assert.match(content(view.root), /Updated alert/); assert.match(content(view.root), /New alert/);
  view.unmount();
});
