import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { act, create } from "react-test-renderer";
import { useEventFeed, type EventMonitor } from "../src/useEventFeed.ts";

test("REST and WS share one bounded feed: no cursor skip, correlation revisions reload, credentials cancel old reads", async () => {
  const before = { window: globalThis.window, document: globalThis.document, fetch: globalThis.fetch, WebSocket: globalThis.WebSocket };
  const sockets: FakeSocket[] = [], calls: string[] = [];
  let monitor!: EventMonitor, revision = 0, delay = false, released: (() => void) | undefined;
  const stamp = "2026-11-07T04:00:00Z";
  class FakeSocket {
    readyState = 1;
    onopen?: () => void; onclose?: () => void; onerror?: () => void; onmessage?: (message: { data: string }) => void;
    constructor(_url: string, _protocols: string[]) { sockets.push(this); }
    addEventListener() {}
    close() { this.readyState = 3; this.onclose?.(); }
    message(data: unknown) { this.onmessage?.({ data: JSON.stringify(data) }); }
  }
  const define = (name: string, value: unknown) => Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  define("window", { setTimeout, clearTimeout, setInterval, clearInterval, location: { protocol: "http:", host: "fixture" }, localStorage: { getItem: () => "credential-a" } });
  define("document", { hidden: false, addEventListener() {}, removeEventListener() {} });
  define("WebSocket", FakeSocket);
  define("fetch", async (path: string, init: RequestInit) => {
    const url = new URL(path, "http://fixture"); calls.push(url.pathname + url.search);
    const owner = new Headers(init.headers).get("Authorization");
    if (delay && url.pathname.endsWith("/events") && !url.pathname.includes("security")) {
      await new Promise<void>(resolve => { released = resolve; init.signal?.addEventListener("abort", () => resolve(), { once: true }); });
    }
    let data: unknown;
    if (url.pathname === "/api/v1/events") {
      const after = Number(url.searchParams.get("after"));
      data = { stream_id: "runtime-A", next_sequence: 900, items: [{ kind: "SessionUpdated", sequence: after + 1, timestamp: stamp, session_id: owner }] };
    } else if (url.pathname === "/api/v1/security/events") data = { items: revision ? [] : [{ event_id: "threat", sequence: 1, correlation_revision: 0, observed_at: stamp }], stream_id: "security-A", next_cursor: "security-A:1" };
    else if (url.pathname === "/api/v1/security/events/threat") data = { event_id: "threat", sequence: 1, correlation_revision: 2, session_id: "confirmed", observed_at: stamp };
    else data = { items: [], next_sequence: 0 };
    return new Response(JSON.stringify({ success: true, data }));
  });
  function Probe({ token }: { token: string }) { monitor = useEventFeed(token); return null; }
  let view: ReturnType<typeof create> | undefined;
  try {
    await act(async () => { view = create(<Probe token="credential-a"/>); });
    await act(async () => { await new Promise(r => setTimeout(r, 180)); });
    assert.equal(sockets.length, 1);
    assert.equal(monitor.sources.runtime.hasMore, true);
    revision = 1;
    sockets[0].message({ success: true, type: "event", stream_id: "runtime-A", data: { sequence: 2, kind: "SecurityEventUpdated", event_id: "threat", timestamp: stamp } });
    await act(async () => { await monitor.refresh(); await new Promise(r => setTimeout(r, 220)); });
    assert.ok(calls.includes("/api/v1/events?after=1&limit=200"));
    assert.ok(!calls.some(c => c.includes("after=900")));
    assert.equal(monitor.events.filter(e => e.feed === "security").length, 1);
    assert.equal(monitor.events.find(e => e.feed === "security")?.session_id, "confirmed");
    delay = true;
    const pending = monitor.refresh();
    await act(async () => { view!.update(<Probe token="credential-b"/>); });
    released?.(); await pending;
    assert.equal(monitor.events.length, 0);
    assert.equal(sockets[0].readyState, 3);
    delay = false;
    await act(async () => { await new Promise(r => setTimeout(r, 180)); });
    assert.equal(sockets.length, 2);
    assert.ok(monitor.events.filter(e => e.feed === "runtime").every(e => e.session_id === "Bearer credential-b"));
    sockets[1].message({ success: true, type: "stream_reset", stream_id: "runtime-B" });
    await act(async () => { await new Promise(r => setTimeout(r, 20)); });
    assert.equal(monitor.sources.runtime.gap, true);
    assert.equal(monitor.sources.request.gap, true);
  } finally {
    if (view) await act(async () => view!.unmount());
    for (const [name, value] of Object.entries(before)) define(name, value);
  }
});
