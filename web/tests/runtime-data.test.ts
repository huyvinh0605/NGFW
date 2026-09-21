import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeEventPage,
  normalizeSessionDetail,
  normalizeSessionPage,
  normalizeStats,
} from "../src/runtimeData.ts";

test("normalizes M2 lifecycle events to the SecurityEvent shape", () => {
  const events = normalizeEventPage({
    items: [
      { sequence: 42, kind: "SessionCreated", session_id: "s-1", timestamp: "2026-09-17T10:00:00Z" },
      { sequence: 43, kind: "SessionInvalidated", session_id: "s-1", timestamp: "2026-09-17T10:01:00Z" },
      null,
      "malformed",
    ],
  });

  assert.equal(events.length, 2);
  assert.equal(events[0].event_id, "42");
  assert.equal(events[0].severity, "INFO");
  assert.equal(events[0].detector, "SESSION_ENGINE");
  assert.equal(events[1].severity, "INFO");
  assert.equal(events[1].metadata?.kind, "SessionInvalidated");
});

test("normalizes runtime stats and tolerates missing optional counters", () => {
  const stats = normalizeStats({ active_sessions: "7", event_drops: 3, applications: null });
  assert.equal(stats.active_sessions, 7);
  assert.equal(stats.event_queue_dropped, 3);
  assert.deepEqual(stats.applications, {});
  assert.equal(stats.blocked_sessions, 0);
});

test("maps runtime tuples and supplies an unavailable context when M2 returns null", () => {
  const sessions = normalizeSessionPage({
    items: [{
      session_id: "s-1",
      original_tuple: { src_ip: "192.168.10.10", src_port: 50000, dst_ip: "203.0.113.10", dst_port: 443, protocol: 6 },
      reply_tuple: { src_ip: "203.0.113.10", src_port: 443, dst_ip: "192.168.10.10", dst_port: 50000, protocol: 6 },
      translated_tuple: { src_ip: "192.0.2.2", src_port: 41000, dst_ip: "203.0.113.10", dst_port: 443, protocol: 6 },
      state: "ESTABLISHED",
      cache_state: "CACHED",
    }, 7],
  });

  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].id, "s-1");
  assert.equal(sessions[0].protocol, "tcp");
  assert.equal(sessions[0].original_tuple?.src_ip, "192.168.10.10");
  assert.equal(sessions[0].translated_tuple?.src_ip, "192.0.2.2");
  assert.equal(sessions[0].fast_path_eligible, true);

  const detail = normalizeSessionDetail({ session: sessions[0], security_context: null });
  assert.ok(detail);
  assert.equal(detail.security_context.session_id, "s-1");
  assert.equal(detail.security_context.ml.available, false);
  assert.equal(detail.security_context.tls.available, false);
});
