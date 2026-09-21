import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeEventPage,
  normalizeSessionDetail,
  normalizeSessionPage,
  normalizeStats,
} from "../src/runtimeData.ts";

test("classifies M2 lifecycle events without calling them threat detections", () => {
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
  assert.equal(events[0].event_class, "runtime");
  assert.equal(events[1].severity, "INFO");
  assert.equal(events[1].event_class, "policy");
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
      quality: { missing_fields: ["counters"] },
    }, 7],
  });

  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].id, "s-1");
  assert.equal(sessions[0].protocol, "tcp");
  assert.equal(sessions[0].original_tuple?.src_ip, "192.168.10.10");
  assert.equal(sessions[0].translated_tuple?.src_ip, "192.0.2.2");
  assert.equal(sessions[0].decision_status, "UNAVAILABLE");
  assert.equal(sessions[0].counters_available, false);
  assert.equal(sessions[0].fast_path_eligible, false);
  assert.equal(sessions[0].path_classification, "UNAVAILABLE");
  assert.equal(sessions[0].application, "Unavailable");
  assert.equal(sessions[0].application_available, false);
  assert.equal(sessions[0].risk_available, false);

  const detail = normalizeSessionDetail({ session: sessions[0], security_context: null });
  assert.ok(detail);
  assert.equal(detail.security_context.session_id, "s-1");
  assert.equal(detail.security_context.ml.available, false);
  assert.equal(detail.security_context.tls.available, false);
});

test("preserves measured zero counters and only reports a verified kernel fast path", () => {
  const sessions = normalizeSessionPage({ items: [{
    session_id: "s-2",
    original_tuple: { src_ip: "192.168.10.20", src_port: 51000, dst_ip: "203.0.113.10", dst_port: 443, protocol: 6 },
    packets_original: 0,
    bytes_original: 0,
    packets_reply: 0,
    bytes_reply: 0,
    quality: { missing_fields: [] },
    decision: "ALLOW",
    cache_state: "CACHED",
    kernel_cache_verified: true,
  }] });
  assert.equal(sessions[0].counters_available, true, "zero can be a measured value");
  assert.equal(sessions[0].decision_status, "EVALUATED");
  assert.equal(sessions[0].path_classification, "FAST");
});

test("does not expose an invalidated cached allow as the current decision", () => {
  const sessions = normalizeSessionPage({ items: [{
    session_id: "s-3",
    original_tuple: { src_ip: "192.168.10.30", src_port: 52000, dst_ip: "203.0.113.10", dst_port: 443, protocol: 6 },
    decision: "ALLOW",
    effective_decision: "ALLOW",
    cache_state: "INVALIDATED",
    invalidation_reason: "policy generation changed",
  }] });
  assert.equal(sessions[0].decision, "");
  assert.equal(sessions[0].decision_status, "INVALIDATED");
  assert.equal(sessions[0].decision_reason, "policy generation changed");
});

test("preserves an explicit revoked DROP while the decision cache is invalidated", () => {
  const sessions = normalizeSessionPage({ items: [{
    session_id: "s-4",
    original_tuple: { src_ip: "192.168.10.40", src_port: 53000, dst_ip: "203.0.113.10", dst_port: 443, protocol: 6 },
    decision: "DROP",
    effective_decision: "DROP",
    cache_state: "INVALIDATED",
    revoked: true,
  }] });
  assert.equal(sessions[0].revoked, true);
  assert.equal(sessions[0].decision, "DROP");
  assert.equal(sessions[0].decision_status, "EVALUATED");
});
