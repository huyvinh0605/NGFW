import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { create } from "react-test-renderer";
import { InspectionHealthPanel, SessionInspectionDetails, ThreatEventTable } from "../src/inspectionComponents.tsx";
import {
  normalizeInspectionHealth,
  normalizeSessionInspection,
  normalizeThreatEvent,
  normalizeThreatEventPage,
} from "../src/inspectionData.ts";
import { normalizeConfigExport, normalizeSessionPage } from "../src/runtimeData.ts";

test("normalizes malformed inspection fields without inventing clean or allowed evidence", () => {
  const value = normalizeSessionInspection({
    mode: 7,
    state: null,
    coverage: "clean",
    application: { name: null, source: "invalid", confidence: "invalid" },
    enforcement: { status: "success", scope: "session" },
    sources: ["ids", 3],
  });
  assert.ok(value);
  assert.equal(value.mode, "OFF");
  assert.equal(value.state, "ERROR");
  assert.equal(value.coverage, "UNAVAILABLE");
  assert.equal(value.application.name, "UNKNOWN");
  assert.equal(value.enforcement.status, "UNAVAILABLE");
  assert.deepEqual(value.sources, ["ids"]);
  assert.doesNotThrow(() => create(<SessionInspectionDetails inspection={value}/>).toJSON());
});

test("preserves uint64 Suricata flow IDs as strings and keeps TLS distinct from HTTPS", () => {
  const event = normalizeThreatEvent({
    event_id: "evt-1",
    suricata_flow_id: "18446744073709551615",
    application: { name: "tls", source: "SURICATA_APP_PROTO", confidence: "HIGH" },
    capture_mode: "IPS",
    signature: "marker",
    verdict: "DROP",
    packet_verdict: "drop",
    enforcement: { mechanism: "SURICATA_NFQUEUE", scope: "PACKET", status: "REPORTED" },
  });
  assert.ok(event);
  assert.equal(event.flow_id, "18446744073709551615");
  assert.equal(event.application, "TLS");
  assert.equal(event.packet_verdict, "drop");
  assert.equal(event.enforcement?.scope, "PACKET");
  assert.equal(event.enforcement?.status, "REPORTED");
});

test("does not confuse a reported packet drop with an applied session guard", () => {
  const [packet, guard] = normalizeThreatEventPage({ items: [
    { event_id: "packet", verdict: "DROP", packet_verdict: "drop", enforcement: { mechanism: "SURICATA_NFQUEUE", scope: "PACKET", status: "REPORTED" } },
    { event_id: "guard", verdict: "ALERT", enforcement: { mechanism: "NFT_SESSION_GUARD", scope: "SESSION", status: "APPLIED" } },
  ] });
  assert.equal(packet.enforcement?.scope, "PACKET");
  assert.equal(packet.enforcement?.status, "REPORTED");
  assert.equal(guard.enforcement?.scope, "SESSION");
  assert.equal(guard.enforcement?.status, "APPLIED");
  assert.doesNotThrow(() => create(<ThreatEventTable events={[packet, guard]}/>).toJSON());
});

test("sensor-down health remains visible and one malformed source cannot crash the panel", () => {
  const health = normalizeInspectionHealth({
    enabled: true,
    status: "degraded",
    generation: 9,
    sources: {
      ips: { sensor_id: "ips", mode: "IPS", state: "UNAVAILABLE", reason: "control socket refused" },
      malformed: "not-an-object",
    },
    stats: { observation_drops: "2", invalid: "NaN" },
    updated_at: "2026-09-23T00:00:00Z",
  });
  assert.ok(health);
  assert.equal(health.sources.ips.state, "UNAVAILABLE");
  assert.equal(health.stats.observation_drops, 2);
  assert.equal("malformed" in health.sources, false);
  const rendered = JSON.stringify(create(<InspectionHealthPanel health={health}/>).toJSON());
  assert.match(rendered, /UNAVAILABLE/);
});

test("keeps requested, configured, capture and lease state separate", () => {
  const health = normalizeInspectionHealth({
    enabled: true,
    status: "degraded",
    ips_queue: { requested: true, configured: true, capture_live: false, lease_active: false },
    sources: { ips: { sensor_id: "ips", state: "DEGRADED", counters: { captured_packets: 0 } } },
  });
  assert.equal(health?.ips_queue.requested, true);
  assert.equal(health?.ips_queue.configured, true);
  assert.equal(health?.ips_queue.capture_live, false);
  assert.equal(health?.ips_queue.lease_active, false);
  assert.equal(health?.sources.ips.counters.captured_packets, 0);
  const output = renderToStaticMarkup(<InspectionHealthPanel health={health}/>);
  assert.match(output, /UNAVAILABLE/);
  assert.match(output, /INACTIVE/);
});

test("M3 config and session inspection survive API normalization", () => {
  const config = normalizeConfigExport({
    running: {
      interfaces: [], zones: [], routes: [], nat_rules: [], default_deny: true,
      policies: [{ id: "p1", name: "TLS only", priority: 10, applications: ["TLS"], application_match_mode: "RESTRICT_L3_ALLOW", security_profile_id: "ips", action: "ALLOW", scope: "SESSION", enabled: true }],
      security_profiles: [{ id: "ips", name: "IPS", inspection: { mode: "IPS", fail_mode: "OPEN", ruleset_id: "m3-builtin-v1" } }],
      inspection: { enabled: true, include_management: false, limits: { app_detection_timeout_ms: 5000 } },
    },
    candidate: null,
    version: { version: 4 },
    candidate_valid: true,
  });
  assert.ok(config);
  assert.equal(config.running.policies[0].application_match_mode, "RESTRICT_L3_ALLOW");
  assert.equal(config.running.security_profiles[0].inspection?.mode, "IPS");
  assert.equal(config.running.inspection?.limits.app_detection_timeout_ms, 5000);

  const sessions = normalizeSessionPage({ items: [{
    session_id: "s1",
    original_tuple: { src_ip: "192.0.2.10", src_port: 50000, dst_ip: "198.51.100.10", dst_port: 443, protocol: 6 },
    inspection: { mode: "IPS", state: "INSPECTING", coverage: "OBSERVED", application: { name: "TLS", source: "SURICATA_APP_PROTO", confidence: "HIGH" }, app_policy_state: "MATCHED", enforcement: { status: "NOT_REQUESTED" } },
  }] });
  assert.equal(sessions[0].application, "TLS");
  assert.equal(sessions[0].inspection?.application.name, "TLS");
});
