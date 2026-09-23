import assert from "node:assert/strict";
import test from "node:test";
import { canCommit, canonicalizePolicy, normalizeService, normalizeServiceList, parseService, policiesEquivalent } from "../src/policy.ts";
import type { SecurityPolicy } from "../src/types.ts";

test("service parser accepts canonical TCP/UDP values and normalizes case/whitespace", () => {
  assert.equal(normalizeService(" TCP:443 "), "tcp:443");
  assert.deepEqual(normalizeServiceList("tcp:80, tcp:443, udp:53"), ["tcp:80", "tcp:443", "udp:53"]);
  assert.deepEqual(normalizeServiceList(["tcp:443", "tcp:80", "tcp:443"]), ["tcp:80", "tcp:443"]);
  assert.equal(parseService("icmp").protocol, "icmp");
});

test("service parser rejects malformed and portless TCP/UDP selectors", () => {
  for (const value of ["80", "tcp", "tcp:", ":80", "tcp:http", "tcp:0", "tcp:65536", "udp:99999", "icmp:80", "tcp:80,,tcp:443"]) {
    assert.throws(() => normalizeServiceList(value), value);
  }
});

function policy(overrides: Partial<SecurityPolicy> = {}): SecurityPolicy {
  return { id: "a", name: "A", priority: 10, source_zones: ["lan", "dmz"], destination_zones: ["wan"], source_addresses: [], destination_addresses: [], services: ["tcp:80", "tcp:443"], applications: [], action: "ALLOW", scope: "SESSION", log_start: true, log_end: true, enabled: true, ...overrides };
}

test("effective policy comparison ignores identity, priority and selector order", () => {
  const left = policy();
  const right = policy({ id: "b", name: "B", priority: 50, source_zones: ["DMZ", "LAN"], services: ["tcp:443", "TCP:80"] });
  assert.deepEqual(canonicalizePolicy(left).services, ["tcp:80", "tcp:443"]);
  assert.equal(policiesEquivalent(left, right), true);
  assert.equal(policiesEquivalent(left, policy({ services: ["tcp:443"] })), false);
});

test("candidate commit readiness requires the current validated revision", () => {
  const running = { max_sessions: 1 } as never;
  const candidate = { max_sessions: 2 } as never;
  const base = { running, candidate, version: { version: 1, author: "", timestamp: "", comment: "", checksum: "" }, candidate_valid: true, candidate_validation_state: "VALID" } as never;
  assert.equal(canCommit(base), true);
  assert.equal(canCommit({ ...base, candidate_validation_state: "STALE" }), false);
  assert.equal(canCommit({ ...base, candidate_validation_state: "VALID" }), true);
  assert.equal(canCommit({ ...base, candidate_validation_state: undefined }), false);
});
