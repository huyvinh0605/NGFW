import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { normalizeConfigExport } from "../src/runtimeData.ts";
import { ConfigStatusBar, ConfigurationPage, InspectionProfileEditor, PolicyEditor, PolicyPage } from "../src/App.tsx";
import type { NGFWConfig, SecurityPolicy, SecurityProfile } from "../src/types.ts";

function wireConfig() {
  return {
    interfaces: [{ id: "dmz-vlan", name: "DMZ VLAN", system_name: "ens38.120", zone_id: "dmz", mode: "VLAN_SUBINTERFACE", parent_interface_id: "dmz-parent", vlan_id: 120, ipv4_addresses: ["10.20.0.1/24"], ipv6_addresses: [], mtu: 1400, admin_state: true, future: { addresses: ["198.51.100.1"] } }],
    zones: [{ id: "dmz", name: "DMZ", description: "", future: { label: "zone" } }],
    routes: [{ id: "route", destination_cidr: "198.51.100.0/24", gateway: "10.20.0.10", interface_id: "dmz-vlan", metric: 120, enabled: true, future: { table: 101 } }],
    nat_rules: [{ id: "nat", name: "NAT", type: "DNAT", source_zone: "wan", destination_zone: "dmz", enabled: true, priority: 10, future: { flags: ["preserve"] } }],
    policies: [{ id: "policy", name: "Web", priority: 10, source_zones: ["lan"], destination_zones: ["dmz"], services: ["tcp:443"], applications: [], action: "ALLOW", scope: "SESSION", log_start: false, log_end: true, enabled: true, future: { audit: ["keep"] } }],
    security_profiles: [{ id: "profile", name: "Combined profile", ids_ips_enabled: true, dpi_enabled: false, dns_security_enabled: false, url_filtering_enabled: false, threat_intel_enabled: false, behavior_enabled: false, ml_detection_enabled: false, tls_mode: "DECRYPT", minimum_block_risk: 80, logging_level: "INFO", inspection_required: true, inspection_failure_action: "DROP", inspection: { mode: "IPS", fail_mode: "OPEN", ruleset_id: "m3-builtin-v1", future: { sensor: "keep" } }, request_gate: { enabled: true, fail_mode: "CLOSE", oversize_action: "BLOCK", unsupported_encoding_action: "BLOCK", block_quic: true }, future: { version: 2 } }],
    inspection: { enabled: true, include_management: false, limits: { app_detection_timeout_ms: 5000, future_limit: { soft: 25 } }, future: { source: "keep" } },
    request_gate: { enabled: true, max_decompression_ratio: 20, future: { queue: "keep" } },
    tls_exclusions: [{ id: "private", name: "Private", enabled: true, reason: "privacy", domains: ["private.lab.test"], ports: [443], future: { reason_code: 7 } }],
    max_sessions: 50000, max_events_queue: 10000, max_http_body_inspection: 65536, max_http_header_size: 32768, max_url_length: 8192, max_ml_input_length: 65536, ml_timeout_millis: 200, request_inspection_timeout_millis: 2000, default_deny: true,
    future: { routing: [{ id: "future-route", weight: 10 }] },
  };
}

function exportConfig() {
  const source = wireConfig();
  const normalized = normalizeConfigExport({ running: source, candidate: source, version: { version: 220 }, candidate_valid: true, candidate_validation: { state: "VALID" } });
  assert.ok(normalized);
  return { source, normalized };
}

test("editable config retains VLAN, M4 and unknown fields at every nesting level", () => {
  const { source, normalized } = exportConfig();
  const c = JSON.parse(JSON.stringify(normalized.candidate));
  assert.equal(c.interfaces[0].parent_interface_id, "dmz-parent");
  assert.equal(c.interfaces[0].vlan_id, 120);
  for (const section of ["interfaces", "zones", "routes", "nat_rules", "policies", "security_profiles"] as const) {
    assert.deepEqual(c[section][0].future, source[section][0].future, section);
  }
  assert.deepEqual(c.security_profiles[0].request_gate, source.security_profiles[0].request_gate);
  assert.deepEqual(c.security_profiles[0].inspection.future, source.security_profiles[0].inspection.future);
  assert.deepEqual(c.inspection.future, source.inspection.future);
  assert.deepEqual(c.inspection.limits.future_limit, source.inspection.limits.future_limit);
  assert.deepEqual(c.request_gate, source.request_gate);
  assert.deepEqual(c.tls_exclusions, source.tls_exclusions);
  assert.deepEqual(c.future, source.future);
});

test("editing nested Candidate fields cannot mutate Running or the HTTP input", () => {
  const { source, normalized } = exportConfig();
  const before = structuredClone(source);
  const c = normalized.candidate as unknown as ReturnType<typeof wireConfig>;
  c.interfaces[0].future.addresses.push("203.0.113.1");
  c.security_profiles[0].request_gate.block_quic = false;
  c.inspection.limits.future_limit.soft = 99;
  c.request_gate.future.queue = "changed";
  c.tls_exclusions[0].future.reason_code = 8;
  assert.deepEqual(source, before);
  assert.deepEqual((normalized.running as unknown as typeof source).request_gate, before.request_gate);
  assert.deepEqual((normalized.running as unknown as typeof source).interfaces[0].future, before.interfaces[0].future);
});

test("config responses missing collections, Candidate, or valid records fail closed", () => {
  const source = wireConfig();
  for (const running of [{}, { ...source, interfaces: [null] }, { ...source, routes: [{ destination_cidr: "default" }] }, { ...source, zones: "invalid" }]) {
    assert.equal(normalizeConfigExport({ running, candidate: source }), null);
  }
  for (const candidate of [undefined, null, {}, { ...source, policies: [7] }]) {
    assert.equal(normalizeConfigExport({ running: source, candidate }), null);
  }
  const nil = { ...source, routes: null, security_profiles: null };
  assert.ok(normalizeConfigExport({ running: nil, candidate: nil }), "Go nil slices remain supported");
});

test("an unrecognized policy action is never rewritten as ALLOW", () => {
  const source = wireConfig();
  source.policies[0].action = "FUTURE_DENY_ACTION";
  const result = normalizeConfigExport({ running: source, candidate: source });
  assert.equal(result?.candidate.policies[0].action, "FUTURE_DENY_ACTION");
});

test("JSON editor save retains hidden fields while editing only a policy name", async () => {
  const { normalized } = exportConfig();
  let saved: NGFWConfig | undefined;
  let view!: ReactTestRenderer;
  await act(async () => { view = create(<ConfigurationPage config={normalized} onBack={() => undefined} onSave={async c => { saved = c; return true; }} onValidate={async () => true} onCommit={async () => true} onRollback={async () => true}/>); });
  try {
    const editor = view.root.findByProps({ "aria-label": "Candidate configuration JSON" });
    const edited = JSON.parse(editor.props.value);
    edited.policies[0].name = "Edited web";
    act(() => editor.props.onChange({ target: { value: JSON.stringify(edited) } }));
    const save = view.root.findAllByType("button").find(b => b.props.title?.includes("Chỉ cập nhật Candidate backend"));
    assert.ok(save);
    await act(async () => { await save.props.onClick(); });
    assert.ok(saved);
    assert.deepEqual(JSON.parse(JSON.stringify(saved)), JSON.parse(JSON.stringify({ ...normalized.candidate, policies: [{ ...normalized.candidate.policies[0], name: "Edited web" }] })));
  } finally { view.unmount(); }
});

test("policy and profile forms retain all hidden fields on name-only edits", async () => {
  const { normalized } = exportConfig();
  const policy = normalized.candidate.policies[0];
  const profile = normalized.candidate.security_profiles[0];
  let savedPolicy: SecurityPolicy | undefined;
  let savedProfile: SecurityProfile | undefined;
  let view!: ReactTestRenderer;
  await act(async () => { view = create(<PolicyEditor value={policy} zones={["lan", "dmz"]} profiles={[profile]} busy={false} onClose={() => undefined} onSave={async p => { savedPolicy = p; }}/>); });
  act(() => view.root.findAllByType("input").find(n => n.props.value === policy.name)!.props.onChange({ target: { value: "Renamed policy" } }));
  await act(async () => { view.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
  assert.ok(savedPolicy);
  assert.deepEqual(JSON.parse(JSON.stringify(savedPolicy)), JSON.parse(JSON.stringify({ ...policy, name: "Renamed policy" })));
  view.unmount();
  await act(async () => { view = create(<InspectionProfileEditor value={profile} busy={false} onClose={() => undefined} onSave={async p => { savedProfile = p; }}/>); });
  act(() => view.root.findAllByType("input").find(n => n.props.value === profile.name)!.props.onChange({ target: { value: "Renamed profile" } }));
  await act(async () => { view.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
  assert.deepEqual(savedProfile, { ...profile, name: "Renamed profile" });
  view.unmount();
});

test("unavailable config cannot advertise a synced Candidate or enable activation", () => {
  const view = create(<ConfigStatusBar config={null} dirty={false} comment="" onComment={() => undefined} busy="" onValidate={async () => undefined} onCommit={async () => undefined} onRollback={async () => undefined}/>);
  assert.ok(view.root.findAllByType("button").every(b => b.props.disabled));
  assert.match(JSON.stringify(view.toJSON()), /Chưa đọc được cấu hình/);
  view.unmount();
});

test("editing or toggling a policy and editing a profile preserve backend array order", async () => {
  const { normalized } = exportConfig();
  const policy = normalized.candidate.policies[0];
  const profile = normalized.candidate.security_profiles[0];
  normalized.candidate.policies = [{ ...policy, id: "late", name: "Later rule", priority: 30 }, policy, { ...policy, id: "last", name: "Last rule", priority: 20 }];
  normalized.candidate.security_profiles = [{ ...profile, id: "other" }, profile];
  let savedPolicies: SecurityPolicy[] = [];
  let savedProfiles: SecurityProfile[] = [];
  let view!: ReactTestRenderer;
  await act(async () => { view = create(<PolicyPage config={normalized} onSave={async p => { savedPolicies = p; return true; }} onSaveProfiles={async p => { savedProfiles = p; return true; }} onValidate={async () => true} onCommit={async () => true} onRollback={async () => true} onOpenAdvanced={() => undefined}/>); });
  try {
    const policyRow = () => view.root.findAllByType("tr").find(row => row.findAllByType("strong").some(n => n.children.includes(policy.name)))!;
    act(() => policyRow().findAllByType("button").find(b => b.props.title === "Sửa")!.props.onClick());
    act(() => view.root.findAllByType("input").find(n => n.props.value === policy.name)!.props.onChange({ target: { value: "New name" } }));
    await act(async () => { view.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
    assert.deepEqual(savedPolicies.map(p => p.id), ["late", "policy", "last"]);
    assert.equal(savedPolicies[1].name, "New name");
    await act(async () => { await policyRow().findAllByType("button").find(b => b.props["aria-label"] === "Tắt policy")!.props.onClick(); });
    assert.deepEqual(savedPolicies.map(p => p.id), ["late", "policy", "last"]);
    assert.equal(savedPolicies[1].enabled, false);
    act(() => view.root.findAllByType("button").filter(b => b.props.title === "Sửa profile")[1].props.onClick());
    act(() => view.root.findAllByType("input").find(n => n.props.value === profile.name)!.props.onChange({ target: { value: "Profile new name" } }));
    await act(async () => { view.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
    assert.deepEqual(savedProfiles.map(p => p.id), ["other", "profile"]);
    assert.deepEqual(savedProfiles[1], { ...profile, name: "Profile new name" });
  } finally { view.unmount(); }
});
