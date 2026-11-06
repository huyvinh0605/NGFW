import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";
import { PolicyEditor } from "../src/App.tsx";
import { serializeServices, serviceEntries } from "../src/policyFields";
import type { InspectionCapabilities, SecurityPolicy, SecurityProfile } from "../src/types";

const policy: SecurityPolicy = { id: "web", name: "Web", priority: 10, source_zones: [], destination_zones: [], services: [], applications: [], action: "ALLOW", scope: "SESSION", enabled: true, log_start: true, log_end: true };
const caps = { supported: true, applications: ["HTTP", "TLS", "DNS", "SSH"] } as InspectionCapabilities;
const profile: SecurityProfile = {
  id: "ips", name: "IPS", ids_ips_enabled: true, dpi_enabled: false,
  dns_security_enabled: false, url_filtering_enabled: false, threat_intel_enabled: false,
  behavior_enabled: false, ml_detection_enabled: false, tls_mode: "BYPASS",
  minimum_block_risk: 0, logging_level: "INFO", inspection_required: false,
  inspection_failure_action: "ALLOW", inspection: { mode: "IPS", fail_mode: "OPEN", ruleset_id: "m3-builtin-v1" },
};
function click(view: ReactTestRenderer, title: string) {
  const button = view.root.findAllByType("button").find((item) => item.children.join("") === title);
  assert.ok(button, title);act(() => button.props.onClick());
}
async function editor(value: SecurityPolicy = policy, capabilities: InspectionCapabilities | null = caps) {
  let saved: SecurityPolicy | undefined;
  let view!: ReactTestRenderer;
  await act(async () => { view = create(<PolicyEditor value={value} zones={["wan", "lan", "dmz", "mgmt"]} profiles={[profile]} capabilities={capabilities} busy={false} onClose={() => undefined} onSave={async (p) => { saved = p; }}/>); });
  const change = (label: string, value: unknown, key = "value") => act(() => view.root.findByProps({ "aria-label": label }).props.onChange({ target: { [key]: value } }));
  const submit = async () => { await act(async () => { view.root.findByType("form").props.onSubmit({ preventDefault() {} }); });return saved; };
  return { view, change, submit, saved: () => saved };
}

test("single-zone changes replace the previous WAN/LAN choice on both sides", async () => {
  const e = await editor();
  e.change("Vùng nguồn WAN", true, "checked");e.change("Vùng nguồn LAN", true, "checked");
  e.change("Vùng đích LAN", true, "checked");e.change("Vùng đích DMZ", true, "checked");
  const saved = await e.submit();
  assert.deepEqual(saved?.source_zones, ["lan"]);assert.deepEqual(saved?.destination_zones, ["dmz"]);
  assert.equal(e.view.root.findByProps({ "aria-label": "Vùng nguồn WAN" }).props.checked, false);
  e.view.unmount();
});

test("existing multiple zones, port ranges and hidden conditions survive a name-only edit", async () => {
  const value = { ...policy, source_zones: ["wan", "lan"], destination_zones: ["dmz", "mgmt"], source_addresses: ["192.168.10.10/32"], destination_addresses: ["10.20.0.10/32"], services: ["tcp:18188", "tcp:18200-18231", "icmp"], future: { keep: [1, 2] } };
  const e = await editor(value);
  assert.equal(e.view.root.findByProps({ "aria-label": "Chọn nhiều vùng nguồn" }).props.checked, true);
  act(() => e.view.root.findAllByType("input").find((item) => item.props.value === value.name)!.props.onChange({ target: { value: "Renamed" } }));
  assert.deepEqual(JSON.parse(JSON.stringify(await e.submit())), { ...value, name: "Renamed" });e.view.unmount();
});

test("switching a multi-zone rule to single never silently drops zones", async () => {
  const e = await editor({ ...policy, source_zones: ["wan", "lan"] });
  e.change("Chọn nhiều vùng nguồn", false, "checked");assert.equal(await e.submit(), undefined);
  e.change("Vùng nguồn LAN", true, "checked");assert.deepEqual((await e.submit())?.source_zones, ["lan"]);e.view.unmount();
});

test("explicit multi-zone and Any choices serialize to the intended matcher", async () => {
  const e = await editor();e.change("Chọn nhiều vùng nguồn", true, "checked");
  e.change("Vùng nguồn WAN", true, "checked");e.change("Vùng nguồn LAN", true, "checked");
  assert.deepEqual((await e.submit())?.source_zones, ["wan", "lan"]);
  e.change("Bất kỳ vùng nguồn", true, "checked");assert.deepEqual((await e.submit())?.source_zones, []);e.view.unmount();
});

test("custom service port/range controls produce backend selectors without typed separators", async () => {
  const e = await editor();click(e.view, "+ Thêm dịch vụ");
  e.change("Cổng đích dịch vụ 1", "8080");click(e.view, "+ Thêm dịch vụ");
  e.change("Giao thức dịch vụ 2", "udp");e.change("Loại cổng dịch vụ 2", "range");e.change("Cổng đích dịch vụ 2", "1000");e.change("Cổng cuối dịch vụ 2", "2000");
  assert.deepEqual((await e.submit())?.services, ["tcp:8080", "udp:1000-2000"]);
  assert.equal((await e.submit())?.scope, "SESSION");
  click(e.view, "+ Thêm dịch vụ");e.change("Giao thức dịch vụ 3", "icmp");
  assert.deepEqual((await e.submit())?.services, ["tcp:8080", "udp:1000-2000", "icmp"]);e.view.unmount();
});

test("unfinished, out-of-range and reversed range entries cannot silently become Any", async () => {
  for (const [first, last] of [["", "80"], ["65536", "65536"], ["443", "80"]]) {
    const e = await editor();click(e.view, "+ Thêm dịch vụ");e.change("Loại cổng dịch vụ 1", "range");e.change("Cổng đích dịch vụ 1", first);e.change("Cổng cuối dịch vụ 1", last);
    assert.equal(await e.submit(), undefined);assert.match(JSON.stringify(e.view.toJSON()), /Dịch vụ 1:/);e.view.unmount();
  }
});

test("application selection uses backend capabilities and requires the IPS contract", async () => {
  const e = await editor({ ...policy, security_profile_id: "ips" });e.change("Ứng dụng HTTP", true, "checked");e.change("Ứng dụng TLS", true, "checked");
  const saved = await e.submit();assert.deepEqual(saved?.applications, ["HTTP", "TLS"]);assert.equal(saved?.application_match_mode, "RESTRICT_L3_ALLOW");
  click(e.view, "Không giới hạn ứng dụng");assert.deepEqual((await e.submit())?.applications, []);assert.equal((await e.submit())?.application_match_mode, undefined);e.view.unmount();
});

test("missing capabilities preserve existing application restrictions and add no invented choices", async () => {
  const value = { ...policy, applications: ["HTTP", "TLS"], application_match_mode: "RESTRICT_L3_ALLOW", security_profile_id: "ips" };
  const e = await editor(value, null);assert.equal(e.view.root.findByProps({ "aria-label": "Ứng dụng HTTP" }).props.disabled, true);
  assert.deepEqual((await e.submit())?.applications, value.applications);
  assert.equal(e.view.root.findAll((item) => item.props["aria-label"] === "Ứng dụng DNS").length, 0);e.view.unmount();
});

test("legacy selectors stay intact; explicit service edits receive strict validation", () => {
  const originals = ["tcp:443", "udp:1000-2000", "icmpv6", "future-protocol:9"];
  assert.deepEqual(serializeServices(serviceEntries(originals)), originals);
  assert.throws(() => serializeServices([{ ...serviceEntries(["tcp:443"])[0], original: undefined, first: "80,443" }]), /cổng đích/);
});
