import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { ConfigurationPage, ConfigStatusBar, PolicyEditor, PolicyPage } from "../src/App.tsx";
import type { ConfigExport, NGFWConfig, SecurityPolicy } from "../src/types.ts";

function baseConfig(): NGFWConfig {
  return {
    interfaces: [],
    zones: [],
    routes: [],
    nat_rules: [],
    policies: [],
    security_profiles: [],
    max_sessions: 50_000,
    max_events_queue: 10_000,
    max_http_body_inspection: 65_536,
    max_http_header_size: 32_768,
    max_url_length: 8_192,
    max_ml_input_length: 65_536,
    ml_timeout_millis: 200,
    request_inspection_timeout_millis: 2_000,
    default_deny: true,
  };
}

function configExport(candidateChanged = true): ConfigExport {
  const running = baseConfig();
  const candidate = { ...baseConfig(), max_sessions: candidateChanged ? 60_000 : 50_000 };
  return {
    running,
    candidate,
    version: {
      version: 7,
      author: "admin",
      timestamp: "2026-09-21T08:00:00Z",
      comment: "known good",
      checksum: "abc123",
    },
    candidate_valid: true,
  };
}

function textOf(node: ReactTestInstance): string {
  return node.children.map((child) => typeof child === "string" ? child : textOf(child)).join("");
}

function button(view: ReactTestRenderer, label: string): ReactTestInstance {
  return view.root.findAllByType("button").find((item) => textOf(item) === label) ?? assert.fail(`button not found: ${label}`);
}

const noopBoolean = async () => true;

test("load Running only changes the editor and warns before replacing dirty Candidate content", async () => {
  const config = configExport(true);
  const calls = { save: 0, validate: 0, commit: 0, rollback: 0 };
  let allowReplacement = false;
  const confirmations: string[] = [];
  const previousWindow = globalThis.window;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      confirm(message: string) {
        confirmations.push(message);
        return allowReplacement;
      },
    },
  });

  let view!: ReactTestRenderer;
  try {
    await act(async () => {
      view = create(<ConfigurationPage
        config={config}
        originPage="policy"
        onBack={() => undefined}
        onSave={async () => { calls.save++; return true; }}
        onValidate={async () => { calls.validate++; return true; }}
        onCommit={async () => { calls.commit++; return true; }}
        onRollback={async () => { calls.rollback++; return true; }}
      />);
    });

    const editor = () => view.root.findByProps({ "aria-label": "Candidate configuration JSON" });
    assert.equal(JSON.parse(editor().props.value).max_sessions, 60_000);

    const loadButton = button(view, "Nạp Running vào trình soạn thảo");
    assert.equal(loadButton.props.title, "Chỉ thay nội dung trình soạn thảo, không áp dụng cấu hình.");
    act(() => loadButton.props.onClick());
    assert.equal(JSON.parse(editor().props.value).max_sessions, 60_000, "cancel must preserve editor content");
    assert.match(confirmations[0], /Candidate hiện có thay đổi chưa commit/);

    allowReplacement = true;
    act(() => button(view, "Nạp Running vào trình soạn thảo").props.onClick());
    assert.equal(JSON.parse(editor().props.value).max_sessions, 50_000);
    assert.deepEqual(calls, { save: 0, validate: 0, commit: 0, rollback: 0 });
    assert.match(textOf(view.root.findByProps({ className: "config-state" })), /Runningv7/);
  } finally {
    view?.unmount();
    if (previousWindow === undefined) delete (globalThis as { window?: Window }).window;
    else Object.defineProperty(globalThis, "window", { configurable: true, value: previousWindow });
  }
});

test("save updates Candidate only and Commit is the separate activation action", async () => {
  const calls = { save: 0, validate: 0, commit: 0, rollback: 0 };
  let saved: NGFWConfig | undefined;
  let view!: ReactTestRenderer;
  await act(async () => {
    view = create(<ConfigurationPage
      config={configExport(true)}
      onBack={() => undefined}
      onSave={async (candidate) => { calls.save++; saved = candidate; return true; }}
      onValidate={async () => { calls.validate++; return true; }}
      onCommit={async () => { calls.commit++; return true; }}
      onRollback={async () => { calls.rollback++; return true; }}
    />);
  });

  const editor = view.root.findByProps({ "aria-label": "Candidate configuration JSON" });
  const edited = { ...JSON.parse(editor.props.value), max_sessions: 70_000 };
  act(() => editor.props.onChange({ target: { value: JSON.stringify(edited, null, 2) } }));
  await act(async () => {
    button(view, "Lưu vào Candidate").props.onClick();
    await Promise.resolve();
  });
  assert.equal(calls.save, 1);
  assert.equal(saved?.max_sessions, 70_000);
  assert.equal(calls.commit, 0, "saving Candidate must not activate it");

  await act(async () => {
    button(view, "Commit").props.onClick();
    await Promise.resolve();
  });
  assert.deepEqual(calls, { save: 1, validate: 0, commit: 1, rollback: 0 });
  view.unmount();
});

test("Policy and JSON pages expose one shared Candidate state and a working back link", async () => {
  const config = configExport(true);
  let opened = 0;
  let backTarget = "";
  let policyView!: ReactTestRenderer;
  let configurationView!: ReactTestRenderer;
  const savePolicies = async (_policies: SecurityPolicy[]) => true;

  await act(async () => {
    policyView = create(<PolicyPage config={config} onSave={savePolicies} onValidate={noopBoolean} onCommit={noopBoolean} onRollback={noopBoolean} onOpenAdvanced={() => { opened++; }}/>)
    configurationView = create(<ConfigurationPage config={config} originPage="policy" onBack={(target) => { backTarget = target; }} onSave={noopBoolean} onValidate={noopBoolean} onCommit={noopBoolean} onRollback={noopBoolean}/>)
  });

  const policyState = textOf(policyView.root.findByProps({ className: "config-state" }));
  const configurationState = textOf(configurationView.root.findByProps({ className: "config-state" }));
  assert.equal(configurationState, policyState);
  assert.match(policyState, /Candidate changed/);
  assert.match(policyState, /Validation: hợp lệ/);
  assert.equal(textOf(configurationView.root.findByProps({ "aria-label": "Breadcrumb" })), "Chính sáchCấu hình JSON");

  act(() => button(policyView, "Mở JSON nâng cao").props.onClick());
  assert.equal(opened, 1);
  act(() => button(configurationView, "← Quay lại Chính sách").props.onClick());
  assert.equal(backTarget, "policy");

  policyView.unmount();
  configurationView.unmount();
});

test("Commit stays disabled when Candidate is already synced and explains why", async () => {
  let view!: ReactTestRenderer;
  await act(async () => {
    view = create(<ConfigStatusBar config={configExport(false)} dirty={false} comment="" onComment={() => undefined} onValidate={async () => undefined} onCommit={async () => undefined} onRollback={async () => undefined}/>);
  });

  const commit = button(view, "Commit");
  assert.equal(commit.props.disabled, true);
  assert.match(commit.props.title, /không có thay đổi để commit/);
  assert.match(textOf(view.root.findByProps({ className: "config-state" })), /không có thay đổi để commit/);
  view.unmount();
});

test("Policy editor keeps comma separated service text and allows clearing Priority while typing", async () => {
  const value: SecurityPolicy = {
    id: "allow-web",
    name: "Web access",
    priority: 10,
    source_zones: ["lan"],
    destination_zones: ["wan"],
    services: ["tcp:80"],
    applications: [],
    action: "ALLOW",
    scope: "SESSION",
    log_start: true,
    log_end: true,
    enabled: true,
  };
  let saved: SecurityPolicy | undefined;
  let view!: ReactTestRenderer;
  await act(async () => {
    view = create(<PolicyEditor value={value} zones={["lan", "wan"]} profiles={[]} busy={false} onClose={() => undefined} onSave={async (policy) => { saved = policy; }}/>);
  });

  const priority = () => view.root.findByProps({ "aria-label": "Policy priority" });
  const services = () => view.root.findByProps({ "aria-label": "Services" });
  act(() => priority().props.onChange({ target: { value: "" } }));
  assert.equal(priority().props.value, "", "Priority must be clearable during editing");
  act(() => services().props.onChange({ target: { value: "tcp:80, udp:53, tcp:443" } }));
  assert.equal(services().props.value, "tcp:80, udp:53, tcp:443", "editor must preserve the raw comma separated text");

  await act(async () => {
    view.root.findByType("form").props.onSubmit({ preventDefault() {} });
    await Promise.resolve();
  });
  assert.equal(saved, undefined, "blank Priority must not save an invalid policy");
  assert.match(textOf(view.root.findByProps({ role: "alert" })), /Priority bắt buộc/);

  act(() => priority().props.onChange({ target: { value: "20" } }));
  await act(async () => {
    view.root.findByType("form").props.onSubmit({ preventDefault() {} });
    await Promise.resolve();
  });
  assert.equal(saved?.priority, 20);
  assert.deepEqual(saved?.services, ["tcp:80", "udp:53", "tcp:443"]);
  view.unmount();
});
