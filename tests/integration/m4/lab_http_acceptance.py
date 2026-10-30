#!/usr/bin/env python3
"""Narrow, reversible Ubuntu M4 HTTP request-gate acceptance run.

Requires the five-VM lab, an already installed/running ngfw-proxy, Paramiko,
Requests, and NGFW_LAB_PASSWORD in the caller's environment. Never prints or
persists the management token. Leaves Running/Candidate at their original
configuration even when a check fails.
"""

import argparse
import copy
import hashlib
import json
import os
import secrets
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko
import requests


HOSTS = {"ngfw": ("192.168.100.1", "huy"), "lan": ("192.168.10.10", "lan"), "dmz": ("10.20.0.10", "dmz")}
API = "http://192.168.100.1:8080/api/v1"


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def json_write(path, value):
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


class Lab:
    def __init__(self, password, evidence):
        self.password = password
        self.evidence = evidence
        self.ssh = {}
        self.http = requests.Session()
        self.http.trust_env = False
        for name, (host, user) in HOSTS.items():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=user, password=password, timeout=8,
                           look_for_keys=False, allow_agent=False)
            self.ssh[name] = client

    def close(self):
        for client in self.ssh.values():
            client.close()
        self.http.close()

    def command(self, host, command, *, sudo=False, timeout=30, evidence=None):
        issued = "sudo -S " + command if sudo else command
        stdin, stdout, stderr = self.ssh[host].exec_command(issued, timeout=timeout)
        if sudo:
            stdin.write(self.password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
        result = {"command": command, "exit_code": stdout.channel.recv_exit_status(),
                  "stdout": stdout.read().decode("utf-8", "replace"),
                  "stderr": stderr.read().decode("utf-8", "replace")}
        if evidence:
            json_write(self.evidence / evidence, result)
        return result

    def api(self, method, path, *, payload=None, evidence=None, timeout=90):
        response = self.http.request(method, API + path, json=payload, timeout=timeout)
        try:
            data = response.json()
        except ValueError:
            data = {"body": response.text[:2000]}
        result = {"method": method, "path": path, "status": response.status_code, "response": data}
        if evidence:
            json_write(self.evidence / evidence, result)
        return result


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--preserve-draft", action="store_true", help="snapshot and restore an existing Candidate while testing Running")
    args = parser.parse_args()
    password = os.environ.get("NGFW_LAB_PASSWORD")
    require(bool(password), "NGFW_LAB_PASSWORD is required")
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = {"started_at": run_id, "checks": {}, "restored": False}
    lab = None
    baseline = None
    initial_candidate = None
    touched_candidate = False
    server_unit = "ngfw-m4-lab-http-" + run_id.lower()
    server_log = "/tmp/" + server_unit + ".jsonl"
    server_script = "/tmp/" + server_unit + ".py"
    started_server = False
    try:
        lab = Lab(password, evidence)
        env = lab.command("ngfw", "cat /etc/ngfw/ngfw.env", sudo=True)
        require(env["exit_code"] == 0, "cannot read management credential on NGFW")
        token = next((line.split("=", 1)[1].strip().strip("\"'") for line in env["stdout"].splitlines()
                      if line.startswith("NGFW_API_TOKEN=")), "")
        require(bool(token), "NGFW_API_TOKEN is absent")
        lab.http.headers["Authorization"] = "Bearer " + token
        config = lab.api("GET", "/config", evidence="initial-config.json")
        require(config["status"] == 200, "cannot read initial config")
        initial = config["response"]["data"]
        baseline = copy.deepcopy(initial["running"])
        initial_candidate = copy.deepcopy(initial["candidate"])
        require(initial_candidate == baseline or args.preserve_draft, "Candidate differs from Running; use --preserve-draft to snapshot and restore it")
        require(not baseline.get("request_gate", {}).get("enabled", False), "M4 is already enabled")
        initial_version = initial["version"]["version"]
        service = lab.command("ngfw", "systemctl is-active ngfw-engine ngfw-api ngfw-proxy", evidence="initial-services.json")
        require(service["stdout"].splitlines() == ["active", "active", "active"], "required services not active")
        if initial_candidate != baseline:
            touched_candidate = True
            stage = lab.api("PUT", "/config/candidate", payload=baseline, evidence="draft-snapshot-stage-running.json")
            require(stage["status"] == 200, "cannot stage Running while preserving draft")
        json_write(evidence / "manifest.json", {"run_id": run_id, "running_version": initial_version,
                                                 "running_checksum": initial["version"]["checksum"],
                                                 "server_script_sha256": hashlib.sha256(Path(__file__).with_name("lab_http_server.py").read_bytes()).hexdigest()})

        with lab.ssh["dmz"].open_sftp() as sftp:
            sftp.put(str(Path(__file__).with_name("lab_http_server.py")), server_script)
        command = "systemd-run --unit=" + shlex.quote(server_unit) + " /usr/bin/python3 " + shlex.quote(server_script) + " --log " + shlex.quote(server_log)
        start = lab.command("dmz", command, sudo=True, evidence="server-start.json")
        require(start["exit_code"] == 0, "cannot start DMZ origin")
        started_server = True
        for _ in range(40):
            ready = lab.command("dmz", "ss -H -lnt sport = :80 | grep -F 10.20.0.10")
            if ready["exit_code"] == 0:
                break
            time.sleep(0.25)
        require(ready["exit_code"] == 0, "DMZ origin did not begin listening")

        baseline_marker = "base-" + secrets.token_hex(5)
        curl = "curl --noproxy '*' --silent --show-error --include --max-time 10 -H " + shlex.quote("X-M4-Marker: " + baseline_marker) + " http://10.20.0.10/clean"
        baseline_result = lab.command("lan", curl, timeout=15, evidence="M4-02-baseline-client.json")
        require(baseline_result["exit_code"] == 0 and "200 OK" in baseline_result["stdout"] and baseline_marker in baseline_result["stdout"], "M4 OFF baseline HTTP failed")
        report["checks"]["M4-02-baseline"] = "PASS"

        invalid = copy.deepcopy(baseline)
        invalid["request_gate"] = {"enabled": True, "worker_count": 5}
        touched_candidate = True
        reject = lab.api("PUT", "/config/candidate", payload=invalid, evidence="M4-03-invalid-candidate.json")
        require(reject["status"] == 400, "invalid M4 candidate was not rejected")
        after_reject = lab.api("GET", "/config")
        require(after_reject["response"]["data"]["candidate"] == baseline and after_reject["response"]["data"]["running"] == baseline, "invalid candidate changed state")
        report["checks"]["M4-03-invalid-config"] = "PASS"

        candidate = copy.deepcopy(baseline)
        candidate["request_gate"] = {"enabled": True}
        candidate["security_profiles"] = (candidate.get("security_profiles") or []) + [{
            "id": "m4-lab-http", "name": "M4 HTTP acceptance", "tls_mode": "METADATA_ONLY",
            "request_gate": {"enabled": True, "fail_mode": "CLOSE", "oversize_action": "BLOCK", "unsupported_encoding_action": "BLOCK"}}]
        candidate["policies"] = (candidate.get("policies") or []) + [{
            "id": "m4-lab-lan-dmz-http", "name": "M4 LAN to DMZ HTTP", "priority": 50,
            "source_zones": ["lan"], "destination_zones": ["dmz"],
            "source_addresses": ["192.168.10.10/32"], "destination_addresses": ["10.20.0.10/32"],
            "services": ["tcp:80"], "security_profile_id": "m4-lab-http",
            "action": "ALLOW", "scope": "SESSION", "enabled": True}]
        stage = lab.api("PUT", "/config/candidate", payload=candidate, evidence="candidate-stage.json")
        require(stage["status"] == 200, "valid M4 candidate rejected: " + str(stage["response"].get("error")))
        commit = lab.api("POST", "/policies/commit", payload={"expected_version": initial_version,
                         "author": "m4-lab", "comment": "Temporary HTTP request-gate acceptance"}, evidence="candidate-commit.json")
        require(commit["status"] == 200, "M4 activation failed: " + str(commit["response"].get("error")))
        report["checks"]["M4-34-activate"] = "PASS"
        for _ in range(20):
            health = lab.api("GET", "/request-gate/health")
            if health["response"]["data"]["status"] == "healthy":
                break
            time.sleep(0.5)
        json_write(evidence / "active-health.json", health)
        require(health["response"]["data"]["status"] == "healthy", "M4 did not become healthy")
        for name, command in [("active-nft.json", "nft -a list ruleset"),
                              ("active-ip-rule.json", "ip -4 rule show"),
                              ("active-ip-route-140.json", "ip -4 route show table 140")]:
            lab.command("ngfw", command, sudo=True, evidence=name)

        for label, body, want in [("clean", None, "200 OK"), ("sqli", "UNION SELECT", "403 Forbidden"),
                                  ("xss", "<script>alert(1)</script>", "403 Forbidden")]:
            marker = label + "-" + secrets.token_hex(5)
            path = "/" + marker
            command = "curl --noproxy '*' --silent --show-error --include --max-time 12 -H " + shlex.quote("X-M4-Marker: " + marker)
            if body is not None:
                command += " -X POST --data " + shlex.quote(body)
            command += " http://10.20.0.10" + path
            result = lab.command("lan", command, timeout=17, evidence="M4-client-" + label + ".json")
            report["checks"]["M4-" + label] = {"expected": want, "marker": marker, "path": path,
                                               "client_exit": result["exit_code"], "response_match": want in result["stdout"]}
        access = lab.command("dmz", "cat " + shlex.quote(server_log), evidence="dmz-access.json")
        lines = [json.loads(line) for line in access["stdout"].splitlines() if line.strip()]
        seen = {line["marker"] for line in lines}
        for label in ["clean", "sqli", "xss"]:
            check = report["checks"]["M4-" + label]
            check["upstream_seen"] = check["marker"] in seen
            check["result"] = "PASS" if check["client_exit"] == 0 and check["response_match"] and check["upstream_seen"] == (label == "clean") else "FAIL"
        for name, command in [("proxy-journal.json", "journalctl -u ngfw-proxy -n 150 --no-pager"),
                              ("engine-journal.json", "journalctl -u ngfw-engine -n 150 --no-pager")]:
            lab.command("ngfw", command, sudo=True, evidence=name)
        lab.api("GET", "/request-gate/health", evidence="active-health-after-traffic.json")
        evidence_response = lab.api("GET", "/request-gate/evidence?limit=128", evidence="request-evidence.json")
        decisions = evidence_response["response"].get("data", {}).get("items", [])
        for label in ["clean", "sqli", "xss"]:
            check = report["checks"]["M4-" + label]
            matches = [item for item in decisions if item["context"]["path"] == check["path"]]
            require(len(matches) == 1, "missing unique request evidence for " + label)
            item = matches[0]
            expected_reason = "GATE_INSPECTION_COMPLETE" if label == "clean" else "GATE_SIGNATURE_BLOCK"
            sid = {"sqli": "9904003", "xss": "9904004"}.get(label)
            check["reason_code"] = item["decision"]["reason_code"]
            check["request_id"] = item["context"]["request_id"]
            check["session_id"] = item["decision"].get("session_id")
            check["evidence_match"] = item["decision"]["reason_code"] == expected_reason and item["decision"]["coverage"] == "COMPLETE" and item["inspection"]["completed"] and (
                sid is None or any(alert.get("signature_id") == sid for alert in item["inspection"].get("alerts", [])))
            if not check["evidence_match"]:
                check["result"] = "FAIL"
    except Exception as error:
        report["error"] = str(error)
    finally:
        if lab is not None:
            try:
                lab.command("ngfw", "journalctl -u ngfw-engine -u ngfw-proxy -n 120 --no-pager", sudo=True, evidence="runtime-journal-final.json")
                if baseline is not None:
                    current = lab.api("GET", "/config")
                    state = current["response"]["data"]
                    if touched_candidate and (state["running"] != baseline or state["candidate"] != baseline):
                        stage = lab.api("PUT", "/config/candidate", payload=baseline, evidence="restore-candidate.json")
                        require(stage["status"] == 200, "failed to restore Candidate")
                        if state["running"] != baseline:
                            restore = lab.api("POST", "/policies/commit", payload={
                                "expected_version": state["version"]["version"], "author": "m4-lab",
                                "comment": "Restore pre-test Running config"}, evidence="restore-commit.json")
                            require(restore["status"] == 200, "failed to restore Running")
                    if touched_candidate and initial_candidate != baseline:
                        draft = lab.api("PUT", "/config/candidate", payload=initial_candidate, evidence="restore-original-draft.json")
                        require(draft["status"] == 200, "failed to restore original Candidate draft")
                    final = lab.api("GET", "/config", evidence="final-config.json")
                    report["config_restored"] = final["response"]["data"]["running"] == baseline and final["response"]["data"]["candidate"] == initial_candidate
                    lab.api("GET", "/request-gate/health", evidence="final-health.json")
                    lab.command("ngfw", "ip -4 rule show; ip -4 route show table 140", sudo=True, evidence="final-ip-routing.json")
                    journal = lab.command("ngfw", "test ! -e /var/lib/ngfw/dataplane-applied.json.activation", sudo=True, evidence="final-journal-absent.json")
                    selector = lab.command("ngfw", "nft -j list table inet ngfw_proxy", sudo=True, evidence="final-selector.json")
                    routes = lab.command("ngfw", "ip -j -4 rule show", sudo=True, evidence="final-routing-rules.json")
                    route_rules = json.loads(routes["stdout"]) if routes["exit_code"] == 0 else []
                    selector_objects = json.loads(selector["stdout"]).get("nftables", []) if selector["exit_code"] == 0 else []
                    report["kernel_restored"] = journal["exit_code"] == 0 and selector["exit_code"] == 0 and routes["exit_code"] == 0 and not any(
                        entry.get("chain", {}).get("hook") == "prerouting" for entry in selector_objects) and not any(
                        entry.get("table") == 140 for entry in route_rules)
                    report["restored"] = report["config_restored"] and report["kernel_restored"]
                if started_server:
                    lab.command("dmz", "systemctl stop " + shlex.quote(server_unit), sudo=True, evidence="server-stop.json")
            except Exception as error:
                report["restore_error"] = str(error)
            lab.close()
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        json_write(evidence / "result.json", report)
        print(json.dumps(report, indent=2))
    return 0 if report["restored"] and not report.get("error") and all(
        item == "PASS" or isinstance(item, dict) and item.get("result") == "PASS"
        for item in report["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
