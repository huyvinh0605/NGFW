#!/usr/bin/env python3
"""M3-03: verify Candidate operations against the real appliance without commit.

Requires requests, paramiko and NGFW_LAB_PASSWORD. Records complete API
envelopes (without authentication headers) and restores the original draft.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


class CaseFailure(RuntimeError):
    pass


class NotRun(RuntimeError):
    pass


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def response_data(envelope):
    if not isinstance(envelope, dict) or envelope.get("success") is not True or "data" not in envelope:
        raise CaseFailure("API response requires success=true and a data member")
    return envelope["data"]


def config_data(envelope):
    """Unwrap exactly once; absent/null fields are errors, never fake drift."""
    data = response_data(envelope)
    if not isinstance(data, dict):
        raise CaseFailure("config response data is not an object")
    for name in ("running", "candidate", "version", "candidate_validation"):
        if not isinstance(data.get(name), dict):
            raise CaseFailure("config response data.%s is missing or not an object" % name)
    version = data["version"].get("version")
    if type(version) is not int or version <= 0:
        raise CaseFailure("config response data.version.version must be a positive integer")
    return data


def nft_semantics(value):
    if isinstance(value, list):
        return [nft_semantics(item) for item in value]
    if isinstance(value, dict):
        return {key: nft_semantics(item) for key, item in value.items()
                if key not in ("handle", "counter")}
    return value


def candidate_semantics(value):
    """Allow documented OR-selector normalization only; retain rule order/action.

    SetCandidateIfValid canonicalizes these fields (policy_canonical.go and
    service.go). Everything outside these selector representations stays exact.
    """
    result = copy.deepcopy(value)
    for policy in result.get("policies", []):
        for field in ("source_zones", "destination_zones", "applications"):
            policy[field] = sorted({item.strip().lower() for item in policy.get(field) or [] if item.strip()})
        for field in ("source_addresses", "destination_addresses"):
            policy[field] = sorted({str(ipaddress.ip_network(item.strip(), strict=False))
                                    for item in policy.get(field) or []})
        services = set()
        for raw in policy.get("services") or []:
            parts = raw.lower().strip().split(":")
            if len(parts) == 1 and parts[0] in ("icmp", "icmpv6"):
                services.add(parts[0])
            elif len(parts) == 2 and parts[0].strip() in ("tcp", "udp"):
                ports = [int(part.strip()) for part in parts[1].split("-")]
                if len(ports) not in (1, 2) or not 1 <= ports[0] <= ports[-1] <= 65535:
                    raise CaseFailure("cannot compare an invalid service selector")
                services.add(parts[0].strip() + ":" + str(ports[0]) +
                             ("-" + str(ports[-1]) if ports[0] != ports[-1] else ""))
            else:
                raise CaseFailure("cannot compare an invalid service selector")
        policy["services"] = sorted(services)
    return result


def draft_for_case(running, marker):
    candidate = copy.deepcopy(running)
    if type(candidate.get("max_sessions")) is not int or candidate["max_sessions"] < 1:
        raise NotRun("Running has no positive max_sessions")
    eligible = [p for p in candidate.get("policies", []) if p.get("enabled") and
                p.get("action") == "ALLOW" and "lan" in (p.get("source_zones") or []) and
                "wan" in (p.get("destination_zones") or []) and
                "mgmt" not in (p.get("source_zones") or [])]
    if not eligible:
        raise NotRun("no existing scoped LAN-to-WAN ALLOW policy for an IDS Candidate")
    policy = min(eligible, key=lambda p: p["priority"])
    candidate["max_sessions"] += 1
    candidate["inspection"] = {"enabled": True, "include_management": False, "limits": {}}
    profile = {"id": marker, "name": "M3-03 temporary Candidate", "tls_mode": "METADATA_ONLY",
               "ids_ips_enabled": True,
               "inspection": {"mode": "IDS", "fail_mode": "OPEN", "ruleset_id": "m3-builtin-v1"}}
    candidate["security_profiles"] = list(candidate.get("security_profiles") or []) + [profile]
    policy["security_profile_id"] = marker
    policy["applications"] = []
    policy["application_match_mode"] = ""
    return candidate


class Lab:
    def __init__(self, root, host, user, api_base):
        import paramiko
        import requests
        self.root, self.host, self.user, self.api_base = root, host, user, api_base.rstrip("/")
        self.password = os.environ["NGFW_LAB_PASSWORD"]
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.session = requests.Session()
        self.token = ""
        self.seq = 0

    def save(self, name, data):
        (self.root / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def connect(self):
        self.ssh.connect(self.host, username=self.user, password=self.password, timeout=8,
                         look_for_keys=False, allow_agent=False)
        # Secret material stays in memory and is excluded from command evidence.
        env = self.command("cat /etc/ngfw/ngfw.env", evidence=False)
        self.token = next((line.split("=", 1)[1].strip().strip("\"'") for line in env.splitlines()
                           if line.startswith("NGFW_API_TOKEN=")), "")
        if not self.token:
            raise NotRun("appliance API token unavailable")

    def command(self, command, evidence=True):
        start = utc()
        issued = "sudo -S -p '' bash -lc " + shlex.quote(command)
        stdin, stdout, stderr = self.ssh.exec_command(issued, timeout=30)
        stdin.write(self.password + "\n")
        stdin.flush()
        stdin.channel.shutdown_write()
        out, err = stdout.read().decode("utf-8", "replace"), stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        if evidence:
            with (self.root / "commands.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"command": command, "started_at": start, "ended_at": utc(),
                                         "exit_code": code, "stdout": out, "stderr": err}) + "\n")
        if code:
            raise CaseFailure("remote command exited %d: %s" % (code, command))
        return out

    def request(self, method, path, body=None, expected=200):
        self.seq += 1
        item = {"method": method, "path": path, "started_at": utc()}
        if body is not None:
            item["request_body"] = body
        name = "api-%03d.json" % self.seq
        try:
            response = self.session.request(method, self.api_base + path,
                                            headers={"Authorization": "Bearer " + self.token},
                                            json=body, timeout=10)
            item.update({"status_code": response.status_code,
                         "response_text": response.text.replace(self.token, "[REDACTED]")})
            payload = response.json()
            if response.status_code != expected:
                raise CaseFailure("%s %s returned HTTP %d (expected %d); see %s" %
                                  (method, path, response.status_code, expected, name))
            return payload
        except Exception as exc:
            item["error"] = type(exc).__name__ + ": " + str(exc)
            raise
        finally:
            item["ended_at"] = utc()
            self.save(name, item)

    def config(self):
        return config_data(self.request("GET", "/config"))

    def candidate(self):
        value = response_data(self.request("GET", "/config/candidate"))
        if not isinstance(value, dict):
            raise CaseFailure("Candidate response data is not an object")
        return value

    def snapshot(self, name):
        nft = json.loads(self.command("nft -j list table inet ngfw"))
        addresses = json.loads(self.command("ip -j address show"))
        routes = json.loads(self.command("ip -j route show table main"))
        files = self.command("sha256sum /var/lib/ngfw/running.json /var/lib/ngfw/dataplane-applied.json")
        services = self.command("systemctl show ngfw-engine ngfw-api ngfw-suricata-ids ngfw-suricata-ips -p Id -p ActiveState -p MainPID -p NRestarts")
        journals = self.command("find /var/lib/ngfw -maxdepth 1 -type f -iname '*activation*' -printf '%f\\n' | sort")
        inspection = response_data(self.request("GET", "/inspection/health"))
        signature = {"nft_semantic_sha256": digest(nft_semantics(nft)),
                     "addresses_sha256": digest(addresses), "routes_sha256": digest(routes),
                     "state_file_hashes": files, "services": services, "activation_files": journals,
                     "inspection_enabled": inspection.get("enabled"), "inspection_status": inspection.get("status")}
        self.save(name + ".json", {"nft": nft, "addresses": addresses, "routes": routes,
                                  "inspection": inspection, "signature": signature})
        return signature

    def identity(self):
        self.command("uname -a; nft --version; suricata --build-info; sha256sum /usr/bin/suricata /usr/local/lib/ngfw/ngfw-engine /usr/local/lib/ngfw/ngfw-api")

    def close(self):
        self.session.close()
        self.ssh.close()
        self.token = ""


def run_case(lab, marker):
    report = {"scenario": "M3-03", "started_at": utc(), "assertions": [], "status": "NOT_RUN"}
    original = baseline = kernel = audit = None
    owned = set()
    attempted = False
    completed = False
    phase = "setup"

    def check(name, passed, observed=None, expected=None, fatal=True):
        report["assertions"].append({"name": name, "status": "PASS" if passed else "FAIL",
                                     "observed": observed, "expected": expected})
        if not passed and fatal:
            raise CaseFailure(name)

    def unchanged(name, config):
        actual = {"running": digest(config["running"]), "version": config["version"]}
        wanted = {"running": digest(baseline["running"]), "version": baseline["version"]}
        check(name, actual == wanted, actual, wanted)

    def save(candidate):
        nonlocal attempted
        attempted = True
        saved = response_data(lab.request("PUT", "/config/candidate", candidate))
        if not isinstance(saved, dict):
            raise CaseFailure("save response data is not an object")
        owned.add(digest(saved))
        check("Candidate save/load roundtrip", lab.candidate() == saved)
        return saved

    try:
        lab.connect()
        baseline = lab.config()
        original = copy.deepcopy(baseline["candidate"])
        if baseline.get("candidate_valid") is not True:
            raise NotRun("original Candidate is invalid and cannot be safely restored with PUT")
        check("baseline Candidate GET matches config view", lab.candidate() == original)
        lab.identity()
        audit = response_data(lab.request("GET", "/audit?limit=1000"))
        kernel = lab.snapshot("kernel-before")
        if kernel["activation_files"]:
            raise NotRun("an activation journal already exists")
        lab.save("config-before.json", baseline)
        draft = draft_for_case(baseline["running"], marker)
        # Recheck immediately before replacing the draft; do not clobber a user edit.
        if lab.candidate() != original:
            raise NotRun("Candidate changed concurrently before the test started")
        phase = "workflow"
        saved = save(draft)
        check("M3 IDS draft remains explicit", saved["inspection"]["enabled"] is True and
              any(p["id"] == marker and p["inspection"]["mode"] == "IDS" for p in saved["security_profiles"]))
        after_save = lab.config()
        unchanged("save/load does not change Running or version", after_save)
        check("new draft has no inherited validation", after_save["candidate_validation"]["state"] == "NOT_RUN")
        check("save/load does not change kernel or services", lab.snapshot("kernel-after-save") == kernel)

        for revision in range(2):
            validation = response_data(lab.request("POST", "/policies/validate"))
            check("Candidate validate returns valid", isinstance(validation, dict) and validation.get("valid") is True)
            view = lab.config()
            state = view["candidate_validation"]
            check("validation covers current revision", state["state"] == "VALID" and
                  bool(state["candidate_checksum"]) and state["candidate_checksum"] == state["checked_checksum"], state)
            check("GET/validate preserves saved Candidate", view["candidate"] == saved)
            unchanged("validate does not change Running or version", view)
            check("validate does not change kernel or services", lab.snapshot("kernel-validated-%d" % revision) == kernel)
            if revision == 0:
                edited = copy.deepcopy(saved)
                edited["max_sessions"] += 1
                saved = save(edited)
                edited_view = lab.config()
                edited_state = edited_view["candidate_validation"]
                check("edit invalidates previous validation", edited_state["state"] == "NOT_RUN" and
                      edited_state["candidate_checksum"] != state["candidate_checksum"] and
                      edited_state["checked_checksum"] != edited_state["candidate_checksum"], edited_state)
                unchanged("edit does not change Running or version", edited_view)
        completed = True
    except Exception as exc:
        report["status"] = "NOT_RUN" if phase == "setup" else "FAIL"
        report["reason"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if original is not None and attempted:
            try:
                current = lab.candidate()
                if current != original:
                    if digest(current) not in owned:
                        raise CaseFailure("Candidate changed externally; cleanup will not overwrite that edit")
                    restored = response_data(lab.request("PUT", "/config/candidate", original))
                    check("restore original Candidate semantics", candidate_semantics(restored) == candidate_semantics(original))
                    report["candidate_restoration"] = {"original_raw_sha256": digest(original),
                                                       "restored_raw_sha256": digest(restored),
                                                       "canonicalization_only": restored != original}
                    prior_state = baseline["candidate_validation"]["state"]
                    if prior_state in ("VALID", "INVALID"):
                        lab.request("POST", "/policies/validate", expected=200 if prior_state == "VALID" else 400)
                final = lab.config()
                check("final Candidate and validation state restored", candidate_semantics(final["candidate"]) == candidate_semantics(original) and
                      final["candidate_validation"]["state"] == baseline["candidate_validation"]["state"])
                unchanged("final Running and version unchanged", final)
                check("final kernel and services unchanged", lab.snapshot("kernel-after") == kernel)
                final_audit = response_data(lab.request("GET", "/audit?limit=1000"))
                before_ids = {item["id"] for item in audit["items"]}
                new = [item for item in final_audit["items"] if item["id"] not in before_ids]
                check("audit delta is complete", len(new) == final_audit["total"] - audit["total"])
                check("no COMMIT or ROLLBACK audit", not any(item["action"] in ("COMMIT", "ROLLBACK") for item in new), new)
                lab.save("audit-delta.json", new)
                lab.save("config-after.json", final)
                report["restore"] = "PASS"
            except Exception as exc:
                report.update(status="FAIL", restore="FAIL", cleanup_error=type(exc).__name__ + ": " + str(exc))
                report["reason"] = report.get("reason") or report["cleanup_error"]
        if completed and report.get("restore") == "PASS" and not any(x["status"] == "FAIL" for x in report["assertions"]):
            report["status"] = "PASS"
        report["workflow_completed"] = completed
        report["ended_at"] = utc()
        report["assertion_counts"] = {state: sum(x["status"] == state for x in report["assertions"])
                                      for state in ("PASS", "FAIL")}
        lab.save("result.json", report)
        lab.close()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--host", default="192.168.100.1")
    parser.add_argument("--user", default="huy")
    parser.add_argument("--api-base", default="http://192.168.100.1:8080/api/v1")
    args = parser.parse_args()
    if not os.environ.get("NGFW_LAB_PASSWORD"):
        parser.error("NGFW_LAB_PASSWORD is required")
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    lab = Lab(args.evidence_dir, args.host, args.user, args.api_base)
    root = Path(__file__).resolve().parents[3]
    identity = {"runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        identity["git_head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        identity["git_head"] = "UNAVAILABLE"
    lab.save("runner-identity.json", identity)
    result = run_case(lab, "m3-03-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
    print(json.dumps({"scenario": result["scenario"], "status": result["status"],
                      "assertion_counts": result["assertion_counts"], "reason": result.get("reason"),
                      "restore": result.get("restore"), "evidence_dir": str(args.evidence_dir)}))
    return 0 if result["status"] == "PASS" else 2 if result["status"] == "NOT_RUN" else 1


if __name__ == "__main__":
    sys.exit(main())
