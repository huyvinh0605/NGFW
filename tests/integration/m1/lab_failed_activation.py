#!/usr/bin/env python3
"""Reproduce M1 matrix row 20 on the real NGFW VM and restore its Candidate.

Requires NGFW_LAB_PASSWORD and an empty evidence directory. The API token is
read over SSH into memory and is never written to the evidence directory.
"""

import copy
import json
import os
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko
import requests


def now():
    return datetime.now(timezone.utc).isoformat()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def normalize_nft(value, epoch):
    """Ignore kernel handles and the M2 cache epoch, checking every other bit."""
    if isinstance(value, list):
        return [normalize_nft(item, epoch) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: normalize_nft(item, epoch) for key, item in value.items()
              if key not in ("handle", "counter")}
    mark = {"ct": {"key": "mark"}}
    match = result.get("match")
    if isinstance(match, dict) and match.get("left") == mark:
        prefix = match.get("right", {}).get("prefix")
        if isinstance(prefix, dict) and isinstance(prefix.get("addr"), int):
            require(prefix["addr"] >> 20 == epoch, "nft cache match has unexpected epoch")
            prefix["addr"] &= 0x000fffff
    mangle = result.get("mangle")
    if isinstance(mangle, dict) and mangle.get("key") == mark:
        operands = mangle["value"]["|"]
        require(operands[0]["&"][0] == mark, "unexpected ct mark update")
        for item in (operands[0]["&"][1], operands[1]):
            require(item >> 20 == epoch, "nft cache mutation has unexpected epoch")
        operands[0]["&"][1] &= 0x000fffff
        operands[1] &= 0x000fffff
    return result


class Gateway:
    def __init__(self, root, password):
        self.root = root
        self.password = password
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.http = requests.Session()
        self.http.trust_env = False

    def connect(self):
        self.ssh.connect("192.168.100.1", username="huy", password=self.password,
                         timeout=8, look_for_keys=False, allow_agent=False)
        env = self.run("cat /etc/ngfw/ngfw.env", sudo=True, record=False)
        require(env["exit_code"] == 0, "cannot read management credential")
        tokens = [line.split("=", 1)[1].strip().strip("\"'")
                  for line in env["stdout"].splitlines()
                  if line.startswith("NGFW_API_TOKEN=")]
        require(len(tokens) == 1 and tokens[0], "management credential missing")
        self.http.headers["Authorization"] = "Bearer " + tokens[0]

    def run(self, command, *, sudo=False, evidence=None, record=True):
        issued = "bash -lc " + shlex.quote(command)
        if sudo:
            issued = "sudo -S -p '' " + issued
        stdin, stdout, stderr = self.ssh.exec_command(issued, timeout=40)
        if sudo:
            stdin.write(self.password + "\n")
            stdin.flush()
            stdin.channel.shutdown_write()
        output = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
        value = {"command": command, "exit_code": stdout.channel.recv_exit_status(),
                 "stdout": output, "stderr": error, "captured_at": now()}
        if record and evidence:
            save(self.root / evidence, value)
        return value

    def api(self, method, path, body=None, evidence=None):
        response = self.http.request(method, "http://192.168.100.1:8080/api/v1" + path,
                                     json=body, timeout=40)
        value = {"method": method, "path": path, "status": response.status_code,
                 "response": response.json(), "captured_at": now()}
        if evidence:
            save(self.root / evidence, value)
        return value

    def config(self, evidence):
        result = self.api("GET", "/config", evidence=evidence)
        require(result["status"] == 200 and result["response"].get("success"),
                "GET /config failed")
        return result["response"]["data"]

    def close(self):
        self.http.close()
        self.ssh.close()


def checked_command(gateway, command, evidence, *, sudo=False):
    result = gateway.run("set -e\n" + command, sudo=sudo, evidence=evidence)
    require(result["exit_code"] == 0, evidence + " failed: " + result["stderr"])
    return result["stdout"]


def addresses(gateway, device, evidence):
    value = checked_command(gateway, "ip -4 -j address show dev " + device, evidence)
    return [item["local"] for link in json.loads(value)
            for item in link.get("addr_info", [])]


def mtu(gateway, device, evidence):
    value = checked_command(gateway, "ip -j link show dev " + device, evidence)
    links = json.loads(value)
    require(len(links) == 1, "missing link " + device)
    return links[0]["mtu"]


def main(root):
    require(not root.exists() or not any(root.iterdir()), "evidence directory is not empty")
    root.mkdir(parents=True, exist_ok=True)
    gateway = Gateway(root, os.environ["NGFW_LAB_PASSWORD"])
    result = {"id": "M1-20", "status": "NOT_RUN", "started_at": now(), "checks": []}
    original = None
    candidate_touched = False
    monitor = None

    def stop_monitor():
        nonlocal monitor
        if monitor is None:
            return ""
        pid, stdout, stderr = monitor
        gateway.run("kill -TERM " + pid, evidence="kernel-monitor-stop.json")
        output = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
        save(root / "kernel-transition.json", {"stdout": output, "stderr": error,
                                               "exit_code": stdout.channel.recv_exit_status(),
                                               "captured_at": now()})
        monitor = None
        return output

    def passed(name, **values):
        result["checks"].append({"name": name, "status": "PASS", **values})
        print("PASS M1-20: " + name, flush=True)

    try:
        gateway.connect()
        original = gateway.config("config-before.json")
        require(original["candidate_validation"]["state"] in ("NOT_RUN", "VALID"),
                "cannot restore the original Candidate validation state with this API")
        baseline_version = original["version"]["version"]
        running = original["running"]
        interfaces = {item["system_name"]: item for item in running["interfaces"]}
        require("ens33" in interfaces and "ens37" in interfaces and "ens39" in interfaces,
                "unexpected appliance interface layout")
        require(interfaces["ens37"]["ipv4_addresses"] == ["192.168.10.1/24"],
                "unexpected LAN address configuration")
        require(not any(item["id"] == "m1-unreachable-route" for item in running["routes"]),
                "test route ID already exists")

        checked_command(gateway,
                        "/usr/local/lib/ngfw/ngfw-engine --verify-network --state-dir /var/lib/ngfw; "
                        "test ! -e /var/lib/ngfw/dataplane-applied.json.activation; "
                        "systemctl is-active ngfw-engine ngfw-api",
                        "preflight.json", sudo=True)
        before_hashes = checked_command(gateway,
                                        "sha256sum /var/lib/ngfw/running.json "
                                        "/usr/local/lib/ngfw/ngfw-engine /usr/local/lib/ngfw/ngfw-api",
                                        "hashes-before.json", sudo=True)
        original_mtu = mtu(gateway, "ens33", "wan-link-before.json")
        require(original_mtu == interfaces["ens33"]["mtu"] and original_mtu > 576,
                "WAN MTU does not match Running or has no lower valid test value")
        require(addresses(gateway, "ens37", "lan-address-before.json") == ["192.168.10.1"],
                "LAN already has a foreign/temporary address")
        route_before = checked_command(gateway,
                                       "ip -4 -j route show exact 198.51.200.0/24",
                                       "test-route-before.json")
        require(json.loads(route_before) == [], "test route already exists")
        default_before = checked_command(gateway, "ip -4 -j route show default",
                                         "default-route-before.json")
        nft_before = json.loads(checked_command(gateway,
                                                "nft -j -s list table inet ngfw",
                                                "nft-before.json", sudo=True))
        applied_before = json.loads(checked_command(gateway,
                                                    "cat /var/lib/ngfw/dataplane-applied.json",
                                                    "applied-before.json", sudo=True))
        require(applied_before["config"] == running
                and applied_before["generation"] == baseline_version,
                "applied snapshot does not match the pre-test Running")
        expected_nft = normalize_nft(nft_before, applied_before["options"]["epoch"])
        passed("baseline is clean", version=baseline_version,
               engine_sha256=before_hashes.splitlines()[1].split()[0])

        target = copy.deepcopy(running)
        for item in target["interfaces"]:
            if item["system_name"] == "ens33":
                item["mtu"] = original_mtu - 1
            if item["system_name"] == "ens37":
                item["ipv4_addresses"].append("192.168.10.99/24")
        target["routes"].append({"id": "m1-unreachable-route",
                                 "destination_cidr": "198.51.200.0/24",
                                 "gateway": "203.0.113.1", "interface_id": interfaces["ens37"]["id"],
                                 "metric": 200, "enabled": True,
                                 "description": "M1 row 20 deliberate invalid gateway"})
        save(root / "candidate-under-test.json", target)
        candidate_touched = True
        saved = gateway.api("PUT", "/config/candidate", target, "candidate-save.json")
        require(saved["status"] == 200 and saved["response"].get("success"),
                "test Candidate was rejected")
        validated = gateway.api("POST", "/policies/validate", {}, "candidate-validate.json")
        require(validated["status"] == 200 and validated["response"].get("success")
                and validated["response"].get("data", {}).get("valid"),
                "test Candidate did not validate")
        monitor_command = "echo $$; exec stdbuf -oL ip -ts monitor link address route"
        _, monitor_stdout, monitor_stderr = gateway.ssh.exec_command(
            "exec sh -c " + shlex.quote(monitor_command), timeout=45)
        monitor_pid = monitor_stdout.readline().strip()
        require(monitor_pid.isdigit(), "cannot start kernel transition monitor")
        monitor = (monitor_pid, monitor_stdout, monitor_stderr)
        time.sleep(.2)
        commit = gateway.api("POST", "/policies/commit",
                             {"expected_version": baseline_version,
                              "author": "m1-row20-acceptance",
                              "comment": "M1 deliberate unreachable gateway activation failure"},
                             "failed-commit.json")
        require(commit["status"] == 409 and not commit["response"].get("success")
                and commit["response"].get("error", {}).get("code") == "COMMIT_FAILED"
                and "invalid gateway" in commit["response"]["error"].get("message", "").lower(),
                "actual kernel route failure was not exercised")
        passed("kernel rejects invalid gateway through API", http_status=commit["status"])
        transition = stop_monitor()
        relevant = [line for line in transition.splitlines()
                    if "192.168.10.99/24" in line and "ens37" in line]
        require(any("Deleted" not in line for line in relevant)
                and any("Deleted" in line for line in relevant),
                "kernel monitor did not observe both temporary address add and delete")
        require("ens33" in transition and "mtu " + str(original_mtu - 1) in transition,
                "kernel monitor did not observe the temporary WAN MTU")
        passed("kernel monitor proves temporary address add/delete and MTU mutation")

        after = gateway.config("config-after-failure.json")
        require(after["version"]["version"] == baseline_version
                and after["running"] == running, "failed activation changed Running")
        after_hashes = checked_command(gateway,
                                       "sha256sum /var/lib/ngfw/running.json "
                                       "/usr/local/lib/ngfw/ngfw-engine /usr/local/lib/ngfw/ngfw-api",
                                       "hashes-after-failure.json", sudo=True)
        require(after_hashes == before_hashes, "Running or installed binaries changed")
        passed("Running version/file and binaries unchanged", version=baseline_version)

        after_addresses = addresses(gateway, "ens37", "lan-address-after-failure.json")
        require(after_addresses == ["192.168.10.1"],
                "rollback left orphan LAN address or lost baseline LAN address")
        require(mtu(gateway, "ens33", "wan-link-after-failure.json") == original_mtu,
                "WAN MTU was not restored")
        route_after = checked_command(gateway,
                                      "ip -4 -j route show exact 198.51.200.0/24",
                                      "test-route-after-failure.json")
        require(json.loads(route_after) == [], "failed target route remained")
        default_after = checked_command(gateway, "ip -4 -j route show default",
                                        "default-route-after-failure.json")
        require(json.loads(default_after) == json.loads(default_before),
                "baseline default route changed")
        passed("LAN address, WAN MTU and routes restored")

        applied_after = json.loads(checked_command(gateway,
                                                   "cat /var/lib/ngfw/dataplane-applied.json",
                                                   "applied-after-failure.json", sudo=True))
        require(applied_after["generation"] == baseline_version
                and applied_after["config"] == running,
                "applied snapshot contains failed target")
        epoch_after = applied_after["options"]["epoch"]
        require(epoch_after > applied_before["options"]["epoch"],
                "compensating activation did not advance cache epoch")
        nft_after = json.loads(checked_command(gateway, "nft -j -s list table inet ngfw",
                                               "nft-after-failure.json", sudo=True))
        require(normalize_nft(nft_after, epoch_after) == expected_nft,
                "nft policy/NAT semantics changed after rollback")
        passed("nft and applied snapshot restored", epoch_before=applied_before["options"]["epoch"],
               epoch_after=epoch_after)

        checked_command(gateway,
                        "test ! -e /var/lib/ngfw/dataplane-applied.json.activation; "
                        "/usr/local/lib/ngfw/ngfw-engine --verify-network --state-dir /var/lib/ngfw; "
                        "/usr/local/lib/ngfw/verify-m1-linux.sh; "
                        "systemctl is-active ngfw-engine ngfw-api",
                        "post-rollback-verification.json", sudo=True)
        passed("journal absent, verifier and services healthy")
        result["status"] = "PASS"
    except Exception as error:
        result["status"] = "FAIL"
        result["error"] = type(error).__name__ + ": " + str(error)
        print("FAIL M1-20: " + result["error"], flush=True)
    finally:
        if monitor is not None:
            try:
                stop_monitor()
            except Exception as error:
                result["monitor_cleanup_error"] = str(error)
                result["status"] = "FAIL"
        if original and candidate_touched:
            try:
                current = gateway.config("config-before-restore.json")
                if current["version"]["version"] != original["version"]["version"] or current["running"] != original["running"]:
                    restore = gateway.api("PUT", "/config/candidate", original["running"],
                                          "running-restore-save.json")
                    require(restore["status"] == 200 and restore["response"].get("success"),
                            "could not stage original Running")
                    validation = gateway.api("POST", "/policies/validate", {},
                                             "running-restore-validate.json")
                    require(validation["status"] == 200 and validation["response"].get("success"),
                            "could not validate original Running")
                    committed = gateway.api("POST", "/policies/commit",
                                            {"expected_version": current["version"]["version"],
                                             "author": "m1-row20-acceptance",
                                             "comment": "restore original Running after acceptance"},
                                            "running-restore-commit.json")
                    require(committed["status"] == 200 and committed["response"].get("success"),
                            "could not commit original Running")
                restored = gateway.api("PUT", "/config/candidate", original["candidate"],
                                       "candidate-restore.json")
                require(restored["status"] == 200 and restored["response"].get("success"),
                        "could not restore original Candidate")
                if original["candidate_validation"]["state"] == "VALID":
                    validation = gateway.api("POST", "/policies/validate", {},
                                             "candidate-restore-validate.json")
                    require(validation["status"] == 200 and validation["response"].get("success"),
                            "could not restore Candidate validation")
                final = gateway.config("config-final.json")
                require(final["running"] == original["running"]
                        and final["candidate"] == original["candidate"],
                        "original Running/Candidate were not restored")
                require(final["candidate_validation"]["state"] == original["candidate_validation"]["state"],
                        "Candidate validation state was not restored")
                checked_command(gateway,
                                "/usr/local/lib/ngfw/ngfw-engine --verify-network --state-dir /var/lib/ngfw; "
                                "test ! -e /var/lib/ngfw/dataplane-applied.json.activation",
                                "final-network-verification.json", sudo=True)
                result["candidate_restored"] = True
                result["final_version"] = final["version"]["version"]
            except Exception as error:
                result["status"] = "FAIL"
                result["restore_error"] = type(error).__name__ + ": " + str(error)
                print("FAIL M1-20 restore: " + result["restore_error"], flush=True)
        gateway.close()
        result["finished_at"] = now()
        save(root / "result.json", result)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: lab_failed_activation.py EMPTY_EVIDENCE_DIRECTORY")
    raise SystemExit(main(Path(sys.argv[1]).resolve()))
