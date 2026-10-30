"""Focused M4-15 recheck with mandatory/optional client auth on TLS 1.2/1.3."""

import json
import secrets
import shlex
import time

from health_poll import HealthObservationError, wait_for_health_counters
from lab_https_acceptance import json_write, require, utc_now


def run_mtls_cases(*, lab, evidence, report, healthy, lan_client, lan_ca, dmz_log,
                   remote_dmz_dir, origin_unit, remote_dir, ca_cert):
    report["client_time_policy"] = "Normal VM OS clock and CA/SAN verification; no override"
    generation = healthy["response"]["data"]["generation"]
    extra_files = []
    ca_bytes = (evidence / "ca.crt").read_bytes()
    dmz_ca = remote_dmz_dir + "/ca.crt"
    lab.upload_bytes("dmz", dmz_ca, ca_bytes, 0o644)

    def origin(label, version="auto", auth="none", cert="origin", close=False):
        lab.command("dmz", "systemctl stop " + shlex.quote(origin_unit), sudo=True)
        parts = ["systemd-run", "--unit=" + origin_unit, "--collect", "--property=RuntimeMaxSec=900",
                 "/usr/bin/python3", remote_dmz_dir + "/origin.py", "--cert", remote_dmz_dir + "/" + cert + ".crt",
                 "--key", remote_dmz_dir + "/" + cert + ".key", "--log", dmz_log,
                 "--ca", dmz_ca, "--tls-version", version, "--client-auth", auth]
        if close:
            parts.append("--close-after-handshake")
        result = lab.command("dmz", " ".join(shlex.quote(p) for p in parts), sudo=True,
                             evidence=label + "/origin-start.json")
        require(result["exit_code"] == 0, "SETUP: temporary TLS origin could not restart")
        for _ in range(20):
            check = lab.command("dmz", "ss -lntp sport = :443", sudo=True, save=False)
            if len(check["stdout"].splitlines()) > 1:
                break
            time.sleep(0.1)
        else:
            require(False, "SETUP: TLS origin did not listen")

    def request(label, *, status, code, counter, requested=False, body=None, host="dmz-m4.test", version=None, blocked=False):
        marker = label.lower() + "-" + secrets.token_hex(6)
        before = lab.api("GET", "/request-gate/health", evidence=label + "/health-before.json")
        parts = [lan_client, "--ca", lan_ca, "--ip", "10.20.0.10", "--host", host,
                 "--path", "/" + marker, "--marker", marker, "--method", "POST" if body else "GET",
                 "--body", body or ""]
        output = lab.command("lan", " ".join(shlex.quote(p) for p in parts), timeout=25,
                             evidence=label + "/client.json")
        client = json.loads(output["stdout"]) if output["stdout"].strip() else {}
        log = lab.command("dmz", "cat " + shlex.quote(dmz_log), sudo=True, evidence=label + "/origin.json")
        origin_rows = [json.loads(line) for line in log["stdout"].splitlines() if line.strip()]
        matches = [item for item in origin_rows if item.get("marker") == marker]
        record = {"marker": marker, "client_exit": output["exit_code"], "client": client,
                  "origin": matches, "result": "PENDING"}
        report["scenarios"][label] = record
        json_write(evidence / "progress.json", report)
        require(output["exit_code"] == 0 and client.get("status") == status and client.get("tls_verified"),
                label + " FAIL: status or normal client CA/SAN verification failed")
        require(len(matches) == (1 if status == 200 else 0), label + " FAIL: unexpected origin HTTP request")
        if matches:
            require(matches[0].get("client_certificate") is False, label + " FAIL: proxy impersonated a client certificate")
            if version:
                require(matches[0].get("tls_version") == "TLSv" + version, label + " FAIL: wrong upstream TLS version")
            require(matches[0].get("body_sha256") == client.get("body_sha256"), label + " FAIL: forwarded payload changed")

        found = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            page = lab.api("GET", "/request-gate/evidence?limit=128")
            found = [item for item in page.get("response", {}).get("data", {}).get("items", [])
                     if item.get("context", {}).get("path") == "/" + marker]
            if len(found) == 1 and (blocked or found[0].get("forward") is not None):
                break
            time.sleep(0.1)
        json_write(evidence / label / "request-evidence.json", page)
        require(len(found) == 1, label + " FAIL: no unique engine request record")
        item = found[0]
        record["evidence"] = item
        decision = item.get("decision", {})
        require(decision.get("config_generation") == generation and decision.get("coverage") == "COMPLETE"
                and decision.get("verdict") == ("BLOCK" if blocked else "ALLOW"),
                label + " FAIL: transport outcome changed authoritative content decision")
        if blocked:
            require(item.get("forward") is None and decision.get("reason_code") == "GATE_SIGNATURE_BLOCK",
                    label + " FAIL: blocked request was forwarded or misclassified")
            after_stamp = item["observed_at"]
        else:
            forward = item.get("forward") or {}
            require(forward.get("http_status") == status and forward.get("reason_code") == code
                    and forward.get("client_certificate_requested", False) is requested,
                    label + " FAIL: missing or incorrect per-request upstream result")
            after_stamp = forward["observed_at"]
        base = before["response"]["data"]["counters"]
        minimum = {key: base.get(key, 0) + 1 for key in ("decrypted", "intercepted", "request_blocked" if blocked else "request_allowed")}
        if counter:
            minimum[counter] = base.get(counter, 0) + 1
        try:
            after, samples = wait_for_health_counters(
                lambda timeout: lab.api("GET", "/request-gate/health", timeout=timeout),
                generation=generation, after=after_stamp, minimum_counters=minimum)
        except HealthObservationError as error:
            json_write(evidence / label / "health-observations.json", error.observations)
            raise RuntimeError(label + " FAIL: " + str(error)) from error
        json_write(evidence / label / "health-observations.json", samples)
        json_write(evidence / label / "health-after.json", after)
        new = after["response"]["data"]["counters"]
        record["counter_deltas"] = {key: new.get(key, 0) - base.get(key, 0) for key in new if new.get(key, 0) != base.get(key, 0)}
        require(new.get("result_report_fail", 0) == base.get("result_report_fail", 0)
                and new.get("bypassed", 0) == base.get("bypassed", 0),
                label + " FAIL: result IPC failed or a TLS error silently bypassed")
        require(counter == "upstream_mtls_unsupported" or new.get("upstream_mtls_unsupported", 0) == base.get("upstream_mtls_unsupported", 0),
                label + " FAIL: optional/auth-free/network failure mislabeled as mandatory mTLS")
        record["result"] = "PASS"
        json_write(evidence / label / "assessment.json", record)
        json_write(evidence / "progress.json", report)
        print(json.dumps({"at": utc_now(), "case": label, "result": "PASS"}), flush=True)

    try:
        request("clean-control", status=200, code="UPSTREAM_RESPONSE_RECEIVED", counter=None, body="ordinary=payload")
        request("sqli-control", status=403, code=None, counter=None, body="UNION SELECT", blocked=True)
        request("xss-control", status=403, code=None, counter=None, body="<script>alert(1)</script>", blocked=True)
        for version in ("1.2", "1.3"):
            tag = "tls" + version.replace(".", "")
            for auth in ("none", "optional", "required"):
                label = tag + "-" + auth
                origin(label, version, auth)
                if auth == "required":
                    request(label, status=502, code="TLS_UPSTREAM_MTLS_UNSUPPORTED",
                            counter="upstream_mtls_unsupported", requested=True)
                else:
                    request(label, status=200, code="UPSTREAM_RESPONSE_RECEIVED", counter=None,
                            requested=auth == "optional", body="payload=" + secrets.token_hex(20), version=version)
            origin(tag + "-hostname-config", version)
            request(tag + "-hostname-mismatch", status=502, code="TLS_UPSTREAM_VERIFY_FAILED", counter="upstream_verify_fail", host="other-m4.test")
            origin(tag + "-network-config", version, "optional", close=True)
            request(tag + "-network-close", status=502, code="TLS_UPSTREAM_CONNECT_FAILED", counter="upstream_connect_fail", requested=True)

        lab.command("dmz", "systemctl stop " + shlex.quote(origin_unit), sudo=True)
        request("tcp-refused", status=502, code="TLS_UPSTREAM_CONNECT_FAILED", counter="upstream_connect_fail")
        report["scenarios"]["M4-15"] = "PASS_TLS12_TLS13_REQUIRED_OPTIONAL_AND_NEGATIVE_CONTROLS"
        report["status"] = "PASS_M4-15_RECHECK"
    finally:
        lab.command("dmz", "rm -f -- " + shlex.quote(dmz_ca), sudo=True, save=False)
        for host, path in extra_files:
            lab.command(host, "rm -f -- " + shlex.quote(path), sudo=True, save=False)
