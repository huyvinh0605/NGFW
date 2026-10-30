"""Continuation of real-VM TLS acceptance, with no replacement NGFW binaries.

Called by lab_https_acceptance.py so the existing CA/config finalizer always
runs. Only synthetic traffic is captured. Engine strace observes writes, never
reads (in particular it cannot capture CA private-key reads by the proxy).
"""

import ast
import copy
import hashlib
import ipaddress
import json
import re
import secrets
import shlex
import ssl
import struct
import time

from health_poll import HealthObservationError, wait_for_health_counters
from lab_https_acceptance import json_write, require, utc_now


def pcap_streams(path):
    """Reassemble Ethernet/IPv4 TCP payloads, rejecting gaps and conflicting bytes."""
    data = path.read_bytes()
    require(len(data) >= 24, "EVIDENCE: truncated capture header")
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    require(endian is not None, "EVIDENCE: unsupported pcap format")
    require(struct.unpack_from(endian + "I", data, 20)[0] == 1,
            "EVIDENCE: expected Ethernet capture")
    offset, streams = 24, {}
    while offset < len(data):
        require(offset + 16 <= len(data), "EVIDENCE: truncated packet header")
        sec, usec, size, wire_size = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        packet = data[offset:offset + size]
        offset += size
        require(len(packet) == size and size == wire_size, "EVIDENCE: capture truncation")
        if len(packet) < 54 or packet[12:14] != b"\x08\x00":
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:
            continue
        total = struct.unpack_from("!H", ip, 2)[0]
        tcp = ip[ihl:total]
        header = (tcp[12] >> 4) * 4
        payload = tcp[header:]
        if not payload:
            continue
        source, destination = struct.unpack_from("!HH", tcp)
        sequence = struct.unpack_from("!I", tcp, 4)[0]
        key = (str(ipaddress.ip_address(ip[12:16])), source,
               str(ipaddress.ip_address(ip[16:20])), destination)
        streams.setdefault(key, []).append((sequence, payload, sec + usec / 1e6))
    result = {}
    for key, packets in streams.items():
        packets.sort(key=lambda item: item[0])
        base = packets[0][0]
        body = bytearray()
        for sequence, payload, _ in packets:
            start = sequence - base
            require(start <= len(body), "EVIDENCE: missing TCP bytes in " + str(key))
            overlap = min(len(body) - start, len(payload))
            require(body[start:start + overlap] == payload[:overlap],
                    "EVIDENCE: conflicting retransmission")
            body.extend(payload[overlap:])
        result[key] = {"bytes": bytes(body), "segments": len(packets),
                       "first": packets[0][2], "last": packets[-1][2]}
    return result


def run_tls_cases(*, lab, evidence, report, candidate, profile_id, policy_id, healthy,
                  lan_client, lan_ca, dmz_log, remote_dmz_dir, origin_unit,
                  remote_dir, origin_cert, ca_cert):
    run_id = report["run_id"]
    capture_units, capture_paths = [], []
    trace_unit = "ngfw-m4-trace-" + run_id
    trace_path = "/tmp/" + trace_unit + ".log"
    cert_read = lab.command("ngfw", "cat " + shlex.quote(origin_cert), sudo=True, save=False)
    require(cert_read["exit_code"] == 0, "SETUP: origin public certificate missing")
    der = ssl.PEM_cert_to_DER_cert(cert_read["stdout"])
    origin_sha = hashlib.sha256(der).hexdigest()
    (evidence / "origin.crt").write_text(cert_read["stdout"], encoding="utf-8")
    report["origin_leaf_sha256"] = origin_sha
    report["client_time_policy"] = "OS clock; no override; CA chain and DNS/IP SAN verified"
    lab.upload_bytes("lan", lan_ca + ".origin", cert_read["stdout"].encode(), 0o644)
    lab.upload_bytes("dmz", remote_dmz_dir + "/ca.crt",
                     (evidence / "ca.crt").read_bytes(), 0o644)
    current = copy.deepcopy(candidate)

    def snapshot(label):
        json_write(evidence / "progress.json", report)
        value = report["scenarios"].get(label)
        status = value.get("result", "PENDING") if isinstance(value, dict) else value
        print(json.dumps({"at": utc_now(), "case": label, "status": status}), flush=True)

    def commit(label, *, mode="DECRYPT", exclusions=None, fail_mode="CLOSE"):
        nonlocal current
        current = copy.deepcopy(candidate)
        profile = next(p for p in current["security_profiles"] if p["id"] == profile_id)
        profile["tls_mode"] = mode
        profile["request_gate"]["fail_mode"] = fail_mode
        current["tls_exclusions"] = exclusions or []
        state = lab.api("GET", "/config")["response"]["data"]
        stage = lab.api("PUT", "/config/candidate", payload=current, evidence=label + "/candidate.json")
        require(stage["status"] == 200, label + " FAIL: valid TLS configuration rejected")
        reply = lab.api("POST", "/policies/commit", payload={
            "expected_version": state["version"]["version"], "author": "m4-tls-acceptance",
            "comment": "Temporary " + label}, evidence=label + "/commit.json")
        require(reply["status"] == 200, label + " FAIL: TLS activation rejected")
        deadline = time.monotonic() + 20
        last = None
        while time.monotonic() < deadline:
            last = lab.api("GET", "/request-gate/health")
            data = last.get("response", {}).get("data", {})
            if (data.get("status") == "healthy" and data.get("https_listener_ready")
                    and data.get("generation") == state["version"]["version"] + 1):
                json_write(evidence / label / "active-health.json", last)
                return last
            time.sleep(0.25)
        json_write(evidence / label / "active-health.json", last)
        require(False, label + " FAIL: gate did not become healthy in its new generation")

    def capture_start(label):
        entries = []
        for name, interface, host in [("lan", "ens37", "192.168.10.10"),
                                      ("dmz", "ens38", "10.20.0.10")]:
            unit = "ngfw-m4-cap-" + run_id + "-" + label.lower().replace("_", "-") + "-" + name
            path = "/tmp/" + unit + ".pcap"
            command = ("systemd-run --unit=" + shlex.quote(unit) + " --collect --property=RuntimeMaxSec=60 "
                       "/usr/bin/tcpdump --immediate-mode -Z root -n -U -s 0 -i " + interface + " -w " + shlex.quote(path) +
                       " " + shlex.quote("host " + host + " and tcp port 443"))
            result = lab.command("ngfw", command, sudo=True, evidence=label + "/capture-start-" + name + ".json")
            require(result["exit_code"] == 0, "SETUP: could not start bounded tcpdump")
            capture_units.append(unit)
            capture_paths.append(path)
            entries.append((name, unit, path))
        time.sleep(0.35)
        return entries

    def capture_stop(label, entries):
        time.sleep(0.3)  # Include TLS close_notify/FIN before flushing each capture.
        for name, unit, path in entries:
            lab.command("ngfw", "systemctl kill --kill-who=main --signal=SIGINT " + shlex.quote(unit), sudo=True)
            for _ in range(20):
                active = lab.command("ngfw", "systemctl is-active " + shlex.quote(unit), save=False)
                if active["stdout"].strip() not in ("active", "deactivating"):
                    break
                time.sleep(0.1)
            lab.command("ngfw", "journalctl -u " + shlex.quote(unit) + " --no-pager -n 12", sudo=True,
                        evidence=label + "/capture-journal-" + name + ".json")
            lab.command("ngfw", "chmod 0644 " + shlex.quote(path), sudo=True)
            sftp = lab.ssh["ngfw"].open_sftp()
            try:
                target = evidence / label / (name + ".pcap")
                target.parent.mkdir(parents=True, exist_ok=True)
                sftp.get(path, str(target))
            finally:
                sftp.close()

    def observe(label, before, increments):
        # Engine timestamp is captured after the client finished. No controller
        # or origin clock is compared to an engine heartbeat.
        stamp = lab.command("ngfw", "date -u +%Y-%m-%dT%H:%M:%S.%NZ", save=False)["stdout"].strip()
        base = before["response"]["data"]
        minimum = {key: base["counters"].get(key, 0) + value for key, value in increments.items()}
        try:
            observed, samples = wait_for_health_counters(
                lambda timeout: lab.api("GET", "/request-gate/health", timeout=timeout),
                generation=base["generation"], after=stamp, minimum_counters=minimum)
        except HealthObservationError as error:
            json_write(evidence / label / "health-observations.json", error.observations)
            raise RuntimeError(label + " FAIL: " + str(error)) from error
        json_write(evidence / label / "health-observations.json", samples)
        json_write(evidence / label / "health-after.json", observed)
        return observed

    def request(label, *, body=None, host="dmz-m4.test", split=False, pin=None, distrust=False):
        marker = label.lower() + "-" + secrets.token_hex(6)
        parts = [lan_client, "--ca", lan_ca + (".origin" if distrust else ""),
                 "--ip", "10.20.0.10", "--host", host, "--path", "/" + marker,
                 "--method", "POST" if body is not None else "GET", "--body", body or "",
                 "--marker", marker]
        if split:
            parts += ["--split-hello"]
        if pin:
            parts += ["--pin-sha256", pin]
        before = lab.api("GET", "/request-gate/health", evidence=label + "/health-before.json")
        output = lab.command("lan", " ".join(shlex.quote(p) for p in parts), timeout=25,
                             evidence=label + "/client.json")
        client = json.loads(output["stdout"].strip()) if output["stdout"].strip() else {}
        origin = lab.command("dmz", "cat " + shlex.quote(dmz_log), sudo=True, evidence=label + "/origin.json")
        matches = [json.loads(line) for line in origin["stdout"].splitlines() if line.strip()]
        matches = [line for line in matches if line.get("marker") == marker]
        page = lab.api("GET", "/request-gate/evidence?limit=128", evidence=label + "/request-evidence.json")
        items = [item for item in page.get("response", {}).get("data", {}).get("items", [])
                 if item.get("context", {}).get("path") == "/" + marker]
        record = {"started_before_health": before["response"]["data"]["updated_at"],
                  "client_exit": output["exit_code"], "client": client,
                  "marker": marker, "origin": matches, "request_evidence": items}
        report["scenarios"][label] = record
        json_write(evidence / label / "assessment.json", record)
        return record, before

    def require_bypass(label, record, before):
        client = record["client"]
        require(record["client_exit"] == 0 and client.get("status") == 200 and client.get("tls_verified")
                and client.get("peer_sha256") == origin_sha and len(record["origin"]) == 1
                and record["origin"][0].get("body_sha256") == client.get("body_sha256"),
                label + " FAIL: BYPASS did not preserve verified certificate/payload")
        require(not record["request_evidence"], label + " FAIL: BYPASS claimed request inspection")
        after = observe(label, before, {"bypassed": 1})
        base, new = before["response"]["data"]["counters"], after["response"]["data"]["counters"]
        require(all(new.get(key, 0) == base.get(key, 0)
                    for key in ("decrypted", "intercepted", "request_allowed", "request_blocked")),
                label + " FAIL: tunnel incorrectly counted as inspected/decrypted")
        record["result"] = "PASS"

    def require_decrypt(label, record, before, *, blocked=False, status=200, counter=None):
        client = record["client"]
        require(record["client_exit"] == 0 and client.get("status") == status and client.get("tls_verified")
                and client.get("peer_sha256") != origin_sha,
                label + " FAIL: verified decryption/status mismatch")
        require(len(record["origin"]) == (1 if status == 200 else 0), label + " FAIL: unexpected upstream request")
        require(len(record["request_evidence"]) == 1, label + " FAIL: missing unique request decision")
        item = record["request_evidence"][0]
        decision = item.get("decision", {})
        require(item.get("context", {}).get("scheme") == "https" and
                decision.get("verdict") == ("BLOCK" if blocked else "ALLOW") and
                decision.get("coverage") == "COMPLETE" and item.get("inspection", {}).get("completed"),
                label + " FAIL: nonmatching traffic was not completely inspected")
        if blocked:
            require(decision.get("reason_code") == "GATE_SIGNATURE_BLOCK" and
                    any(str(a.get("signature_id")) == "9904003"
                        for a in item.get("inspection", {}).get("alerts", [])),
                    label + " FAIL: attack block lacks Suricata SID 9904003")
        changes = {"decrypted": 1, "intercepted": 1,
                   "request_blocked" if blocked else "request_allowed": 1}
        if counter:
            changes[counter] = 1
        observe(label, before, changes)
        record["result"] = "PASS"

    def compare_capture(label, record):
        lan = pcap_streams(evidence / label / "lan.pcap")
        dmz = pcap_streams(evidence / label / "dmz.pcap")
        port = int(record["client"]["local_address"].rsplit(":", 1)[1])
        upstream = lan.get(("192.168.10.10", port, "10.20.0.10", 443))
        require(upstream is not None, "EVIDENCE: client TLS stream missing")
        matched = [(key, value) for key, value in dmz.items()
                   if key[2:] == ("10.20.0.10", 443) and value["bytes"] == upstream["bytes"]]
        require(len(matched) == 1, label + " FAIL: client-to-origin TLS bytes changed in tunnel")
        key, stream = matched[0]
        server = dmz.get((key[2], key[3], key[0], key[1]))
        response = lan.get(("10.20.0.10", 443, "192.168.10.10", port))
        require(server is not None and response is not None and server["bytes"] == response["bytes"],
                label + " FAIL: origin-to-client TLS bytes changed in tunnel")
        comparison = {"request_bytes": len(upstream["bytes"]),
                      "request_sha256": hashlib.sha256(upstream["bytes"]).hexdigest(),
                      "response_bytes": len(response["bytes"]),
                      "response_sha256": hashlib.sha256(response["bytes"]).hexdigest(),
                      "client_payload_segments": upstream["segments"], "upstream_tuple": key,
                      "request_identical": True, "response_identical": True}
        json_write(evidence / label / "tcp-stream-comparison.json", comparison)
        record["wire_bytes"] = comparison

    def trace_decisions():
        trace = lab.command("ngfw", "cat " + shlex.quote(trace_path), sudo=True, save=False)
        (evidence / "engine-write-strace.log").write_text(trace["stdout"], encoding="utf-8")
        decisions = []
        for line in trace["stdout"].splitlines():
            match = re.search(r'write\(\d+, ("(?:[^"\\]|\\.)*"),', line)
            if not match:
                continue
            try:
                value = ast.literal_eval(match[1])
                if not value.startswith("{"):
                    continue
                reply = json.loads(value)
            except (SyntaxError, ValueError):
                continue
            decision = reply.get("data", {})
            if isinstance(decision, dict) and "upstream_ip" in decision and "action" in decision:
                decisions.append(decision)
        json_write(evidence / "connection-decisions.json", decisions)
        return decisions

    try:
        pid = lab.command("ngfw", "systemctl show ngfw-engine --property=MainPID --value", save=False)["stdout"].strip()
        require(pid.isdigit() and int(pid) > 1, "SETUP: engine PID missing")
        tasks = lab.command("ngfw", "ps -T -p " + pid + " -o tid=", save=False)
        tids = tasks["stdout"].split()
        require(tids and all(tid.isdigit() for tid in tids), "SETUP: engine task inventory failed")
        # Attach only existing Go threads. Following forked ip/nft children can
        # disrupt their shutdown during configuration activation; no -f here.
        trace = lab.command("ngfw", "systemd-run --unit=" + shlex.quote(trace_unit) +
                            " --collect --property=RuntimeMaxSec=900 --property=TimeoutStopSec=5 "
                            "/usr/bin/strace -ttt -s 16384 -e trace=write -p " +
                            ",".join(tids) + " -o " + shlex.quote(trace_path), sudo=True, evidence="engine-trace-start.json")
        require(trace["exit_code"] == 0, "SETUP: engine decision observer could not start")
        time.sleep(0.3)

        commit("M4-09-config", mode="BYPASS")
        captures = capture_start("M4-09")
        record, before = request("M4-09", body="bypass-byte-check=UNION SELECT&nonce=" + secrets.token_hex(32))
        capture_stop("M4-09", captures)
        require_bypass("M4-09", record, before)
        compare_capture("M4-09", record)
        report["scenarios"]["M4-09"] = record
        snapshot("M4-09")

        variations = [
            ("domain-match", {"domains": ["dmz-m4.test"]}, True),
            ("domain-miss", {"domains": ["other-m4.test"]}, False),
            ("cidr-match", {"destination_cidrs": ["10.20.0.10/32"]}, True),
            ("cidr-miss", {"destination_cidrs": ["10.20.0.11/32"]}, False),
            ("port-match", {"ports": [443]}, True),
            ("port-miss", {"ports": [4443]}, False),
            ("all-match", {"domains": ["dmz-m4.test"], "destination_cidrs": ["10.20.0.0/24"], "ports": [443]}, True),
            ("and-domain-miss", {"domains": ["other-m4.test"], "destination_cidrs": ["10.20.0.10/32"], "ports": [443]}, False),
            ("or-domain-match", {"domains": ["other-m4.test", "dmz-m4.test"]}, True),
            ("wildcard-match", {"domains": ["*.dmz-m4.test"]}, True),
            ("wildcard-apex-miss", {"domains": ["*.dmz-m4.test"]}, False),
        ]
        for name, selectors, bypass in variations:
            label = "M4-10-" + name
            exclusion = {"id": "acceptance-exclusion", "name": label, "enabled": True,
                         "reason": "Synthetic VM TLS exclusion acceptance", **selectors}
            active = commit(label, exclusions=[exclusion])
            record, before = request(label, body="UNION SELECT",
                                     host="api.dmz-m4.test" if name == "wildcard-match" else "dmz-m4.test")
            if bypass:
                require_bypass(label, record, before)
            else:
                require_decrypt(label, record, before, blocked=True, status=403)
            decisions = trace_decisions()
            matching = [d for d in decisions if d.get("config_generation") == active["response"]["data"]["generation"]
                        and d.get("policy_id") == policy_id]
            require(len(matching) == 1 and matching[0].get("action") == ("BYPASS" if bypass else "DECRYPT")
                    and matching[0].get("reason_code") == ("TLS_EXCLUSION" if bypass else "GATE_INSPECTION_REQUIRED"),
                    label + " FAIL: engine connection decision does not match selectors")
            record["connection_decision"] = matching[0]
            snapshot(label)
        report["scenarios"]["M4-10"] = "PASS"
        snapshot("M4-10")

        commit("M4-11-config", mode="BYPASS")
        captures = capture_start("M4-11-bypass")
        record, before = request("M4-11-bypass", split=True, body="split-hello=" + secrets.token_hex(16))
        capture_stop("M4-11-bypass", captures)
        require_bypass("M4-11-bypass", record, before)
        compare_capture("M4-11-bypass", record)
        require(record["client"].get("client_hello_chunks", 0) >= 5
                and record["wire_bytes"].get("client_payload_segments", 0) >= 5,
                "EVIDENCE: ClientHello was not split across captured TCP segments")
        commit("M4-11-decrypt-config")
        record, before = request("M4-11-decrypt", split=True, body="UNION SELECT")
        require_decrypt("M4-11-decrypt", record, before, blocked=True, status=403)
        require(record["client"].get("client_hello_chunks", 0) >= 5,
                "EVIDENCE: DECRYPT control did not fragment its ClientHello")
        report["scenarios"]["M4-11"] = "PASS"
        snapshot("M4-11")

        active = commit("M4-12-close-config")
        record, before = request("M4-12-no-sni-close", host="10.20.0.10")
        require(record["client_exit"] != 0 and not record["origin"] and not record["request_evidence"],
                "M4-12 FAIL: no-SNI fail-close was forwarded or claimed clean")
        after = observe("M4-12-no-sni-close", before, {"handler_failed": 1})
        require(after["response"]["data"]["counters"].get("decrypted", 0) ==
                before["response"]["data"]["counters"].get("decrypted", 0),
                "M4-12 FAIL: no-SNI rejection counted as decrypted")
        decisions = trace_decisions()
        require(any(d.get("config_generation") == active["response"]["data"]["generation"]
                    and d.get("action") == "BLOCK" and d.get("reason_code") == "TLS_SNI_UNAVAILABLE"
                    for d in decisions), "M4-12 FAIL: no-SNI lacks explicit engine limitation")
        record["result"] = "PASS"
        commit("M4-12-open-config", fail_mode="OPEN")
        record, before = request("M4-12-no-sni-open", host="10.20.0.10")
        require_bypass("M4-12-no-sni-open", record, before)
        capabilities = lab.api("GET", "/request-gate/capabilities", evidence="M4-12-capabilities.json")
        require("ECH" in json.dumps(capabilities), "M4-12 FAIL: ECH limitation is not advertised")
        report["scenarios"]["M4-12"] = "PARTIAL_NO_SNI_PASSED_ECH_TRAFFIC_NOT_RUN"
        snapshot("M4-12")

        commit("M4-13-config")
        record, before = request("M4-13-hostname-mismatch", host="other-m4.test")
        require_decrypt("M4-13-hostname-mismatch", record, before, status=502, counter="upstream_verify_fail")
        report["scenarios"]["M4-13"] = "PARTIAL_HOSTNAME_MISMATCH_PASSED_UNTRUSTED_CHAIN_NOT_RUN"
        snapshot("M4-13")

        for label, options in [("M4-14-distrust", {"distrust": True}),
                               ("M4-14-pinning", {"pin": origin_sha})]:
            record, before = request(label, **options)
            require(record["client_exit"] != 0 and not record["origin"] and not record["request_evidence"],
                    label + " FAIL: rejecting MITM CA/pin caused forwarding or silent bypass")
            require(("unknown authority" if options.get("distrust") else "TLS_PIN_MISMATCH")
                    in record["client"].get("error", ""), label + " FAIL: client did not reject expected CA/pin")
            after = observe(label, before, {"tls_handshake_fail": 1})
            require(all(after["response"]["data"]["counters"].get(key, 0) ==
                        before["response"]["data"]["counters"].get(key, 0)
                        for key in ("bypassed", "decrypted", "intercepted")),
                    label + " FAIL: handshake rejection silently retried/claimed decryption")
            record["result"] = "PASS"
        report["scenarios"]["M4-14"] = "PASS"
        snapshot("M4-14")

        # Upstream TLS 1.3 client-certificate request is deliberately independent
        # of client->proxy trust. The proxy must not invent a client identity.
        lab.command("dmz", "systemctl stop " + shlex.quote(origin_unit), sudo=True)
        cmd = ("systemd-run --unit=" + shlex.quote(origin_unit) + " --collect --property=RuntimeMaxSec=600 "
               "/usr/bin/python3 " + shlex.quote(remote_dmz_dir + "/origin.py") +
               " --cert " + shlex.quote(remote_dmz_dir + "/origin.crt") +
               " --key " + shlex.quote(remote_dmz_dir + "/origin.key") +
               " --log " + shlex.quote(dmz_log) + " --require-client-cert --ca " +
               shlex.quote(remote_dmz_dir + "/ca.crt"))
        start = lab.command("dmz", cmd, sudo=True, evidence="M4-15-origin-start.json")
        require(start["exit_code"] == 0, "SETUP: upstream mTLS origin did not start")
        time.sleep(0.4)
        record, before = request("M4-15-mtls")
        require(record["client_exit"] == 0 and record["client"].get("status") == 502
                and not record["origin"], "M4-15 FAIL: unsupported upstream mTLS was not rejected before origin")
        # A generic 502 alone cannot meet the explicit failure-reason requirement.
        after = observe("M4-15-mtls", before, {"upstream_mtls_unsupported": 1})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(item.get("forward") for item in record["request_evidence"]):
            page = lab.api("GET", "/request-gate/evidence?limit=128", evidence="M4-15-mtls/request-evidence-after-forward.json")
            record["request_evidence"] = [item for item in page.get("response", {}).get("data", {}).get("items", [])
                                          if item.get("context", {}).get("path") == "/" + record["marker"]]
            if not any(item.get("forward") for item in record["request_evidence"]):
                time.sleep(0.1)
        lab.command("dmz", "journalctl -u " + shlex.quote(origin_unit) + " --no-pager -n 30", sudo=True,
                    evidence="M4-15-origin-journal.json")
        record["health_after"] = after["response"]["data"]
        def failure_codes(value):
            found = []
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ("reason_code", "error_code", "failure_code") and isinstance(item, str):
                        found.append(item)
                    found.extend(failure_codes(item))
            elif isinstance(value, list):
                for item in value:
                    found.extend(failure_codes(item))
            return found

        record["reported_failure_codes"] = failure_codes(record)
        record["explicit_mtls_failure"] = "TLS_UPSTREAM_MTLS_UNSUPPORTED" in record["reported_failure_codes"]
        report["scenarios"]["M4-15"] = "PASS" if record["explicit_mtls_failure"] else "FAIL_MISSING_EXPLICIT_MTLS_REASON"
        record["result"] = "PASS" if record["explicit_mtls_failure"] else "FAIL"
        snapshot("M4-15")
        require(record["explicit_mtls_failure"],
                "M4-15 FAIL: upstream mTLS returns 502 with no origin request, but lacks the explicit per-request failure reason required by section 14.3 / CODE_CONTRACTS")
        report["status"] = "PASS_TLS_CONTINUATION_WITH_PARTIALS"
    finally:
        trace_decisions()
        lab.command("ngfw", "systemctl kill --kill-who=main --signal=SIGINT " + shlex.quote(trace_unit), sudo=True, save=False)
        lab.command("ngfw", "systemctl stop " + shlex.quote(trace_unit), sudo=True, save=False)
        for unit in capture_units:
            lab.command("ngfw", "systemctl stop " + shlex.quote(unit), sudo=True, save=False)
        for path in capture_paths + [trace_path]:
            lab.command("ngfw", "rm -f -- " + shlex.quote(path), sudo=True, save=False)
        lab.command("lan", "rm -f -- " + shlex.quote(lan_ca + ".origin"), save=False)
        lab.command("dmz", "rm -f -- " + shlex.quote(remote_dmz_dir + "/ca.crt"), save=False)
