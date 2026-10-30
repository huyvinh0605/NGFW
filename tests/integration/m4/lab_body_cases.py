"""M4-19..23 using real HTTP/1.1 wire framing over verified TLS."""

import copy
import json
import secrets
import shlex
import time

from health_poll import HealthObservationError, wait_for_health_counters
from lab_https_acceptance import json_write, require, utc_now


def body_client_source():
    return r'''#!/usr/bin/env python3
import argparse, gzip, hashlib, http.client, json, socket, ssl, zlib
p=argparse.ArgumentParser();p.add_argument('--ca',required=True);p.add_argument('--case',required=True);p.add_argument('--marker',required=True);a=p.parse_args()
kind=a.case;marker=a.marker;path='/'+marker
plain=('ordinary='+marker).encode();body=plain;encoding='';chunked=False;method='POST';extra=[]
if kind.endswith('-attack'):plain=('q=UNION SELECT '+marker).encode();body=plain
if kind.startswith('chunked-'):chunked=True
if kind.startswith('gzip-'):body=gzip.compress(plain,mtime=0);encoding='gzip'
if kind.startswith('deflate-'):body=zlib.compress(plain);encoding='deflate'
if kind=='bomb':plain=b'A'*400000;body=gzip.compress(plain,mtime=0);encoding='gzip'
if kind.startswith('oversize-'):plain=('ordinary='+marker+'&tail='+'a'*70000).encode();body=plain
if kind=='malformed':method='GET';plain=body=b'';extra=['BadHeader']
if kind=='headers':method='GET';plain=body=b'';extra=['X-Large: '+'x'*40000]
if kind=='url':method='GET';plain=body=b'';path+='x'*9000
headers=[method+' '+path+' HTTP/1.1','Host: dmz-m4.test','X-M4-Marker: '+marker,'Content-Type: application/x-www-form-urlencoded','Connection: close']+extra
if encoding:headers.append('Content-Encoding: '+encoding)
if chunked:
 headers.append('Transfer-Encoding: chunked')
 parts=[body[:5],body[5:10],body[10:]]
 wire_body=b''.join(('%x\r\n'%len(part)).encode()+part+b'\r\n' for part in parts if part)+b'0\r\n\r\n'
else:
 headers.append('Content-Length: '+str(len(body)))
 wire_body=body[:65537] if kind=='oversize-strict' else body
wire=('\r\n'.join(headers)+'\r\n\r\n').encode()+wire_body
result={'case':kind,'marker':marker,'path':path,'body_bytes':len(body),'decoded_body_bytes':len(plain),'sent_wire_body_bytes':len(wire_body),'body_sha256':hashlib.sha256(body).hexdigest(),'decoded_body_sha256':hashlib.sha256(plain).hexdigest(),'wire_sha256':hashlib.sha256(wire).hexdigest(),'content_encoding':encoding,'chunked':chunked}
context=ssl.create_default_context(cafile=a.ca);context.set_alpn_protocols(['http/1.1'])
try:
 with socket.create_connection(('10.20.0.10',443),timeout=8) as tcp:
  with context.wrap_socket(tcp,server_hostname='dmz-m4.test') as conn:
   conn.settimeout(15);result.update(tls_verified=True,tls_version=conn.version(),alpn=conn.selected_alpn_protocol(),local_address=conn.getsockname())
   try:conn.sendall(wire)
   except OSError as error:result['send_error']=str(error)
   response=http.client.HTTPResponse(conn,method=method);response.begin();data=response.read(1<<20)
   result.update(status=response.status,response_body=data.decode('utf-8','replace'),http_version=response.version)
except Exception as error:result['error']=type(error).__name__+': '+str(error)
print(json.dumps(result),flush=True)
raise SystemExit(1 if 'error' in result else 0)
'''


def run_body_cases(*, lab, evidence, report, healthy, lan_client, lan_ca, dmz_log, profile_id):
    generation = healthy["response"]["data"]["generation"]
    report["body_limits"] = {"raw_bytes": 65536, "decoded_bytes": 262144,
                             "decompression_ratio": 20, "default_request_timeout_ms": 2000}

    def records():
        result, cursor = [], 0
        for _ in range(16):
            reply = lab.api("GET", "/request-gate/evidence?after_sequence=" + str(cursor) + "&limit=128")
            require(reply["status"] == 200, "body case evidence query failed")
            page = reply["response"]["data"]
            result.extend(page.get("items", []))
            if not page.get("has_more"):
                return result
            require(page["next_sequence"] > cursor, "body evidence pagination made no progress")
            cursor = page["next_sequence"]
        raise RuntimeError("body evidence exceeded bounded page collection")

    def request(row, label, *, status, reason=None, coverage="COMPLETE", completed=True,
                counter=None, parser=False, kind=None):
        marker = label + "-" + secrets.token_hex(6)
        before = lab.api("GET", "/request-gate/health", evidence=label + "/health-before.json")
        cleared = lab.command("dmz", "truncate -s 0 " + shlex.quote(dmz_log), sudo=True)
        require(cleared["exit_code"] == 0, "SETUP: origin log could not be cleared")
        command = shlex.join(["python3", lan_client, "--ca", lan_ca, "--case", kind or label, "--marker", marker])
        output = lab.command("lan", command, timeout=25, evidence=label + "/client.json")
        client = json.loads(output["stdout"]) if output["stdout"].strip() else {}
        origin_output = lab.command("dmz", "cat " + shlex.quote(dmz_log), sudo=True, evidence=label + "/origin.json")
        require(origin_output["exit_code"] == 0, "SETUP: origin log unavailable")
        origin = [json.loads(line) for line in origin_output["stdout"].splitlines() if line.strip()]
        deadline = time.monotonic() + (1 if parser else 6)
        matching, all_items = [], []
        while True:
            all_items = records()
            matching = [item for item in all_items if item.get("context", {}).get("path") == client.get("path")]
            if parser or len(matching) == 1 and (matching[0]["decision"]["verdict"] != "ALLOW" or matching[0].get("forward")):
                break
            if time.monotonic() > deadline:
                break
            time.sleep(.1)
        json_write(evidence / label / "request-evidence.json", matching)
        observed_health = lab.api("GET", "/request-gate/health", evidence=label + "/health-observed.json")
        record = {"row": row, "result": "PENDING", "client": client, "origin": origin,
                  "request_evidence": matching, "expected_http": status}
        report["scenarios"][label] = record
        json_write(evidence / "progress.json", report)
        require(output["exit_code"] == 0 and client.get("tls_verified") and client.get("alpn") == "http/1.1",
                row + " FAIL: verified HTTP/1.1 client failed in " + label)
        require(client.get("status") == status,
                row + " FAIL: " + label + " returned HTTP " + str(client.get("status")) + ", expected " + str(status))
        require(len(origin) == (1 if status == 200 else 0), row + " FAIL: origin delivery/absence mismatch in " + label)
        if origin:
            require(origin[0].get("marker") == marker and origin[0].get("body_sha256") == client["body_sha256"],
                    row + " FAIL: forwarded body differs from the original application body")
        if parser:
            require(not matching, row + " FAIL: malformed/oversize parser input acquired request verdict evidence")
        else:
            require(len(matching) == 1, row + " FAIL: no unique engine evidence for " + label)
            item = matching[0]
            decision, inspection = item["decision"], item["inspection"]
            require(decision["config_generation"] == generation and decision["coverage"] == coverage
                    and decision["reason_code"] == reason and decision["verdict"] == ("ALLOW" if status == 200 else "BLOCK")
                    and inspection.get("completed", False) is completed,
                    row + " FAIL: incorrect verdict/reason/coverage/completion in " + label)
            if status == 200:
                require(item.get("forward", {}).get("http_status") == 200
                        and item["forward"]["reason_code"] == "UPSTREAM_RESPONSE_RECEIVED",
                        row + " FAIL: successful transport result missing")
                stamp = item["forward"]["observed_at"]
            else:
                require(item.get("forward") is None, row + " FAIL: blocked request was forwarded")
                stamp = item["observed_at"]
            if status == 403:
                require(any(str(alert.get("signature_id")) == "9904003" for alert in inspection.get("alerts", [])),
                        row + " FAIL: expected SQLi SID missing after body processing")
            base = before["response"]["data"]["counters"]
            minimum = {"request_allowed" if status == 200 else "request_blocked":
                       base.get("request_allowed" if status == 200 else "request_blocked", 0) + 1}
            if counter:
                minimum[counter] = base.get(counter, 0) + 1
            try:
                after, observations = wait_for_health_counters(
                    lambda timeout: lab.api("GET", "/request-gate/health", timeout=timeout),
                    generation=generation, after=stamp, minimum_counters=minimum)
            except HealthObservationError as error:
                json_write(evidence / label / "health-observations.json", error.observations)
                raise RuntimeError(row + " FAIL: " + str(error)) from error
            json_write(evidence / label / "health-observations.json", observations)
            json_write(evidence / label / "health-after.json", after)
            require(after["response"]["data"]["counters"].get("result_report_fail", 0) == base.get("result_report_fail", 0),
                    row + " FAIL: result reporting failed")
        record["result"] = "PASS"
        json_write(evidence / label / "assessment.json", record)
        json_write(evidence / "progress.json", report)
        print(json.dumps({"at": utc_now(), "row": row, "control": label, "result": "PASS"}), flush=True)

    def passed(row):
        report[row] = "PASS"
        json_write(evidence / "progress.json", report)
        print(json.dumps({"at": utc_now(), "case": row, "result": "PASS"}), flush=True)

    def profile(mode, oversize):
        nonlocal generation
        state = lab.api("GET", "/config")["response"]["data"]
        target = copy.deepcopy(state["running"])
        selected = next(item for item in target["security_profiles"] if item["id"] == profile_id)
        selected["request_gate"]["fail_mode"] = mode
        selected["request_gate"]["oversize_action"] = oversize
        label = "profile-" + mode.lower() + "-" + oversize.lower()
        saved = lab.api("PUT", "/config/candidate", payload=target, evidence=label + "-save.json")
        require(saved["status"] == 200, "SETUP: body limit profile rejected")
        commit = lab.api("POST", "/policies/commit", payload={"expected_version": state["version"]["version"],
                         "author": "m4-body-acceptance", "comment": label}, evidence=label + "-commit.json")
        require(commit["status"] == 200, "SETUP: body limit profile commit failed")
        generation = commit["response"]["data"]["version"]
        for _ in range(40):
            health = lab.api("GET", "/request-gate/health")
            data = health["response"]["data"]
            if data.get("generation") == generation and data.get("status") == "healthy" and data.get("workers_ready", 0) > 0:
                return
            time.sleep(.25)
        require(False, "SETUP: new body limit profile not healthy")

    request("M4-19", "chunked-clean", status=200, reason="GATE_INSPECTION_COMPLETE")
    request("M4-19", "chunked-attack", status=403, reason="GATE_SIGNATURE_BLOCK")
    passed("M4-19")
    for encoding in ("gzip", "deflate"):
        request("M4-20", encoding + "-clean", status=200, reason="GATE_INSPECTION_COMPLETE")
        request("M4-20", encoding + "-attack", status=403, reason="GATE_SIGNATURE_BLOCK")
    passed("M4-20")
    request("M4-21", "decompression-bomb", kind="bomb", status=413,
            reason="GATE_DECOMPRESSION_LIMIT", coverage="PARTIAL", completed=False, counter="decompression_limit")
    passed("M4-21")
    request("M4-22", "oversize-strict", status=413, reason="GATE_REQUEST_TOO_LARGE",
            coverage="PARTIAL", completed=False, counter="body_limit")
    profile("OPEN", "ALLOW_PARTIAL")
    request("M4-22", "oversize-partial", status=200, reason="GATE_REQUEST_TOO_LARGE",
            coverage="PARTIAL", completed=False, counter="fail_open")
    passed("M4-22")
    profile("CLOSE", "BLOCK")
    request("M4-23", "malformed", status=400, parser=True)
    request("M4-23", "headers", status=431, parser=True)
    request("M4-23", "url", status=414, parser=True)
    passed("M4-23")
    report["status"] = "PASS_M4_19_M4_23"
