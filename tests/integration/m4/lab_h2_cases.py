"""Real concurrent HTTP/2 requests over one verified TLS/TCP connection."""

import json
import secrets
import shlex
import time

from health_poll import HealthObservationError, wait_for_health_counters
from lab_https_acceptance import json_write, require, utc_now


def h2_client_source():
    return r'''package main

import (
    "context"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/http/httptrace"
    "os"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

type sample struct {
    Marker string `json:"marker"`
    Kind string `json:"kind"`
    BodySHA256 string `json:"body_sha256"`
    BodyBytes int `json:"body_bytes"`
    Status int `json:"status"`
    Protocol string `json:"http_protocol"`
    ALPN string `json:"alpn"`
    TLSVersion string `json:"tls_version"`
    TLSVerified bool `json:"tls_verified"`
    LocalAddress string `json:"local_address"`
    ResponseBody string `json:"response_body"`
    StartedNS int64 `json:"started_ns"`
    FinishedNS int64 `json:"finished_ns"`
    Error string `json:"error,omitempty"`
}

func main() {
    caPath := flag.String("ca", "", "trusted CA")
    nonce := flag.String("nonce", "", "unique synthetic marker")
    count := flag.Int("count", 2, "simultaneous requests, 2..24")
    flag.Parse()
    if *count < 2 || *count > 24 || *nonce == "" { panic("invalid batch arguments") }
    pem, err := os.ReadFile(*caPath)
    if err != nil { panic(err) }
    roots := x509.NewCertPool()
    if !roots.AppendCertsFromPEM(pem) { panic("invalid CA") }
    var dials, handshakes atomic.Int32
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "dmz-m4.test", MinVersion: tls.VersionTLS12},
        ForceAttemptHTTP2: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1,
        DialContext: func(ctx context.Context, network, ignored string) (net.Conn, error) {
            if dials.Add(1) != 1 { return nil, fmt.Errorf("second TCP connection requested") }
            return (&net.Dialer{Timeout: 5*time.Second}).DialContext(ctx, network, "10.20.0.10:443")
        },
    }
    defer transport.CloseIdleConnections()
    client := &http.Client{Transport: transport, Timeout: 20*time.Second}
    request := func(marker, kind, body string, method string) sample {
        result := sample{Marker: marker, Kind: kind, BodyBytes: len(body), BodySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(body))), StartedNS: time.Now().UnixNano()}
        req, err := http.NewRequest(method, "https://dmz-m4.test/"+marker, strings.NewReader(body))
        if err != nil { result.Error=err.Error(); result.FinishedNS=time.Now().UnixNano(); return result }
        req.Header.Set("X-M4-Marker", marker)
        if method=="POST" { req.Header.Set("Content-Type", "application/x-www-form-urlencoded") }
        trace := &httptrace.ClientTrace{
            GotConn: func(info httptrace.GotConnInfo) { result.LocalAddress=info.Conn.LocalAddr().String() },
            TLSHandshakeDone: func(_ tls.ConnectionState, _ error) { handshakes.Add(1) },
        }
        req=req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
        response, err := client.Do(req)
        if err != nil { result.Error=err.Error(); result.FinishedNS=time.Now().UnixNano(); return result }
        data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
        _=response.Body.Close()
        result.Status=response.StatusCode; result.Protocol=response.Proto; result.ResponseBody=string(data)
        if readErr != nil { result.Error=readErr.Error() }
        if response.TLS != nil {
            result.TLSVerified=len(response.TLS.VerifiedChains)>0
            result.ALPN=response.TLS.NegotiatedProtocol
            result.TLSVersion=tls.VersionName(response.TLS.Version)
        }
        result.FinishedNS=time.Now().UnixNano()
        return result
    }
    warmup := request(*nonce+"-warmup", "warmup", "", "GET")
    results := make([]sample,*count)
    if warmup.Error=="" && warmup.Status==200 && warmup.Protocol=="HTTP/2.0" && warmup.TLSVerified {
        start:=make(chan struct{}); var done sync.WaitGroup
        for i:=range results {
            done.Add(1)
            go func(index int) {
                defer done.Done(); <-start
                marker:=fmt.Sprintf("%s-%02d", *nonce,index)
                kind,body:="clean","ordinary="+marker
                if index%3==1 {
                    kind,body="sqli","UNION SELECT "+marker
                    if index%2==0 { kind,body="xss","<script>alert(1)</script>"+marker }
                }
                results[index]=request(marker,kind,body,"POST")
            }(i)
        }
        close(start); done.Wait()
    }
    type point struct { ns int64; delta int }
    points:=make([]point,0,len(results)*2); failed:=warmup.Error!="" || warmup.Status!=200
    for _,value:=range results {
        if value.StartedNS!=0 { points=append(points,point{value.StartedNS,1},point{value.FinishedNS,-1}) }
        if value.Error!="" || value.Status==0 { failed=true }
    }
    sort.Slice(points,func(i,j int)bool { if points[i].ns==points[j].ns{return points[i].delta>points[j].delta};return points[i].ns<points[j].ns })
    active,peak:=0,0;for _,p:=range points {active+=p.delta;if active>peak {peak=active}}
    _=json.NewEncoder(os.Stdout).Encode(map[string]any{"warmup":warmup,"requests":results,"tcp_dials":dials.Load(),"tls_handshakes":handshakes.Load(),"max_concurrent_requests":peak})
    if failed {os.Exit(1)}
}
'''


def run_h2_cases(*, lab, evidence, report, healthy, lan_client, lan_ca, dmz_log):
    generation = healthy["response"]["data"]["generation"]
    report["h2_test_limits"] = {"requests": [2, 24], "worker_count": 2,
                                "request_timeout_ms": 10000, "tls_time_override": False}

    def pages(after):
        found = {}
        for _ in range(16):
            reply = lab.api("GET", "/request-gate/evidence?after_sequence=" + str(after) + "&limit=128")
            require(reply["status"] == 200, "M4 H2 evidence query failed")
            page = reply["response"]["data"]
            for item in page.get("items", []):
                found[item["context"]["request_id"]] = item
            next_sequence = page["next_sequence"]
            require(next_sequence >= after, "M4 evidence cursor regressed")
            if not page.get("has_more"):
                return list(found.values()), next_sequence
            require(next_sequence > after, "M4 evidence pagination made no progress")
            after = next_sequence
        raise RuntimeError("M4 evidence exceeded bounded page collection")

    for scenario, count in (("M4-17", 2), ("M4-18", 24)):
        nonce = scenario.lower() + "-" + secrets.token_hex(7)
        _, cursor = pages(0)
        before = lab.api("GET", "/request-gate/health", evidence=scenario + "/health-before.json")
        cleared = lab.command("dmz", "truncate -s 0 " + shlex.quote(dmz_log), sudo=True)
        require(cleared["exit_code"] == 0, "SETUP: could not clear test origin log")
        command = shlex.join([lan_client, "--ca", lan_ca, "--nonce", nonce, "--count", str(count)])
        output = lab.command("lan", command, timeout=35, evidence=scenario + "/client.json")
        client = json.loads(output["stdout"]) if output["stdout"].strip() else {}
        record = {"result": "PENDING", "nonce": nonce, "count": count, "client": client}
        report["scenarios"][scenario] = record
        json_write(evidence / "progress.json", report)
        require(output["exit_code"] == 0, scenario + " FAIL: concurrent client transport failed")
        requests = client.get("requests", [])
        warmup = client.get("warmup", {})
        require(len(requests) == count and client.get("tcp_dials") == 1 and client.get("tls_handshakes") == 1,
                scenario + " FAIL: batch did not use exactly one TLS/TCP connection")
        require(client.get("max_concurrent_requests", 0) >= count,
                scenario + " FAIL: not all requests were concurrently in flight")
        for item in [warmup] + requests:
            require(not item.get("error") and item.get("tls_verified") is True
                    and item.get("http_protocol") == "HTTP/2.0" and item.get("alpn") == "h2"
                    and item.get("local_address") == warmup.get("local_address"),
                    scenario + " FAIL: TLS/H2 verification or shared socket changed")
        require(warmup.get("status") == 200, scenario + " FAIL: H2 warmup failed")
        clean = [item for item in requests if item["kind"] == "clean"]
        attacks = [item for item in requests if item["kind"] != "clean"]
        require(clean and attacks, scenario + " FAIL: missing positive/negative controls")
        for item in requests:
            require(item["status"] == (200 if item["kind"] == "clean" else 403),
                    scenario + " FAIL: request verdict mismatch for " + item["marker"])

        expected = {"/" + item["marker"]: item for item in [warmup] + requests}
        deadline = time.monotonic() + 8
        matching = {}
        while True:
            items, _ = pages(cursor)
            matching = {item["context"]["path"]: item for item in items
                        if item.get("context", {}).get("path") in expected}
            if len(matching) == len(expected) and all(
                item.get("forward") is not None
                for path, item in matching.items() if expected[path]["kind"] in ("warmup", "clean")):
                break
            if time.monotonic() > deadline:
                json_write(evidence / scenario / "request-evidence-timeout.json", items)
                raise RuntimeError(scenario + " FAIL: missing request-correlated engine/API evidence")
            time.sleep(.1)
        json_write(evidence / scenario / "request-evidence.json", matching)
        connections, sessions, ids, decisions, ordinals, stamps = set(), set(), set(), set(), set(), []
        for path, item in matching.items():
            sent = expected[path]
            context, inspection, decision = item["context"], item["inspection"], item["decision"]
            connections.add(context["connection_id"]); sessions.add(context.get("session_id"))
            ids.add(context["request_id"]); decisions.add(decision["decision_id"]); ordinals.add(context["request_ordinal"])
            require(context["http_version"] == "HTTP/2.0" and context["scheme"] == "https"
                    and context["body_bytes"] == sent["body_bytes"] and inspection.get("completed") is True
                    and inspection.get("coverage") == "COMPLETE" and decision.get("coverage") == "COMPLETE"
                    and decision.get("config_generation") == generation,
                    scenario + " FAIL: HTTP/2 request identity, body size, coverage or generation mismatch")
            blocked = sent["kind"] not in ("warmup", "clean")
            require(decision["verdict"] == ("BLOCK" if blocked else "ALLOW"),
                    scenario + " FAIL: cross-request verdict mismatch")
            if blocked:
                sid = 9904003 if sent["kind"] == "sqli" else 9904004
                require(item.get("forward") is None and decision.get("reason_code") == "GATE_SIGNATURE_BLOCK"
                        and any(str(alert.get("signature_id")) == str(sid) for alert in inspection.get("alerts", [])),
                        scenario + " FAIL: blocked stream forwarded or has another stream's signature")
                stamps.append(item["observed_at"])
            else:
                forward = item["forward"]
                require(decision.get("reason_code") == "GATE_INSPECTION_COMPLETE"
                        and forward.get("http_status") == 200
                        and forward.get("reason_code") == "UPSTREAM_RESPONSE_RECEIVED",
                        scenario + " FAIL: clean request missing successful forward result")
                stamps.append(forward["observed_at"])
        require(len(connections) == 1 and len(sessions) == 1 and None not in sessions and "" not in sessions
                and len(ids) == len(expected) and len(decisions) == len(expected) and len(ordinals) == len(expected),
                scenario + " FAIL: request IDs/ordinals collided or requests used different connections/sessions")

        raw_origin = lab.command("dmz", "cat " + shlex.quote(dmz_log), sudo=True, evidence=scenario + "/origin.json")
        require(raw_origin["exit_code"] == 0, scenario + " FAIL: could not read origin")
        origin = [json.loads(line) for line in raw_origin["stdout"].splitlines() if line.strip()]
        allowed = {item["marker"]: item for item in [warmup] + clean}
        require(len(origin) == len(allowed) and {item["marker"] for item in origin} == set(allowed),
                scenario + " FAIL: attack reached origin or a clean request was lost/duplicated")
        for item in origin:
            require(item["body_sha256"] == allowed[item["marker"]]["body_sha256"],
                    scenario + " FAIL: cross-request body contamination at origin")
        base = before["response"]["data"]["counters"]
        minimum = {"intercepted": base.get("intercepted", 0) + 1,
                   "decrypted": base.get("decrypted", 0) + 1,
                   "request_allowed": base.get("request_allowed", 0) + len(clean) + 1,
                   "request_blocked": base.get("request_blocked", 0) + len(attacks)}
        try:
            after, observations = wait_for_health_counters(
                lambda timeout: lab.api("GET", "/request-gate/health", timeout=timeout),
                generation=generation, after=max(stamps), minimum_counters=minimum)
        except HealthObservationError as error:
            json_write(evidence / scenario / "health-observations.json", error.observations)
            raise RuntimeError(scenario + " FAIL: " + str(error)) from error
        json_write(evidence / scenario / "health-observations.json", observations)
        json_write(evidence / scenario / "health-after.json", after)
        counters = after["response"]["data"]["counters"]
        require(all(counters.get(key, 0) == base.get(key, 0) for key in ("bypassed", "result_report_fail", "inspection_timeout")),
                scenario + " FAIL: request bypass, result-report error or inspection timeout")
        record.update(result="PASS", clean=len(clean), attacks=len(attacks),
                      connection_id=next(iter(connections)), session_id=next(iter(sessions)),
                      unique_request_ids=len(ids), max_concurrency=client["max_concurrent_requests"],
                      origin_bodies_match=True, blocked_origin_requests=0)
        report[scenario] = "PASS"
        json_write(evidence / scenario / "assessment.json", record)
        json_write(evidence / "progress.json", report)
        print(json.dumps({"at": utc_now(), "case": scenario, "result": "PASS", "clean": len(clean),
                          "attacks": len(attacks), "max_concurrency": client["max_concurrent_requests"]}), flush=True)
    report["status"] = "PASS_M4_17_M4_18"
