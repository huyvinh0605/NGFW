package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestM4ZeroAndUnknownNeverBecomeAllow(t *testing.T) {
	if GateFailMode("").Valid() || GateFailMode("OTHER").Valid() || TLSGateAction("").Valid() || TLSGateAction("ALLOW").Valid() || RequestVerdict("").Valid() || RequestVerdict("CLEAN").Valid() || RequestCoverage("").Valid() || RequestCoverage("CLEAN").Valid() {
		t.Fatal("zero or unknown M4 enum was accepted")
	}
	for _, mode := range []GateFailMode{GateFailOpen, GateFailClose} {
		if !mode.Valid() {
			t.Fatalf("valid fail mode %q rejected", mode)
		}
	}
	for _, action := range []TLSGateAction{TLSGateBypass, TLSGateMetadataOnly, TLSGateDecrypt, TLSGateInspectHTTP, TLSGateBlock} {
		if !action.Valid() {
			t.Fatalf("valid TLS action %q rejected", action)
		}
	}
	for _, verdict := range []RequestVerdict{RequestAllow, RequestBlock, RequestUnavailable} {
		if !verdict.Valid() {
			t.Fatalf("valid verdict %q rejected", verdict)
		}
	}
	for _, coverage := range []RequestCoverage{CoverageComplete, RequestCoveragePartial, RequestCoverageUnavailable, CoverageNotRequested} {
		if !coverage.Valid() {
			t.Fatalf("valid coverage %q rejected", coverage)
		}
	}
	if (RequestCoveragePartial == RequestCoverage(CoveragePartial)) && (RequestCoverageUnavailable == RequestCoverage(CoverageUnavailable)) {
		// Wire values intentionally match M3; the Go types do not.
	} else {
		t.Fatal("M4 coverage wire values drifted from contract")
	}
}

func TestM4PlainHTTPConnectionActionWireContract(t *testing.T) {
	plain := false
	open := ProxyConnectionOpen{ConnectionID: "conn", IsTLS: &plain}
	encoded, err := json.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"is_tls":false`) {
		t.Fatalf("plain HTTP must explicitly identify its transport: %s", encoded)
	}
	var decoded ProxyConnectionOpen
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.IsTLS == nil || *decoded.IsTLS {
		t.Fatalf("plain HTTP transport identity was lost: %+v, %v", decoded, err)
	}
	decision, err := json.Marshal(ProxyConnectionDecision{Action: TLSGateInspectHTTP})
	if err != nil || !strings.Contains(string(decision), `"action":"INSPECT_HTTP"`) {
		t.Fatalf("plain HTTP inspection action drifted: %s, %v", decision, err)
	}
}

func TestM4RequestContextRoundTripAndClone(t *testing.T) {
	stream := uint32(11)
	input := RequestContext{RequestID: "r1", ConnectionID: "c1", RequestOrdinal: 1<<54 + 7, HTTPVersion: "HTTP/2.0", StreamID: &stream, Method: "POST", Scheme: "https", Host: "app.example", Path: "/orders", QueryPresent: true}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "raw_query") {
		t.Fatal("request context persisted raw query")
	}
	var output RequestContext
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatal(err)
	}
	if output.RequestOrdinal != input.RequestOrdinal || output.StreamID == nil || *output.StreamID != stream || !output.QueryPresent {
		t.Fatalf("request identity changed: %#v", output)
	}
	copy := output.Clone()
	*copy.StreamID = 19
	if *output.StreamID != 11 {
		t.Fatal("stream pointer was shared between requests")
	}
}

func TestM4EvidenceAndHealthClonesAreIndependent(t *testing.T) {
	result := RequestInspectionResult{RequestID: "r1", Coverage: CoverageComplete, Completed: true, Alerts: []RequestAlert{{SignatureID: "941100", Action: "alert"}}}
	clone := result.Clone()
	clone.Alerts[0].SignatureID = "other"
	if result.Alerts[0].SignatureID != "941100" {
		t.Fatal("alert state was shared")
	}
	health := RequestGateHealth{Counters: map[string]uint64{"request_allowed": 1}}
	copy := health.Clone()
	copy.Counters["request_allowed"]++
	if health.Counters["request_allowed"] != 1 {
		t.Fatal("health counters were shared")
	}
	for _, value := range []any{ProxyConnectionOpen{}, ProxyConnectionDecision{Action: TLSGateDecrypt, FailMode: GateFailClose}, result, RequestDecision{Verdict: RequestBlock, Coverage: CoverageComplete, HTTPStatus: 403, ReasonCode: "GATE_SIGNATURE_BLOCK"}, health} {
		encoded, err := json.Marshal(value)
		if err != nil || !json.Valid(encoded) {
			t.Fatalf("invalid M4 JSON for %T: %v", value, err)
		}
	}
}
