package engine

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
)

func gateRequestInput(open domain.ProxyConnectionOpen, connectionDecision domain.ProxyConnectionDecision) domain.ProxyRequestEvaluation {
	requestID := "fedcba9876543210fedcba9876543210"
	return domain.ProxyRequestEvaluation{
		Context: domain.RequestContext{
			RequestID: requestID, ConnectionID: open.ConnectionID, SessionID: connectionDecision.SessionID,
			RequestOrdinal: 1, HTTPVersion: "HTTP/1.1", Method: "GET", Scheme: "http",
			Host: "lab.example", Path: "/", HeaderBytes: 100,
		},
		Inspection: domain.RequestInspectionResult{RequestID: requestID, Completed: true, Coverage: domain.CoverageComplete},
	}
}

func TestM4EvaluateRequestAuthoritativeVerdicts(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	open := gateTestOpen(false)
	connection, err := service.OpenConnection(context.Background(), open)
	if err != nil || connection.Action != domain.TLSGateInspectHTTP {
		t.Fatalf("connection gate setup: %+v %v", connection, err)
	}
	input := gateRequestInput(open, connection)
	clean, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || clean.Verdict != domain.RequestAllow || clean.Coverage != domain.CoverageComplete || clean.HTTPStatus != 0 || clean.ConfigGeneration != 1 || clean.PolicyID != "web" || clean.DecisionID == "" {
		t.Fatalf("clean authoritative verdict: %+v %v", clean, err)
	}
	storedContext, storedDecision, ok := service.GetRequestDecision(input.Context.RequestID)
	if !ok || storedContext.ConnectionID != open.ConnectionID || storedDecision.DecisionID != clean.DecisionID {
		t.Fatalf("bounded engine decision record absent: %+v %+v %v", storedContext, storedDecision, ok)
	}
	input.Inspection.Alerts = []domain.RequestAlert{{Detector: "suricata", SignatureID: "2012345", Action: "blocked", Category: "web-application-attack"}}
	malicious, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || malicious.Verdict != domain.RequestBlock || malicious.HTTPStatus != 403 || malicious.ReasonCode != "GATE_SIGNATURE_BLOCK" {
		t.Fatalf("blocking alert not enforced: %+v %v", malicious, err)
	}
	input.Inspection.Alerts[0].Action = "allowed"
	nonblocking, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || nonblocking.Verdict != domain.RequestAllow || nonblocking.Coverage != domain.CoverageComplete {
		t.Fatalf("alert action conflated with request verdict: %+v %v", nonblocking, err)
	}
}

func TestM4EvaluateRequestFailureModesAndPartial(t *testing.T) {
	for _, failMode := range []domain.GateFailMode{domain.GateFailOpen, domain.GateFailClose} {
		config := gateTestConfig()
		config.Profiles[0].RequestGate.FailMode = failMode
		if failMode == domain.GateFailOpen {
			config.Profiles[0].RequestGate.OversizeAction = "ALLOW_PARTIAL"
		}
		service := gateTestService(t, config)
		open := gateTestOpen(false)
		connection, _ := service.OpenConnection(context.Background(), open)
		input := gateRequestInput(open, connection)
		input.Inspection = domain.RequestInspectionResult{RequestID: input.Context.RequestID, Completed: false, Coverage: domain.RequestCoverageUnavailable, ErrorCode: "GATE_EVE_INCOMPLETE"}
		outage, err := service.EvaluateRequest(context.Background(), input)
		if err != nil || outage.Coverage != domain.RequestCoverageUnavailable || outage.ReasonCode != "GATE_EVE_INCOMPLETE" {
			t.Fatalf("outage mislabeled clean: %+v %v", outage, err)
		}
		if failMode == domain.GateFailOpen && (outage.Verdict != domain.RequestAllow || outage.HTTPStatus != 0) || failMode == domain.GateFailClose && (outage.Verdict != domain.RequestBlock || outage.HTTPStatus != 503) {
			t.Fatalf("wrong failure mode %s: %+v", failMode, outage)
		}
		input.Context.Truncated = true
		input.Inspection.Coverage = domain.RequestCoveragePartial
		partial, err := service.EvaluateRequest(context.Background(), input)
		if err != nil || partial.Coverage != domain.RequestCoveragePartial || partial.ReasonCode != "GATE_REQUEST_TOO_LARGE" {
			t.Fatalf("partial body lost: %+v %v", partial, err)
		}
		if failMode == domain.GateFailOpen && (partial.Verdict != domain.RequestAllow || partial.HTTPStatus != 0) || failMode == domain.GateFailClose && (partial.Verdict != domain.RequestBlock || partial.HTTPStatus != 413) {
			t.Fatalf("wrong oversize mode %s: %+v", failMode, partial)
		}
	}
}

func TestM4EvaluateRequestUnsupportedEncodingUsesProfileAction(t *testing.T) {
	for _, test := range []struct {
		name   string
		mode   domain.GateFailMode
		action string
		want   domain.RequestVerdict
		status int
	}{
		{"open-block", domain.GateFailOpen, "BLOCK", domain.RequestBlock, 503},
		{"open-partial", domain.GateFailOpen, "ALLOW_PARTIAL", domain.RequestAllow, 0},
		{"close-partial", domain.GateFailClose, "ALLOW_PARTIAL", domain.RequestBlock, 503},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := gateTestConfig()
			config.Profiles[0].RequestGate.FailMode = test.mode
			config.Profiles[0].RequestGate.UnsupportedEncodingAction = test.action
			service := gateTestService(t, config)
			open := gateTestOpen(false)
			connection, _ := service.OpenConnection(context.Background(), open)
			input := gateRequestInput(open, connection)
			input.Inspection = domain.RequestInspectionResult{
				RequestID: input.Context.RequestID, Coverage: domain.RequestCoverageUnavailable,
				ErrorCode: "GATE_UNSUPPORTED_ENCODING",
			}
			decision, err := service.EvaluateRequest(context.Background(), input)
			if err != nil || decision.Verdict != test.want || decision.HTTPStatus != test.status || decision.Coverage != domain.RequestCoverageUnavailable || decision.ReasonCode != "GATE_UNSUPPORTED_ENCODING" {
				t.Fatalf("unsupported encoding was not profile-controlled: %+v %v", decision, err)
			}
			input.Inspection.ErrorCode = "GATE_REQUEST_MALFORMED"
			malformed, err := service.EvaluateRequest(context.Background(), input)
			if err != nil || malformed.Verdict != domain.RequestBlock || malformed.HTTPStatus != 400 || malformed.ReasonCode != "GATE_REQUEST_MALFORMED" {
				t.Fatalf("malformed encoded body escaped: %+v %v", malformed, err)
			}
		})
	}
}

func TestM4EvaluateRequestRechecksPolicyAndBlock(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	open := gateTestOpen(false)
	connection, _ := service.OpenConnection(context.Background(), open)
	input := gateRequestInput(open, connection)
	initial, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || initial.Verdict != domain.RequestAllow {
		t.Fatalf("initial allow failed: %+v %v", initial, err)
	}
	if err := service.Runtime.AddTemporaryBlock(domain.TemporaryBlock{ID: "b1", Indicator: open.SourceIP, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	blocked, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || blocked.Verdict != domain.RequestBlock || blocked.HTTPStatus != 403 {
		t.Fatalf("new block bypassed cached allow: %+v %v", blocked, err)
	}
	service.Runtime.RemoveTemporaryBlock(open.SourceIP)
	program := service.Runtime.CurrentProgram()
	program.Rules = append([]connectivity.Rule{{ID: "deny", Priority: 1, Action: domain.DecisionDrop, Enabled: true}}, program.Rules...)
	if err := service.Runtime.Activate(program, 2, "policy deny"); err != nil {
		t.Fatal(err)
	}
	denied, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || denied.Verdict != domain.RequestBlock || denied.ConfigGeneration != 2 || denied.HTTPStatus != 403 || denied.ReasonCode != "GATE_POLICY_NOT_ALLOWED" {
		t.Fatalf("old connection allow survived generation change: %+v %v", denied, err)
	}
}

func TestM4EvaluateRequestIdentityAndCapacity(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	service.MaxConnections = 1
	service.MaxDecisions = 1
	open := gateTestOpen(false)
	connection, _ := service.OpenConnection(context.Background(), open)
	input := gateRequestInput(open, connection)
	input.Context.ConnectionID = "00000000000000000000000000000000"
	missing, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || missing.Verdict != domain.RequestBlock || missing.HTTPStatus != 503 {
		t.Fatalf("unknown connection authorized: %+v %v", missing, err)
	}
	input.Context.ConnectionID = open.ConnectionID
	input.Context.SessionID = "foreign-session"
	foreign, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || foreign.Verdict != domain.RequestBlock || foreign.HTTPStatus != 403 {
		t.Fatalf("foreign session accepted: %+v %v", foreign, err)
	}
	input.Context.SessionID = connection.SessionID
	input.Inspection.RequestID = "other-request"
	if _, err := service.EvaluateRequest(context.Background(), input); err == nil {
		t.Fatal("mismatched detector result accepted")
	}
	second := gateTestOpen(false)
	second.ConnectionID = "11111111111111111111111111111111"
	second.SourcePort++
	capacity, err := service.OpenConnection(context.Background(), second)
	if err != nil || capacity.Action != domain.TLSGateBlock || capacity.ReasonCode != "GATE_ENGINE_UNAVAILABLE" {
		t.Fatalf("unbounded gate registry: %+v %v", capacity, err)
	}
}

func TestM4EvaluateRequestUnixIPC(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	path := filepath.Join(t.TempDir(), "gate.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- gateipc.NewServer(service).ServeUnix(ctx, path) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("IPC listener not ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	open := gateTestOpen(false)
	var connection domain.ProxyConnectionDecision
	client := gateipc.NewClient(path)
	if _, err := client.CallAtGeneration(context.Background(), gateipc.OpenConnection, open, &connection, 1); err != nil {
		t.Fatal(err)
	}
	input := gateRequestInput(open, connection)
	var verdict domain.RequestDecision
	meta, err := client.CallAtGeneration(context.Background(), gateipc.EvaluateRequest, input, &verdict, 1)
	if err != nil || verdict.Verdict != domain.RequestAllow || meta.DecisionID != verdict.DecisionID || meta.ConfigGeneration != verdict.ConfigGeneration {
		t.Fatalf("request verdict IPC mismatch: %+v %+v %v", meta, verdict, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPC listener did not stop")
	}
}

func TestM4RequestEvidenceIsBoundedRedactedAndVisibleInSessionDetail(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	service.MaxDecisions = 2
	open := gateTestOpen(false)
	original := domain.Tuple{
		Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr(open.SourceIP), SrcPort: uint16(open.SourcePort),
		DstIP: netip.MustParseAddr(open.OriginalIP), DstPort: uint16(open.OriginalPort), Protocol: 6,
	}
	reply := original.Reverse()
	record := conntrack.Record{
		Identity:      domain.ConntrackIdentity{BootID: "boot", ID: 777, Family: domain.FamilyIPv4, Original: original},
		OriginalTuple: original, ReplyTuple: &reply,
		Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true},
	}
	tracked, _, err := service.Runtime.Store.Apply(record, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Runtime.Store.SetZones(tracked.SessionID, "lan", "wan"); err != nil {
		t.Fatal(err)
	}
	connection, err := service.OpenConnection(context.Background(), open)
	if err != nil || connection.SessionID != tracked.SessionID {
		t.Fatalf("gate connection did not link M2 session: %+v %v", connection, err)
	}
	for i := 0; i < 3; i++ {
		input := gateRequestInput(open, connection)
		input.Context.RequestID = strings.Repeat(string(rune('a'+i)), 32)
		input.Context.RequestOrdinal = uint64(i + 1)
		input.Context.Path = "/" + strings.Repeat("p", 400)
		input.Context.QueryPresent = true
		input.Inspection.RequestID = input.Context.RequestID
		input.Inspection.Alerts = make([]domain.RequestAlert, 6)
		for j := range input.Inspection.Alerts {
			input.Inspection.Alerts[j] = domain.RequestAlert{
				Detector: "suricata", SignatureID: "123", Category: "web",
				Message: strings.Repeat("m", 300), Action: "alert",
			}
		}
		decision, err := service.EvaluateRequest(context.Background(), input)
		if err != nil || decision.Verdict != domain.RequestAllow {
			t.Fatalf("evidence request %d failed: %+v %v", i, decision, err)
		}
	}
	if _, _, ok := service.GetRequestDecision(strings.Repeat("a", 32)); ok {
		t.Fatal("old request record survived bounded eviction")
	}
	page := service.ListRequestGateEvidence(0, 1)
	if len(page.Items) != 1 || !page.HasMore || page.Items[0].Sequence != 2 {
		t.Fatalf("bounded evidence pagination failed: %+v", page)
	}
	next := service.ListRequestGateEvidence(page.NextSequence, 1)
	if len(next.Items) != 1 || next.HasMore || next.Items[0].Sequence != 3 {
		t.Fatalf("second evidence page failed: %+v", next)
	}
	evidence := next.Items[0]
	if !evidence.PathTruncated || len(evidence.Context.Path) > 256 || !evidence.AlertsTruncated || evidence.AlertCount != 6 || len(evidence.Inspection.Alerts) != 4 || len(evidence.Inspection.Alerts[0].Message) > 128 {
		t.Fatalf("retained evidence was not bounded: %+v", evidence)
	}
	encoded, _ := json.Marshal(evidence)
	if strings.Contains(string(encoded), "Cookie") || strings.Contains(string(encoded), "Authorization") || strings.Contains(string(encoded), "raw_query") || strings.Contains(string(encoded), "raw_body") {
		t.Fatalf("sensitive raw fields leaked into evidence: %s", encoded)
	}
	adapter := &RuntimeServiceAdapter{Runtime: service.Runtime, Gate: service}
	detail, err := adapter.GetSession(context.Background(), tracked.SessionID)
	if err != nil || len(detail.RequestGate) != 2 || detail.RequestGate[0].Sequence != 3 {
		t.Fatalf("session detail omitted bounded request evidence: %+v %v", detail.RequestGate, err)
	}
	detail.RequestGate[0].Inspection.Alerts[0].Message = "mutated"
	again, _ := adapter.GetSession(context.Background(), tracked.SessionID)
	if again.RequestGate[0].Inspection.Alerts[0].Message == "mutated" {
		t.Fatal("session detail exposed mutable engine evidence")
	}
	events, _, _ := service.Runtime.Events.Read(0, 16)
	found := false
	for _, event := range events {
		if event.Kind == domain.EventRequestGateDecision && event.SessionID == tracked.SessionID && event.Class == domain.EventClassSecurity {
			found = true
		}
	}
	if !found {
		t.Fatal("request verdict did not publish a bounded runtime security event")
	}
}

func TestM4RequestEvidenceByteCapAndConcurrentReads(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	open := gateTestOpen(false)
	connection, _ := service.OpenConnection(context.Background(), open)
	input := gateRequestInput(open, connection)
	_, _ = service.EvaluateRequest(context.Background(), input)
	first := service.ListRequestGateEvidence(0, 1)
	if len(first.Items) != 1 {
		t.Fatal("missing first evidence record")
	}
	encoded, _ := json.Marshal(first.Items[0])
	service.MaxEvidenceBytes = len(encoded) + 32
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			copyInput := input
			copyInput.Context.RequestID = strings.Repeat(string(rune('A'+i)), 32)
			copyInput.Inspection.RequestID = copyInput.Context.RequestID
			_, _ = service.EvaluateRequest(context.Background(), copyInput)
			_ = service.ListRequestGateEvidence(0, 2)
			_ = service.RequestEvidenceForSession("missing", 32)
		}(i)
	}
	workers.Wait()
	service.gateMu.Lock()
	count, used, capBytes := len(service.gateDecisions), service.gateDecisionBytes, service.MaxEvidenceBytes
	service.gateMu.Unlock()
	if count > 1 || used > capBytes || used < 0 {
		t.Fatalf("evidence store exceeded byte cap: count=%d used=%d cap=%d", count, used, capBytes)
	}
}
