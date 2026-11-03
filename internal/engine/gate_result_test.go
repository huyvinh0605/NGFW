package engine

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
)

func resultFixture(t *testing.T) (*GateService, domain.ProxyRequestResult) {
	t.Helper()
	service := gateTestService(t, gateTestConfig())
	open := gateTestOpen(true)
	open.OriginalPort = 443
	open.TLS = domain.TLSContext{SNI: "lab.example", Available: true}
	connection, err := service.OpenConnection(context.Background(), open)
	if err != nil || connection.Action != domain.TLSGateDecrypt {
		t.Fatalf("TLS fixture: %+v %v", connection, err)
	}
	input := gateRequestInput(open, connection)
	input.Context.Scheme = "https"
	decision, err := service.EvaluateRequest(context.Background(), input)
	if err != nil || decision.Verdict != domain.RequestAllow {
		t.Fatalf("ALLOW fixture: %+v %v", decision, err)
	}
	instance, err := service.engineInstance()
	if err != nil {
		t.Fatal(err)
	}
	service.InterceptionReady = func(generation uint64) bool { return generation == 1 }
	return service, domain.ProxyRequestResult{EngineInstanceID: instance, RequestID: input.Context.RequestID, ConnectionID: input.Context.ConnectionID,
		DecisionID: decision.DecisionID, ConfigGeneration: decision.ConfigGeneration, HTTPStatus: 502,
		ReasonCode: "TLS_UPSTREAM_MTLS_UNSUPPORTED", ClientCertificateRequested: true}
}

func TestM4RequestResultPreservesInspectionAndAdvancesEvidenceCursor(t *testing.T) {
	service, result := resultFixture(t)
	before := service.ListRequestGateEvidence(0, 1).Items[0]
	encoded, _ := json.Marshal(result)
	reply, err := service.HandleGate(context.Background(), gateipc.ReportRequestResult, encoded)
	if err != nil || reply.Meta.DecisionID != result.DecisionID || reply.Meta.ConfigGeneration != result.ConfigGeneration {
		t.Fatalf("report IPC: %+v %v", reply, err)
	}
	page := service.ListRequestGateEvidence(before.Sequence, 1)
	if len(page.Items) != 1 {
		t.Fatalf("cursor missed result annotation: %+v", page)
	}
	item := page.Items[0]
	if item.Decision != before.Decision || item.Forward == nil || item.Forward.ReasonCode != result.ReasonCode ||
		item.Forward.HTTPStatus != 502 || !item.Forward.ClientCertificateRequested || item.Forward.ObservedAt.Before(before.ObservedAt) {
		t.Fatalf("forward failure corrupted inspection/correlation: %+v", item)
	}
	item.Forward.ReasonCode = "mutated copy"
	if got := service.ListRequestGateEvidence(0, 1).Items[0].Forward.ReasonCode; got != result.ReasonCode {
		t.Fatal("forward evidence aliases retained state")
	}
	sequence := service.gateSequence
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := service.ReportRequestResult(context.Background(), result); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if service.gateSequence != sequence {
		t.Fatal("duplicate reports generated new events")
	}
	result.HTTPStatus, result.ReasonCode = 200, "UPSTREAM_RESPONSE_RECEIVED"
	if _, err := service.ReportRequestResult(context.Background(), result); err == nil {
		t.Fatal("conflicting result replaced failure")
	}
}

func TestM4RequestResultRejectsForeignStaleAndFabricatedFacts(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*GateService, *domain.ProxyRequestResult)
	}{
		{"request", func(_ *GateService, r *domain.ProxyRequestResult) { r.RequestID = strings.Repeat("0", 32) }},
		{"connection", func(_ *GateService, r *domain.ProxyRequestResult) { r.ConnectionID = strings.Repeat("0", 32) }},
		{"decision", func(_ *GateService, r *domain.ProxyRequestResult) { r.DecisionID = strings.Repeat("0", 32) }},
		{"generation", func(_ *GateService, r *domain.ProxyRequestResult) { r.ConfigGeneration++ }},
		{"engine instance", func(_ *GateService, r *domain.ProxyRequestResult) { r.EngineInstanceID = strings.Repeat("0", 32) }},
		{"mtls without certificate request", func(_ *GateService, r *domain.ProxyRequestResult) { r.ClientCertificateRequested = false }},
		{"wrong status", func(_ *GateService, r *domain.ProxyRequestResult) { r.HTTPStatus = 200 }},
		{"raw error", func(_ *GateService, r *domain.ProxyRequestResult) { r.ReasonCode = "error with secret path or headers" }},
		{"denied request", func(s *GateService, r *domain.ProxyRequestResult) {
			v := s.gateDecisions[r.RequestID]
			v.evidence.Decision.Verdict = domain.RequestBlock
			s.gateDecisions[r.RequestID] = v
		}},
		{"plaintext mtls", func(s *GateService, r *domain.ProxyRequestResult) {
			v := s.gateDecisions[r.RequestID]
			v.evidence.Context.Scheme = "http"
			s.gateDecisions[r.RequestID] = v
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, result := resultFixture(t)
			test.change(service, &result)
			if _, err := service.ReportRequestResult(context.Background(), result); err == nil {
				t.Fatal("invalid result accepted")
			}
			if item := service.ListRequestGateEvidence(0, 1).Items[0]; item.Forward != nil {
				t.Fatal("rejected result changed evidence")
			}
		})
	}
}

func TestM4RequestResultRespectsEvidenceByteBudget(t *testing.T) {
	service, result := resultFixture(t)
	before := service.gateDecisionBytes
	service.MaxEvidenceBytes = before
	if _, err := service.ReportRequestResult(context.Background(), result); err == nil {
		t.Fatal("oversized annotation accepted")
	}
	if service.gateDecisionBytes > before || service.ListRequestGateEvidence(0, 1).Items[0].Forward != nil {
		t.Fatal("evidence byte budget exceeded")
	}
}
