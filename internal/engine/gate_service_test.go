package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
	"github.com/kltngfw/ngfw/internal/session"
)

func gateTestConfig() domain.Config {
	c := config.Defaults()
	c.RequestGate = &domain.RequestGateConfig{Enabled: true}
	c.Interfaces = []domain.Interface{
		{ID: "lan-if", ZoneID: "lan", IPv4Addresses: []string{"192.168.10.1/24"}},
		{ID: "wan-if", ZoneID: "wan", IPv4Addresses: []string{"192.0.2.2/24"}},
		{ID: "dmz-if", ZoneID: "dmz", IPv4Addresses: []string{"10.20.0.1/24"}},
	}
	c.Routes = []domain.Route{{ID: "default", DestinationCIDR: "0.0.0.0/0", InterfaceID: "wan-if", Enabled: true}}
	c.Profiles = []domain.SecurityProfile{{ID: "gate", TLSMode: domain.TLSDecrypt, RequestGate: &domain.RequestGateProfile{Enabled: true, FailMode: domain.GateFailClose, OversizeAction: "BLOCK", UnsupportedEncodingAction: "BLOCK"}}}
	c.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, SecurityProfileID: "gate", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	return c
}

func gateTestService(t *testing.T, c domain.Config) *GateService {
	t.Helper()
	program, err := connectivity.CompileM4(c, 1)
	if err != nil {
		t.Fatal(err)
	}
	return &GateService{Runtime: NewRuntime(nil, program, 1, session.RuntimeLimits{MaxSessions: 8})}
}

func gateTestOpen(isTLS bool) domain.ProxyConnectionOpen {
	return domain.ProxyConnectionOpen{
		ConnectionID: "0123456789abcdef0123456789abcdef", SourceIP: "192.168.10.10", SourcePort: 50000,
		OriginalIP: "203.0.113.10", OriginalPort: 80, Protocol: "tcp", IsTLS: &isTLS,
	}
}

func TestM4OpenConnectionPlainHTTPRequiresSynchronousGate(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	open := gateTestOpen(false)
	decision, err := service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateInspectHTTP || decision.PolicyID != "web" || decision.ProfileID != "gate" || decision.ConfigGeneration != 1 || decision.DecisionID == "" || decision.SessionID != "" || decision.ReasonCode != "GATE_INSPECTION_REQUIRED" {
		t.Fatalf("plaintext request gate decision = %+v, %v", decision, err)
	}
	if decision.Action == domain.TLSGateBypass || decision.Action == domain.TLSGateMetadataOnly || decision.Action == domain.TLSGateDecrypt {
		t.Fatal("plaintext inspection was converted into tunnel/TLS action")
	}
	payload, _ := json.Marshal(open)
	result, err := service.HandleGate(context.Background(), gateipc.OpenConnection, payload)
	if err != nil || result.Meta.ConfigGeneration != 1 || result.Meta.DecisionID == "" {
		t.Fatalf("IPC handler did not return authoritative decision: %+v, %v", result, err)
	}
	if got, ok := result.Data.(domain.ProxyConnectionDecision); !ok || got.Action != domain.TLSGateInspectHTTP {
		t.Fatalf("IPC response bypassed plain HTTP gate: %+v", result.Data)
	}
}

func TestM4OpenConnectionFirstMatchDenyAndBlockOverride(t *testing.T) {
	c := gateTestConfig()
	service := gateTestService(t, c)
	open := gateTestOpen(false)
	if err := service.Runtime.AddTemporaryBlock(domain.TemporaryBlock{ID: "block", Indicator: open.SourceIP, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	decision, err := service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateBlock || decision.ReasonCode != "GATE_POLICY_NOT_ALLOWED" {
		t.Fatalf("temporary block bypassed: %+v, %v", decision, err)
	}
	service.Runtime.RemoveTemporaryBlock(open.SourceIP)
	// The compiled first-match program must outrank the later M4 ALLOW plan.
	program := service.Runtime.CurrentProgram()
	program.Rules = append([]connectivity.Rule{{ID: "deny", Priority: 1, Action: domain.DecisionDrop, Enabled: true}}, program.Rules...)
	if err := service.Runtime.Activate(program, 2, "policy changed"); err != nil {
		t.Fatal(err)
	}
	decision, err = service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateBlock || decision.PolicyID != "deny" || decision.ConfigGeneration != 2 {
		t.Fatalf("first-match deny bypassed: %+v, %v", decision, err)
	}
}

func TestM4OpenConnectionLinkedSNATAndDNAT(t *testing.T) {
	c := gateTestConfig()
	c.Policies = append(c.Policies, domain.SecurityPolicy{ID: "published", Priority: 20, SourceZones: []string{"wan"}, DestinationZones: []string{"dmz"}, Services: []string{"tcp:443"}, SecurityProfileID: "gate", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true})
	service := gateTestService(t, c)
	apply := func(original, reply domain.Tuple, id uint32) string {
		t.Helper()
		record := conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", ID: id, Family: original.Family, Original: original}, OriginalTuple: original, ReplyTuple: &reply, Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true}}
		value, _, err := service.Runtime.Store.Apply(record, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		source, destination := inferSessionZones(service.Runtime.CurrentProgram(), value)
		if _, err := service.Runtime.Store.SetZones(value.SessionID, source, destination); err != nil {
			t.Fatal(err)
		}
		return value.SessionID
	}
	snatOriginal := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6}
	snatReply := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: snatOriginal.DstIP, SrcPort: 443, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 55000, Protocol: 6}
	snatID := apply(snatOriginal, snatReply, 1)
	open := gateTestOpen(true)
	open.OriginalPort = 443
	open.TLS = domain.TLSContext{SNI: "lab.example", Available: true}
	decision, err := service.OpenConnection(context.Background(), open)
	if err != nil || decision.SessionID != snatID || decision.Action != domain.TLSGateDecrypt {
		t.Fatalf("SNAT linked to wrong session or action: %+v, %v", decision, err)
	}
	dnatOriginal := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("198.51.100.10"), SrcPort: 50001, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 8443, Protocol: 6}
	dnatReply := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("10.20.0.10"), SrcPort: 443, DstIP: dnatOriginal.SrcIP, DstPort: dnatOriginal.SrcPort, Protocol: 6}
	dnatID := apply(dnatOriginal, dnatReply, 2)
	dnatOpen := gateTestOpen(true)
	dnatOpen.TLS = domain.TLSContext{SNI: "dmz.example", Available: true}
	dnatOpen.ConnectionID = "11111111111111111111111111111111"
	dnatOpen.SourceIP, dnatOpen.SourcePort = dnatOriginal.SrcIP.String(), int(dnatOriginal.SrcPort)
	dnatOpen.OriginalIP, dnatOpen.OriginalPort = "10.20.0.10", 443
	decision, err = service.OpenConnection(context.Background(), dnatOpen)
	if err != nil || decision.SessionID != dnatID || decision.Action != domain.TLSGateDecrypt || decision.PolicyID != "published" || decision.UpstreamIP != "10.20.0.10" {
		t.Fatalf("DNAT post-translation flow not linked: %+v, %v", decision, err)
	}
	dnatOpen.OriginalIP, dnatOpen.OriginalPort = "192.0.2.2", 8443
	decision, err = service.OpenConnection(context.Background(), dnatOpen)
	if err != nil || decision.Action != domain.TLSGateBlock {
		t.Fatalf("pre-DNAT VIP was used as verified upstream: %+v, %v", decision, err)
	}
}

func TestM4OpenConnectionTLSModesAndExclusion(t *testing.T) {
	c := gateTestConfig()
	c.TLSExclusions = []domain.TLSExclusion{{ID: "bank", Enabled: true, Domains: []string{"*.example.com"}, DestinationCIDRs: []string{"203.0.113.0/24"}, Ports: []int{443}, Reason: "pinning"}}
	open := gateTestOpen(true)
	open.OriginalPort = 443
	open.TLS = domain.TLSContext{SNI: "api.example.com", Available: true}
	for _, tc := range []struct {
		mode domain.TLSMode
		want domain.TLSGateAction
	}{
		{domain.TLSBypass, domain.TLSGateBypass},
		{domain.TLSMetadata, domain.TLSGateMetadataOnly},
		{domain.TLSDecrypt, domain.TLSGateBypass},
	} {
		c.Profiles[0].TLSMode = tc.mode
		service := gateTestService(t, c)
		decision, err := service.OpenConnection(context.Background(), open)
		if err != nil || decision.Action != tc.want {
			t.Fatalf("mode %s produced %+v, %v", tc.mode, decision, err)
		}
		if tc.mode == domain.TLSDecrypt && decision.ReasonCode != "TLS_EXCLUSION" {
			t.Fatalf("exclusion not explicit: %+v", decision)
		}
	}
	open.TLS.SNI = "example.com" // wildcard must not match apex
	c.Profiles[0].TLSMode = domain.TLSDecrypt
	decision, err := gateTestService(t, c).OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateDecrypt {
		t.Fatalf("non-matching TLS host bypassed decryption: %+v, %v", decision, err)
	}
	open.TLS.SNI = "api.example.com"
	service := gateTestService(t, c)
	program := service.Runtime.CurrentProgram()
	program.Rules = append([]connectivity.Rule{{ID: "deny", Priority: 1, Action: domain.DecisionDrop, Enabled: true}}, program.Rules...)
	if err := service.Runtime.Activate(program, 2, "deny before exclusion"); err != nil {
		t.Fatal(err)
	}
	decision, err = service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateBlock || decision.PolicyID != "deny" {
		t.Fatalf("TLS exclusion overrode first-match L3 deny: %+v, %v", decision, err)
	}
}

func TestM4OpenConnectionClientHelloFailureUsesEngineProfile(t *testing.T) {
	for _, failure := range []string{"TLS_CLIENTHELLO_TIMEOUT", "TLS_CLIENTHELLO_INVALID", ""} {
		for _, mode := range []domain.GateFailMode{domain.GateFailOpen, domain.GateFailClose} {
			config := gateTestConfig()
			config.Profiles[0].RequestGate.FailMode = mode
			service := gateTestService(t, config)
			open := gateTestOpen(true)
			open.OriginalPort = 443
			open.TLSFailureCode = failure
			decision, err := service.OpenConnection(context.Background(), open)
			wantAction := domain.TLSGateBlock
			if mode == domain.GateFailOpen {
				wantAction = domain.TLSGateBypass
			}
			wantReason := failure
			if failure == "" {
				wantReason = "TLS_SNI_UNAVAILABLE"
			}
			if err != nil || decision.Action != wantAction || decision.ReasonCode != wantReason {
				t.Fatalf("failure=%q mode=%s decision=%+v err=%v", failure, mode, decision, err)
			}
		}
	}
	service := gateTestService(t, gateTestConfig())
	plain := gateTestOpen(false)
	plain.TLSFailureCode = "TLS_CLIENTHELLO_INVALID"
	if _, err := service.OpenConnection(context.Background(), plain); err == nil {
		t.Fatal("plain HTTP carried TLS failure code")
	}
}

func TestM4OpenConnectionGenerationAndValidation(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	open := gateTestOpen(false)
	for _, mutate := range []func(*domain.ProxyConnectionOpen){
		func(v *domain.ProxyConnectionOpen) { v.IsTLS = nil },
		func(v *domain.ProxyConnectionOpen) { v.Protocol = "udp" },
		func(v *domain.ProxyConnectionOpen) { v.ConnectionID = "bad" },
		func(v *domain.ProxyConnectionOpen) { v.OriginalIP = "invalid" },
		func(v *domain.ProxyConnectionOpen) { v.TLS.SNI = "claimed.example" },
	} {
		invalid := open
		mutate(&invalid)
		if _, err := service.OpenConnection(context.Background(), invalid); err == nil {
			t.Fatalf("accepted malformed open connection: %+v", invalid)
		}
	}
	c := gateTestConfig()
	c.RequestGate = nil
	c.Profiles = nil
	c.Policies = []domain.SecurityPolicy{{ID: "drop", Priority: 1, Action: domain.DecisionDrop, Enabled: true}}
	program, err := connectivity.CompileM4(c, 2)
	if err != nil || service.Runtime.Activate(program, 2, "policy changed") != nil {
		t.Fatalf("activation failed: %v", err)
	}
	decision, err := service.OpenConnection(context.Background(), open)
	if err != nil || decision.ConfigGeneration != 2 || decision.Action != domain.TLSGateBlock || decision.PolicyID != "drop" {
		t.Fatalf("stale ALLOW survived generation change: %+v, %v", decision, err)
	}
	_, err = service.HandleGate(context.Background(), gateipc.EvaluateRequest, json.RawMessage(`{}`))
	var ipcErr *gateipc.ProtocolError
	if !errors.As(err, &ipcErr) || ipcErr.Code != gateipc.CodeMalformed {
		t.Fatalf("unimplemented IPC operation was accepted: %v", err)
	}
}

func TestM4OpenConnectionRealUnixIPC(t *testing.T) {
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
		select {
		case err := <-done:
			t.Fatalf("gate server failed: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("gate server did not listen")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var decision domain.ProxyConnectionDecision
	meta, err := gateipc.NewClient(path).CallAtGeneration(context.Background(), gateipc.OpenConnection, gateTestOpen(false), &decision, 1)
	if err != nil || decision.Action != domain.TLSGateInspectHTTP || decision.DecisionID != meta.DecisionID || decision.ConfigGeneration != meta.ConfigGeneration {
		t.Fatalf("authoritative Unix gate round trip failed: %+v %+v %v", meta, decision, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gate server did not stop")
	}
}
