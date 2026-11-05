package engine

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
)

func proxyLookupRecord(open domain.ProxyConnectionOpen, id uint32) conntrack.Record {
	tuple := domain.Tuple{Family: domain.FamilyIPv4, Protocol: 6,
		SrcIP: netip.MustParseAddr(open.SourceIP), SrcPort: uint16(open.SourcePort),
		DstIP: netip.MustParseAddr(open.OriginalIP), DstPort: uint16(open.OriginalPort)}
	reply := tuple.Reverse()
	return conntrack.Record{Identity: domain.ConntrackIdentity{BootID: "boot", ID: id, Family: tuple.Family, Original: tuple},
		OriginalTuple: tuple, ReplyTuple: &reply,
		Presence: conntrack.Presence{OriginalTuple: true, ReplyTuple: true, ID: true}}
}

func trackProxyRecord(t *testing.T, service *GateService, record conntrack.Record) domain.RuntimeSession {
	t.Helper()
	value, _, err := service.Runtime.Store.Apply(record, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	source, destination := inferSessionZones(service.Runtime.CurrentProgram(), value)
	value, err = service.Runtime.Store.SetZones(value.SessionID, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestM4ReusedTupleBindsCurrentKernelIncarnation(t *testing.T) {
	for _, currentAlreadyObserved := range []bool{false, true} {
		name := "new-event-delayed"
		if currentAlreadyObserved {
			name = "old-and-new-aliases"
		}
		t.Run(name, func(t *testing.T) {
			service := gateTestService(t, gateTestConfig())
			source := conntrack.NewFakeSource(8)
			service.Runtime.Source = source
			open := gateTestOpen(false)
			oldRecord := proxyLookupRecord(open, 100)
			oldRecord.TCPState = "TIME_WAIT"
			old := trackProxyRecord(t, service, oldRecord)
			currentRecord := proxyLookupRecord(open, 101)
			if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: currentRecord}); err != nil {
				t.Fatal(err)
			}
			var current domain.RuntimeSession
			if currentAlreadyObserved {
				current = trackProxyRecord(t, service, currentRecord)
			}
			connection, err := service.OpenConnection(context.Background(), open)
			if err != nil || connection.Action != domain.TLSGateInspectHTTP || connection.SessionID == old.SessionID {
				t.Fatalf("new connection was denied or pinned to an expired incarnation: %+v %v", connection, err)
			}
			if !currentAlreadyObserved {
				if connection.SessionID != "" {
					t.Fatalf("unobserved live incarnation was invented: %+v", connection)
				}
				current = trackProxyRecord(t, service, currentRecord)
			}
			input := gateRequestInput(open, connection)
			decision, err := service.EvaluateRequest(context.Background(), input)
			if err != nil || decision.Verdict != domain.RequestAllow || decision.SessionID != current.SessionID {
				t.Fatalf("clean request falsely blocked by tuple reuse: %+v %v", decision, err)
			}
			input.Inspection.Alerts = []domain.RequestAlert{{Detector: "suricata", SignatureID: "9904003", Action: "allowed"}}
			decision, err = service.EvaluateRequest(context.Background(), input)
			if err != nil || decision.Verdict != domain.RequestBlock || decision.ReasonCode != "GATE_SIGNATURE_BLOCK" {
				t.Fatalf("corrected binding bypassed signature enforcement: %+v %v", decision, err)
			}
			// A connection already bound to the current incarnation must never
			// follow another NEW event for the same tuple.
			source.Forget(currentRecord.Identity)
			replacement := proxyLookupRecord(open, 102)
			if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: replacement}); err != nil {
				t.Fatal(err)
			}
			trackProxyRecord(t, service, replacement)
			input.Inspection.Alerts = nil
			decision, err = service.EvaluateRequest(context.Background(), input)
			if err != nil || decision.Verdict != domain.RequestBlock {
				t.Fatalf("bound proxy connection migrated to a different kernel flow: %+v %v", decision, err)
			}
		})
	}
}

func TestM4LiveReplyLookupResolvesPostDNAT(t *testing.T) {
	c := gateTestConfig()
	c.Policies[0].SourceZones, c.Policies[0].DestinationZones = []string{"wan"}, []string{"dmz"}
	service := gateTestService(t, c)
	source := conntrack.NewFakeSource(8)
	service.Runtime.Source = source
	open := gateTestOpen(true)
	open.SourceIP, open.OriginalIP, open.OriginalPort = "198.51.100.10", "10.20.0.10", 443
	open.TLS = domain.TLSContext{SNI: "dmz.example", Available: true}
	record := proxyLookupRecord(open, 200)
	record.OriginalTuple.DstIP, record.OriginalTuple.DstPort = netip.MustParseAddr("192.0.2.2"), 8443
	record.Identity.Original = record.OriginalTuple
	current := trackProxyRecord(t, service, record)
	if err := source.Emit(conntrack.Event{Kind: conntrack.EventNew, Record: record}); err != nil {
		t.Fatal(err)
	}
	decision, err := service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateDecrypt || decision.SessionID != current.SessionID {
		t.Fatalf("post-DNAT target did not resolve through the live reply tuple: %+v %v", decision, err)
	}
	if _, err := service.Runtime.Store.MarkRevoked(current.SessionID, 1, "test current incarnation"); err != nil {
		t.Fatal(err)
	}
	decision, err = service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateBlock {
		t.Fatalf("live lookup bypassed a current revoke: %+v %v", decision, err)
	}
}

type proxyReplySource struct {
	conntrack.Source
	record conntrack.Record
	err    error
}

func (s proxyReplySource) LookupReply(context.Context, domain.Tuple, uint16) (conntrack.Record, error) {
	return s.record, s.err
}

func TestM4LiveLookupFailureCannotUseCachedAllow(t *testing.T) {
	for _, mode := range []domain.GateFailMode{domain.GateFailOpen, domain.GateFailClose} {
		for _, scenario := range []string{"absent", "unavailable", "wrong-zone", "wrong-namespace", "wrong-reply", "no-id"} {
			t.Run(string(mode)+"/"+scenario, func(t *testing.T) {
				c := gateTestConfig()
				c.Profiles[0].RequestGate.FailMode = mode
				service := gateTestService(t, c)
				open := gateTestOpen(false)
				record := proxyLookupRecord(open, 300)
				trackProxyRecord(t, service, record)
				source := proxyReplySource{Source: conntrack.NewFakeSource(8), record: record}
				switch scenario {
				case "absent":
					source.err = conntrack.ErrFlowNotFound
				case "unavailable":
					source.err = errors.New("kernel unavailable")
				case "wrong-zone":
					source.record.Identity.Zone++
				case "wrong-namespace":
					source.record.Identity.NetworkNS = "other"
				case "wrong-reply":
					copy := *record.ReplyTuple
					copy.DstPort++
					source.record.ReplyTuple = &copy
				case "no-id":
					source.record.Identity.ID = 0
				}
				service.Runtime.Source = source
				decision, err := service.OpenConnection(context.Background(), open)
				if err != nil || decision.Action != domain.TLSGateBlock || decision.ReasonCode != "GATE_ENGINE_UNAVAILABLE" {
					t.Fatalf("unverified live flow used a cached ALLOW: %+v %v", decision, err)
				}
			})
		}
	}
}

func TestM4LiveLookupKeepsSourceBlockAndBoundedWait(t *testing.T) {
	service := gateTestService(t, gateTestConfig())
	open := gateTestOpen(false)
	record := proxyLookupRecord(open, 400)
	trackProxyRecord(t, service, record)
	service.Runtime.Source = proxyReplySource{Source: conntrack.NewFakeSource(8), record: record}
	if err := service.Runtime.AddTemporaryBlock(domain.TemporaryBlock{ID: "test", Indicator: open.SourceIP, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	decision, err := service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateBlock || decision.ReasonCode != "GATE_POLICY_NOT_ALLOWED" {
		t.Fatalf("live lookup ignored the source block: %+v %v", decision, err)
	}
	service.Runtime.RemoveTemporaryBlock(open.SourceIP)
	for i := 0; i < cap(service.Runtime.refreshSlots); i++ {
		service.Runtime.refreshSlots <- struct{}{}
	}
	started := time.Now()
	decision, err = service.OpenConnection(context.Background(), open)
	if err != nil || decision.Action != domain.TLSGateBlock || time.Since(started) > time.Second {
		t.Fatalf("saturated live lookup did not fail within its bound: %+v %v", decision, err)
	}
	for i := 0; i < cap(service.Runtime.refreshSlots); i++ {
		<-service.Runtime.refreshSlots
	}
	if _, err := service.Runtime.Store.Resolve(flow.Key{Tuple: record.OriginalTuple}); err != nil {
		t.Fatal("a failed live lookup mutated the session store", err)
	}
}
