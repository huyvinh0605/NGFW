package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestInspectionEnumsAndZeroValues(t *testing.T) {
	if got := UnknownApplication(); got.Name != "UNKNOWN" || got.Source != ApplicationSourceUnknown || got.Confidence != ApplicationConfidenceUnknown {
		t.Fatalf("unexpected unknown application: %#v", got)
	}
	if got := (ApplicationIdentity{}).NormalizeZero(); got.Name != "UNKNOWN" || !got.Source.Valid() || !got.Confidence.Valid() {
		t.Fatalf("zero application was not normalized: %#v", got)
	}
	if InspectionMode("bogus").Valid() || InspectionState("bogus").Valid() || CoverageState("bogus").Valid() || AppPolicyState("bogus").Valid() || LatestVerdict("bogus").Valid() {
		t.Fatal("invalid enum accepted")
	}
}

func TestSessionInspectionCloneIsolated(t *testing.T) {
	now := time.Now().UTC()
	s := DefaultSessionInspection()
	s.Sources = []string{"ids"}
	s.MissingEvidence = []string{"sensor_lag"}
	s.Application.FirstSeen = &now
	s.Enforcement.ObservedAt = &now
	c := s.Clone()
	c.Sources[0] = "ips"
	c.MissingEvidence[0] = "changed"
	*c.Application.FirstSeen = c.Application.FirstSeen.Add(time.Second)
	if s.Sources[0] != "ids" || s.MissingEvidence[0] != "sensor_lag" || s.Application.FirstSeen.Equal(*c.Application.FirstSeen) {
		t.Fatal("inspection clone shares mutable state")
	}
}

func TestThreatEventJSONRoundTripPreservesLargeFlowID(t *testing.T) {
	flow := uint64(1<<54 + 7)
	tx := "99"
	e := ThreatEvent{EventID: "e1", SuricataFlowID: "18014398509481991", TransactionID: &tx, Severity: SeverityHigh, Verdict: VerdictAlert, CorrelationState: CorrelationUncorrelated}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "" || e.SuricataFlowID != "18014398509481991" || flow == 0 {
		t.Fatal("flow id was not retained as a string")
	}
	var decoded ThreatEvent
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SuricataFlowID != e.SuricataFlowID || decoded.Severity != SeverityHigh {
		t.Fatalf("round trip changed event: %#v", decoded)
	}
}

func TestRuntimeSessionCloneCopiesInspection(t *testing.T) {
	s := RuntimeSession{SessionID: "s1"}
	v := DefaultSessionInspection()
	v.Sources = []string{"ids"}
	s.Inspection = &v
	c := s.Clone()
	c.Inspection.Sources[0] = "ips"
	if s.Inspection.Sources[0] != "ids" {
		t.Fatal("runtime clone shares inspection slices")
	}
}

func TestThreatEventCloneCopiesApplicationTimes(t *testing.T) {
	now := time.Now().UTC()
	event := ThreatEvent{EventID: "e1", Application: ApplicationIdentity{Name: "HTTP", FirstSeen: &now, LastSeen: &now}}
	clone := event.Clone()
	*clone.Application.FirstSeen = clone.Application.FirstSeen.Add(time.Second)
	*clone.Application.LastSeen = clone.Application.LastSeen.Add(2 * time.Second)
	if event.Application.FirstSeen.Equal(*clone.Application.FirstSeen) || event.Application.LastSeen.Equal(*clone.Application.LastSeen) {
		t.Fatal("threat clone shares application timestamps")
	}
}
