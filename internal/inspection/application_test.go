package inspection

import (
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestNormalizeAndMergeApplication(t *testing.T) {
	if got := NormalizeApplication("http"); got.Name != "HTTP" || got.Confidence != domain.ApplicationConfidenceHigh {
		t.Fatalf("unexpected HTTP identity: %#v", got)
	}
	if got := NormalizeApplication("weird"); got.Name != "OTHER" || got.RawName != "weird" {
		t.Fatalf("unexpected unknown identity: %#v", got)
	}
	for _, raw := range []string{"failed", "unknown", "undetected"} {
		if got := NormalizeApplication(raw); got.Name != "UNKNOWN" || got.Confidence != domain.ApplicationConfidenceUnknown {
			t.Fatalf("%q must remain unavailable, got %#v", raw, got)
		}
	}
	a := NormalizeApplication("HTTP")
	a.Confidence = domain.ApplicationConfidenceHigh
	now := time.Now()
	a.FirstSeen = &now
	b := NormalizeApplication("TLS")
	b.Confidence = domain.ApplicationConfidenceHigh
	b.LastSeen = ptrTime(now.Add(time.Second))
	merged := MergeApplication(a, b)
	if merged.Name != "TLS" || merged.Conflicted || merged.FirstSeen == nil || merged.LastSeen == nil {
		t.Fatalf("newer transition/time merge failed: %#v", merged)
	}
}

func TestMergeApplicationHonorsTimeConfidenceAndProtocolTransition(t *testing.T) {
	baseTime := time.Date(2026, 9, 23, 1, 0, 0, 0, time.UTC)
	http := NormalizeApplication("HTTP")
	http.FirstSeen, http.LastSeen = ptrTime(baseTime), ptrTime(baseTime)
	http.Revision = 4

	olderWeak := NormalizeApplication("TLS")
	olderWeak.Source = domain.ApplicationSourcePortHeuristic
	olderWeak.Confidence = domain.ApplicationConfidenceLow
	olderWeak.FirstSeen, olderWeak.LastSeen = ptrTime(baseTime.Add(-time.Second)), ptrTime(baseTime.Add(-time.Second))
	if got := MergeApplication(http, olderWeak); got.Name != "HTTP" || got.Conflicted {
		t.Fatalf("late weak evidence downgraded application: %#v", got)
	}

	transition := NormalizeApplication("TLS")
	transition.FirstSeen, transition.LastSeen = ptrTime(baseTime.Add(time.Second)), ptrTime(baseTime.Add(time.Second))
	if got := MergeApplication(http, transition); got.Name != "TLS" || got.Conflicted || got.Revision != 5 {
		t.Fatalf("newer strong transition was not accepted: %#v", got)
	}

	contradiction := NormalizeApplication("TLS")
	contradiction.FirstSeen, contradiction.LastSeen = ptrTime(baseTime), ptrTime(baseTime)
	if got := MergeApplication(http, contradiction); got.Name != "HTTP" || !got.Conflicted {
		t.Fatalf("same-time equal-authority contradiction was not retained safely: %#v", got)
	}
}

func TestApplicationFromObservationAndBoundedBytes(t *testing.T) {
	obs := Observation{Protocol: &ProtocolMetadata{HTTPHost: "example.test"}}
	if got := ApplicationFromObservation(obs); got.Name != "HTTP" {
		t.Fatalf("HTTP metadata not normalized: %#v", got)
	}
	if got, err := InspectBoundedBytes("ssh", []byte("SSH-2.0-test\r\n")); err != nil || got.Name != "SSH" {
		t.Fatalf("SSH helper failed: %#v %v", got, err)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
