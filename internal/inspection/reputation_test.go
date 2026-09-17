package inspection

import (
	"github.com/kltngfw/ngfw/internal/domain"
	"testing"
	"time"
)

func TestReputationExpiry(t *testing.T) {
	s := NewReputationStore(1)
	if !s.Upsert(domain.ReputationEntry{Indicator: "bad.example", IndicatorType: "MALICIOUS_DOMAIN", ReputationScore: 90, Source: "test", Enabled: true, ExpiresAt: time.Now().Add(time.Hour).Unix()}) {
		t.Fatal("upsert failed")
	}
	ctx := s.LookupContext("", "bad.example")
	if ctx.DomainScore != 90 {
		t.Fatalf("score=%d", ctx.DomainScore)
	}
	s.PurgeExpired(time.Now().Add(2 * time.Hour))
	if _, ok := s.Lookup("bad.example"); ok {
		t.Fatal("expired indicator remained")
	}
}
