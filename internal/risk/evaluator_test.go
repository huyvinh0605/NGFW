package risk

import (
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestCorrelationIsExplainableAndClamped(t *testing.T) {
	e := NewEvaluator(DefaultWeights())
	c := &domain.SecurityContext{IPS: domain.IPSContext{MaxSeverity: domain.SeverityHigh}, ML: domain.MLContext{Available: true, PredictedClass: "SQL_INJECTION", Confidence: .95}}
	r := e.Evaluate(c)
	if r.Score > 100 {
		t.Fatalf("score not clamped: %d", r.Score)
	}
	joined := strings.Join(r.Reasons, " ")
	if !strings.Contains(joined, "correlated") {
		t.Fatalf("missing correlation reason: %v", r.Reasons)
	}
}
func TestBenignMLDoesNotAddRisk(t *testing.T) {
	r := NewEvaluator(DefaultWeights()).Evaluate(&domain.SecurityContext{ML: domain.MLContext{Available: true, PredictedClass: "BENIGN", Confidence: .99}})
	if r.Score != 0 {
		t.Fatalf("benign ML added %d", r.Score)
	}
}
