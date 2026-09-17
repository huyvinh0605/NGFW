package risk

import (
	"fmt"
	"math"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

type Weights struct {
	IPS              int `json:"ips"`
	ThreatIntel      int `json:"threat_intel"`
	ML               int `json:"ml"`
	Behavior         int `json:"behavior"`
	Reputation       int `json:"reputation"`
	TLS              int `json:"tls"`
	CorrelationBonus int `json:"correlation_bonus"`
}

func DefaultWeights() Weights {
	return Weights{IPS: 40, ThreatIntel: 25, ML: 20, Behavior: 20, Reputation: 20, TLS: 10, CorrelationBonus: 25}
}

type Evaluator struct {
	Weights           Weights
	MLBlockConfidence float64
}

func NewEvaluator(weights Weights) *Evaluator {
	if weights == (Weights{}) {
		weights = DefaultWeights()
	}
	return &Evaluator{Weights: weights, MLBlockConfidence: .90}
}

func (e *Evaluator) Evaluate(ctx *domain.SecurityContext) domain.RiskContext {
	if ctx == nil {
		return domain.RiskContext{}
	}
	result := domain.RiskContext{}
	add := func(source string, value int, confidence float64, reason string) {
		if confidence < 0 {
			confidence = 0
		}
		if confidence > 1 {
			confidence = 1
		}
		v := int(math.Round(float64(value) * confidence))
		if v <= 0 {
			return
		}
		result.Score += v
		result.Contributions = append(result.Contributions, domain.RiskContribution{Source: source, Value: v, Confidence: confidence, Reason: reason})
		result.Reasons = append(result.Reasons, reason)
	}
	if ctx.IPS.MaxSeverity != "" {
		add("IPS", e.Weights.IPS, severityConfidence(ctx.IPS.MaxSeverity), fmt.Sprintf("IPS severity=%s", ctx.IPS.MaxSeverity))
	}
	if ctx.Reputation.SrcIPScore > 0 {
		add("THREAT_INTEL", e.Weights.ThreatIntel, scoreConfidence(ctx.Reputation.SrcIPScore), fmt.Sprintf("source reputation=%d", ctx.Reputation.SrcIPScore))
	}
	if ctx.Reputation.DstIPScore > 0 {
		add("THREAT_INTEL", e.Weights.ThreatIntel/2, scoreConfidence(ctx.Reputation.DstIPScore), fmt.Sprintf("destination reputation=%d", ctx.Reputation.DstIPScore))
	}
	if ctx.Reputation.DomainScore > 0 {
		add("REPUTATION", e.Weights.Reputation, scoreConfidence(ctx.Reputation.DomainScore), fmt.Sprintf("domain reputation=%d", ctx.Reputation.DomainScore))
	}
	if ctx.ML.Available && ctx.ML.PredictedClass != "" && strings.ToUpper(ctx.ML.PredictedClass) != "BENIGN" {
		add("ML", e.Weights.ML, ctx.ML.Confidence, fmt.Sprintf("ML %s confidence=%.2f", ctx.ML.PredictedClass, ctx.ML.Confidence))
	}
	if len(ctx.Behavior.AnomalyEvents) > 0 {
		add("BEHAVIOR", e.Weights.Behavior, maxEventConfidence(ctx.Behavior.AnomalyEvents), fmt.Sprintf("behavior anomalies=%d", len(ctx.Behavior.AnomalyEvents)))
	}
	for _, ev := range ctx.Signals {
		switch strings.ToUpper(ev.Detector) {
		case "URL", "DNS":
			add(strings.ToUpper(ev.Detector), e.Weights.Reputation, eventConfidence(ev), fmt.Sprintf("%s signal: %s", strings.ToUpper(ev.Detector), ev.Category))
		case "TLS":
			add("TLS", e.Weights.TLS, eventConfidence(ev), fmt.Sprintf("TLS signal: %s", ev.Category))
		}
	}
	if ctx.TLS.Available && !ctx.TLS.Decrypted && ctx.TLS.TLSVersion == "" {
		add("TLS", e.Weights.TLS, .5, "TLS metadata unavailable")
	}
	if hasIndependentCorrelation(ctx) {
		result.Score += e.Weights.CorrelationBonus
		result.Reasons = append(result.Reasons, "independent IPS and ML signals correlated")
		result.Contributions = append(result.Contributions, domain.RiskContribution{Source: "CORRELATION", Value: e.Weights.CorrelationBonus, Confidence: 1, Reason: "independent IPS and ML signals correlated"})
	}
	if result.Score > 100 {
		result.Score = 100
	}
	result.Level = level(result.Score)
	return result
}

func severityConfidence(s domain.Severity) float64 {
	switch s {
	case domain.SeverityCritical:
		return 1
	case domain.SeverityHigh:
		return .9
	case domain.SeverityMedium:
		return .65
	case domain.SeverityLow:
		return .4
	default:
		return .1
	}
}
func scoreConfidence(score int) float64 {
	if score <= 0 {
		return 0
	}
	if score >= 100 {
		return 1
	}
	return float64(score) / 100
}
func maxEventConfidence(events []domain.SecurityEvent) float64 {
	x := 0.0
	for _, v := range events {
		if v.Confidence > x {
			x = v.Confidence
		}
	}
	if x == 0 {
		return .5
	}
	return x
}
func eventConfidence(ev domain.SecurityEvent) float64 {
	if ev.Confidence <= 0 {
		return severityConfidence(ev.Severity)
	}
	if ev.Confidence > 1 {
		return 1
	}
	return ev.Confidence
}
func hasIndependentCorrelation(c *domain.SecurityContext) bool {
	if !c.ML.Available || c.ML.Confidence < .9 || strings.EqualFold(c.ML.PredictedClass, "BENIGN") {
		return false
	}
	return c.IPS.MaxSeverity == domain.SeverityHigh || c.IPS.MaxSeverity == domain.SeverityCritical
}
func level(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "GUARDED"
	default:
		return "LOW"
	}
}
