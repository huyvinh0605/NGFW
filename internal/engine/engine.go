package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/enforcement"
	"github.com/kltngfw/ngfw/internal/events"
	"github.com/kltngfw/ngfw/internal/policy"
	"github.com/kltngfw/ngfw/internal/risk"
	"github.com/kltngfw/ngfw/internal/session"
)

type FlowObservation struct {
	Key                   domain.FlowKey
	SourceZone            string
	DestinationZone       string
	Application           string
	ApplicationConfidence float64
	RiskHints             []domain.SecurityEvent
	Reputation            domain.ReputationContext
	TLS                   domain.TLSContext
	DNS                   domain.DNSContext
	ML                    domain.MLContext
	Packets               uint64
	Bytes                 uint64
	FromClient            bool
}

type SignalProvider interface {
	Start(context.Context) error
	Events() <-chan domain.SecurityEvent
	Health() domain.ComponentHealth
}

type Engine struct {
	Config      *config.Manager
	Sessions    *session.Store
	Risk        *risk.Evaluator
	Policy      *policy.Evaluator
	Enforcement enforcement.Interface
	Events      *events.Bus
	mu          sync.RWMutex
	health      map[string]domain.ComponentHealth
	blockMu     sync.RWMutex
	blocks      map[string]domain.TemporaryBlock
}

func New(cfg *config.Manager, enf enforcement.Interface) *Engine {
	c := cfg.Running()
	return &Engine{Config: cfg, Sessions: session.NewStore(c.MaxSessions), Risk: risk.NewEvaluator(risk.DefaultWeights()), Policy: policy.NewEvaluator(c.DefaultDeny), Enforcement: enf, Events: events.NewBus(c.MaxEventsQueue), health: map[string]domain.ComponentHealth{}, blocks: map[string]domain.TemporaryBlock{}}
}

func (e *Engine) EvaluateFlow(ctx context.Context, obs FlowObservation) (*domain.Session, *domain.SecurityContext, domain.PolicyDecision, error) {
	now := time.Now().UTC()
	if block, ok := e.ActiveBlock(obs.Key.SrcIP, now); ok {
		return nil, nil, domain.PolicyDecision{Action: domain.DecisionDrop, Scope: "SOURCE", Reason: "temporary block: " + block.Reason}, nil
	}
	sess, created, err := e.Sessions.GetOrCreate(ctx, obs.Key, obs.SourceZone, obs.DestinationZone, now)
	if err != nil {
		return nil, nil, domain.PolicyDecision{}, err
	}
	if !created && !sess.Invalidated && sess.FastPathEligible && sess.PolicyVersion == e.Config.Version().Version {
		_, _ = e.Sessions.Update(sess.ID, func(s *domain.Session) error {
			s.LastSeen = now
			if obs.FromClient {
				s.PacketsUp += obs.Packets
				s.BytesUp += obs.Bytes
			} else {
				s.PacketsDown += obs.Packets
				s.BytesDown += obs.Bytes
			}
			return nil
		})
		if updated, ok := e.Sessions.Get(sess.ID); ok {
			sess = updated
		}
		return sess, e.context(sess), domain.PolicyDecision{Action: sess.Decision, Scope: "SESSION", PolicyID: sess.PolicyID, ConfigVersion: sess.PolicyVersion, Reason: "cached fast-path decision"}, nil
	}
	if _, err = e.Sessions.Update(sess.ID, func(s *domain.Session) error {
		s.LastSeen = now
		if obs.Key.Protocol == "tcp" || obs.Key.Protocol == "TCP" {
			s.TCPState = "ESTABLISHED"
		}
		s.Application = obs.Application
		s.ApplicationConfidence = obs.ApplicationConfidence
		if obs.FromClient {
			s.PacketsUp += obs.Packets
			s.BytesUp += obs.Bytes
		} else {
			s.PacketsDown += obs.Packets
			s.BytesDown += obs.Bytes
		}
		return nil
	}); err != nil {
		return nil, nil, domain.PolicyDecision{}, err
	}
	ctxObj, ok := e.Sessions.GetContext(sess.SecurityContextID)
	if !ok {
		return nil, nil, domain.PolicyDecision{}, errors.New("security context disappeared")
	}
	_, err = e.Sessions.UpdateContext(sess.SecurityContextID, func(c *domain.SecurityContext) error {
		c.Network = domain.NetworkContext{SrcIP: obs.Key.SrcIP, DstIP: obs.Key.DstIP, SrcPort: obs.Key.SrcPort, DstPort: obs.Key.DstPort, Protocol: obs.Key.Protocol, SrcZone: obs.SourceZone, DstZone: obs.DestinationZone}
		c.App.Application = obs.Application
		c.App.Confidence = obs.ApplicationConfidence
		c.TLS = obs.TLS
		c.DNS = obs.DNS
		c.Reputation = obs.Reputation
		c.ML = obs.ML
		for _, ev := range obs.RiskHints {
			attachEvent(c, ev)
		}
		return nil
	})
	if err != nil {
		return nil, nil, domain.PolicyDecision{}, err
	}
	ctxObj, _ = e.Sessions.GetContext(sess.SecurityContextID)
	ctxObj.Risk = e.Risk.Evaluate(ctxObj)
	if _, err = e.Sessions.UpdateContext(sess.SecurityContextID, func(c *domain.SecurityContext) error { c.Risk = ctxObj.Risk; return nil }); err != nil {
		return nil, nil, domain.PolicyDecision{}, err
	}
	c := e.Config.Running()
	profiles := map[string]domain.SecurityProfile{}
	for _, p := range c.Profiles {
		profiles[p.ID] = p
	}
	decision := policy.NewEvaluator(c.DefaultDeny).Evaluate(ctxObj, c.Policies, profiles, e.Config.Version().Version)
	continuousInspection := decision.Scope == "REQUEST"
	if profile, ok := profiles[decision.PolicyID]; ok {
		continuousInspection = continuousInspection || profile.InspectionRequired
	}
	if _, err = e.Sessions.UpdateContext(sess.SecurityContextID, func(x *domain.SecurityContext) error {
		x.Policy = domain.PolicyContext{MatchedPolicyID: decision.PolicyID, Action: decision.Action, Scope: decision.Scope, Reason: decision.Reason}
		return nil
	}); err != nil {
		return nil, nil, decision, err
	}
	if err := e.apply(ctx, sess.ID, decision); err != nil {
		return nil, ctxObj, decision, err
	}
	updated, err := e.Sessions.Update(sess.ID, func(s *domain.Session) error {
		s.PolicyID = decision.PolicyID
		s.PolicyVersion = decision.ConfigVersion
		s.DecisionVersion++
		s.RiskScore = ctxObj.Risk.Score
		s.Decision = decision.Action
		s.Invalidated = false
		s.FastPathEligible = !continuousInspection && decision.Action == domain.DecisionAllow && ctxObj.Risk.Score < 60 && stableForFastPath(ctxObj)
		if s.FastPathEligible {
			s.FastPathReason = "allow, stable low-risk context"
		}
		return nil
	})
	if err != nil {
		return nil, ctxObj, decision, err
	}
	e.Events.Publish(domain.SecurityEvent{EventID: eventID(), Timestamp: now, FlowID: ctxObj.FlowID, SessionID: updated.ID, Detector: "FIREWALL", Category: "DECISION", Severity: severityForDecision(decision.Action), Confidence: 1, SourceIP: obs.Key.SrcIP, DestinationIP: obs.Key.DstIP, Application: obs.Application, Evidence: bounded(decision.Reason, 512), RecommendedAction: string(decision.Action)})
	return updated, ctxObj, decision, nil
}

func (e *Engine) IngestEvent(ev domain.SecurityEvent) error {
	if ev.EventID == "" {
		ev.EventID = eventID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Evidence != "" {
		ev.Evidence = bounded(ev.Evidence, 4096)
	}
	if ev.SessionID == "" && ev.FlowID != "" {
		if sess, ok := e.Sessions.FindByFlowID(ev.FlowID); ok {
			ev.SessionID = sess.ID
		}
	}
	if ev.SessionID != "" {
		ctx, ok := e.Sessions.Get(ev.SessionID)
		if ok {
			_, err := e.Sessions.UpdateContext(ctx.SecurityContextID, func(c *domain.SecurityContext) error { attachEvent(c, ev); c.Risk = e.Risk.Evaluate(c); return nil })
			_ = e.Sessions.Invalidate(ev.SessionID, "security event: "+ev.Category)
			e.Events.Publish(ev)
			return err
		}
	}
	e.Events.Publish(ev)
	return nil
}

func (e *Engine) apply(ctx context.Context, id string, d domain.PolicyDecision) error {
	switch d.Action {
	case domain.DecisionAllow:
		return e.Enforcement.AllowSession(ctx, id)
	case domain.DecisionDrop:
		return e.Enforcement.DropSession(ctx, id)
	case domain.DecisionReject:
		return e.Enforcement.RejectSession(ctx, id)
	case domain.DecisionReset:
		return e.Enforcement.ResetSession(ctx, id)
	case domain.DecisionRateLimit:
		return e.Enforcement.RateLimit(ctx, id, d.RatePerSecond, d.Burst)
	case domain.DecisionTempBlock:
		return e.Enforcement.TemporaryBlock(ctx, domain.TemporaryBlock{ID: eventID(), Indicator: id, Reason: d.Reason, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute)})
	default:
		return fmt.Errorf("unsupported decision %q", d.Action)
	}
}
func (e *Engine) context(s *domain.Session) *domain.SecurityContext {
	c, _ := e.Sessions.GetContext(s.SecurityContextID)
	return c
}
func (e *Engine) ListSessions() []*domain.Session { return e.Sessions.List() }
func (e *Engine) GetSession(id string) (*domain.Session, *domain.SecurityContext, bool) {
	s, ok := e.Sessions.Get(id)
	if !ok {
		return nil, nil, false
	}
	c, _ := e.Sessions.GetContext(s.SecurityContextID)
	return s, c, true
}
func (e *Engine) Health() map[string]domain.ComponentHealth {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := map[string]domain.ComponentHealth{}
	for k, v := range e.health {
		out[k] = v
	}
	out["enforcement"] = e.Enforcement.Health()
	out["session_engine"] = domain.ComponentHealth{Name: "session_engine", Status: "ok", UpdatedAt: time.Now()}
	out["dataplane"] = domain.ComponentHealth{Name: "dataplane", Status: "ok", UpdatedAt: time.Now()}
	return out
}
func (e *Engine) SetHealth(h domain.ComponentHealth) {
	e.mu.Lock()
	e.health[h.Name] = h
	e.mu.Unlock()
}

func (e *Engine) AddTemporaryBlock(ctx context.Context, block domain.TemporaryBlock) error {
	if block.ExpiresAt.IsZero() {
		block.ExpiresAt = time.Now().Add(5 * time.Minute)
	}
	if err := e.Enforcement.TemporaryBlock(ctx, block); err != nil {
		return err
	}
	e.blockMu.Lock()
	e.blocks[block.Indicator] = block
	e.blockMu.Unlock()
	return nil
}
func (e *Engine) RemoveTemporaryBlock(indicator string) {
	e.blockMu.Lock()
	delete(e.blocks, indicator)
	e.blockMu.Unlock()
}
func (e *Engine) ActiveBlock(indicator string, now time.Time) (domain.TemporaryBlock, bool) {
	e.blockMu.RLock()
	b, ok := e.blocks[indicator]
	e.blockMu.RUnlock()
	if !ok {
		return domain.TemporaryBlock{}, false
	}
	if !b.ExpiresAt.After(now) {
		e.RemoveTemporaryBlock(indicator)
		return domain.TemporaryBlock{}, false
	}
	return b, true
}
func (e *Engine) SweepBlocks(now time.Time) {
	e.blockMu.Lock()
	defer e.blockMu.Unlock()
	for indicator, b := range e.blocks {
		if !b.ExpiresAt.After(now) {
			delete(e.blocks, indicator)
		}
	}
}

func (e *Engine) AttachSignalProvider(ctx context.Context, provider SignalProvider) error {
	if provider == nil {
		return errors.New("signal provider is nil")
	}
	if err := provider.Start(ctx); err != nil {
		e.SetHealth(domain.ComponentHealth{Name: "ids", Status: "down", Message: err.Error(), UpdatedAt: time.Now()})
		return err
	}
	e.SetHealth(provider.Health())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-provider.Events():
				if !ok {
					return
				}
				_ = e.IngestEvent(ev)
				e.SetHealth(provider.Health())
			}
		}
	}()
	return nil
}
func attachEvent(c *domain.SecurityContext, ev domain.SecurityEvent) {
	switch strings.ToUpper(ev.Detector) {
	case "IPS":
		c.IPS.Alerts = appendBounded(c.IPS.Alerts, ev, 128)
		if ev.Severity.Weight() > c.IPS.MaxSeverity.Weight() {
			c.IPS.MaxSeverity = ev.Severity
		}
	case "BEHAVIOR":
		c.Behavior.AnomalyEvents = appendBounded(c.Behavior.AnomalyEvents, ev, 128)
	case "ML":
		c.ML.PredictedClass = ev.Category
		c.ML.Confidence = ev.Confidence
		c.ML.Available = true
	default:
		c.Signals = appendBounded(c.Signals, ev, 128)
	}
	if ev.SourceIP != "" && c.Network.SrcIP == "" {
		c.Network.SrcIP = ev.SourceIP
	}
	if ev.DestinationIP != "" && c.Network.DstIP == "" {
		c.Network.DstIP = ev.DestinationIP
	}
}
func appendBounded(in []domain.SecurityEvent, ev domain.SecurityEvent, max int) []domain.SecurityEvent {
	in = append(in, ev)
	if len(in) > max {
		in = in[len(in)-max:]
	}
	return in
}
func stableForFastPath(c *domain.SecurityContext) bool {
	return c.App.Application != "" && c.App.Confidence >= .8 && len(c.IPS.Alerts) == 0 && len(c.Behavior.AnomalyEvents) == 0 && (!c.ML.Available || strings.EqualFold(c.ML.PredictedClass, "BENIGN") || c.ML.Confidence < .9)
}
func severityForDecision(d domain.Decision) domain.Severity {
	switch d {
	case domain.DecisionAllow:
		return domain.SeverityInfo
	case domain.DecisionRateLimit:
		return domain.SeverityMedium
	default:
		return domain.SeverityHigh
	}
}
func eventID() string { return fmt.Sprintf("evt-%d", time.Now().UnixNano()) }
func bounded(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
