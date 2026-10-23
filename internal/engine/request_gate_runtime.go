package engine

import (
	"context"
	"errors"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

// RequestGateHealth reports only facts the engine can currently verify. In
// particular, a configured gate is down until the production proxy reports
// live listeners/workers through a trusted, generation-bound heartbeat.
func (s *RuntimeServiceAdapter) RequestGateHealth(ctx context.Context) (domain.RequestGateHealth, error) {
	if err := ctx.Err(); err != nil {
		return domain.RequestGateHealth{}, err
	}
	if s == nil || s.Runtime == nil || s.Config == nil {
		return domain.RequestGateHealth{}, errors.New("request-gate runtime unavailable")
	}
	health := domain.RequestGateHealth{
		Status: "disabled", Generation: s.Runtime.CurrentGeneration(),
		Counters: map[string]uint64{
			"intercepted": 0, "bypassed": 0, "decrypted": 0,
			"request_allowed": 0, "request_blocked": 0,
			"fail_open": 0, "fail_close": 0, "inspection_timeout": 0,
			"queue_rejected": 0, "tls_handshake_fail": 0,
			"upstream_verify_fail": 0, "body_limit": 0,
			"decompression_limit": 0,
		}, UpdatedAt: time.Now().UTC(),
	}
	running := s.Config.Running()
	health.Enabled = domain.UsesM4(running)
	if health.Enabled {
		health.Status = "down"
		health.WorkersTotal = running.RequestGate.WithDefaults().WorkerCount
	}
	beat, observed, fresh := s.Gate.observedHealth(running, health.Generation)
	if fresh {
		health.ProxyReachable = true
		health.UpdatedAt = observed
		health.FailureCode = beat.FailureCode
		for key, count := range beat.Counters {
			health.Counters[key] = count
		}
		if health.Enabled && s.Gate.interceptionReady(health.Generation) {
			health.HTTPListenerReady, health.HTTPSListenerReady = beat.HTTPListenerReady, beat.HTTPSListenerReady
			health.CALoaded = beat.CALoaded
			health.WorkersReady, health.QueueDepth = beat.WorkersReady, beat.QueueDepth
			health.ActiveConnections, health.ActiveRequests = beat.ActiveConnections, beat.ActiveRequests
			health.Status = "degraded"
			if beat.HTTPListenerReady && beat.HTTPSListenerReady && beat.WorkersReady == health.WorkersTotal && (!gateRequiresCA(running) || beat.CALoaded) && beat.FailureCode == "" {
				health.Status = "healthy"
			}
		}
	}
	return health, nil
}

func (s *RuntimeServiceAdapter) RequestGateCapabilities(ctx context.Context) (domain.RequestGateCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return domain.RequestGateCapabilities{}, err
	}
	health, _ := s.RequestGateHealth(ctx)
	return domain.RequestGateCapabilities{
		Supported: true, ProductionReady: health.Status == "healthy",
		HTTPVersions: []string{"HTTP/1.1", "HTTP/2"},
		ConnectionActions: []domain.TLSGateAction{
			domain.TLSGateBypass, domain.TLSGateMetadataOnly,
			domain.TLSGateInspectHTTP, domain.TLSGateDecrypt, domain.TLSGateBlock,
		},
		FailModes:         []domain.GateFailMode{domain.GateFailOpen, domain.GateFailClose},
		Limits:            domain.DefaultRequestGateConfig(),
		RuntimeIPCVersion: domain.RuntimeIPCProtocolVersion,
		BuildVersion:      runtimeBuildVersion(),
		Limitations: []string{
			"Transparent interception supports IPv4 TCP; TCP/80 is plaintext HTTP and other explicit TCP gate ports are TLS",
			"Readiness requires verified kernel activation and fresh generation-bound proxy observations",
			"HTTP/3 and ECH decryption are unsupported",
			"Upstream mTLS impersonation and response-body scanning are unsupported",
		},
	}, nil
}

func (s *RuntimeServiceAdapter) ListRequestGateEvidence(ctx context.Context, after uint64, limit int) (domain.RequestGateEvidencePage, error) {
	if err := ctx.Err(); err != nil {
		return domain.RequestGateEvidencePage{}, err
	}
	if s == nil || s.Gate == nil {
		return domain.RequestGateEvidencePage{}, errors.New("request-gate service unavailable")
	}
	return s.Gate.ListRequestGateEvidence(after, limit), nil
}
