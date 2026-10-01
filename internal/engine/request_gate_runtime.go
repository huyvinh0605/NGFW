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
	if !domain.UsesM4(running) {
		return health, nil
	}
	health.Enabled = true
	health.Status = "down"
	health.WorkersTotal = running.RequestGate.WithDefaults().WorkerCount
	return health, nil
}

func (s *RuntimeServiceAdapter) RequestGateCapabilities(ctx context.Context) (domain.RequestGateCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return domain.RequestGateCapabilities{}, err
	}
	return domain.RequestGateCapabilities{
		Supported: true, ProductionReady: false,
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
			"Linux transparent interception and post-DNAT original destination require Ubuntu capability evidence",
			"production proxy activation and live worker readiness are not verified",
			"HTTP/3 and ECH decryption are unsupported",
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
