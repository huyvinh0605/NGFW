package proxy

import "sync/atomic"

type requestGateCounters struct {
	activeRequests      atomic.Int64
	intercepted         atomic.Uint64
	requestAllowed      atomic.Uint64
	requestBlocked      atomic.Uint64
	failOpen            atomic.Uint64
	failClose           atomic.Uint64
	inspectionTimeout   atomic.Uint64
	queueRejected       atomic.Uint64
	capacityRejected    atomic.Uint64
	engineUnavailable   atomic.Uint64
	bodyLimit           atomic.Uint64
	decompressionLimit  atomic.Uint64
	upstreamVerifyFail  atomic.Uint64
	upstreamConnectFail atomic.Uint64
}

// RequestGateStats is a lock-free snapshot for the T29 health endpoint.
// Counters are verdict/availability facts, never request content.
type RequestGateStats struct {
	ActiveRequests int
	Counters       map[string]uint64
}

func (gate *HTTP1RequestGate) Stats() RequestGateStats {
	if gate == nil {
		return RequestGateStats{}
	}
	c := &gate.counters
	return RequestGateStats{ActiveRequests: int(c.activeRequests.Load()), Counters: map[string]uint64{
		"intercepted":           c.intercepted.Load(),
		"request_allowed":       c.requestAllowed.Load(),
		"request_blocked":       c.requestBlocked.Load(),
		"fail_open":             c.failOpen.Load(),
		"fail_close":            c.failClose.Load(),
		"inspection_timeout":    c.inspectionTimeout.Load(),
		"queue_rejected":        c.queueRejected.Load(),
		"capacity_rejected":     c.capacityRejected.Load(),
		"engine_unavailable":    c.engineUnavailable.Load(),
		"body_limit":            c.bodyLimit.Load(),
		"decompression_limit":   c.decompressionLimit.Load(),
		"upstream_verify_fail":  c.upstreamVerifyFail.Load(),
		"upstream_connect_fail": c.upstreamConnectFail.Load(),
	}}
}
