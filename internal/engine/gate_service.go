package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/gateipc"
	"github.com/kltngfw/ngfw/internal/session"
)

// GateService uses the authoritative M2 runtime. It owns no policy copy,
// session store, or independent firewall engine. Scope is the engine's own
// conntrack namespace/zone, not an untrusted value supplied over proxy IPC.
type GateService struct {
	Runtime *Runtime
	Scope   flow.Scope
}

func (service *GateService) HandleGate(ctx context.Context, operation gateipc.Operation, payload json.RawMessage) (gateipc.Result, error) {
	if operation != gateipc.OpenConnection {
		return gateipc.Result{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	var open domain.ProxyConnectionOpen
	if err := json.Unmarshal(payload, &open); err != nil {
		return gateipc.Result{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	decision, err := service.OpenConnection(ctx, open)
	if err != nil {
		return gateipc.Result{}, err
	}
	return gateipc.Result{Meta: gateipc.ResponseMeta{ConfigGeneration: decision.ConfigGeneration, DecisionID: decision.DecisionID}, Data: decision}, nil
}

// OpenConnection authorizes transport handling only. INSPECT_HTTP and DECRYPT
// do not authorize forwarding any HTTP request: T23 supplies that verdict.
func (service *GateService) OpenConnection(ctx context.Context, open domain.ProxyConnectionOpen) (domain.ProxyConnectionDecision, error) {
	if service == nil || service.Runtime == nil || service.Runtime.Store == nil {
		return domain.ProxyConnectionDecision{}, &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
	}
	if err := ctx.Err(); err != nil {
		return domain.ProxyConnectionDecision{}, err
	}
	client, upstream, err := validateGateOpen(open)
	if err != nil {
		return domain.ProxyConnectionDecision{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return domain.ProxyConnectionDecision{}, err
	}
	base := domain.ProxyConnectionDecision{
		DecisionID: hex.EncodeToString(random[:]), FailMode: domain.GateFailClose,
		Action: domain.TLSGateBlock, ReasonCode: "GATE_ENGINE_UNAVAILABLE",
		UpstreamIP: upstream.Addr().String(), UpstreamPort: int(upstream.Port()),
	}
	if *open.IsTLS {
		if host, err := configpkg.CanonicalTLSDomain(open.TLS.SNI); err == nil && !strings.HasPrefix(host, "*.") {
			base.UpstreamHost = host
		}
	}

	family := domain.FamilyIPv6
	if client.Addr().Is4() {
		family = domain.FamilyIPv4
	}
	tuple := domain.Tuple{
		Family: family, SrcIP: client.Addr(), SrcPort: client.Port(),
		DstIP: upstream.Addr(), DstPort: upstream.Port(), Protocol: 6,
	}
	key := flow.Key{Scope: service.Scope, Tuple: tuple}
	// A generation switch may race conntrack lookup or policy evaluation. A
	// bounded retry keeps old ALLOW results from escaping after activation.
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return domain.ProxyConnectionDecision{}, err
		}
		program := service.Runtime.CurrentProgram()
		generation := program.Generation
		if generation == 0 || generation != service.Runtime.CurrentGeneration() {
			continue
		}
		decision := base
		decision.ConfigGeneration = generation
		linked, lookupErr := service.Runtime.Store.Resolve(key)
		switch {
		case errors.Is(lookupErr, session.ErrAliasAmbiguous):
			decision.ReasonCode = "GATE_ENGINE_UNAVAILABLE"
		case lookupErr == nil:
			decision.SessionID = linked.SessionID
			if policyTupleForSession(linked) != tuple || linked.State == domain.SessionClosed || linked.Revoked {
				decision.ReasonCode = "GATE_ENGINE_UNAVAILABLE"
				break
			}
			policy, evaluateErr := service.Runtime.Evaluate(linked.SessionID)
			if evaluateErr != nil {
				decision.ReasonCode = "GATE_ENGINE_UNAVAILABLE"
				break
			}
			if policy.ConfigVersion != generation {
				continue
			}
			current, ok := service.Runtime.Store.Get(linked.SessionID)
			if !ok || current.Revoked || current.State == domain.SessionClosed || current.EffectiveDecision == domain.DecisionDrop || current.EffectiveDecision == domain.DecisionReject {
				decision.ReasonCode = "GATE_POLICY_NOT_ALLOWED"
				break
			}
			view := connectivity.ViewFromTuple(tuple, current.SourceZone, current.DestinationZone)
			decision = service.decideGate(program, view, upstream, open, decision, policy.Action)
		case errors.Is(lookupErr, session.ErrSessionMissing):
			// Conntrack notifications may arrive after the proxy accepts a flow.
			// Use the same immutable first-match program, never a proxy matcher.
			sourceZone, destinationZone := program.InferZones(tuple)
			view := connectivity.ViewFromTuple(tuple, sourceZone, destinationZone)
			decision = service.decideGate(program, view, upstream, open, decision, program.Evaluate(view).Action)
		default:
			decision.ReasonCode = "GATE_ENGINE_UNAVAILABLE"
		}
		// A new source block must outrank every cached or newly calculated ALLOW.
		if service.Runtime.gateSourceBlocked(client.Addr()) {
			decision.Action = domain.TLSGateBlock
			decision.ReasonCode = "GATE_POLICY_NOT_ALLOWED"
		}
		if service.Runtime.CurrentGeneration() == generation {
			return decision, nil
		}
	}
	base.ConfigGeneration = service.Runtime.CurrentGeneration()
	return base, nil // policy moved repeatedly; fail closed, never use stale ALLOW
}

func (service *GateService) decideGate(program connectivity.Program, view connectivity.View, upstream netip.AddrPort, open domain.ProxyConnectionOpen, decision domain.ProxyConnectionDecision, baseAction domain.Decision) domain.ProxyConnectionDecision {
	match := program.Evaluate(view)
	if baseAction != domain.DecisionAllow || match.Action != domain.DecisionAllow {
		decision.PolicyID = match.PolicyID
		decision.ReasonCode = "GATE_POLICY_NOT_ALLOWED"
		return decision
	}
	decision.PolicyID = match.PolicyID
	plan := connectivity.SelectRequestGate(program, view)
	if !plan.Enabled {
		decision.Action = domain.TLSGateBypass
		decision.ReasonCode = "GATE_NOT_REQUESTED"
		return decision
	}
	if plan.Generation != decision.ConfigGeneration || plan.PolicyID != match.PolicyID || !plan.FailMode.Valid() {
		decision.ReasonCode = "GATE_ENGINE_UNAVAILABLE"
		return decision
	}
	decision.ProfileID = plan.ProfileID
	decision.FailMode = plan.FailMode
	if !*open.IsTLS {
		decision.Action = domain.TLSGateInspectHTTP
		decision.ReasonCode = "GATE_INSPECTION_REQUIRED"
		return decision
	}
	switch plan.TLSMode {
	case domain.TLSBypass:
		decision.Action = domain.TLSGateBypass
		decision.ReasonCode = "GATE_NOT_REQUESTED"
	case domain.TLSMetadata:
		decision.Action = domain.TLSGateMetadataOnly
		decision.ReasonCode = "GATE_NOT_REQUESTED"
	case domain.TLSDecrypt:
		if _, excluded := plan.MatchTLSExclusion(open.TLS.SNI, upstream); excluded {
			decision.Action = domain.TLSGateBypass
			decision.ReasonCode = "TLS_EXCLUSION"
		} else {
			decision.Action = domain.TLSGateDecrypt
			decision.ReasonCode = "GATE_INSPECTION_REQUIRED"
		}
	default:
		decision.ReasonCode = "GATE_ENGINE_UNAVAILABLE"
	}
	return decision
}

func validateGateOpen(open domain.ProxyConnectionOpen) (netip.AddrPort, netip.AddrPort, error) {
	if len(open.ConnectionID) != 32 || open.IsTLS == nil || !strings.EqualFold(open.Protocol, "tcp") || open.SourcePort < 1 || open.SourcePort > 65535 || open.OriginalPort < 1 || open.OriginalPort > 65535 {
		return netip.AddrPort{}, netip.AddrPort{}, errors.New("invalid connection identity or transport")
	}
	if _, err := hex.DecodeString(open.ConnectionID); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	source, sourceErr := netip.ParseAddr(open.SourceIP)
	destination, destinationErr := netip.ParseAddr(open.OriginalIP)
	if sourceErr != nil || destinationErr != nil {
		return netip.AddrPort{}, netip.AddrPort{}, errors.New("invalid connection address")
	}
	source, destination = source.Unmap(), destination.Unmap()
	if source.BitLen() != destination.BitLen() || source.IsUnspecified() || source.IsMulticast() || destination.IsUnspecified() || destination.IsMulticast() {
		return netip.AddrPort{}, netip.AddrPort{}, errors.New("invalid connection address family")
	}
	if len(open.TLS.SNI) > 253 || len(open.TLS.ALPN) > 256 {
		return netip.AddrPort{}, netip.AddrPort{}, errors.New("TLS metadata limit exceeded")
	}
	if !*open.IsTLS && (open.TLS.Available || open.TLS.Decrypted || open.TLS.SNI != "" || open.TLS.ALPN != "") {
		return netip.AddrPort{}, netip.AddrPort{}, errors.New("plain HTTP cannot claim TLS metadata")
	}
	return netip.AddrPortFrom(source, uint16(open.SourcePort)), netip.AddrPortFrom(destination, uint16(open.OriginalPort)), nil
}

func (r *Runtime) gateSourceBlocked(address netip.Addr) bool {
	r.mu.RLock()
	block, blocked := r.blocks[address.String()]
	r.mu.RUnlock()
	return blocked && block.ExpiresAt.After(time.Now())
}
