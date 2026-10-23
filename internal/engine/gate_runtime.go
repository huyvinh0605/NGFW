package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
)

const gateHeartbeatTTL = 5 * time.Second

func (service *GateService) engineInstance() (string, error) {
	service.instanceOnce.Do(func() {
		var id [16]byte
		_, service.instanceErr = rand.Read(id[:])
		if service.instanceErr == nil {
			service.instanceID = hex.EncodeToString(id[:])
		}
	})
	return service.instanceID, service.instanceErr
}

func (service *GateService) gateTime() time.Time {
	if service.healthNow != nil {
		return service.healthNow()
	}
	return time.Now().UTC()
}

func (service *GateService) interceptionReady(generation uint64) bool {
	return service.InterceptionReady != nil && service.InterceptionReady(generation)
}

// RuntimeDescriptor is read from Running and the matching immutable generation.
// It remains inactive until the kernel activation owner confirms interception.
func (service *GateService) RuntimeDescriptor(ctx context.Context) (domain.RequestGateRuntime, error) {
	if ctx == nil || service == nil || service.Runtime == nil || service.RunningConfig == nil {
		return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
	}
	if prepared, ok := service.preparedRuntime(); ok {
		return prepared, ctx.Err()
	}
	instance, err := service.engineInstance()
	if err != nil {
		return domain.RequestGateRuntime{}, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return domain.RequestGateRuntime{}, err
		}
		generation := service.Runtime.CurrentGeneration()
		value, version := service.RunningConfig()
		if generation == 0 || generation != version || generation != service.Runtime.CurrentGeneration() {
			continue
		}
		if len(configpkg.ValidateRequestGate(value)) != 0 {
			return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
		}
		limits := domain.EffectiveRequestGateConfig(value)
		limits.Enabled = domain.UsesM4(value)
		result := domain.RequestGateRuntime{
			EngineInstanceID: instance, ConfigGeneration: generation, Config: limits,
			RequiresCA:        gateRequiresCA(value),
			InterceptionReady: limits.Enabled && service.interceptionReady(generation),
		}
		if limits.Enabled && service.ActivationArtifacts != nil {
			result.ExpectedArtifacts = service.ActivationArtifacts(generation)
		}
		if generation == service.Runtime.CurrentGeneration() {
			return result, nil
		}
	}
	return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeStaleGeneration}
}

func gateRequiresCA(value domain.Config) bool {
	if !domain.UsesM4(value) {
		return false
	}
	for _, policy := range value.Policies {
		if !policy.Enabled || policy.Action != domain.DecisionAllow {
			continue
		}
		for _, profile := range value.Profiles {
			if profile.ID == policy.SecurityProfileID && profile.RequestGate != nil && profile.RequestGate.Enabled && profile.TLSMode == domain.TLSDecrypt {
				return true
			}
		}
	}
	return false
}

// checkProxyRuntime also protects against engine restart at the same persisted
// generation. Unbound direct library users have no deployed runtime descriptor.
func (service *GateService) checkProxyRuntime(instance string, generation uint64) error {
	if _, preparing := service.preparedRuntime(); preparing {
		return &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
	}
	if service.RunningConfig == nil && instance == "" && generation == 0 {
		return nil
	}
	expected, err := service.engineInstance()
	if err != nil {
		return err
	}
	if instance != expected || generation == 0 || generation != service.Runtime.CurrentGeneration() {
		return &gateipc.ProtocolError{Code: gateipc.CodeStaleGeneration}
	}
	if !service.interceptionReady(generation) {
		return &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
	}
	return nil
}

// SyncProxy accepts at most one fresh proxy owner and a monotonically increasing
// sequence. A stale-generation ping receives the new descriptor but cannot
// replace current readiness. Wall-clock timestamps are never accepted from IPC.
func (service *GateService) SyncProxy(ctx context.Context, beat domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error) {
	if len(beat.Artifacts.RulesetID) > 128 || len(beat.Artifacts.RulesetHash) > 64 || len(beat.Artifacts.WorkerConfigHash) > 64 || len(beat.Artifacts.CAFingerprint) > 64 || (beat.PreparationID != "" && !domain.ValidGateInstanceID(beat.PreparationID)) {
		return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	if !domain.ValidGateInstanceID(beat.ProxyInstanceID) || beat.Sequence == 0 || len(beat.Counters) > 32 || !domain.ValidGateFailureCode(beat.FailureCode) || beat.WorkersReady < 0 || beat.WorkersReady > 4 || beat.QueueDepth < 0 || beat.QueueDepth > 1024 || beat.ActiveConnections < 0 || beat.ActiveConnections > 50000 || beat.ActiveRequests < 0 || beat.ActiveRequests > 1024 {
		return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	for key := range beat.Counters {
		if !domain.ValidGateCounter(key) {
			return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
		}
	}
	runtime, err := service.RuntimeDescriptor(ctx)
	if err != nil {
		return domain.RequestGateRuntime{}, err
	}
	if beat.EngineInstanceID != runtime.EngineInstanceID || beat.Generation != runtime.ConfigGeneration || beat.PreparationID != runtime.PreparationID {
		return runtime, nil
	}
	if beat.WorkersReady > runtime.Config.WorkerCount || beat.QueueDepth > runtime.Config.QueueItems || beat.ActiveRequests > runtime.Config.MaxConcurrentRequests {
		return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	if runtime.InterceptionReady && beat.WorkersReady > 0 && runtime.ExpectedArtifacts != (domain.RequestGateArtifacts{}) && beat.Artifacts != runtime.ExpectedArtifacts {
		return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
	}
	if !runtime.Config.Enabled || (!runtime.InterceptionReady && runtime.PreparationID == "") {
		if beat.HTTPListenerReady || beat.HTTPSListenerReady || beat.WorkersReady != 0 || beat.ActiveConnections != 0 || beat.ActiveRequests != 0 || beat.QueueDepth != 0 {
			return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeMalformed}
		}
	}
	now := service.gateTime()
	service.healthMu.Lock()
	defer service.healthMu.Unlock()
	previous := service.heartbeat
	if previous.Generation == beat.Generation && previous.EngineInstanceID == beat.EngineInstanceID && previous.PreparationID == beat.PreparationID {
		if previous.ProxyInstanceID == beat.ProxyInstanceID && beat.Sequence <= previous.Sequence {
			return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeStaleGeneration}
		}
		if previous.ProxyInstanceID != beat.ProxyInstanceID && now.Sub(service.heartbeatAt) < gateHeartbeatTTL {
			return domain.RequestGateRuntime{}, &gateipc.ProtocolError{Code: gateipc.CodeEngineDown}
		}
	}
	beat.Counters = (domain.RequestGateHealth{Counters: beat.Counters}).Clone().Counters
	service.heartbeat, service.heartbeatAt = beat, now
	return runtime, nil
}

func (service *GateService) observedHealth(value domain.Config, generation uint64) (domain.RequestGateHeartbeat, time.Time, bool) {
	if service == nil {
		return domain.RequestGateHeartbeat{}, time.Time{}, false
	}
	now := service.gateTime()
	service.healthMu.Lock()
	defer service.healthMu.Unlock()
	beat, received := service.heartbeat, service.heartbeatAt
	if received.IsZero() || now.Before(received) || now.Sub(received) >= gateHeartbeatTTL || beat.Generation != generation || beat.PreparationID != "" {
		return domain.RequestGateHeartbeat{}, time.Time{}, false
	}
	beat.Counters = (domain.RequestGateHealth{Counters: beat.Counters}).Clone().Counters
	return beat, received, true
}
