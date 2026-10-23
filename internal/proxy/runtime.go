package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	configpkg "github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
)

var ErrGateRuntimeInvalid = errors.New("GATE_RUNTIME_INVALID")

type RuntimeSynchronizer interface {
	Sync(context.Context, domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error)
}

type IPCRuntimeSynchronizer struct{ Client *gateipc.Client }

func (syncer IPCRuntimeSynchronizer) Sync(ctx context.Context, beat domain.RequestGateHeartbeat) (domain.RequestGateRuntime, error) {
	if syncer.Client == nil {
		return domain.RequestGateRuntime{}, ErrGateRuntimeInvalid
	}
	var runtime domain.RequestGateRuntime
	meta, err := syncer.Client.Call(ctx, gateipc.GateHealthPing, beat, &runtime)
	if err != nil {
		return domain.RequestGateRuntime{}, err
	}
	if meta.ConfigGeneration != runtime.ConfigGeneration || meta.DecisionID != runtime.EngineInstanceID || !validRuntimeDescriptor(runtime) {
		return domain.RequestGateRuntime{}, ErrGateRuntimeInvalid
	}
	return runtime, nil
}

func validRuntimeDescriptor(runtime domain.RequestGateRuntime) bool {
	if !domain.ValidGateInstanceID(runtime.EngineInstanceID) || runtime.ConfigGeneration == 0 {
		return false
	}
	if !runtime.Config.Enabled {
		return !runtime.InterceptionReady && !runtime.RequiresCA && runtime.PreparationID == ""
	}
	if runtime.PreparationID != "" && (!domain.ValidGateInstanceID(runtime.PreparationID) || runtime.InterceptionReady) {
		return false
	}
	return len(configpkg.ValidateRequestGate(domain.Config{RequestGate: &runtime.Config})) == 0
}

// ManagedRuntime owns all listeners, active connections and worker processes
// for one immutable descriptor. Close must cancel and join those resources.
type ManagedRuntime interface {
	Snapshot() domain.RequestGateHeartbeat
	Close()
}

type RuntimeFactory func(context.Context, domain.RequestGateRuntime) (ManagedRuntime, error)

// RuntimeSupervisor has a single reconciliation owner. A generation/engine
// change or IPC outage closes the old runtime before any replacement starts.
type RuntimeSupervisor struct {
	Synchronizer RuntimeSynchronizer
	Factory      RuntimeFactory
	Interval     time.Duration
	OnError      func(error)
	instanceID   string
	sequence     uint64
	descriptor   domain.RequestGateRuntime
	active       ManagedRuntime
	failure      string
}

func (supervisor *RuntimeSupervisor) Run(ctx context.Context) error {
	if ctx == nil || supervisor.Synchronizer == nil || supervisor.Factory == nil {
		return ErrGateRuntimeInvalid
	}
	interval := supervisor.Interval
	if interval == 0 {
		interval = time.Second
	}
	if interval < 100*time.Millisecond || interval > 2*time.Second {
		return ErrGateRuntimeInvalid
	}
	defer supervisor.Close()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastError := ""
	for {
		err := supervisor.Reconcile(ctx)
		if err != nil && err.Error() != lastError && supervisor.OnError != nil {
			supervisor.OnError(err)
		}
		lastError = ""
		if err != nil {
			lastError = err.Error()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Reconcile is called serially by Run. It is exported for controlled lifecycle
// integration without timers or test-only alternate process paths.
func (supervisor *RuntimeSupervisor) Reconcile(ctx context.Context) error {
	if ctx == nil || supervisor.Synchronizer == nil || supervisor.Factory == nil {
		return ErrGateRuntimeInvalid
	}
	if ctx.Err() != nil {
		supervisor.Close()
		return ctx.Err()
	}
	if supervisor.instanceID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		supervisor.instanceID = hex.EncodeToString(id[:])
	}
	if supervisor.sequence == ^uint64(0) {
		supervisor.Close()
		return ErrGateRuntimeInvalid
	}
	supervisor.sequence++
	beat := domain.RequestGateHeartbeat{FailureCode: supervisor.failure}
	if supervisor.active != nil {
		beat = supervisor.active.Snapshot()
	}
	beat.ProxyInstanceID, beat.Sequence = supervisor.instanceID, supervisor.sequence
	beat.EngineInstanceID, beat.Generation = supervisor.descriptor.EngineInstanceID, supervisor.descriptor.ConfigGeneration
	beat.PreparationID = supervisor.descriptor.PreparationID
	next, err := supervisor.Synchronizer.Sync(ctx, beat)
	// A failed preparation can legitimately return to the older Running
	// generation. Only a descriptor issued by this engine may direct it.
	stale := supervisor.descriptor.PreparationID == "" && next.PreparationID == "" && next.EngineInstanceID == supervisor.descriptor.EngineInstanceID && next.ConfigGeneration < supervisor.descriptor.ConfigGeneration
	changedWithoutGeneration := supervisor.descriptor.PreparationID == "" && next.PreparationID == "" && next.EngineInstanceID == supervisor.descriptor.EngineInstanceID && next.ConfigGeneration == supervisor.descriptor.ConfigGeneration && (next.Config != supervisor.descriptor.Config || next.RequiresCA != supervisor.descriptor.RequiresCA)
	if err != nil || !validRuntimeDescriptor(next) || stale || changedWithoutGeneration {
		supervisor.Close()
		supervisor.failure = "GATE_ENGINE_UNAVAILABLE"
		return errors.New(supervisor.failure)
	}
	if next != supervisor.descriptor {
		promoted := supervisor.descriptor.PreparationID != "" && next.PreparationID == "" && next.InterceptionReady && next.EngineInstanceID == supervisor.descriptor.EngineInstanceID && next.ConfigGeneration == supervisor.descriptor.ConfigGeneration && next.Config == supervisor.descriptor.Config && next.RequiresCA == supervisor.descriptor.RequiresCA
		if promoted && next.ExpectedArtifacts != (domain.RequestGateArtifacts{}) && beat.Artifacts != next.ExpectedArtifacts {
			promoted = false
		}
		if !promoted {
			supervisor.Close()
		}
		supervisor.descriptor = next
		supervisor.failure = ""
	}
	if !next.Config.Enabled {
		return nil
	}
	if !next.InterceptionReady && next.PreparationID == "" {
		supervisor.failure = "GATE_INTERCEPTION_UNAVAILABLE"
		return nil
	}
	if supervisor.active != nil && beat.FailureCode != "" {
		supervisor.Close() // retire a stopped listener or poisoned detector pool
	}
	if supervisor.active == nil {
		active, err := supervisor.Factory(ctx, next)
		if err != nil || active == nil {
			if active != nil {
				active.Close()
			}
			supervisor.failure = "GATE_RUNTIME_INVALID"
			if err != nil && domain.ValidGateFailureCode(err.Error()) {
				supervisor.failure = err.Error()
			}
			return errors.New(supervisor.failure)
		}
		supervisor.active = active
		supervisor.failure = ""
	}
	return nil
}

func (supervisor *RuntimeSupervisor) Close() {
	if supervisor.active != nil {
		supervisor.active.Close()
		supervisor.active = nil
	}
}
