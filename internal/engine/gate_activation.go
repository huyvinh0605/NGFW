package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

// PrepareGateRuntime exposes only resource requirements over the existing
// gate IPC. Candidate policy never becomes authoritative here. Requests are
// refused until Running, Runtime and the verified kernel generation agree.
// This does not acquire the config manager lock: it also works while a
// CommitWithGeneration callback holds that lock, including compensation.
func (service *GateService) PrepareGateRuntime(ctx context.Context, value domain.Config, generation uint64) (domain.RequestGateArtifacts, error) {
	if !domain.UsesM4(value) {
		service.CompleteGatePreparation()
		return domain.RequestGateArtifacts{}, nil
	}
	instance, err := service.engineInstance()
	if err != nil {
		return domain.RequestGateArtifacts{}, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return domain.RequestGateArtifacts{}, err
	}
	descriptor := domain.RequestGateRuntime{EngineInstanceID: instance, ConfigGeneration: generation,
		Config: domain.EffectiveRequestGateConfig(value), RequiresCA: gateRequiresCA(value), PreparationID: hex.EncodeToString(nonce[:])}
	service.preparationMu.Lock()
	service.preparation = &descriptor
	service.preparationMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		service.healthMu.Lock()
		beat, received := service.heartbeat, service.heartbeatAt
		service.healthMu.Unlock()
		if beat.PreparationID == descriptor.PreparationID && beat.EngineInstanceID == instance && beat.Generation == generation && service.gateTime().Sub(received) < gateHeartbeatTTL && !service.gateTime().Before(received) {
			if beat.FailureCode != "" && beat.FailureCode != "GATE_INTERCEPTION_UNAVAILABLE" {
				service.CompleteGatePreparation()
				return domain.RequestGateArtifacts{}, errors.New("M4 proxy preflight: " + beat.FailureCode)
			}
			if beat.HTTPListenerReady && beat.HTTPSListenerReady && beat.WorkersReady == descriptor.Config.WorkerCount && (!descriptor.RequiresCA || beat.CALoaded) && beat.FailureCode == "" && validPreparedArtifacts(beat.Artifacts, descriptor) {
				return beat.Artifacts, nil
			}
		}
		select {
		case <-ctx.Done():
			service.CompleteGatePreparation()
			return domain.RequestGateArtifacts{}, errors.New("M4 proxy preflight did not obtain ready listeners, CA and workers: " + ctx.Err().Error())
		case <-ticker.C:
		}
	}
}

func validPreparedArtifacts(artifacts domain.RequestGateArtifacts, runtime domain.RequestGateRuntime) bool {
	validHash := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 32
	}
	return artifacts.RulesetID == runtime.Config.RulesetID && validHash(artifacts.RulesetHash) && validHash(artifacts.WorkerConfigHash) && (!runtime.RequiresCA || validHash(artifacts.CAFingerprint))
}

func (service *GateService) CompleteGatePreparation() {
	service.preparationMu.Lock()
	service.preparation = nil
	service.preparationMu.Unlock()
}

// Finalization must not advertise success if the preflight process died while
// the kernel transaction or Running persistence was in progress.
func (service *GateService) ConfirmGatePreparation(generation uint64) error {
	runtime, preparing := service.preparedRuntime()
	if !preparing {
		return nil
	}
	service.healthMu.Lock()
	beat, received := service.heartbeat, service.heartbeatAt
	service.healthMu.Unlock()
	if runtime.ConfigGeneration != generation || beat.PreparationID != runtime.PreparationID || service.gateTime().Sub(received) >= gateHeartbeatTTL || !beat.HTTPListenerReady || !beat.HTTPSListenerReady || beat.WorkersReady != runtime.Config.WorkerCount || runtime.RequiresCA && !beat.CALoaded || beat.FailureCode != "" {
		return errors.New("M4 prepared proxy lost readiness before publication")
	}
	return nil
}

func (service *GateService) preparedRuntime() (domain.RequestGateRuntime, bool) {
	service.preparationMu.RLock()
	defer service.preparationMu.RUnlock()
	if service.preparation == nil {
		return domain.RequestGateRuntime{}, false
	}
	return *service.preparation, true
}
