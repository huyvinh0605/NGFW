package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/dataplane"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engine"
	"github.com/kltngfw/ngfw/internal/engineipc"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/inspection/eve"
	sensorpkg "github.com/kltngfw/ngfw/internal/inspection/sensor"
	"github.com/kltngfw/ngfw/internal/session"
)

// The engine binary is the privileged owner of all Linux M1 dataplane state.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if runtime.GOOS != "linux" {
		logger.Error("ngfw-engine M1 dataplane requires Linux")
		os.Exit(1)
	}
	stateDir := os.Getenv("NGFW_STATE_DIR")
	if stateDir == "" {
		stateDir = filepath.Join(".", "state")
	}
	initial := config.Defaults()
	if path := os.Getenv("NGFW_CONFIG"); path != "" {
		loaded, loadErr := config.LoadFile(path)
		if loadErr != nil {
			logger.Error("configuration file failed", "error", loadErr)
			os.Exit(1)
		}
		initial = loaded
	}
	m, err := config.NewManager(stateDir, initial)
	if err != nil {
		logger.Error("configuration manager failed", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	network := dataplane.NewNetworkReconciler(dataplane.NewExecIPCommandRunner(os.Getenv("NGFW_IP_BINARY")))
	nftables := dataplane.NewNftRunner(os.Getenv("NGFW_NFT_BINARY"))
	forwarding := dataplane.NewSysctlForwarding()
	controller, err := dataplane.NewController(network, nftables, forwarding, filepath.Join(stateDir, "dataplane-applied.json"))
	if err != nil {
		logger.Error("dataplane controller failed", "error", err)
		os.Exit(1)
	}
	recoveringActivation := controller.RecoveryPending()
	epochAllocator, epochErr := dataplane.NewEpochAllocator(filepath.Join(stateDir, "runtime-epoch.json"))
	if epochErr != nil {
		logger.Error("kernel cache epoch unavailable; M2 will run in safe no-cache mode", "error", epochErr)
	}
	compileOptions := func(desired domain.Config) dataplane.M2CompileOptions {
		zoneSlots := makeZoneSlots(desired)
		epoch := uint16(0)
		if epochAllocator != nil {
			allocated, allocateErr := epochAllocator.Allocate()
			if allocateErr != nil {
				logger.Error("kernel cache epoch exhausted; using full policy path", "error", allocateErr)
			} else {
				epoch = allocated
			}
		}
		return dataplane.M2CompileOptions{Epoch: epoch, ZoneSlots: zoneSlots, CacheEnabled: epoch > 0 && len(zoneSlots) > 0 && len(zoneSlots) <= dataplane.MaxZoneSlots}
	}
	validateInspectionArtifacts := func(desired domain.Config) error {
		if !domain.UsesM3(desired) {
			return nil
		}
		manifestPath, managedRoot := inspectionManifestPaths()
		_, validateErr := sensorpkg.ValidateActivationArtifacts(
			manifestPath,
			managedRoot,
			requestedInspectionModes(desired),
			map[string]struct{}{config.BuiltinM3RulesetID: {}},
		)
		return validateErr
	}
	applyDataplane := func(applyContext context.Context, desired domain.Config, targetGeneration uint64) error {
		options := compileOptions(desired)
		return controller.ApplyRuntimePrepared(applyContext, desired, options, targetGeneration)
	}
	startupContext, cancelStartup := context.WithTimeout(ctx, 60*time.Second)
	startupGeneration := m.Version().Version
	if err := validateInspectionArtifacts(m.Running()); err != nil {
		cancelStartup()
		logger.Error("running M3 configuration references unavailable or modified inspection artifacts", "error", err)
		os.Exit(1)
	}
	if err := applyDataplane(startupContext, m.Running(), startupGeneration); err != nil {
		cancelStartup()
		logger.Error("startup dataplane reconciliation failed", "error", err)
		os.Exit(1)
	}
	cancelStartup()
	logger.Info("running configuration reconciled to Linux dataplane", "version", m.Version().Version, "recovered_interrupted_activation", recoveringActivation)
	if err := forwarding.EnsureConntrack(ctx); err != nil {
		logger.Warn("conntrack accounting/events/timestamps unavailable; session metadata may be partial", "error", err)
	}

	generation := m.Version().Version
	program, programErr := connectivity.CompileForCapabilities(m.Running(), generation, connectivity.Capabilities{Inspection: true})
	if programErr != nil {
		logger.Error("M2 connectivity program failed", "error", programErr)
		os.Exit(1)
	}
	var source conntrack.Source
	ctSource, sourceErr := conntrack.NewLinuxSource(os.Getenv("NGFW_NETWORK_NAMESPACE"))
	if sourceErr != nil {
		logger.Error("conntrack source unavailable; forwarding remains active with degraded session tracking", "error", sourceErr)
	} else {
		source = ctSource
	}
	runtimeLimits := session.DefaultRuntimeLimits()
	if m.Running().MaxSessions > 0 {
		runtimeLimits.MaxSessions = m.Running().MaxSessions
	}
	if m.Running().MaxEventsQueue > 0 {
		runtimeLimits.MaxEventQueue = m.Running().MaxEventsQueue
	}
	runtimeEngine := engine.NewRuntime(source, program, m.Version().Version, runtimeLimits)
	// A revoked conntrack set contains kernel IDs whose namespace/boot/start
	// provenance is not encoded in nft's integer set. Clear it once per engine
	// start so an ID reused after restart cannot inherit a stale DROP fence.
	if err := nftables.ClearRevokedSessions(ctx); err != nil {
		logger.Warn("could not clear stale conntrack revoke fences; session revoke safety is degraded", "error", err)
	}
	runtimeEngine.SetGuardEnforcer(dataplane.NewRuntimeGuardManager(nftables))
	if source != nil {
		if err := runtimeEngine.Start(ctx); err != nil {
			logger.Error("conntrack resync failed; forwarding remains active with degraded session tracking", "error", err)
		}
	}
	if domain.UsesM3(m.Running()) || recoveringActivation {
		if err := nftables.ClearInspectionRuntimeState(ctx); err != nil {
			logger.Warn("could not clear stale M3 guards/leases", "error", err)
		}
	}
	var inspectionMu sync.Mutex
	var leaseCancel context.CancelFunc
	var leaseDone chan struct{}
	var activeInspectionLimits domain.InspectionLimits
	var activeInspectionModes uint8
	var inspectionStatusMu sync.RWMutex
	var activeIPSRuntime *engine.InspectionRuntime
	var activeIPSLease *dataplane.IPSLeaseManager
	var ipsRequested bool
	configureInspection := func(value domain.Config) error {
		inspectionMu.Lock()
		defer inspectionMu.Unlock()
		targetIPS := runningUsesIPS(value)
		inspectionStatusMu.Lock()
		ipsRequested = targetIPS
		activeIPSRuntime = nil
		activeIPSLease = nil
		inspectionStatusMu.Unlock()
		if leaseCancel != nil {
			leaseCancel()
			leaseCancel = nil
			if leaseDone != nil {
				select {
				case <-leaseDone:
				case <-time.After(3 * time.Second):
					return errors.New("timed out stopping previous IPS lease manager")
				}
			}
			leaseDone = nil
		}
		current := runtimeEngine.InspectionRuntime()
		if domain.UsesM3(value) || current != nil {
			leaseCtx, cancelLeaseStop := context.WithTimeout(context.Background(), 2*time.Second)
			_ = dataplane.StopIPSLease(leaseCtx, nftables)
			cancelLeaseStop()
		}
		if !domain.UsesM3(value) {
			if current != nil {
				current.Stop()
				runtimeEngine.SetInspectionRuntime(nil)
			}
			return nil
		}
		limits := domain.EffectiveInspectionConfig(value).Limits
		requestedModes := requestedInspectionModes(value)
		modeMask := inspectionModeMask(requestedModes)
		if current != nil && (limits != activeInspectionLimits || modeMask != activeInspectionModes) {
			current.Stop()
			runtimeEngine.SetInspectionRuntime(nil)
			current = nil
		}
		if current == nil {
			inspectionSources := loadInspectionSources(logger, stateDir, limits, value)
			current = engine.NewInspectionRuntimeWithScope(runtimeEngine, limits, inspectionSources, flow.Scope{NetworkNamespace: os.Getenv("NGFW_NETWORK_NAMESPACE")})
			current.SetExecutor(dataplane.NewInspectionGuardManager(nftables, 10000))
			runtimeEngine.SetInspectionRuntime(current)
			if err := current.Start(ctx); err != nil {
				logger.Warn("M3 inspection runtime degraded", "error", err)
			}
			for _, active := range runtimeEngine.Store.List() {
				current.OnSessionChanged(active)
			}
			activeInspectionLimits = limits
			activeInspectionModes = modeMask
		}
		if targetIPS {
			var leaseCtx context.Context
			leaseCtx, leaseCancel = context.WithCancel(ctx)
			leaseDone = make(chan struct{})
			lease := dataplane.NewIPSLeaseManager(nftables)
			inspectionStatusMu.Lock()
			activeIPSRuntime = current
			activeIPSLease = lease
			inspectionStatusMu.Unlock()
			go func(active *engine.InspectionRuntime, done chan struct{}) {
				defer close(done)
				lease.Run(leaseCtx, func() bool {
					return active.CaptureLive("ips", time.Now().UTC())
				})
			}(current, leaseDone)
		}
		return nil
	}
	startupInspectionErr := configureInspection(m.Running())
	if startupInspectionErr != nil {
		logger.Warn("inspection runtime configuration failed", "error", startupInspectionErr)
	} else {
		finalizeContext, finalizeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if finalizeErr := controller.FinalizeActivation(finalizeContext, m.Running(), m.Version().Version); finalizeErr != nil {
			logger.Warn("startup activation journal remains pending", "error", finalizeErr)
		}
		finalizeCancel()
	}
	defer func() {
		inspectionMu.Lock()
		if leaseCancel != nil {
			leaseCancel()
			if leaseDone != nil {
				select {
				case <-leaseDone:
				case <-time.After(3 * time.Second):
					logger.Warn("timed out stopping IPS lease manager")
				}
			}
		}
		if current := runtimeEngine.InspectionRuntime(); current != nil {
			current.Stop()
		}
		inspectionMu.Unlock()
	}()
	service := engine.NewRuntimeServiceAdapter(runtimeEngine, m, nil)
	service.ApplyGeneration = applyDataplane
	service.FinalizeActivation = controller.FinalizeActivation
	service.BeforeActivate = func(_ context.Context, desired domain.Config, _ uint64) error {
		return validateInspectionArtifacts(desired)
	}
	service.InspectionQueueStatus = func() domain.InspectionQueueStatus {
		inspectionStatusMu.RLock()
		requested, active, lease := ipsRequested, activeIPSRuntime, activeIPSLease
		inspectionStatusMu.RUnlock()
		result := domain.InspectionQueueStatus{Requested: requested}
		if active != nil {
			result.Configured = active.HasSource("ips")
			result.CaptureLive = active.CaptureLive("ips", time.Now().UTC())
		}
		if lease != nil {
			state := lease.State()
			result.LeaseActive = state.Active
			result.LastRenewal = state.LastRenewal
			result.LastError = state.LastError
		}
		return result
	}
	service.AfterActivate = func(_ context.Context, value domain.Config, _ uint64) error { return configureInspection(value) }
	ipcServer := engineipc.NewRuntimeServer(engineipc.DefaultSocketPath(stateDir), service)
	ipcErrors := make(chan error, 1)
	go func() { ipcErrors <- ipcServer.Serve(ctx) }()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	logger.Info("ngfw engine started", "ipc_socket", ipcServer.SocketPath)
	for {
		select {
		case <-ctx.Done():
			logger.Info("ngfw engine stopped")
			return
		case serveErr := <-ipcErrors:
			if serveErr != nil {
				logger.Error("engine IPC server stopped", "error", serveErr)
				os.Exit(1)
			}
			return
		case now := <-ticker.C:
			for _, closed := range runtimeEngine.Store.CleanupExpired(now, 512) {
				_ = runtimeEngine.ReleaseExpiredSession(closed)
			}
			runtimeEngine.SweepBlocks(now)
		}
	}
}

func inspectionModeMask(modes map[domain.InspectionMode]bool) uint8 {
	var result uint8
	if modes[domain.InspectionModeIDS] {
		result |= 1
	}
	if modes[domain.InspectionModeIPS] {
		result |= 2
	}
	return result
}

func runningUsesIPS(value domain.Config) bool {
	return requestedInspectionModes(value)[domain.InspectionModeIPS]
}

func requestedInspectionModes(value domain.Config) map[domain.InspectionMode]bool {
	result := map[domain.InspectionMode]bool{}
	if !domain.UsesM3(value) {
		return result
	}
	profiles := make(map[string]domain.InspectionMode, len(value.Profiles))
	for _, profile := range value.Profiles {
		if profile.Inspection != nil {
			profiles[profile.ID] = profile.Inspection.Mode
		}
	}
	for _, policy := range value.Policies {
		if !policy.Enabled {
			continue
		}
		if mode := profiles[policy.SecurityProfileID]; mode == domain.InspectionModeIDS || mode == domain.InspectionModeIPS {
			result[mode] = true
		}
	}
	return result
}

func loadInspectionSources(logger *slog.Logger, stateDir string, limits domain.InspectionLimits, running domain.Config) []inspection.EventSource {
	manifestPath, root := inspectionManifestPaths()
	manifest, err := sensorpkg.LoadManifest(manifestPath, root)
	if err != nil {
		logger.Warn("inspection manifest unavailable; M3 metadata is degraded", "path", manifestPath, "error", err)
		return nil
	}
	sources := make([]inspection.EventSource, 0, len(manifest.Sensors))
	requestedModes := requestedInspectionModes(running)
	for _, definition := range manifest.Sensors {
		if !requestedModes[definition.Mode] {
			continue
		}
		position := inspection.SourcePosition{SensorID: definition.ID, SensorEpoch: definition.Epoch, SensorConfigHash: definition.ConfigHash, RulesetID: definition.RulesetID, Mode: definition.Mode}
		checkpoint := eve.FileCheckpointStore{Path: filepath.Join(stateDir, "inspection-"+definition.ID+".checkpoint.json")}
		reader := eve.NewReader(definition.EVEPath, position, checkpoint)
		reader.LineBytes = limits.WithDefaults().EVELineBytes
		reader.NormalizedBytes = limits.WithDefaults().NormalizedEventBytes
		reader.EpochPath = definition.EpochPath
		reader.DiscoverySIDs = map[uint32]struct{}{}
		for _, sid := range definition.DiscoverySIDs {
			reader.DiscoverySIDs[sid] = struct{}{}
		}
		sources = append(sources, sensorpkg.NewMonitoredSource(definition.ID, reader, definition.ControlSocket))
	}
	return sources
}

func inspectionManifestPaths() (string, string) {
	manifestPath := os.Getenv("NGFW_INSPECTION_MANIFEST")
	if manifestPath == "" {
		manifestPath = "/etc/ngfw/inspection/manifest.json"
	}
	root := os.Getenv("NGFW_INSPECTION_ROOT")
	if root == "" {
		root = "/var/lib/ngfw/inspection"
	}
	return manifestPath, root
}

func makeZoneSlots(config domain.Config) map[string]uint8 {
	ids := make([]string, 0, len(config.Zones))
	for _, zone := range config.Zones {
		ids = append(ids, zone.ID)
	}
	sort.Strings(ids)
	slots := make(map[string]uint8, len(ids))
	for index, id := range ids {
		if index >= dataplane.MaxZoneSlots {
			break
		}
		slots[id] = uint8(index + 1)
	}
	return slots
}
