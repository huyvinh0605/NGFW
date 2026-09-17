package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/dataplane"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engine"
	"github.com/kltngfw/ngfw/internal/engineipc"
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
	applyM2 := func(applyContext context.Context, desired domain.Config) error {
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
		options := dataplane.M2CompileOptions{Epoch: epoch, ZoneSlots: zoneSlots, CacheEnabled: epoch > 0 && len(zoneSlots) > 0 && len(zoneSlots) <= dataplane.MaxZoneSlots}
		return controller.ApplyM2(applyContext, desired, options)
	}
	startupContext, cancelStartup := context.WithTimeout(ctx, 60*time.Second)
	if err := applyM2(startupContext, m.Running()); err != nil {
		cancelStartup()
		logger.Error("startup dataplane reconciliation failed", "error", err)
		os.Exit(1)
	}
	cancelStartup()
	logger.Info("running configuration reconciled to Linux dataplane", "version", m.Version().Version, "recovered_interrupted_activation", recoveringActivation)
	if err := forwarding.EnsureConntrack(ctx); err != nil {
		logger.Warn("conntrack accounting/events/timestamps unavailable; session metadata may be partial", "error", err)
	}

	program, programErr := connectivity.CompileM2(m.Running(), m.Version().Version)
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
	service := engine.NewRuntimeServiceAdapter(runtimeEngine, m, func(applyContext context.Context, desired domain.Config) error {
		return applyM2(applyContext, desired)
	})
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
