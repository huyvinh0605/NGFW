package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/dataplane"
)

func runCommand(args []string, output io.Writer) int {
	flags := flag.NewFlagSet("ngfw-engine", flag.ContinueOnError)
	flags.SetOutput(output)
	verify := flags.Bool("verify-network", false, "verify Running interfaces/addresses/routes without changing kernel or configuration")
	stateDir := os.Getenv("NGFW_STATE_DIR")
	if stateDir == "" {
		stateDir = "/var/lib/ngfw"
	}
	flags.StringVar(&stateDir, "state-dir", stateDir, "directory containing persisted running.json")
	if err := flags.Parse(args); err != nil || !*verify || flags.NArg() != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return verifyNetworkCommand(ctx, stateDir, dataplane.NewExecIPCommandRunner(os.Getenv("NGFW_IP_BINARY")), output)
}

func verifyNetworkCommand(ctx context.Context, stateDir string, runner dataplane.IPCommandRunner, output io.Writer) int {
	value, version, err := config.LoadRunningFile(filepath.Join(stateDir, "running.json"))
	if err == nil {
		err = dataplane.NewNetworkReconciler(runner).Verify(ctx, value)
	}
	if err != nil {
		fmt.Fprintf(output, "FAIL  Running network verification: %v\n", err)
		return 1
	}
	fmt.Fprintf(output, "PASS  Running network matches kernel (version=%d, interfaces=%d, configured_routes=%d)\n", version.Version, len(value.Interfaces), len(value.Routes))
	return 0
}

func monitorNetwork(ctx context.Context, controller *dataplane.Controller, logger *slog.Logger) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	lastError := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			repaired, err := controller.MaintainNetwork(checkCtx)
			cancel()
			if err != nil {
				if err.Error() != lastError {
					logger.Error("managed network verification/repair failed", "error", err)
				}
				lastError = err.Error()
				continue
			}
			if repaired {
				logger.Warn("managed network drift reconciled to applied configuration")
			}
			lastError = ""
		}
	}
}
