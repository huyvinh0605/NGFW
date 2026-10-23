package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kltngfw/ngfw/internal/gateipc"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/proxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "ca" {
		if err := runCACommand(os.Args[2:]); err != nil {
			logger.Error("CA command failed", "error", err)
			os.Exit(1)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := gateipc.NewClient(envOr("NGFW_REQUEST_GATE_SOCKET", gateipc.DefaultSocketPath))
	builder := proxy.RuntimeBuilder{
		Client:             client,
		Resolver:           proxy.TPROXYOriginalDestinationResolver{},
		Transparent:        true,
		CACertPath:         envOr("NGFW_PROXY_CA_CERT", "/var/lib/ngfw/ca/ca.crt"),
		CAKeyPath:          envOr("NGFW_PROXY_CA_KEY", "/var/lib/ngfw/ca/ca.key"),
		UpstreamCAPath:     os.Getenv("NGFW_PROXY_UPSTREAM_CA"),
		SuricataBinary:     envOr("NGFW_SURICATA_BINARY", "/usr/bin/suricata"),
		SuricataConfigPath: envOr("NGFW_REQUEST_WORKER_CONFIG", "/etc/ngfw/request-gate/suricata.yaml"),
		WorkerRoot:         envOr("NGFW_REQUEST_WORKER_ROOT", "/var/lib/ngfw/request-workers"),
		RulesetID:          "m4-builtin-v1", RulesetPath: "/etc/ngfw/request-gate/rules/request-gate.rules",
		// Preparation opens resources; only the published engine generation
		// with verified TPROXY state can authorize application traffic.
	}
	supervisor := &proxy.RuntimeSupervisor{
		Synchronizer: proxy.IPCRuntimeSynchronizer{Client: client}, Factory: builder.Start,
		OnError: func(err error) { logger.Warn("request-gate runtime unavailable", "reason", err.Error()) },
	}
	logger.Info("ngfw proxy synchronizing with authoritative engine")
	if err := supervisor.Run(ctx); err != nil {
		logger.Error("proxy runtime stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func runCACommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ngfw-proxy ca init|fingerprint (set NGFW_PROXY_CA_CERT and NGFW_PROXY_CA_KEY)")
	}
	certPath, keyPath := os.Getenv("NGFW_PROXY_CA_CERT"), os.Getenv("NGFW_PROXY_CA_KEY")
	if certPath == "" {
		certPath = "/var/lib/ngfw/ca/ca.crt"
	}
	if keyPath == "" {
		keyPath = "/var/lib/ngfw/ca/ca.key"
	}
	var ca *inspection.MITMCA
	var err error
	switch args[0] {
	case "init":
		ca, err = inspection.InitMITMCA(certPath, keyPath)
	case "fingerprint":
		ca, err = inspection.LoadMITMCA(certPath, keyPath)
	default:
		return fmt.Errorf("unknown CA command %q", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Println(ca.FingerprintSHA256())
	return nil
}
