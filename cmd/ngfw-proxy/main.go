package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/enforcement"
	"github.com/kltngfw/ngfw/internal/engine"
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
	initial := config.Defaults()
	if path := os.Getenv("NGFW_CONFIG"); path != "" {
		loaded, err := config.LoadFile(path)
		if err != nil {
			logger.Error("configuration file failed", "error", err)
			os.Exit(1)
		}
		initial = loaded
	}
	manager, err := config.NewManager(os.Getenv("NGFW_STATE_DIR"), initial)
	if err != nil {
		logger.Error("configuration manager failed", "error", err)
		os.Exit(1)
	}
	eng := engine.New(manager, enforcement.NewMemory())
	upstream := os.Getenv("NGFW_PROXY_UPSTREAM")
	if upstream == "" {
		upstream = "http://127.0.0.1:8081"
	}
	gate, err := proxy.NewGate(eng, upstream)
	if err != nil {
		logger.Error("proxy setup failed", "error", err)
		os.Exit(1)
	}
	caCert, caKey := os.Getenv("NGFW_PROXY_CA_CERT"), os.Getenv("NGFW_PROXY_CA_KEY")
	if (caCert == "") != (caKey == "") {
		logger.Error("both NGFW_PROXY_CA_CERT and NGFW_PROXY_CA_KEY are required for CA mode")
		os.Exit(1)
	}
	var ca *inspection.MITMCA
	if caCert != "" {
		ca, err = inspection.LoadMITMCA(caCert, caKey)
		if err != nil {
			logger.Error("MITM CA unavailable", "error", err)
			os.Exit(1)
		}
		limits := domain.EffectiveRequestGateConfig(initial)
		if err := ca.ConfigureLeafCache(limits.LeafCacheEntries, time.Duration(limits.LeafCacheTTLSeconds)*time.Second); err != nil {
			logger.Error("invalid leaf certificate cache limits", "error", err)
			os.Exit(1)
		}
	}
	gate.FailClosedOnInspectionError = os.Getenv("NGFW_PROXY_FAIL_CLOSED") == "1"
	gate.Reputation = inspection.NewReputationStore(100000)
	if mlURL := os.Getenv("NGFW_ML_URL"); mlURL != "" {
		gate.ML = inspection.NewMLClient(mlURL, time.Duration(initial.MLTimeoutMillis)*time.Millisecond)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	addr := os.Getenv("NGFW_PROXY_ADDR")
	if addr == "" {
		addr = ":8088"
	}
	server := &http.Server{Addr: addr, Handler: gate, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("ngfw request gate listening", "addr", addr, "upstream", upstream)
		var err error
		if ca != nil {
			listener, listenErr := tls.Listen("tcp", addr, ca.TLSConfig([]string{"h2", "http/1.1"}))
			if listenErr != nil {
				logger.Error("proxy TLS listener failed", "error", listenErr)
				stop()
				return
			}
			err = server.Serve(listener)
		} else if cert, key := os.Getenv("NGFW_PROXY_CERT"), os.Getenv("NGFW_PROXY_KEY"); cert != "" && key != "" {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			err = server.ListenAndServeTLS(cert, key)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("proxy stopped", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
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
