package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/enforcement"
	"github.com/kltngfw/ngfw/internal/engine"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/proxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
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
		if caCert, caKey := os.Getenv("NGFW_PROXY_CA_CERT"), os.Getenv("NGFW_PROXY_CA_KEY"); caCert != "" && caKey != "" {
			ca, caErr := inspection.LoadMITMCA(caCert, caKey, true)
			if caErr != nil {
				logger.Error("MITM CA setup failed", "error", caErr)
				stop()
				return
			}
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
