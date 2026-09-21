package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kltngfw/ngfw/internal/auth"
	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engineipc"
	"github.com/kltngfw/ngfw/internal/management"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	stateRoot := os.Getenv("NGFW_STATE_DIR")
	if stateRoot == "" {
		stateRoot = filepath.Join(".", "state")
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
	// The engine owns running.json. The API keeps only candidate/editor state
	// in a separate directory and seeds it from the engine when available.
	engineClient := engineipc.NewRuntimeClient(engineipc.DefaultSocketPath(stateRoot))
	var engineVersion domain.ConfigVersion
	var engineSnapshot domain.Config
	var haveEngineSnapshot bool
	if running, version, loadErr := engineClient.GetRunningConfig(context.Background()); loadErr == nil {
		initial = running
		engineSnapshot, engineVersion, haveEngineSnapshot = running, version, true
	}
	apiStateDir := os.Getenv("NGFW_API_STATE_DIR")
	if apiStateDir == "" {
		apiStateDir = filepath.Join(stateRoot, "management")
	}
	manager, err := config.NewManager(apiStateDir, initial)
	if err != nil {
		logger.Error("configuration manager failed", "error", err)
		os.Exit(1)
	}
	if haveEngineSnapshot {
		manager.SyncRunning(engineSnapshot, engineVersion)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	// The API has no local session engine or enforcement object. All runtime
	// state and privileged mutations are served by ngfw-engine over IPC.
	api := management.NewRuntimeAPI(engineClient, manager, os.Getenv("NGFW_API_TOKEN"), logger)
	if username, password := os.Getenv("NGFW_ADMIN_USER"), os.Getenv("NGFW_ADMIN_PASSWORD"); username != "" && password != "" {
		users := auth.NewStore(0)
		if addErr := users.AddUser("admin", username, password, auth.RoleAdmin); addErr != nil {
			logger.Error("admin user setup failed", "error", addErr)
			os.Exit(1)
		}
		api.Auth = users
	}
	addr := os.Getenv("NGFW_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{Addr: addr, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 95 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("ngfw api listening", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("api stopped", "error", err)
			cancel()
		}
	}()
	<-ctx.Done()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = api.Shutdown(shutdown)
	_ = server.Shutdown(shutdown)
}
