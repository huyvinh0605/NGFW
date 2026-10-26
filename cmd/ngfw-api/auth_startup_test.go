package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPIStartupWithoutCredentialsFailsBeforeStateOrListener(t *testing.T) {
	if os.Getenv("NGFW_AUTH_STARTUP_TEST") == "1" {
		main()
		return
	}
	state := filepath.Join(t.TempDir(), "uncreated-state")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAPIStartupWithoutCredentialsFailsBeforeStateOrListener$")
	command.Env = append(os.Environ(), "NGFW_AUTH_STARTUP_TEST=1", "NGFW_API_TOKEN=", "NGFW_ADMIN_USER=", "NGFW_ADMIN_PASSWORD=", "NGFW_CONFIG=", "NGFW_STATE_DIR="+state, "NGFW_API_ADDR=127.0.0.1:0")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("API did not reject missing credentials before starting")
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "management authentication not configured") {
		t.Fatalf("unexpected startup result: %v %s", err, output)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("unauthenticated startup touched state: %v", err)
	}
}
