package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

type readOnlyNetworkRunner struct {
	calls []string
}

func (r *readOnlyNetworkRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	r.calls = append(r.calls, command)
	switch command {
	case "-details -json link show":
		return []byte(`[{"ifname":"eth0","ifindex":2,"mtu":1500,"flags":["UP"]}]`), nil
	case "-json address show":
		return []byte(`[]`), nil
	default:
		return nil, errors.New("verification attempted unexpected/mutating command: " + command)
	}
}

func TestVerifyNetworkCommandFailsOnMissingIPWithoutModifyingState(t *testing.T) {
	dir := t.TempDir()
	value := config.Defaults()
	value.Interfaces = []domain.Interface{{ID: "wan", SystemName: "eth0", Mode: domain.InterfaceL3, MTU: 1500, AdminState: true, IPv4Addresses: []string{"192.0.2.2/24"}}}
	data, _ := json.Marshal(map[string]any{"config": value, "version": domain.ConfigVersion{Version: 92}})
	path := filepath.Join(dir, "running.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	runner := &readOnlyNetworkRunner{}
	if status := verifyNetworkCommand(context.Background(), dir, runner, &output); status != 1 || !strings.Contains(output.String(), "192.0.2.2/24") {
		t.Fatalf("failed baseline was accepted: status=%d output=%s", status, &output)
	}
	after, _ := os.ReadFile(path)
	files, _ := os.ReadDir(dir)
	if !bytes.Equal(data, after) || len(files) != 1 || len(runner.calls) != 2 {
		t.Fatal("read-only verification mutated state or executed extra commands")
	}
	output.Reset()
	missing := filepath.Join(dir, "absent")
	if verifyNetworkCommand(context.Background(), missing, runner, &output) == 0 {
		t.Fatal("missing Running reported healthy")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("verify created a state directory")
	}
}

func TestNetworkCommandRejectsUnknownFlagsAndPositionalArguments(t *testing.T) {
	for _, args := range [][]string{{"--unknown"}, {"--verify-network", "unexpected"}, {"--state-dir", "missing"}} {
		var output bytes.Buffer
		if runCommand(args, &output) != 2 {
			t.Fatalf("invalid CLI accepted: %v", args)
		}
	}
}
