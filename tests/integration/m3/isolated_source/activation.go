//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/dataplane"
	"github.com/kltngfw/ngfw/internal/domain"
)

type noForwarding struct{}

func (noForwarding) Ensure(context.Context) error { return nil }

func activationCheck(err error) {
	if err != nil {
		panic(err)
	}
}

func activationRequire(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func activationCommand(args ...string) string {
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, err, output))
	}
	return string(output)
}

func isolatedM3Config(address string) domain.Config {
	value := config.Defaults()
	value.Zones = []domain.Zone{{ID: "lan", Name: "isolated LAN"}}
	value.Interfaces = []domain.Interface{{ID: "lan0", Name: "isolated LAN", SystemName: "m3lan0", ZoneID: "lan", Mode: domain.InterfaceL3, IPv4Addresses: []string{address}, AdminState: true}}
	value.Inspection = &domain.InspectionConfig{Enabled: true, Limits: domain.DefaultInspectionLimits()}
	return value
}

func writeActivationJSON(path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	activationCheck(err)
	activationCheck(os.WriteFile(path, append(data, '\n'), 0600))
}

func isolatedController(state string) *dataplane.Controller {
	controller, err := dataplane.NewController(dataplane.NewNetworkReconciler(dataplane.NewExecIPCommandRunner("")), dataplane.NewNftRunner(""), noForwarding{}, state)
	activationCheck(err)
	return controller
}

func runActivationProbe(root, phase string) {
	currentNS, err := os.Readlink("/proc/self/ns/net")
	activationCheck(err)
	initialNS, err := os.Readlink("/proc/1/ns/net")
	activationCheck(err)
	activationRequire(os.Geteuid() == 0 && currentNS != initialNS, "root in disposable network namespace required")
	activationRequire(filepath.Dir(root) == "/tmp" && strings.HasPrefix(filepath.Base(root), "ngfw-m3-activation-"), "evidence dir must be under /tmp/ngfw-m3-activation-*")
	state := filepath.Join(root, "dataplane-applied.json")
	previous := isolatedM3Config("192.0.2.2/24")
	target := isolatedM3Config("192.0.2.3/24")
	target.Routes = []domain.Route{{ID: "activation-test-route", DestinationCIDR: "198.51.120.0/24", Gateway: "192.0.2.1", InterfaceID: "lan0", Metric: 120, Enabled: true}}
	if phase == "child" {
		controller := isolatedController(state)
		activationCheck(controller.ApplyRuntimePrepared(context.Background(), target, dataplane.M2CompileOptions{}, 2))
		activationRequire(controller.RecoveryPending() == false, "unexpected live recovery marker before crash")
		writeActivationJSON(filepath.Join(root, "child-ready.json"), map[string]any{"generation": 2, "address": activationCommand("ip", "-4", "-o", "addr", "show", "dev", "m3lan0"), "route": activationCommand("ip", "-4", "route", "show", "198.51.120.0/24"), "journal_exists": true})
		time.Sleep(20 * time.Second)
		panic("parent failed to terminate interrupted activation child")
	}
	activationCheck(os.Mkdir(root, 0700))
	activationCommand("ip", "link", "add", "m3lan0", "type", "dummy")
	activationCommand("ip", "link", "set", "m3lan0", "up")
	controller := isolatedController(state)
	activationCheck(controller.ApplyRuntimePrepared(context.Background(), previous, dataplane.M2CompileOptions{}, 1))
	baseSnapshot, _, _, err := dataplane.PrepareM3Activation(previous, 1, dataplane.M2CompileOptions{})
	activationCheck(err)
	activationCheck(controller.FinalizeActivation(context.Background(), previous, 1))
	writeActivationJSON(filepath.Join(root, "baseline.json"), baseSnapshot)
	bad := target
	bad.Routes = []domain.Route{{ID: "invalid-next-hop", DestinationCIDR: "203.0.113.0/24", Gateway: "203.0.113.1", InterfaceID: "lan0", Metric: 1, Enabled: true}}
	failed := controller.ApplyRuntimePrepared(context.Background(), bad, dataplane.M2CompileOptions{}, 2)
	activationRequire(failed != nil, "invalid next-hop unexpectedly activated")
	activationRequire(!controller.RecoveryPending(), "failed activation did not finish compensation")
	activationCheck(dataplane.NewNetworkReconciler(dataplane.NewExecIPCommandRunner("")).VerifyTransition(context.Background(), bad, previous))
	activationCheck(controller.VerifyActivation(context.Background(), baseSnapshot))
	writeActivationJSON(filepath.Join(root, "activation-failure-rollback.json"), map[string]any{"error": failed.Error(), "base_verified": true, "link": activationCommand("ip", "-4", "-o", "addr", "show", "dev", "m3lan0"), "nft_inspection": activationCommand("nft", "-j", "list", "table", "inet", "ngfw_inspection")})
	child := exec.Command(os.Args[0], "--activation-phase=child", "--evidence-dir", root)
	activationCheck(child.Start())
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := filepath.Join(root, "child-ready.json")
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(ready); err != nil {
		child.Process.Kill()
		child.Wait()
		panic("prepared activation child did not reach the crash point")
	}
	activationRequire(strings.Contains(activationCommand("ip", "-4", "route", "show", "198.51.120.0/24"), "198.51.120.0/24"), "target kernel route was not live before simulated crash")
	activationRequire(strings.Contains(activationCommand("ip", "-4", "-o", "addr", "show", "dev", "m3lan0"), "192.0.2.3/24"), "target kernel address was not live before simulated crash")
	activationCheck(child.Process.Kill())
	child.Wait()
	restarted := isolatedController(state)
	activationRequire(restarted.RecoveryPending(), "activation journal did not trigger startup recovery")
	activationCheck(restarted.ApplyRuntimePrepared(context.Background(), previous, dataplane.M2CompileOptions{}, 1))
	activationCheck(restarted.VerifyActivation(context.Background(), baseSnapshot))
	activationCheck(dataplane.NewNetworkReconciler(dataplane.NewExecIPCommandRunner("")).VerifyTransition(context.Background(), target, previous))
	activationCheck(restarted.FinalizeActivation(context.Background(), previous, 1))
	_, journalErr := os.Stat(state + ".activation")
	activationRequire(os.IsNotExist(journalErr), "activation journal remained after recovery")
	after := map[string]any{"generation": 1, "address": activationCommand("ip", "-4", "-o", "addr", "show", "dev", "m3lan0"), "route": activationCommand("ip", "-4", "route", "show", "198.51.120.0/24"), "nft_inspection": activationCommand("nft", "-j", "list", "table", "inet", "ngfw_inspection"), "journal_removed": true, "baseline_snapshot_verified": true}
	activationRequire(strings.Contains(after["address"].(string), "192.0.2.2/24") && !strings.Contains(after["address"].(string), "192.0.2.3/24"), "interrupted address was not restored")
	activationRequire(strings.TrimSpace(after["route"].(string)) == "", "interrupted route remained after recovery")
	writeActivationJSON(filepath.Join(root, "interrupted-recovery.json"), after)
	writeActivationJSON(filepath.Join(root, "result.json"), map[string]any{"status": "PASS", "scope": "real production Controller, nft and iproute2 in disposable Ubuntu VM network namespace; injected invalid route and SIGKILL after retained activation journal; does not restart systemd appliance", "invalid_route_rolled_back": true, "interrupted_target_recovered": true})
	fmt.Println("PASS M3-27: real activation failure compensates; restart from retained journal restores previous network and nft snapshot")
}
