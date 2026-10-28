//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

// This suite is opt-in and must be launched through unshare --net. The real
// Linux ip/nft adapters operate only in that disposable namespace.
func requireNetworkRecoveryNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("NGFW_NETWORK_NETNS_TEST") != "1" {
		t.Skip("set NGFW_NETWORK_NETNS_TEST=1 and launch the test binary through unshare --net")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("root in a disposable network namespace required")
	}
}

func networkRecoveryCommand(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
	return string(out)
}

func networkRecoveryConfigs() (domain.Config, domain.Config) {
	base := config.Defaults()
	base.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	base.Interfaces = []domain.Interface{
		{ID: "lan", SystemName: "m3lan0", ZoneID: "lan", Mode: domain.InterfaceL3, MTU: 1500, AdminState: true, IPv4Addresses: []string{"192.0.2.2/24"}, IPv6Addresses: []string{"2001:db8:27::2/64"}},
		{ID: "wan", SystemName: "m3wan0", ZoneID: "wan", Mode: domain.InterfaceL3, MTU: 1500, AdminState: true, IPv4Addresses: []string{"198.51.100.2/24"}},
	}
	base.Inspection = &domain.InspectionConfig{Enabled: true, Limits: domain.DefaultInspectionLimits()}
	base.Profiles = []domain.SecurityProfile{{ID: "ids", IDSIPSEnabled: true, TLSMode: domain.TLSMetadata, Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIDS, FailMode: "OPEN", RulesetID: config.BuiltinM3RulesetID}}}
	base.Policies = []domain.SecurityPolicy{{ID: "allow", SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, SecurityProfileID: "ids", Priority: 10, Scope: "SESSION", Action: domain.DecisionAllow, Enabled: true}}
	target := base
	target.Interfaces = append([]domain.Interface(nil), base.Interfaces...)
	target.Interfaces[0].Mode = domain.InterfaceVLANParent
	target.Interfaces[0].ZoneID = ""
	target.Interfaces[0].IPv4Addresses = nil
	target.Interfaces[0].IPv6Addresses = nil
	target.Interfaces = append(target.Interfaces, domain.Interface{ID: "vlan", SystemName: "m3lan0.27", ParentInterfaceID: "lan", VLANID: 27, ZoneID: "lan", Mode: domain.InterfaceVLANSub, MTU: 1400, AdminState: true, IPv4Addresses: []string{"192.0.2.3/24"}, IPv6Addresses: []string{"2001:db8:27::3/64"}})
	target.Routes = []domain.Route{{ID: "target-route", DestinationCIDR: "198.18.27.0/24", Gateway: "192.0.2.1", InterfaceID: "vlan", Metric: 27, Enabled: true}}
	return base, target
}

type recoveryFaultIP struct {
	delegate IPCommandRunner
	match    string
	after    bool
	armed    bool
	hit      bool
	denyBase bool
	cancel   context.CancelFunc
	trace    []string
}

var errRecoveryFault = errors.New("injected network operation interruption")

func (r *recoveryFaultIP) Run(ctx context.Context, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	r.trace = append(r.trace, command)
	if r.denyBase && strings.Contains(command, "addr replace 192.0.2.2/24") {
		return nil, errors.New("injected persistent restore permission failure")
	}
	selected := r.armed && strings.Contains(command, r.match)
	if selected {
		r.armed = false
		r.hit = true
		if !r.after {
			return nil, errRecoveryFault
		}
	}
	out, err := r.delegate.Run(ctx, args...)
	if err == nil && selected && r.after {
		if r.cancel != nil {
			r.cancel()
			return out, ctx.Err()
		}
		return out, errRecoveryFault
	}
	return out, err
}

type recoveryFaultNft struct {
	*NftRunner
	corrupt bool
}

func (r *recoveryFaultNft) ApplyBundle(ctx context.Context, bundle RulesetBundle) error {
	if r.corrupt {
		r.corrupt = false
		bundle.PolicyTransaction += "\nINVALID_M3_ACTIVATION_TRANSACTION\n"
	}
	return r.NftRunner.ApplyBundle(ctx, bundle)
}

func recoveryFixture(t *testing.T) (*Controller, *NetworkReconciler, *recoveryFaultIP, *recoveryFaultNft, string, domain.Config, domain.Config) {
	t.Helper()
	requireNetworkRecoveryNamespace(t)
	base, target := networkRecoveryConfigs()
	for _, value := range []domain.Config{base, target} {
		if validation := (config.Validator{}).Validate(value); len(validation) > 0 {
			t.Fatalf("invalid recovery fixture: %v", validation)
		}
	}
	for _, name := range []string{"m3lan0", "m3wan0"} {
		networkRecoveryCommand(t, "ip", "link", "add", name, "type", "dummy")
		t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
	}
	ip := &recoveryFaultIP{delegate: NewExecIPCommandRunner("")}
	network := NewNetworkReconciler(ip)
	rules := &recoveryFaultNft{NftRunner: NewNftRunner("")}
	state := filepath.Join(t.TempDir(), "dataplane-applied.json")
	controller, err := NewController(network, rules, &fakeForwarding{}, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.ApplyRuntime(context.Background(), base, M2CompileOptions{}, 1); err != nil {
		t.Fatal(err)
	}
	return controller, network, ip, rules, state, base, target
}

func assertRecoveredNetwork(t *testing.T, controller *Controller, network *NetworkReconciler, source, base domain.Config, state string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := network.VerifyTransition(ctx, source, base); err != nil {
		t.Fatalf("managed stale state or missing baseline after recovery: %v", err)
	}
	snapshot, _, _, err := PrepareM3Activation(base, 1, M2CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.VerifyActivation(ctx, snapshot); err != nil {
		t.Fatalf("baseline network/nft verification failed: %v", err)
	}
	if controller.RecoveryPending() {
		t.Fatal("successful compensation still marked pending")
	}
	if _, err := os.Stat(state + ".activation"); !os.IsNotExist(err) {
		t.Fatalf("successful compensation retained journal: %v", err)
	}
	applied, exists, err := loadAppliedSnapshot(state)
	if err != nil || !exists || applied.Generation != 1 {
		t.Fatalf("failed target was published: exists=%v generation=%d err=%v", exists, applied.Generation, err)
	}
	actual, _ := configChecksum(applied.Config)
	expected, _ := configChecksum(base)
	if actual != expected {
		t.Fatal("applied snapshot differs from baseline")
	}
}

func saveRecoveryEvidence(t *testing.T, label string, value any) {
	t.Helper()
	root := os.Getenv("NGFW_NETWORK_EVIDENCE_DIR")
	if root == "" {
		return
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, label+".json"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxNetworkRecoveryOperationFailures(t *testing.T) {
	requireNetworkRecoveryNamespace(t)
	for _, scenario := range []struct {
		name, match string
		after       bool
	}{
		{"vlan-before", "link add link m3lan0 name m3lan0.27", false},
		{"vlan-after", "link add link m3lan0 name m3lan0.27", true},
		{"mtu-before", "link set dev m3lan0.27 mtu", false},
		{"ipv4-before", "-4 addr replace 192.0.2.3/24", false},
		{"ipv4-after", "-4 addr replace 192.0.2.3/24", true},
		{"cancel-after-ipv4", "-4 addr replace 192.0.2.3/24", true},
		{"ipv6-after", "-6 addr replace 2001:db8:27::3/64", true},
		{"route-before", "-4 route replace 198.18.27.0/24", false},
		{"route-after", "-4 route replace 198.18.27.0/24", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			controller, network, ip, _, state, base, target := recoveryFixture(t)
			ip.match, ip.after, ip.armed = scenario.match, scenario.after, true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var wantErr error = errRecoveryFault
			if scenario.name == "cancel-after-ipv4" {
				ip.cancel = cancel
				wantErr = context.Canceled
			}
			err := controller.ApplyRuntimePrepared(ctx, target, M2CompileOptions{}, 2)
			if !ip.hit || !errors.Is(err, wantErr) {
				t.Fatalf("fault not exercised: hit=%t err=%v", ip.hit, err)
			}
			assertRecoveredNetwork(t, controller, network, target, base, state)
			// Recovery must also be safe after every object was already removed.
			for i := 0; i < 3; i++ {
				if err := network.Restore(context.Background(), target, base); err != nil {
					t.Fatalf("repeated restore %d: %v", i, err)
				}
			}
			saveRecoveryEvidence(t, scenario.name, map[string]any{"status": "PASS", "error": err.Error(), "commands": ip.trace, "addresses": networkRecoveryCommand(t, "ip", "-json", "address", "show"), "routes": networkRecoveryCommand(t, "ip", "-4", "-json", "route", "show"), "repeated_restore": 3})
		})
	}
}

func TestLinuxNetworkRecoveryNftAndPersistentFailure(t *testing.T) {
	requireNetworkRecoveryNamespace(t)
	t.Run("real-nft-reject", func(t *testing.T) {
		controller, network, ip, rules, state, base, target := recoveryFixture(t)
		rules.corrupt = true
		err := controller.ApplyRuntimePrepared(context.Background(), target, M2CompileOptions{}, 2)
		if err == nil || !strings.Contains(err.Error(), "syntax error") {
			t.Fatalf("real nft parser did not reject the injected transaction: %v", err)
		}
		assertRecoveredNetwork(t, controller, network, target, base, state)
		saveRecoveryEvidence(t, "nft-reject", map[string]any{"status": "PASS", "error": err.Error(), "commands": ip.trace})
	})
	t.Run("persistent-restore-failure-and-restart", func(t *testing.T) {
		controller, network, ip, rules, state, base, target := recoveryFixture(t)
		ip.match, ip.armed, ip.denyBase = "route replace", true, true
		err := controller.ApplyRuntimePrepared(context.Background(), target, M2CompileOptions{}, 2)
		if err == nil || !controller.RecoveryPending() {
			t.Fatalf("unrestored target not retained for recovery: %v", err)
		}
		if _, err := os.Stat(state + ".activation"); err != nil {
			t.Fatal("failed recovery lost durable journal:", err)
		}
		trace := strings.Join(ip.trace, "\n")
		lastTarget := strings.LastIndex(trace, "-4 addr replace 192.0.2.3/24")
		firstRestore := strings.Index(trace, "-4 addr replace 192.0.2.2/24")
		// Baseline activation appears first; inspect only after the first failure.
		if at := strings.Index(trace, "-4 route replace 198.18.27.0/24"); at >= 0 {
			firstRestore = strings.Index(trace[at:], "-4 addr replace 192.0.2.2/24") + at
		}
		if lastTarget > firstRestore {
			t.Fatal("failed restoration reinstalled the interrupted target")
		}
		ip.denyBase = false
		restarted, restartErr := NewController(network, rules, &fakeForwarding{}, state)
		if restartErr != nil {
			t.Fatal(restartErr)
		}
		if !restarted.RecoveryPending() {
			t.Fatal("restart ignored retained activation journal")
		}
		if err := restarted.ApplyRuntimePrepared(context.Background(), base, M2CompileOptions{}, 1); err != nil {
			t.Fatal(err)
		}
		if err := restarted.FinalizeActivation(context.Background(), base, 1); err != nil {
			t.Fatal(err)
		}
		assertRecoveredNetwork(t, restarted, network, target, base, state)
		saveRecoveryEvidence(t, "persistent-failure-restart", map[string]any{"status": "PASS", "initial_error": err.Error(), "journal_retained_until_recovery": true, "commands": ip.trace})
	})
}

func TestLinuxNetworkRecoveryPendingJournal(t *testing.T) {
	requireNetworkRecoveryNamespace(t)
	for _, scenario := range []string{"replay-journaled-target", "new-target-until-recovered"} {
		t.Run(scenario, func(t *testing.T) {
			controller, network, ip, rules, state, base, target := recoveryFixture(t)
			if err := controller.ApplyRuntimePrepared(context.Background(), target, M2CompileOptions{}, 2); err != nil {
				t.Fatal(err)
			}
			// Real prepared target/journal, followed by the kernel-only part of
			// compensation: simulate termination before its journal was removed.
			if err := network.Restore(context.Background(), target, base); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewController(network, rules, &fakeForwarding{}, state)
			if err != nil || !restarted.RecoveryPending() {
				t.Fatalf("interrupted compensation journal missing: %v", err)
			}
			if scenario == "replay-journaled-target" {
				if err := restarted.ApplyRuntimePrepared(context.Background(), target, M2CompileOptions{}, 2); err != nil {
					t.Fatal(err)
				}
				if err := restarted.FinalizeActivation(context.Background(), target, 2); err != nil {
					t.Fatal(err)
				}
				if err := network.VerifyTransition(context.Background(), base, target); err != nil {
					t.Fatal("replaying journaled target retained previous kernel objects:", err)
				}
			} else {
				newTarget := cloneNetworkTestConfig(t, base)
				newTarget.Interfaces[0].IPv4Addresses = []string{"192.0.2.4/24"}
				newTarget.Interfaces[0].IPv6Addresses = []string{"2001:db8:27::4/64"}
				before, err := os.ReadFile(state + ".activation")
				if err != nil {
					t.Fatal(err)
				}
				if err := restarted.ApplyRuntimePrepared(context.Background(), newTarget, M2CompileOptions{}, 3); !errors.Is(err, ErrActivationRecoveryPending) {
					t.Fatal("unrelated target did not report pending recovery before mutation:", err)
				}
				after, err := os.ReadFile(state + ".activation")
				if err != nil || string(before) != string(after) {
					t.Fatal("rejected new target replaced the original recovery journal")
				}
				if err := network.VerifyTransition(context.Background(), target, base); err != nil {
					t.Fatal("rejected new target mutated the current network:", err)
				}
				if err := restarted.ApplyRuntimePrepared(context.Background(), base, M2CompileOptions{}, 1); err != nil {
					t.Fatal(err)
				}
				if err := restarted.FinalizeActivation(context.Background(), base, 1); err != nil {
					t.Fatal(err)
				}
				if err := restarted.ApplyRuntimePrepared(context.Background(), newTarget, M2CompileOptions{}, 2); err != nil {
					t.Fatal("new activation remained blocked after recovery:", err)
				}
				if err := restarted.FinalizeActivation(context.Background(), newTarget, 2); err != nil {
					t.Fatal(err)
				}
				if err := network.VerifyTransition(context.Background(), base, newTarget); err != nil {
					t.Fatal(err)
				}
			}
			saveRecoveryEvidence(t, scenario, map[string]any{"status": "PASS", "commands": ip.trace, "addresses": networkRecoveryCommand(t, "ip", "-json", "address", "show")})
		})
	}
}
