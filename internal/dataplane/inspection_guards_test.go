package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type fakeInspectionNft struct {
	mu       sync.Mutex
	scripts  []string
	contains bool
	err      error
	applyErr error
	readErr  error
}

func (f *fakeInspectionNft) ApplyInspectionMutation(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, s)
	if f.applyErr != nil {
		return f.applyErr
	}
	return f.err
}
func (f *fakeInspectionNft) InspectionSetContains(_ context.Context, _, _ string) (bool, error) {
	if f.readErr != nil {
		return f.contains, f.readErr
	}
	return f.contains, f.err
}

func guardIdentity() domain.ConntrackIdentity {
	return domain.ConntrackIdentity{Zone: 2, ID: 99, Original: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.168.10.10"), SrcPort: 50000, DstIP: netip.MustParseAddr("203.0.113.10"), DstPort: 443, Protocol: 6}}
}
func TestInspectionGuardUsesQualifiedFullIdentity(t *testing.T) {
	fake := &fakeInspectionNft{contains: true}
	manager := NewInspectionGuardManager(fake, 10)
	key, err := BuildInspectionGuardKey(guardIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.InstallAppGuard(context.Background(), key, time.Minute); err != nil {
		t.Fatal(err)
	}
	script := fake.scripts[0]
	for _, want := range []string{"2 . 99", "192.168.10.10 . 50000", "203.0.113.10 . 443", "tcp", "timeout 60s"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
}
func TestGuardDoesNotReportAppliedWithoutReadback(t *testing.T) {
	manager := NewInspectionGuardManager(&fakeInspectionNft{contains: false}, 10)
	result, err := manager.ExecuteInspectionIntent(context.Background(), domain.InspectionIntent{Kind: domain.IntentInstallAppGuard, Identity: guardIdentity(), RequestedAction: domain.DecisionDrop})
	if err == nil || result.Status == domain.EnforcementApplied {
		t.Fatalf("false apply result: %#v %v", result, err)
	}
}
func TestGuardRenewalRefreshesTimeoutInOneNftTransaction(t *testing.T) {
	fake := &fakeInspectionNft{contains: true}
	manager := NewInspectionGuardManager(fake, 10)
	key, err := BuildInspectionGuardKey(guardIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RenewAppGuard(context.Background(), key, time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(fake.scripts) != 1 || !strings.Contains(fake.scripts[0], "delete element") || !strings.Contains(fake.scripts[0], "add element") || !strings.Contains(fake.scripts[0], "timeout 60s") {
		t.Fatalf("renewal was not an atomic delete+add batch: %#v", fake.scripts)
	}
}
func TestLeaseUsesTimeoutAndCanBeStopped(t *testing.T) {
	fake := &fakeInspectionNft{}
	if err := RenewIPSLease(context.Background(), fake, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := StopIPSLease(context.Background(), fake); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.scripts, "\n")
	if !strings.HasPrefix(fake.scripts[0], "flush set inet ngfw_inspection ips_ready") || !strings.Contains(joined, "ipv4 . tcp timeout 3s") || !strings.Contains(joined, "flush set inet ngfw_inspection ips_ready") {
		t.Fatalf("lease scripts wrong: %s", joined)
	}
}

func TestInspectionGuardInstallIsIdempotentAfterExactReadback(t *testing.T) {
	fake := &fakeInspectionNft{contains: true, applyErr: errors.New("element already exists")}
	manager := NewInspectionGuardManager(fake, 1)
	key, err := BuildInspectionGuardKey(guardIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.InstallAppGuard(context.Background(), key, time.Minute); err != nil {
		t.Fatalf("exact existing guard was not idempotent: %v", err)
	}
}

func TestInspectionGuardCapacityRemainsBoundedDuringConcurrentInstalls(t *testing.T) {
	fake := &fakeInspectionNft{contains: true}
	manager := NewInspectionGuardManager(fake, 1)
	identities := []domain.ConntrackIdentity{guardIdentity(), guardIdentity()}
	identities[1].ID++
	identities[1].Original.SrcPort++
	var wg sync.WaitGroup
	results := make(chan error, len(identities))
	for _, identity := range identities {
		key, err := BuildInspectionGuardKey(identity)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() { defer wg.Done(); results <- manager.InstallAppGuard(context.Background(), key, time.Minute) }()
	}
	wg.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful installs=%d want=1", successes)
	}
}

func TestIPSLeaseStateExpiresAndStopsWhenCaptureIsNotLive(t *testing.T) {
	fake := &fakeInspectionNft{}
	manager := NewIPSLeaseManager(fake)
	now := time.Unix(100, 0).UTC()
	manager.tick(context.Background(), now, true)
	if !manager.StateAt(now.Add(2 * time.Second)).Active {
		t.Fatal("fresh lease reported inactive")
	}
	stale := manager.StateAt(now.Add(4 * time.Second))
	if stale.Active || !strings.Contains(stale.LastError, "stale") {
		t.Fatalf("expired lease state=%#v", stale)
	}
	manager.tick(context.Background(), now.Add(5*time.Second), false)
	if manager.StateAt(now.Add(5*time.Second)).Active || !strings.Contains(fake.scripts[len(fake.scripts)-1], "flush set") {
		t.Fatal("non-live capture did not remove lease")
	}
}
