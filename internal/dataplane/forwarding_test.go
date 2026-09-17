package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSysctlForwardingPersistsEnablesAndVerifies(t *testing.T) {
	directory := t.TempDir()
	runtimePath := filepath.Join(directory, "proc", "ip_forward")
	persistPath := filepath.Join(directory, "sysctl.d", "90-ngfw-ip-forward.conf")
	if err := os.MkdirAll(filepath.Dir(runtimePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimePath, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	manager := &SysctlForwarding{RuntimePath: runtimePath, PersistPath: persistPath}
	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	runtimeValue, _ := os.ReadFile(runtimePath)
	persisted, _ := os.ReadFile(persistPath)
	if string(runtimeValue) != "1\n" {
		t.Fatalf("runtime forwarding=%q", runtimeValue)
	}
	if !hasEnabledForwarding(string(persisted)) {
		t.Fatalf("persistent forwarding is not enabled: %q", persisted)
	}
	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure is not idempotent: %v", err)
	}
}

func TestSysctlForwardingHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := &SysctlForwarding{RuntimePath: filepath.Join(t.TempDir(), "runtime"), PersistPath: filepath.Join(t.TempDir(), "persist")}
	if err := manager.Ensure(ctx); err == nil {
		t.Fatal("expected canceled context")
	}
}

func TestSysctlForwardingConntrackSettings(t *testing.T) {
	directory := t.TempDir()
	settings := []ConntrackSysctl{
		{Name: "net.netfilter.nf_conntrack_acct", RuntimePath: filepath.Join(directory, "acct")},
		{Name: "net.netfilter.nf_conntrack_events", RuntimePath: filepath.Join(directory, "events")},
	}
	manager := &SysctlForwarding{ConntrackSettings: settings, ConntrackPersist: filepath.Join(directory, "sysctl.d", "conntrack.conf")}
	for _, setting := range settings {
		if err := os.MkdirAll(filepath.Dir(setting.RuntimePath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(setting.RuntimePath, []byte("0\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.EnsureConntrack(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, setting := range settings {
		value, err := os.ReadFile(setting.RuntimePath)
		if err != nil || string(value) != "1\n" {
			t.Fatalf("%s runtime=%q err=%v", setting.Name, value, err)
		}
	}
}
