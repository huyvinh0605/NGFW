package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const forwardingSysctl = "net.ipv4.ip_forward = 1\n"

type ConntrackSysctl struct {
	Name        string
	RuntimePath string
}

type ForwardingEnsurer interface {
	Ensure(context.Context) error
}

// SysctlForwarding enables forwarding immediately through procfs and writes a
// sysctl.d fragment so the setting survives a reboot. Both files are read back
// before an apply is considered successful.
type SysctlForwarding struct {
	RuntimePath       string
	PersistPath       string
	ConntrackSettings []ConntrackSysctl
	ConntrackPersist  string
}

func NewSysctlForwarding() *SysctlForwarding {
	return &SysctlForwarding{
		RuntimePath: "/proc/sys/net/ipv4/ip_forward",
		PersistPath: "/etc/sysctl.d/90-ngfw-ip-forward.conf",
		ConntrackSettings: []ConntrackSysctl{
			{Name: "net.netfilter.nf_conntrack_acct", RuntimePath: "/proc/sys/net/netfilter/nf_conntrack_acct"},
			{Name: "net.netfilter.nf_conntrack_events", RuntimePath: "/proc/sys/net/netfilter/nf_conntrack_events"},
			{Name: "net.netfilter.nf_conntrack_timestamp", RuntimePath: "/proc/sys/net/netfilter/nf_conntrack_timestamp"},
		},
		ConntrackPersist: "/etc/sysctl.d/91-ngfw-conntrack.conf",
	}
}

func (s *SysctlForwarding) Ensure(ctx context.Context) error {
	if s == nil || s.RuntimePath == "" || s.PersistPath == "" {
		return errors.New("IPv4 forwarding paths are not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.PersistPath), 0755); err != nil {
		return fmt.Errorf("create sysctl.d directory: %w", err)
	}
	current, err := os.ReadFile(s.PersistPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read persistent IPv4 forwarding setting: %w", err)
	}
	if string(current) != forwardingSysctl {
		if err := writeAtomic(s.PersistPath, []byte(forwardingSysctl), 0644); err != nil {
			return fmt.Errorf("persist IPv4 forwarding setting: %w", err)
		}
	}
	if err := os.WriteFile(s.RuntimePath, []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("enable runtime IPv4 forwarding: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtimeValue, err := os.ReadFile(s.RuntimePath)
	if err != nil {
		return fmt.Errorf("verify runtime IPv4 forwarding: %w", err)
	}
	if strings.TrimSpace(string(runtimeValue)) != "1" {
		return fmt.Errorf("verify runtime IPv4 forwarding: got %q", strings.TrimSpace(string(runtimeValue)))
	}
	persisted, err := os.ReadFile(s.PersistPath)
	if err != nil {
		return fmt.Errorf("verify persistent IPv4 forwarding: %w", err)
	}
	if !hasEnabledForwarding(string(persisted)) {
		return errors.New("verify persistent IPv4 forwarding: setting is not enabled")
	}
	return nil
}

// EnsureConntrack enables the accounting, event and timestamp knobs used by
// the M2 adapter. It is intentionally separate from Ensure: a kernel without
// one of these optional conntrack sysctls can still forward traffic under M1,
// while the engine reports degraded tracking and continues with available
// metadata.
func (s *SysctlForwarding) EnsureConntrack(ctx context.Context) error {
	if s == nil || len(s.ConntrackSettings) == 0 {
		return nil
	}
	if s.ConntrackPersist == "" {
		return errors.New("conntrack sysctl persistence path is not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.ConntrackPersist), 0755); err != nil {
		return fmt.Errorf("create conntrack sysctl.d directory: %w", err)
	}
	var persisted strings.Builder
	for _, setting := range s.ConntrackSettings {
		if strings.TrimSpace(setting.Name) == "" || setting.RuntimePath == "" {
			return errors.New("conntrack sysctl setting is incomplete")
		}
		persisted.WriteString(setting.Name)
		persisted.WriteString(" = 1\n")
	}
	if err := writeAtomic(s.ConntrackPersist, []byte(persisted.String()), 0644); err != nil {
		return fmt.Errorf("persist conntrack settings: %w", err)
	}
	var unavailable []string
	for _, setting := range s.ConntrackSettings {
		if err := os.WriteFile(setting.RuntimePath, []byte("1\n"), 0644); err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				unavailable = append(unavailable, setting.Name)
				continue
			}
			return fmt.Errorf("enable %s: %w", setting.Name, err)
		}
		value, err := os.ReadFile(setting.RuntimePath)
		if err != nil {
			return fmt.Errorf("verify %s: %w", setting.Name, err)
		}
		if strings.TrimSpace(string(value)) != "1" {
			return fmt.Errorf("verify %s: got %q", setting.Name, strings.TrimSpace(string(value)))
		}
	}
	if len(unavailable) > 0 {
		return fmt.Errorf("conntrack sysctls unavailable: %s", strings.Join(unavailable, ", "))
	}
	return nil
}

func hasEnabledForwarding(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "net.ipv4.ip_forward" && strings.TrimSpace(parts[1]) == "1" {
			return true
		}
	}
	return false
}

func writeAtomic(path string, payload []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".ngfw-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		// Windows cannot replace an existing file with Rename. The appliance
		// path is Linux, while this fallback keeps unit tests portable.
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return err
		}
		if retryErr := os.Rename(temporaryName, path); retryErr != nil {
			return retryErr
		}
	}
	if directory, err := os.Open(filepath.Dir(path)); err == nil {
		syncErr := directory.Sync()
		_ = directory.Close()
		if syncErr != nil && runtime.GOOS != "windows" {
			return syncErr
		}
	}
	return nil
}
