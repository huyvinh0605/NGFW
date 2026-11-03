//go:build linux

package dataplane

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

// Opt-in, real nft/conntrack test in a disposable namespace. The host's NGFW
// tables, addresses, services and routes are never changed by this test.
func TestLinuxInspectionGuardExactIdentityAndLifecycle(t *testing.T) {
	if os.Getenv("NGFW_NFT_NETNS_TEST") != "1" {
		t.Skip("set NGFW_NFT_NETNS_TEST=1 on the Ubuntu lab as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ns := fmt.Sprintf("m4guard-%d", os.Getpid())
	command := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	command("ip", "netns", "add", ns)
	defer func() { _ = exec.Command("ip", "netns", "del", ns).Run() }()
	command("ip", "-n", ns, "link", "set", "lo", "up")
	wrapper := filepath.Join(t.TempDir(), "nft-in-namespace")
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec ip netns exec "+ns+" "+nft+" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runner := NewNftRunner(wrapper)
	if err := runner.EnsureInspectionSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.ApplyInspectionMutation(ctx, "add chain inet ngfw_inspection test_output { type filter hook output priority 0; policy accept; }\nadd rule inet ngfw_inspection test_output meta l4proto { tcp, udp } ct id vmap @app_denied_v4\n"); err != nil {
		t.Fatal(err)
	}
	start := func(source string) (*exec.Cmd, io.WriteCloser, *bufio.Scanner) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "python3", "-u", "-c", source)
		in, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd, in, bufio.NewScanner(out)
	}
	_, _, server := start("import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('127.0.0.1',18888))\nprint('READY')\nwhile True:\n data,addr=s.recvfrom(256)\n s.sendto(data,addr)\n")
	if !server.Scan() || server.Text() != "READY" {
		t.Fatal("origin did not start")
	}
	_, clientIn, client := start("import socket,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(('127.0.0.1',0))\ns.connect(('127.0.0.1',18888))\ns.settimeout(.25)\nprint(s.getsockname()[1])\nfor line in sys.stdin:\n try:\n  s.send(line.strip().encode())\n  print('ECHO:'+s.recv(256).decode())\n except (socket.timeout,PermissionError):\n  print('BLOCKED')\n")
	if !client.Scan() {
		t.Fatal("client did not start")
	}
	port, err := strconv.ParseUint(client.Text(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	probe := func(label string, allow bool) {
		t.Helper()
		if _, err := fmt.Fprintln(clientIn, label); err != nil || !client.Scan() {
			t.Fatalf("probe %s failed: %v", label, err)
		}
		want := "BLOCKED"
		if allow {
			want = "ECHO:" + label
		}
		if client.Text() != want {
			t.Fatalf("%s: got %q, want %q", label, client.Text(), want)
		}
		t.Logf("%s: %s", label, want)
	}
	probe("baseline", true)
	ct := command("ip", "netns", "exec", ns, "conntrack", "-L", "-p", "udp", "--sport", strconv.FormatUint(port, 10), "--dport", "18888", "-o", "id")
	match := regexp.MustCompile(`\bid=(\d+)`).FindStringSubmatch(ct)
	if len(match) != 2 {
		t.Fatalf("missing real conntrack ID: %s", ct)
	}
	id, _ := strconv.ParseUint(match[1], 10, 32)
	key, err := BuildInspectionGuardKey(domain.ConntrackIdentity{ID: uint32(id), Original: domain.Tuple{
		Family: domain.FamilyIPv4, Protocol: 17, SrcIP: netip.MustParseAddr("127.0.0.1"), DstIP: netip.MustParseAddr("127.0.0.1"), SrcPort: uint16(port), DstPort: 18888}})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewInspectionGuardManager(runner, 8)
	wrongZone, wrongProtocol, wrongPort := key, key, key
	wrongZone.ConntrackZone = 2
	wrongProtocol.Original.Protocol = 6
	wrongPort.Original.DstPort++
	for _, other := range []InspectionGuardKey{wrongZone, wrongProtocol, wrongPort} {
		if err := manager.InstallAppGuard(ctx, other, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	probe("nonmatching-zone-protocol-port", true)
	if err := manager.InstallAppGuard(ctx, key, time.Minute); err != nil {
		t.Fatal(err)
	}
	probe("exact-identity-block", false)
	if err := manager.RenewAppGuard(ctx, key, time.Minute); err != nil {
		t.Fatal(err)
	}
	probe("renewed-identity-block", false)
	if err := manager.RemoveAppGuard(ctx, key); err != nil {
		t.Fatal(err)
	}
	probe("removed-identity-allows", true)
	if err := manager.InstallAppGuard(ctx, key, time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	probe("expired-element-allows", true)
	if err := manager.ClearOwned(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.InstallAppGuard(ctx, key, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := runner.ClearInspectionRuntimeState(ctx); err != nil {
		t.Fatal(err)
	}
	probe("startup-clear-allows", true)
	state := command("ip", "netns", "exec", ns, "nft", "-j", "list", "table", "inet", "ngfw_inspection")
	if strings.Contains(state, "app_guard_i") || strings.Contains(state, "app_denied_z") {
		t.Fatal("dynamic chains/sets leaked after startup clear")
	}
}
