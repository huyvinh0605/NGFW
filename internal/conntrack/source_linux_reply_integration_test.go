//go:build linux

package conntrack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestLinuxSourceReplyLookupFollowsDNAT(t *testing.T) {
	if os.Getenv("NGFW_CONNTRACK_REPLY_TEST") != "1" {
		t.Skip("requires explicit isolated network namespace run")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || initial == current {
		t.Fatal("reply lookup test must run in an isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "replace", "198.51.100.3/32", "dev", "lo"}} {
		if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("namespace setup: %s %v", output, err)
		}
	}
	server, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	port := server.Addr().(*net.TCPAddr).Port
	rules := fmt.Sprintf("table ip ngfw_reply_lookup_test {\n chain output {\n type nat hook output priority dstnat; policy accept;\n ip daddr 198.51.100.3 tcp dport 8443 dnat to 127.0.0.1:%d;\n }\n}\n", port)
	command := exec.CommandContext(ctx, "nft", "-f", "-")
	command.Stdin = strings.NewReader(rules)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("namespace DNAT: %s %v", output, err)
	}
	defer exec.Command("nft", "delete", "table", "ip", "ngfw_reply_lookup_test").Run()
	source, err := NewLinuxSource("reply-test")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, zone := range []uint16{0, 1} {
		if zone == 1 {
			command := exec.CommandContext(ctx, "nft", "-f", "-")
			command.Stdin = strings.NewReader("table inet ngfw_reply_zone_test {\n chain output {\n type filter hook output priority raw; policy accept;\n ct zone set 1;\n }\n chain prerouting {\n type filter hook prerouting priority raw; policy accept;\n ct zone set 1;\n }\n}\n")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("namespace zone: %s %v", output, err)
			}
			defer exec.Command("nft", "delete", "table", "inet", "ngfw_reply_zone_test").Run()
		}
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
		client, err := dialer.DialContext(ctx, "tcp4", "198.51.100.3:8443")
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		reply := domain.Tuple{Family: domain.FamilyIPv4, Protocol: 6,
			SrcIP: netip.MustParseAddr("127.0.0.1"), SrcPort: uint16(port),
			DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(client.LocalAddr().(*net.TCPAddr).Port)}
		got, err := source.LookupReply(ctx, reply, zone)
		if err != nil || got.Identity.ID == 0 || got.Identity.Zone != zone || got.Identity.Original.DstIP != netip.MustParseAddr("198.51.100.3") || got.Identity.Original.DstPort != 8443 || got.ReplyTuple == nil || *got.ReplyTuple != reply {
			t.Fatalf("DNAT reply did not identify the original kernel flow: %+v %v", got, err)
		}
		byOriginal, err := source.Get(ctx, Identity(got.Identity))
		if err != nil || byOriginal.Identity != got.Identity {
			t.Fatalf("original/reply incarnation mismatch: %+v %v", byOriginal.Identity, err)
		}
		if _, err := source.LookupReply(ctx, reply, zone^1); !errors.Is(err, ErrFlowNotFound) {
			t.Fatalf("cross-zone lookup was not absent: %v", err)
		}
		t.Logf("real DNAT zone %d CT ID %d: %s -> reply %s", zone, got.Identity.ID, got.Identity.Original, reply)
	}
}
