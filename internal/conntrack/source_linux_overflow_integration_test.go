//go:build linux

package conntrack

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type overflowSink struct {
	first   chan struct{}
	resume  chan struct{}
	events  chan Event
	losses  chan Loss
	pause   sync.Once
	release sync.Once
}

func (s *overflowSink) TryEnqueue(event Event) bool {
	s.pause.Do(func() { close(s.first); <-s.resume })
	select {
	case s.events <- event:
		return true
	default:
		return false
	}
}

func (s *overflowSink) ReportLoss(loss Loss) {
	select {
	case s.losses <- loss:
	default:
	}
}

func (s *overflowSink) unblock() { s.release.Do(func() { close(s.resume) }) }

func socketDrops(conn *netlink.Conn) (uint64, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid uint32
	var inner error
	if err := raw.Control(func(fd uintptr) {
		address, err := unix.Getsockname(int(fd))
		if err != nil {
			inner = err
			return
		}
		pid = address.(*unix.SockaddrNetlink).Pid
	}); err != nil {
		return 0, err
	}
	if inner != nil {
		return 0, inner
	}
	data, err := os.ReadFile("/proc/net/netlink")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[1] == "12" && fields[2] == strconv.FormatUint(uint64(pid), 10) {
			return strconv.ParseUint(fields[8], 10, 64)
		}
	}
	return 0, fmt.Errorf("NETLINK_NETFILTER socket pid %d not found", pid)
}

func TestLinuxSourceRecoversAfterReceiveOverflow(t *testing.T) {
	if os.Getenv("NGFW_CONNTRACK_OVERFLOW_TEST") != "1" {
		t.Skip("requires explicit isolated network namespace run")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil || initial == current {
		t.Fatal("overflow test must run in an isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	source, err := NewLinuxSource("overflow-test")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.events.SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	sink := &overflowSink{first: make(chan struct{}), resume: make(chan struct{}),
		events: make(chan Event, 4096), losses: make(chan Loss, 32)}
	defer sink.unblock()
	if err := source.Subscribe(ctx, sink); err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 64)
		for {
			if _, _, err := server.ReadFromUDP(buffer); err != nil {
				return
			}
		}
	}()
	send := func(port int) {
		t.Helper()
		conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, server.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		_, err = conn.Write([]byte("ngfw-isolated-overflow-test"))
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	send(30001)
	select {
	case <-sink.first:
	case <-ctx.Done():
		t.Fatal("did not receive the first real conntrack event")
	}
	for port := 31000; port < 31512; port++ {
		send(port)
	}
	drops, err := socketDrops(source.events)
	if err != nil || drops == 0 {
		t.Fatalf("test did not actually overflow the kernel receive queue: drops=%d err=%v", drops, err)
	}
	t.Logf("real kernel multicast drops while receiver paused: %d", drops)
	sink.unblock()
	select {
	case loss := <-sink.losses:
		if loss.Fatal {
			t.Fatalf("receive overflow incorrectly killed the subscriber: %+v", loss)
		}
		t.Logf("recoverable loss reported: %+v", loss)
	case <-ctx.Done():
		t.Fatal("kernel loss was not reported")
	}
	// This flow is created after the overflow, on the same live subscription.
	send(32001)
	var marker Record
	waiting := true
	for waiting {
		select {
		case event := <-sink.events:
			if event.Record.OriginalTuple.SrcPort == 32001 {
				marker = event.Record
				waiting = false
			}
		case loss := <-sink.losses:
			if loss.Fatal {
				t.Fatalf("subscriber failed while recovering: %+v", loss)
			}
		case <-ctx.Done():
			t.Fatal("NEW event after overflow never reached the same subscriber")
		}
	}
	t.Logf("new event after overflow observed, CT ID=%d", marker.Identity.ID)
	found := false
	result, err := source.Dump(ctx, DumpLimits{MaxRecords: 2048, MaxBytes: 8 << 20, Deadline: 3 * time.Second}, func(record Record) error {
		if record.Identity == marker.Identity {
			found = true
		}
		return nil
	})
	if err != nil || !result.Complete || !found {
		t.Fatalf("resync after overflow incomplete: result=%+v found=%v err=%v", result, found, err)
	}
	t.Logf("complete post-loss dump: %d flows", result.Records)
}
