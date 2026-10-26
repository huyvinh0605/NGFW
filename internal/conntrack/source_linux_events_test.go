//go:build linux

package conntrack

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
)

type eventFunctionSink struct {
	event func(Event) bool
	loss  func(Loss)
}

func (s eventFunctionSink) TryEnqueue(value Event) bool { return s.event(value) }
func (s eventFunctionSink) ReportLoss(value Loss)       { s.loss(value) }

func TestEventReaderContinuesAfterRecoverableReceiveErrors(t *testing.T) {
	tuple := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.10"),
		DstIP: netip.MustParseAddr("198.51.100.20"), SrcPort: 40000, DstPort: 443, Protocol: 6}
	attribute, _, err := tupleQueryAttribute(tuple, 0)
	if err != nil {
		t.Fatal(err)
	}
	message, err := netfilter.MarshalNetlink(netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink, MessageType: 0,
		Family: netfilter.ProtoIPv4, Flags: netlink.Create | netlink.Excl,
	}, []netfilter.Attribute{attribute, {Type: 12, Data: netfilter.Uint32Bytes(123)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		err  error
		loss bool
	}{
		{"overflow", unix.ENOBUFS, true},
		{"wrapped overflow", fmt.Errorf("receive: %w", unix.ENOBUFS), true},
		{"consumed bad datagram", fmt.Errorf("%w: truncated", ErrDumpIncomplete), true},
		{"interrupted syscall", unix.EINTR, false},
		{"read timeout", os.ErrDeadlineExceeded, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var reads, received int
			var losses []Loss
			sink := eventFunctionSink{
				event: func(event Event) bool {
					received++
					if event.Kind != EventNew || event.Record.Identity.ID != 123 {
						t.Errorf("unexpected event after receive gap: %+v", event)
					}
					cancel()
					return true
				},
				loss: func(loss Loss) { losses = append(losses, loss) },
			}
			err := receiveConntrackEvents(ctx, "init", "boot", sink, func() ([]netlink.Message, error) {
				reads++
				if reads == 1 {
					return nil, test.err
				}
				return []netlink.Message{message}, nil
			})
			if err != nil || received != 1 {
				t.Fatalf("event reader did not recover: received=%d err=%v", received, err)
			}
			if test.loss {
				if len(losses) != 1 || losses[0].Fatal || losses[0].Count != 1 {
					t.Fatalf("recoverable gap must request resync without killing subscription: %+v", losses)
				}
			} else if len(losses) != 0 {
				t.Fatalf("non-consuming interruption reported data loss: %+v", losses)
			}
		})
	}
}

func TestEventReaderReportsPermanentFailureAndCancellation(t *testing.T) {
	var losses []Loss
	sink := eventFunctionSink{event: func(Event) bool { return true },
		loss: func(loss Loss) { losses = append(losses, loss) }}
	err := receiveConntrackEvents(context.Background(), "init", "boot", sink,
		func() ([]netlink.Message, error) { return nil, unix.EBADF })
	if !errors.Is(err, unix.EBADF) || len(losses) != 1 || !losses[0].Fatal {
		t.Fatalf("permanent receive failure was hidden: err=%v losses=%+v", err, losses)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	losses = nil
	err = receiveConntrackEvents(ctx, "init", "boot", sink,
		func() ([]netlink.Message, error) { return nil, ctx.Err() })
	if err != nil || len(losses) != 0 {
		t.Fatalf("normal cancellation reported fatal loss: err=%v losses=%+v", err, losses)
	}
}
