//go:build linux

package conntrack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/mdlayher/netlink"
	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

type LinuxSource struct {
	mu        sync.Mutex
	events    *ct.Conn
	dump      *ct.Conn
	networkNS string
	bootID    string
	closed    bool
}

func NewLinuxSource(networkNS string) (*LinuxSource, error) {
	// Keep event and dump sockets separate so a slow bounded dump cannot stop
	// multicast delivery. The library owns the netlink framing and decoder; no
	// conntrack command output is parsed here.
	events, err := ct.Dial(&netlink.Config{Strict: true})
	if err != nil {
		return nil, fmt.Errorf("dial conntrack event socket: %w", err)
	}
	dump, err := ct.Dial(&netlink.Config{Strict: true})
	if err != nil {
		_ = events.Close()
		return nil, fmt.Errorf("dial conntrack dump socket: %w", err)
	}
	bootID := "unknown-boot"
	if value, readErr := os.ReadFile("/proc/sys/kernel/random/boot_id"); readErr == nil && strings.TrimSpace(string(value)) != "" {
		bootID = strings.TrimSpace(string(value))
	}
	return &LinuxSource{events: events, dump: dump, networkNS: networkNS, bootID: bootID}, nil
}

func (s *LinuxSource) Subscribe(ctx context.Context, sink EventSink) error {
	if sink == nil {
		return errors.New("nil event sink")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSourceClosed
	}
	conn := s.events
	s.mu.Unlock()
	channel := make(chan ct.Event, 1024)
	errCh, err := conn.Listen(channel, 1, netfilter.GroupsCT)
	if err != nil {
		return fmt.Errorf("listen conntrack events: %w", err)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-channel:
				if !ok {
					return
				}
				if ev.Flow == nil {
					continue
				}
				converted, convertErr := recordFromFlow(*ev.Flow, s.networkNS, s.bootID)
				if convertErr != nil {
					sink.ReportLoss(Loss{Reason: convertErr.Error(), Count: 1, At: time.Now().UTC()})
					continue
				}
				kind := EventUpdate
				switch ev.Type {
				case ct.EventNew:
					kind = EventNew
				case ct.EventDestroy:
					kind = EventDestroy
				}
				if !sink.TryEnqueue(Event{Kind: kind, Record: converted, Received: time.Now().UTC()}) {
					sink.ReportLoss(Loss{Reason: "event sink queue full", Count: 1, At: time.Now().UTC()})
				}
			case err := <-errCh:
				if err != nil {
					sink.ReportLoss(Loss{Reason: err.Error(), Count: 1, At: time.Now().UTC()})
				}
				return
			}
		}
	}()
	return nil
}

func (s *LinuxSource) Dump(ctx context.Context, limits DumpLimits, visit func(Record) error) (DumpResult, error) {
	if visit == nil {
		return DumpResult{}, errors.New("nil dump visitor")
	}
	if limits.MaxRecords <= 0 {
		limits.MaxRecords = 200000
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = 64 << 20
	}
	if limits.Deadline <= 0 {
		limits.Deadline = 30 * time.Second
	}
	if err := ctx.Err(); err != nil {
		return DumpResult{Complete: false, Reason: err.Error()}, err
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, limits.Deadline)
	defer cancel()
	// ti-mo/conntrack exposes a typed dump; cap the number of decoded records
	// before handing them to the engine. The adapter never exposes its backing
	// slice, and a future raw-netlink transport can replace this implementation
	// without changing the Source contract.
	flows, err := s.dump.Dump(nil)
	if err != nil {
		return DumpResult{Complete: false, Reason: err.Error()}, err
	}
	result := DumpResult{Complete: true}
	for _, flow := range flows {
		select {
		case <-deadlineCtx.Done():
			result.Complete = false
			result.Reason = deadlineCtx.Err().Error()
			return result, ErrDumpIncomplete
		default:
		}
		if result.Records >= limits.MaxRecords {
			result.Complete = false
			result.Reason = "record limit"
			return result, ErrDumpIncomplete
		}
		record, convertErr := recordFromFlow(flow, s.networkNS, s.bootID)
		if convertErr != nil {
			result.Complete = false
			result.Reason = convertErr.Error()
			return result, convertErr
		}
		estimated := estimateRecordBytes(record)
		if result.Bytes+estimated > limits.MaxBytes {
			result.Complete = false
			result.Reason = "byte limit"
			return result, ErrDumpIncomplete
		}
		if err := visit(record); err != nil {
			result.Complete = false
			result.Reason = err.Error()
			return result, err
		}
		result.Records++
		result.Bytes += estimated
	}
	return result, nil
}

func (s *LinuxSource) Get(ctx context.Context, id Identity) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	// The high-level library requires a complete flow tuple for Get. Use a
	// bounded dump and exact identity match; this is intentionally slower than
	// packet forwarding and is only used to verify stale tracking entries.
	var found *Record
	_, err := s.Dump(ctx, DumpLimits{MaxRecords: 200000, MaxBytes: 64 << 20, Deadline: time.Second}, func(r Record) error {
		if sameIdentity(r.Identity, domain.ConntrackIdentity{BootID: id.BootID, NetworkNS: id.NetworkNS, Zone: id.Zone, Family: id.Family, ID: id.ID, KernelStart: id.KernelStart, Original: id.Original}) {
			copy := r
			found = &copy
		}
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	if found == nil {
		return Record{}, errors.New("conntrack record not found")
	}
	return *found, nil
}

func (s *LinuxSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	events, dump := s.events, s.dump
	s.mu.Unlock()
	var first error
	if events != nil {
		if err := events.Close(); err != nil {
			first = err
		}
	}
	if dump != nil {
		if err := dump.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func sameIdentity(a, b domain.ConntrackIdentity) bool {
	if a.BootID != "" && b.BootID != "" && a.BootID != b.BootID {
		return false
	}
	if a.NetworkNS != "" && b.NetworkNS != "" && a.NetworkNS != b.NetworkNS {
		return false
	}
	if a.ID != 0 && b.ID != 0 && a.ID != b.ID {
		return false
	}
	if a.KernelStart != 0 && b.KernelStart != 0 && a.KernelStart != b.KernelStart {
		return false
	}
	if a.Zone != b.Zone || a.Family != b.Family {
		return false
	}
	return a.Original == b.Original
}

func recordFromFlow(f ct.Flow, networkNS, bootID string) (Record, error) {
	o, err := tupleFromCT(f.TupleOrig)
	if err != nil {
		return Record{}, err
	}
	r, replyErr := tupleFromCT(f.TupleReply)
	var reply *domain.Tuple
	presence := Presence{OriginalTuple: true, ID: f.ID != 0, Mark: f.Mark != 0, Zone: f.Zone != 0, Counters: f.CountersOrig.Packets != 0 || f.CountersOrig.Bytes != 0 || f.CountersReply.Packets != 0 || f.CountersReply.Bytes != 0, Timeout: f.Timeout != 0, Timestamp: !f.Timestamp.Start.IsZero(), ProtoInfo: f.ProtoInfo.TCP != nil}
	if replyErr == nil && r.Valid() {
		reply = &r
		presence.ReplyTuple = true
	}
	identity := domain.ConntrackIdentity{BootID: bootID, NetworkNS: networkNS, Zone: f.Zone, Family: o.Family, ID: f.ID, Original: o}
	start := f.Timestamp.Start
	if !start.IsZero() {
		identity.KernelStart = uint64(start.UnixNano())
	}
	state := ""
	seenReply := f.Status.Value&ct.StatusSeenReply != 0
	if f.ProtoInfo.TCP != nil {
		state = tcpState(f.ProtoInfo.TCP.State)
	}
	return Record{Identity: identity, OriginalTuple: o, ReplyTuple: reply, PacketsOriginal: f.CountersOrig.Packets, BytesOriginal: f.CountersOrig.Bytes, PacketsReply: f.CountersReply.Packets, BytesReply: f.CountersReply.Bytes, Timeout: time.Duration(f.Timeout) * time.Second, KernelStart: start, TCPState: state, SeenReply: seenReply, Mark: f.Mark, Presence: presence, ObservedAt: time.Now().UTC()}, nil
}

func tupleFromCT(t ct.Tuple) (domain.Tuple, error) {
	family := domain.FamilyIPv4
	if t.IP.IsIPv6() {
		family = domain.FamilyIPv6
	}
	proto := t.Proto
	if proto.Protocol == 0 {
		return domain.Tuple{}, errors.New("conntrack tuple has no protocol")
	}
	tuple := domain.Tuple{Family: family, SrcIP: t.IP.SourceAddress, DstIP: t.IP.DestinationAddress, SrcPort: proto.SourcePort, DstPort: proto.DestinationPort, Protocol: proto.Protocol, ICMPID: proto.ICMPID, ICMPType: proto.ICMPType, ICMPCode: proto.ICMPCode}
	if !tuple.Valid() {
		return domain.Tuple{}, errors.New("invalid conntrack tuple")
	}
	return tuple, nil
}

func tcpState(value uint8) string {
	states := [...]string{"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN", "CLOSE"}
	if int(value) < len(states) {
		return states[value]
	}
	return fmt.Sprintf("TCP_%d", value)
}
