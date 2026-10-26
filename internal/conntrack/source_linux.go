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
	"golang.org/x/sys/unix"
)

type LinuxSource struct {
	mu         sync.Mutex
	events     *netlink.Conn
	networkNS  string
	bootID     string
	closed     bool
	subscribed bool
}

func NewLinuxSource(networkNS string) (*LinuxSource, error) {
	// The multicast socket is never used for requests. Each dump/Get gets a
	// separate socket so an interrupted multipart reply cannot poison the next
	// request, and a slow dump cannot stop event reception.
	events, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Strict: true})
	if err != nil {
		return nil, fmt.Errorf("dial conntrack event socket: %w", err)
	}
	bootID := "unknown-boot"
	if value, readErr := os.ReadFile("/proc/sys/kernel/random/boot_id"); readErr == nil && strings.TrimSpace(string(value)) != "" {
		bootID = strings.TrimSpace(string(value))
	}
	return &LinuxSource{events: events, networkNS: networkNS, bootID: bootID}, nil
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
	if s.subscribed {
		s.mu.Unlock()
		return errors.New("conntrack source already subscribed")
	}
	conn := s.events
	for _, group := range []uint32{1, 2, 3} { // NFNLGRP_CONNTRACK_NEW/UPDATE/DESTROY
		if err := conn.JoinGroup(group); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("join conntrack event group %d: %w", group, err)
		}
	}
	s.subscribed = true
	s.mu.Unlock()
	go func() {
		buffer := make([]byte, maxConntrackDatagram)
		err := receiveConntrackEvents(ctx, s.networkNS, s.bootID, sink, func() ([]netlink.Message, error) {
			messages, _, err := readNetlinkDatagram(ctx, conn, buffer)
			return messages, err
		})
		if err != nil {
			// A permanently failed subscriber must not remain joined with an
			// unread receive queue. Runtime health retains the fatal loss.
			s.mu.Lock()
			closeSocket := s.events == conn
			if s.events == conn {
				s.events = nil
			}
			s.mu.Unlock()
			if closeSocket {
				_ = conn.Close()
			}
		}
	}()
	return nil
}

func receiveConntrackEvents(ctx context.Context, networkNS, bootID string, sink EventSink, read func() ([]netlink.Message, error)) error {
	for {
		messages, err := read()
		if ctx.Err() != nil {
			return nil
		}
		if isReadTimeout(err) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			// ENOBUFS reports lost multicast messages, not a broken socket.
			// A malformed/truncated datagram has also already been consumed.
			// Report the gap for resync and keep draining; otherwise one burst
			// (including events queued while a VM was suspended) permanently
			// stops NEW/UPDATE/DESTROY observation until engine restart.
			fatal := !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, ErrDumpIncomplete)
			sink.ReportLoss(Loss{Reason: err.Error(), Count: 1, At: time.Now().UTC(), Fatal: fatal})
			if fatal {
				return err
			}
			continue
		}
		for _, msg := range messages {
			if msg.Header.Type == netlink.Overrun || msg.Header.Type == netlink.Error {
				sink.ReportLoss(Loss{Reason: "conntrack event stream overrun/error", Count: 1, At: time.Now().UTC()})
				continue
			}
			record, kind, decodeErr := decodeConntrackMessage(msg, networkNS, bootID)
			if decodeErr != nil {
				sink.ReportLoss(Loss{Reason: decodeErr.Error(), Count: 1, At: time.Now().UTC()})
				continue
			}
			if !sink.TryEnqueue(Event{Kind: kind, Record: record, Received: time.Now().UTC()}) {
				sink.ReportLoss(Loss{Reason: "event sink queue full", Count: 1, At: time.Now().UTC()})
			}
		}
	}
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
	deadlineCtx, cancel := context.WithTimeout(ctx, limits.Deadline)
	defer cancel()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return DumpResult{Reason: ErrSourceClosed.Error()}, ErrSourceClosed
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Strict: true})
	if err != nil {
		return DumpResult{Complete: false, Reason: err.Error()}, err
	}
	defer conn.Close()
	return streamConntrackDump(deadlineCtx, conn, limits, s.networkNS, s.bootID, visit)
}

func (s *LinuxSource) Get(ctx context.Context, id Identity) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return Record{}, ErrSourceClosed
	}
	if (id.BootID != "" && id.BootID != s.bootID) || (id.NetworkNS != "" && id.NetworkNS != s.networkNS) ||
		!id.Original.Valid() || id.Original.Family != id.Family || id.ID == 0 && id.KernelStart == 0 {
		return Record{}, ErrAmbiguousIdentity
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Strict: true})
	if err != nil {
		return Record{}, err
	}
	defer conn.Close()
	return getConntrackFlow(ctx, conn, id, s.networkNS, s.bootID)
}

func (s *LinuxSource) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	events := s.events
	s.events = nil
	s.mu.Unlock()
	if events != nil {
		return events.Close()
	}
	return nil
}

func recordFromFlow(f ct.Flow, presence Presence, networkNS, bootID string) (Record, error) {
	o, err := tupleFromCT(f.TupleOrig)
	if err != nil {
		return Record{}, err
	}
	r, replyErr := tupleFromCT(f.TupleReply)
	var reply *domain.Tuple
	if presence.ReplyTuple && replyErr != nil {
		return Record{}, fmt.Errorf("invalid conntrack reply tuple: %w", replyErr)
	}
	if replyErr == nil && r.Valid() {
		reply = &r
	}
	zone := f.Zone
	if zone == 0 && f.TupleOrig.Zone != 0 {
		zone = f.TupleOrig.Zone
	}
	identity := domain.ConntrackIdentity{BootID: bootID, NetworkNS: networkNS, Zone: zone, Family: o.Family, ID: f.ID, Original: o}
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
