//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/mdlayher/netlink"
	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
)

// A datagram is bounded before any conntrack records are decoded. The kernel
// may send multiple nlmsghdrs in one datagram, but never a partial record that
// we can safely use for negative reconciliation.
const maxConntrackDatagram = 64 << 10
const netlinkPollInterval = 250 * time.Millisecond

func isReadTimeout(err error) bool {
	var timeout net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout()
}

// Callers own one receive buffer per socket and finish decoding before reuse.
func readNetlinkDatagram(ctx context.Context, conn *netlink.Conn, buffer []byte) ([]netlink.Message, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	deadline := time.Now().Add(netlinkPollInterval)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, 0, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var n, flags int
	var from unix.Sockaddr
	var recvErr error
	err = raw.Read(func(fd uintptr) bool {
		n, _, flags, from, recvErr = unix.Recvmsg(int(fd), buffer, nil, unix.MSG_DONTWAIT)
		return !errors.Is(recvErr, unix.EAGAIN) && !errors.Is(recvErr, unix.EWOULDBLOCK)
	})
	if err != nil {
		return nil, 0, err
	}
	if recvErr != nil {
		return nil, 0, recvErr
	}
	if flags&unix.MSG_TRUNC != 0 {
		return nil, 0, fmt.Errorf("%w: truncated netlink datagram", ErrDumpIncomplete)
	}
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok || sender.Pid != 0 {
		return nil, 0, fmt.Errorf("%w: non-kernel netlink sender", ErrDumpIncomplete)
	}
	if n <= 0 {
		return nil, 0, fmt.Errorf("%w: empty netlink datagram", ErrDumpIncomplete)
	}
	rawMessages, err := syscall.ParseNetlinkMessage(buffer[:n])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: malformed netlink datagram: %v", ErrDumpIncomplete, err)
	}
	messages := make([]netlink.Message, 0, len(rawMessages))
	for _, value := range rawMessages {
		messages = append(messages, netlink.Message{
			Header: netlink.Header{
				Length:   value.Header.Len,
				Type:     netlink.HeaderType(value.Header.Type),
				Flags:    netlink.HeaderFlags(value.Header.Flags),
				Sequence: value.Header.Seq,
				PID:      value.Header.Pid,
			},
			Data: value.Data,
		})
	}
	return messages, n, nil
}

func decodeConntrackMessage(msg netlink.Message, networkNS, bootID string) (Record, EventKind, error) {
	header, attrs, err := netfilter.UnmarshalNetlink(msg)
	if err != nil {
		return Record{}, "", err
	}
	if header.SubsystemID != netfilter.NFSubsysCTNetlink {
		return Record{}, "", fmt.Errorf("unexpected netfilter subsystem %d", header.SubsystemID)
	}
	if header.Family != netfilter.ProtoIPv4 && header.Family != netfilter.ProtoIPv6 {
		return Record{}, "", fmt.Errorf("unexpected conntrack family %d", header.Family)
	}
	var presence Presence
	var topZone, tupleZone *uint16
	for _, attr := range attrs {
		switch attr.Type {
		case 1: // CTA_TUPLE_ORIG
			presence.OriginalTuple = true
			for _, child := range attr.Children {
				if child.Type == 3 { // CTA_TUPLE_ZONE
					if len(child.Data) != 2 {
						return Record{}, "", errors.New("invalid conntrack tuple zone length")
					}
					zone := binary.BigEndian.Uint16(child.Data)
					tupleZone = &zone
					presence.Zone = true
				}
			}
		case 2: // CTA_TUPLE_REPLY
			presence.ReplyTuple = true
		case 4: // CTA_PROTOINFO
			presence.ProtoInfo = true
		case 7: // CTA_TIMEOUT
			presence.Timeout = true
		case 8: // CTA_MARK
			presence.Mark = true
		case 9: // CTA_COUNTERS_ORIG
			presence.CountersOriginal = true
		case 10: // CTA_COUNTERS_REPLY
			presence.CountersReply = true
		case 12: // CTA_ID
			presence.ID = true
		case 18: // CTA_ZONE
			if len(attr.Data) != 2 {
				return Record{}, "", errors.New("invalid conntrack zone length")
			}
			zone := binary.BigEndian.Uint16(attr.Data)
			topZone = &zone
			presence.Zone = true
		case 20: // CTA_TIMESTAMP
			presence.Timestamp = true
		}
	}
	presence.Counters = presence.CountersOriginal && presence.CountersReply
	if topZone != nil && tupleZone != nil && *topZone != *tupleZone {
		return Record{}, "", ErrAmbiguousIdentity
	}
	var event ct.Event
	if err := event.Unmarshal(msg); err != nil || event.Flow == nil {
		return Record{}, "", fmt.Errorf("decode conntrack flow: %v", err)
	}
	record, err := recordFromFlow(*event.Flow, presence, networkNS, bootID)
	if err != nil {
		return Record{}, "", err
	}
	if header.Family == netfilter.ProtoIPv4 && record.Identity.Family != domain.FamilyIPv4 ||
		header.Family == netfilter.ProtoIPv6 && record.Identity.Family != domain.FamilyIPv6 {
		return Record{}, "", errors.New("conntrack header/tuple family mismatch")
	}
	kind := EventUpdate
	switch event.Type {
	case ct.EventNew:
		kind = EventNew
	case ct.EventDestroy:
		kind = EventDestroy
	}
	return record, kind, nil
}

func netlinkStatus(data []byte) error {
	if len(data) == 0 {
		return nil // NLMSG_DONE without a status payload
	}
	if len(data) < 4 {
		return errors.New("short netlink status")
	}
	code := int32(binary.NativeEndian.Uint32(data[:4]))
	if code == 0 {
		return nil
	}
	if code > 0 {
		return fmt.Errorf("invalid positive netlink status %d", code)
	}
	return unix.Errno(-code)
}

func streamConntrackDump(ctx context.Context, conn *netlink.Conn, limits DumpLimits, networkNS, bootID string, visit func(Record) error) (DumpResult, error) {
	request, err := netfilter.MarshalNetlink(netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink,
		MessageType: 1, // IPCTNL_MSG_CT_GET
		Family:      netfilter.ProtoUnspec,
		Flags:       netlink.Request | netlink.Dump,
	}, nil)
	if err != nil {
		return DumpResult{Reason: err.Error()}, err
	}
	sent, err := conn.Send(request)
	if err != nil {
		return DumpResult{Reason: err.Error()}, err
	}
	result := DumpResult{}
	buffer := make([]byte, maxConntrackDatagram)
	fail := func(reason string, cause error) (DumpResult, error) {
		result.Reason = reason
		return result, cause
	}
	for {
		if err := ctx.Err(); err != nil {
			return fail(err.Error(), ErrDumpIncomplete)
		}
		messages, wireBytes, err := readNetlinkDatagram(ctx, conn, buffer)
		if isReadTimeout(err) && ctx.Err() == nil {
			continue
		}
		if err != nil {
			return fail(err.Error(), fmt.Errorf("%w: %v", ErrDumpIncomplete, err))
		}
		if result.Bytes+int64(wireBytes) > limits.MaxBytes {
			return fail("wire byte limit", ErrDumpIncomplete)
		}
		result.Bytes += int64(wireBytes)
		for _, msg := range messages {
			if msg.Header.Sequence != sent.Header.Sequence ||
				msg.Header.PID != 0 && msg.Header.PID != sent.Header.PID ||
				msg.Header.Flags&netlink.DumpInterrupted != 0 {
				return fail("sequence/PID mismatch or interrupted dump", ErrDumpIncomplete)
			}
			switch msg.Header.Type {
			case netlink.Done:
				if err := netlinkStatus(msg.Data); err != nil {
					return fail(err.Error(), ErrDumpIncomplete)
				}
				result.Complete = true
				return result, nil
			case netlink.Error:
				if err := netlinkStatus(msg.Data); err != nil {
					return fail(err.Error(), ErrDumpIncomplete)
				}
				continue
			case netlink.Overrun:
				return fail("netlink overrun", ErrDumpIncomplete)
			case netlink.Noop:
				continue
			}
			if result.Records >= limits.MaxRecords {
				return fail("record limit", ErrDumpIncomplete)
			}
			record, _, err := decodeConntrackMessage(msg, networkNS, bootID)
			if err != nil {
				return fail(err.Error(), fmt.Errorf("%w: %v", ErrDumpIncomplete, err))
			}
			if err := visit(record); err != nil {
				return fail(err.Error(), err)
			}
			result.Records++
		}
	}
}

func tupleQueryAttribute(tuple domain.Tuple, zone uint16) (netfilter.Attribute, netfilter.ProtoFamily, error) {
	if !tuple.Valid() {
		return netfilter.Attribute{}, 0, ErrAmbiguousIdentity
	}
	family := netfilter.ProtoIPv4
	ipSrcType, ipDstType := uint16(1), uint16(2)
	if tuple.Family == domain.FamilyIPv6 && tuple.SrcIP.Is6() && tuple.DstIP.Is6() {
		family, ipSrcType, ipDstType = netfilter.ProtoIPv6, 3, 4
	} else if tuple.Family != domain.FamilyIPv4 || !tuple.SrcIP.Is4() || !tuple.DstIP.Is4() {
		return netfilter.Attribute{}, 0, ErrAmbiguousIdentity
	}
	proto := netfilter.Attribute{Type: 2, Nested: true, Children: []netfilter.Attribute{{Type: 1, Data: []byte{tuple.Protocol}}}}
	switch tuple.Protocol {
	case unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6:
		typeField, codeField, idField := uint16(5), uint16(6), uint16(4)
		if tuple.Protocol == unix.IPPROTO_ICMPV6 {
			typeField, codeField, idField = 9, 10, 8
		}
		proto.Children = append(proto.Children, netfilter.Attribute{Type: typeField, Data: []byte{tuple.ICMPType}},
			netfilter.Attribute{Type: codeField, Data: []byte{tuple.ICMPCode}},
			netfilter.Attribute{Type: idField, Data: netfilter.Uint16Bytes(tuple.ICMPID)})
	default:
		proto.Children = append(proto.Children,
			netfilter.Attribute{Type: 2, Data: netfilter.Uint16Bytes(tuple.SrcPort)},
			netfilter.Attribute{Type: 3, Data: netfilter.Uint16Bytes(tuple.DstPort)})
	}
	children := []netfilter.Attribute{
		{Type: 1, Nested: true, Children: []netfilter.Attribute{
			{Type: ipSrcType, Data: tuple.SrcIP.AsSlice()},
			{Type: ipDstType, Data: tuple.DstIP.AsSlice()},
		}},
		proto,
	}
	if zone != 0 {
		children = append(children, netfilter.Attribute{Type: 3, Data: netfilter.Uint16Bytes(zone)})
	}
	return netfilter.Attribute{Type: 1, Nested: true, Children: children}, family, nil
}

func getConntrackFlow(ctx context.Context, conn *netlink.Conn, id Identity, networkNS, bootID string) (Record, error) {
	attribute, family, err := tupleQueryAttribute(id.Original, id.Zone)
	if err != nil {
		return Record{}, err
	}
	attrs := []netfilter.Attribute{attribute}
	if id.Zone != 0 {
		attrs = append(attrs, netfilter.Attribute{Type: 18, Data: netfilter.Uint16Bytes(id.Zone)})
	}
	request, err := netfilter.MarshalNetlink(netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink,
		MessageType: 1, // IPCTNL_MSG_CT_GET
		Family:      family,
		Flags:       netlink.Request | netlink.Acknowledge,
	}, attrs)
	if err != nil {
		return Record{}, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	sent, err := conn.Send(request)
	if err != nil {
		return Record{}, err
	}
	var found *Record
	acknowledged := false
	buffer := make([]byte, maxConntrackDatagram)
	for {
		if err := queryCtx.Err(); err != nil {
			return Record{}, err
		}
		messages, _, err := readNetlinkDatagram(queryCtx, conn, buffer)
		if isReadTimeout(err) && queryCtx.Err() == nil {
			continue
		}
		if err != nil {
			return Record{}, err
		}
		for _, msg := range messages {
			if msg.Header.Sequence != sent.Header.Sequence ||
				msg.Header.PID != 0 && msg.Header.PID != sent.Header.PID {
				return Record{}, ErrAmbiguousIdentity
			}
			switch msg.Header.Type {
			case netlink.Error:
				status := netlinkStatus(msg.Data)
				if errors.Is(status, unix.ENOENT) && found == nil {
					return Record{}, ErrFlowNotFound
				}
				if status != nil {
					return Record{}, status
				}
				acknowledged = true
				continue
			case netlink.Done:
				if err := netlinkStatus(msg.Data); err != nil {
					return Record{}, err
				}
				acknowledged = true
				continue
			case netlink.Overrun:
				return Record{}, ErrDumpIncomplete
			case netlink.Noop:
				continue
			}
			record, _, err := decodeConntrackMessage(msg, networkNS, bootID)
			if err != nil {
				return Record{}, err
			}
			if record.Identity.Zone != id.Zone || record.Identity.Family != id.Family || record.Identity.Original != id.Original ||
				(id.ID != 0 && (!record.Presence.ID || record.Identity.ID != id.ID)) ||
				(id.KernelStart != 0 && (!record.Presence.Timestamp || record.Identity.KernelStart != id.KernelStart)) {
				return Record{}, ErrAmbiguousIdentity
			}
			if found != nil {
				return Record{}, ErrAmbiguousIdentity
			}
			copy := record
			found = &copy
		}
		if acknowledged && found != nil {
			return *found, nil
		}
	}
}
