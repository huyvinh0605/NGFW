//go:build linux

package conntrack

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
)

func TestDecodeConntrackPresenceDistinguishesExplicitZero(t *testing.T) {
	original := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.10"), DstIP: netip.MustParseAddr("198.51.100.20"), SrcPort: 40000, DstPort: 443, Protocol: 6}
	tuple, _, err := tupleQueryAttribute(original, 0)
	if err != nil {
		t.Fatal(err)
	}
	message, err := netfilter.MarshalNetlink(netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink, MessageType: 0,
		Family: netfilter.ProtoIPv4, Flags: netlink.Create | netlink.Excl,
	}, []netfilter.Attribute{
		tuple,
		{Type: 8, Data: netfilter.Uint32Bytes(0)},  // CTA_MARK explicitly zero
		{Type: 7, Data: netfilter.Uint32Bytes(0)},  // CTA_TIMEOUT explicitly zero
		{Type: 12, Data: netfilter.Uint32Bytes(5)}, // CTA_ID
		{Type: 9, Nested: true, Children: []netfilter.Attribute{
			{Type: 1, Data: netfilter.Uint64Bytes(0)},
			{Type: 2, Data: netfilter.Uint64Bytes(0)},
		}},
		{Type: 10, Nested: true, Children: []netfilter.Attribute{
			{Type: 1, Data: netfilter.Uint64Bytes(0)},
			{Type: 2, Data: netfilter.Uint64Bytes(0)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, kind, err := decodeConntrackMessage(message, "init", "boot")
	if err != nil {
		t.Fatal(err)
	}
	if kind != EventNew || !record.Presence.Mark || !record.Presence.Timeout || !record.Presence.Counters ||
		!record.Presence.CountersOriginal || !record.Presence.CountersReply ||
		!record.Presence.ID || record.Mark != 0 || record.Timeout != 0 || record.Identity.ID != 5 {
		t.Fatalf("wrong zero-valued presence: kind=%s record=%+v", kind, record)
	}
}

func TestDecodeConntrackPresenceTracksSingleCounterDirection(t *testing.T) {
	original := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.10"), DstIP: netip.MustParseAddr("198.51.100.20"), SrcPort: 40000, DstPort: 443, Protocol: 6}
	tuple, _, err := tupleQueryAttribute(original, 0)
	if err != nil {
		t.Fatal(err)
	}
	message, err := netfilter.MarshalNetlink(netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink, MessageType: 0, Family: netfilter.ProtoIPv4,
	}, []netfilter.Attribute{
		tuple,
		{Type: 10, Nested: true, Children: []netfilter.Attribute{
			{Type: 1, Data: netfilter.Uint64Bytes(0)},
			{Type: 2, Data: netfilter.Uint64Bytes(0)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := decodeConntrackMessage(message, "init", "boot")
	if err != nil {
		t.Fatal(err)
	}
	if record.Presence.Counters || record.Presence.CountersOriginal || !record.Presence.CountersReply {
		t.Fatalf("single counter direction was collapsed: %+v", record.Presence)
	}
}

func TestTupleQueryAttributeSelectsIPv6AndICMPv6(t *testing.T) {
	tuple := domain.Tuple{Family: domain.FamilyIPv6, SrcIP: netip.MustParseAddr("2001:db8::10"), DstIP: netip.MustParseAddr("2001:db8::20"), Protocol: 58, ICMPID: 9, ICMPType: 128}
	attr, family, err := tupleQueryAttribute(tuple, 3)
	if err != nil || family != netfilter.ProtoIPv6 {
		t.Fatalf("IPv6 query family=%v err=%v", family, err)
	}
	if len(attr.Children) != 3 || len(attr.Children[0].Children) != 2 ||
		attr.Children[0].Children[0].Type != 3 || attr.Children[0].Children[1].Type != 4 ||
		len(attr.Children[1].Children) != 4 {
		t.Fatalf("incorrect IPv6/ICMPv6 query attributes: %+v", attr)
	}
}

func TestDecodeConntrackRejectsConflictingZones(t *testing.T) {
	tuple := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.10"), DstIP: netip.MustParseAddr("198.51.100.20"), SrcPort: 40000, DstPort: 443, Protocol: 6}
	attribute, _, err := tupleQueryAttribute(tuple, 3)
	if err != nil {
		t.Fatal(err)
	}
	message, err := netfilter.MarshalNetlink(netfilter.Header{
		SubsystemID: netfilter.NFSubsysCTNetlink, MessageType: 0, Family: netfilter.ProtoIPv4,
	}, []netfilter.Attribute{attribute, {Type: 18, Data: netfilter.Uint16Bytes(4)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeConntrackMessage(message, "init", "boot"); !errors.Is(err, ErrAmbiguousIdentity) {
		t.Fatalf("conflicting zones were accepted: %v", err)
	}
}

func TestNetlinkStatusClassifiesENOENT(t *testing.T) {
	data := make([]byte, 4)
	// nlmsgerr status uses native byte order and a negative errno.
	code := int32(-int(unix.ENOENT))
	binary.NativeEndian.PutUint32(data, uint32(code))
	if !errors.Is(netlinkStatus(data), unix.ENOENT) {
		t.Fatalf("ENOENT not preserved: %v", netlinkStatus(data))
	}
}
