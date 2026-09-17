package domain

import (
	"fmt"
	"net/netip"
	"strings"
)

// IPFamily identifies the address family carried by a normalized tuple.
type IPFamily uint8

const (
	FamilyUnknown IPFamily = 0
	FamilyIPv4    IPFamily = 4
	FamilyIPv6    IPFamily = 6
)

func (f IPFamily) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

// Tuple is a typed, directional L3/L4 tuple. It is deliberately comparable
// once embedded in flow.Key; callers must not use an ad-hoc concatenated
// string as the identity of a connection.
type Tuple struct {
	Family   IPFamily   `json:"family"`
	SrcIP    netip.Addr `json:"src_ip"`
	SrcPort  uint16     `json:"src_port,omitempty"`
	DstIP    netip.Addr `json:"dst_ip"`
	DstPort  uint16     `json:"dst_port,omitempty"`
	Protocol uint8      `json:"protocol"`
	ICMPType uint8      `json:"icmp_type,omitempty"`
	ICMPCode uint8      `json:"icmp_code,omitempty"`
	ICMPID   uint16     `json:"icmp_id,omitempty"`
}

func (t Tuple) Valid() bool {
	if t.SrcIP == (netip.Addr{}) || t.DstIP == (netip.Addr{}) || t.Protocol == 0 {
		return false
	}
	if t.Family == FamilyIPv4 && (!t.SrcIP.Is4() || !t.DstIP.Is4()) {
		return false
	}
	if t.Family == FamilyIPv6 && (!t.SrcIP.Is6() || t.SrcIP.Is4() || !t.DstIP.Is6() || t.DstIP.Is4()) {
		return false
	}
	return t.SrcIP.BitLen() == t.DstIP.BitLen()
}

func (t Tuple) Reverse() Tuple {
	r := t
	r.SrcIP, r.DstIP = t.DstIP, t.SrcIP
	r.SrcPort, r.DstPort = t.DstPort, t.SrcPort
	if t.Protocol == 1 || t.Protocol == 58 { // ICMP/ICMPv6 echo request/reply.
		switch t.ICMPType {
		case 8:
			r.ICMPType = 0
		case 0:
			r.ICMPType = 8
		case 128:
			r.ICMPType = 129
		case 129:
			r.ICMPType = 128
		}
	}
	return r
}

func (t Tuple) String() string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%d|%d|%d|%d|%d", t.Family, t.SrcIP, t.DstIP, t.SrcPort, t.DstPort, t.Protocol, t.ICMPType, t.ICMPCode, t.ICMPID, t.SrcIP.BitLen())
}

// ParseProtocol accepts the names used by the configuration as well as a
// decimal protocol number. Unknown names are rejected rather than silently
// becoming a wildcard.
func ParseProtocol(value string) (uint8, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp", "6":
		return 6, true
	case "udp", "17":
		return 17, true
	case "icmp", "1":
		return 1, true
	case "icmpv6", "58":
		return 58, true
	default:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(value), "%d", &n); err == nil && n > 0 && n <= 255 {
			return uint8(n), true
		}
		return 0, false
	}
}

func TupleFromFlowKey(k FlowKey) (Tuple, error) {
	src, err := netip.ParseAddr(strings.TrimSpace(k.SrcIP))
	if err != nil {
		return Tuple{}, fmt.Errorf("invalid source IP: %w", err)
	}
	dst, err := netip.ParseAddr(strings.TrimSpace(k.DstIP))
	if err != nil {
		return Tuple{}, fmt.Errorf("invalid destination IP: %w", err)
	}
	if src.Is4() != dst.Is4() {
		return Tuple{}, fmt.Errorf("mixed IP families")
	}
	proto, ok := ParseProtocol(k.Protocol)
	if !ok {
		return Tuple{}, fmt.Errorf("unsupported protocol %q", k.Protocol)
	}
	if k.SrcPort < 0 || k.SrcPort > 65535 || k.DstPort < 0 || k.DstPort > 65535 {
		return Tuple{}, fmt.Errorf("port outside range")
	}
	family := FamilyIPv6
	if src.Is4() {
		family = FamilyIPv4
	}
	return Tuple{Family: family, SrcIP: src, SrcPort: uint16(k.SrcPort), DstIP: dst, DstPort: uint16(k.DstPort), Protocol: proto}, nil
}

func (t Tuple) FlowKey(namespace string) FlowKey {
	protocol := fmt.Sprintf("%d", t.Protocol)
	switch t.Protocol {
	case 1:
		protocol = "icmp"
	case 6:
		protocol = "tcp"
	case 17:
		protocol = "udp"
	case 58:
		protocol = "icmpv6"
	}
	return FlowKey{SrcIP: t.SrcIP.String(), DstIP: t.DstIP.String(), SrcPort: int(t.SrcPort), DstPort: int(t.DstPort), Protocol: protocol, Namespace: namespace}
}
