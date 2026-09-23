package eve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

const (
	MaxDefaultLineBytes = 1 << 20
	MaxNormalizedBytes  = 8 << 10
	MaxMetadataString   = 1024
	MaxHTTPPath         = 4096
	MaxALPN             = 8
)

type RawEnvelope struct {
	Timestamp string          `json:"timestamp"`
	EventType string          `json:"event_type"`
	FlowID    json.RawMessage `json:"flow_id"`
	TxID      json.RawMessage `json:"tx_id"`
	SrcIP     string          `json:"src_ip"`
	DstIP     string          `json:"dest_ip"`
	SrcPort   json.RawMessage `json:"src_port"`
	DstPort   json.RawMessage `json:"dest_port"`
	Proto     string          `json:"proto"`
	AppProto  string          `json:"app_proto"`
	Direction string          `json:"direction"`
	Alert     *RawAlert       `json:"alert"`
	Verdict   *RawVerdict     `json:"verdict"`
	Flow      *RawFlow        `json:"flow"`
	HTTP      *RawHTTP        `json:"http"`
	DNS       json.RawMessage `json:"dns"`
	TLS       *RawTLS         `json:"tls"`
	SSH       *RawSSH         `json:"ssh"`
	Stats     *RawStats       `json:"stats"`
}

type RawAlert struct {
	SignatureID json.RawMessage `json:"signature_id"`
	Rev         json.RawMessage `json:"rev"`
	Signature   string          `json:"signature"`
	Category    string          `json:"category"`
	Severity    json.RawMessage `json:"severity"`
	Action      string          `json:"action"`
	GID         json.RawMessage `json:"gid"`
}
type RawVerdict struct {
	Action string `json:"action"`
}
type RawFlow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}
type RawHTTP struct {
	Host   string `json:"hostname"`
	Method string `json:"http_method"`
	URL    string `json:"url"`
}
type RawTLS struct {
	SNI     string          `json:"sni"`
	Version string          `json:"version"`
	ALPN    json.RawMessage `json:"alpn"`
}
type RawSSH struct {
	Client string `json:"client"`
	Server string `json:"server"`
}
type RawStats struct {
	Uptime   json.RawMessage `json:"uptime"`
	Captured json.RawMessage `json:"capture.kernel_packets"` // legacy flattened fixture
	Drops    json.RawMessage `json:"capture.kernel_drops"`   // legacy flattened fixture
	Capture  struct {
		KernelPackets json.RawMessage `json:"kernel_packets"`
		KernelDrops   json.RawMessage `json:"kernel_drops"`
	} `json:"capture"`
	Timestamp string `json:"timestamp"`
}

func ParseTimestamp(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			parsed = parsed.UTC()
			return &parsed, nil
		}
	}
	return nil, fmt.Errorf("invalid timestamp %q", value)
}

func ParseProtocol(value string) (uint8, bool) { return domain.ParseProtocol(value) }

func ParseLine(line []byte, source inspection.SourcePosition) (inspection.Observation, error) {
	return ParseLineWithLimit(line, source, MaxNormalizedBytes)
}

func ParseLineWithLimit(line []byte, source inspection.SourcePosition, maxNormalizedBytes int) (inspection.Observation, error) {
	if len(line) > MaxDefaultLineBytes {
		return inspection.Observation{}, inspection.ErrEVETooLarge
	}
	var raw RawEnvelope
	if err := json.Unmarshal(line, &raw); err != nil {
		return inspection.Observation{}, fmt.Errorf("%w: %v", inspection.ErrEVEMalformed, err)
	}
	kind := strings.ToLower(strings.TrimSpace(raw.EventType))
	if !isKnownKind(kind) {
		return inspection.Observation{}, fmt.Errorf("%w: %s", inspection.ErrEVEUnknownType, kind)
	}
	observed, err := ParseTimestamp(raw.Timestamp)
	if err != nil {
		return inspection.Observation{}, fmt.Errorf("%w: %v", inspection.ErrEVEMalformed, err)
	}
	obs := inspection.Observation{Source: source, Kind: kind, ObservedAt: observed, IngestedAt: time.Now().UTC(), Direction: normalizeDirection(raw.Direction), App: appIdentity(raw.AppProto, kind, observed)}
	if flow, ok := uint64Value(raw.FlowID); ok {
		obs.FlowID, obs.HasFlowID = flow, true
	}
	if tx, ok := uint64Value(raw.TxID); ok {
		obs.TransactionID = &tx
	}
	if tuple := normalizeTuple(raw); tuple != nil {
		obs.Tuple, obs.FlowTuple = tuple, cloneTuple(tuple)
	} else if raw.SrcIP != "" || raw.DstIP != "" || raw.Proto != "" {
		obs.MissingEvidence = append(obs.MissingEvidence, "tuple_unavailable")
	}
	if raw.Flow != nil {
		obs.FlowStart, _ = ParseTimestamp(raw.Flow.Start)
		obs.FlowEnd, _ = ParseTimestamp(raw.Flow.End)
	}
	if raw.Alert != nil {
		obs.Alert = normalizeAlert(raw.Alert, raw.Verdict)
	}
	protocol := normalizeProtocol(raw, kind)
	if protocol != nil {
		obs.Protocol = protocol
	}
	if raw.Stats != nil {
		obs.Stats = normalizeStats(raw.Stats)
	}
	if obs.ObservedAt == nil {
		obs.MissingEvidence = append(obs.MissingEvidence, "timestamp_unavailable")
	}
	obs.ID = EventID(source, line)
	if maxNormalizedBytes <= 0 {
		maxNormalizedBytes = MaxNormalizedBytes
	}
	if maxNormalizedBytes > 16<<10 {
		maxNormalizedBytes = 16 << 10
	}
	if size, _ := json.Marshal(obs); len(size) > maxNormalizedBytes {
		obs.Truncated = true
		obs.Protocol = truncateProtocol(obs.Protocol)
		obs.App.RawName = truncate(obs.App.RawName, MaxMetadataString)
		obs.MissingEvidence = append(obs.MissingEvidence, "normalized_event_truncated")
	}
	if size, _ := json.Marshal(obs); len(size) > maxNormalizedBytes {
		obs.Protocol = nil
		obs.App.RawName = ""
		if obs.Alert != nil {
			obs.Alert.Signature = truncate(obs.Alert.Signature, 256)
			obs.Alert.Category = truncate(obs.Alert.Category, 256)
		}
	}
	if size, _ := json.Marshal(obs); len(size) > maxNormalizedBytes {
		return inspection.Observation{}, fmt.Errorf("%w: normalized observation exceeds %d bytes", inspection.ErrEVETooLarge, maxNormalizedBytes)
	}
	return obs, nil
}

func isKnownKind(kind string) bool {
	switch kind {
	case "alert", "flow", "http", "dns", "tls", "ssh", "stats", "discovery":
		return true
	default:
		return false
	}
}

func appIdentity(raw, kind string, observed *time.Time) domain.ApplicationIdentity {
	name := strings.TrimSpace(raw)
	if name == "" {
		switch kind {
		case "http":
			name = "HTTP"
		case "tls":
			name = "TLS"
		case "dns":
			name = "DNS"
		case "ssh":
			name = "SSH"
		}
	}
	identity := inspection.NormalizeApplication(name)
	if observed != nil {
		v := *observed
		identity.FirstSeen, identity.LastSeen = &v, &v
	}
	return identity
}

func normalizeTuple(raw RawEnvelope) *domain.Tuple {
	src, err1 := netip.ParseAddr(strings.TrimSpace(raw.SrcIP))
	dst, err2 := netip.ParseAddr(strings.TrimSpace(raw.DstIP))
	proto, ok := ParseProtocol(raw.Proto)
	if err1 != nil || err2 != nil || !ok || src.Is4() != dst.Is4() {
		return nil
	}
	srcPort, srcPortOK := uint64Value(raw.SrcPort)
	dstPort, dstPortOK := uint64Value(raw.DstPort)
	// TCP/UDP tuples require both ports and each value must fit before it is
	// converted to uint16.  A truncated value could otherwise correlate an
	// unrelated session (for example 65536 becoming port 0).
	if proto == 6 || proto == 17 {
		if !srcPortOK || !dstPortOK || srcPort > 65535 || dstPort > 65535 {
			return nil
		}
	} else if (srcPortOK && srcPort > 65535) || (dstPortOK && dstPort > 65535) {
		return nil
	}
	family := domain.FamilyIPv6
	if src.Is4() {
		family = domain.FamilyIPv4
	}
	t := &domain.Tuple{Family: family, SrcIP: src, DstIP: dst, SrcPort: uint16(srcPort), DstPort: uint16(dstPort), Protocol: proto}
	if !t.Valid() {
		return nil
	}
	return t
}

func cloneTuple(t *domain.Tuple) *domain.Tuple {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func normalizeDirection(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "to_server", "to_client":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func normalizeAlert(raw *RawAlert, verdict *RawVerdict) *inspection.AlertObservation {
	a := &inspection.AlertObservation{Signature: truncate(raw.Signature, MaxMetadataString), Category: truncate(raw.Category, MaxMetadataString), SignatureAction: truncate(raw.Action, 64)}
	if v, ok := uint64Value(raw.SignatureID); ok && v <= uint64(^uint32(0)) {
		a.SignatureID, a.HasSignatureID = uint32(v), true
	}
	if v, ok := uint64Value(raw.Rev); ok && v <= uint64(^uint32(0)) {
		a.SignatureRevision = uint32(v)
	}
	if v, ok := intValue(raw.Severity); ok && v >= 1 && v <= 255 {
		a.Severity = &v
	}
	if verdict != nil && strings.TrimSpace(verdict.Action) != "" {
		action := truncate(verdict.Action, 64)
		a.PacketVerdict = &action
	}
	return a
}

func normalizeProtocol(raw RawEnvelope, kind string) *inspection.ProtocolMetadata {
	p := &inspection.ProtocolMetadata{}
	if raw.HTTP != nil {
		p.HTTPHost, p.HTTPMethod, p.HTTPPath = truncate(raw.HTTP.Host, MaxMetadataString), truncate(raw.HTTP.Method, 64), truncatePath(raw.HTTP.URL)
	}
	if raw.TLS != nil {
		p.TLSSNI, p.TLSVersion = truncate(raw.TLS.SNI, MaxMetadataString), truncate(raw.TLS.Version, 64)
		p.ALPN = parseALPN(raw.TLS.ALPN)
	}
	if raw.SSH != nil {
		p.SSHBanner = truncate(strings.TrimSpace(raw.SSH.Client+" "+raw.SSH.Server), MaxMetadataString)
	}
	if kind == "dns" && len(raw.DNS) > 0 && string(raw.DNS) != "null" {
		var dns struct {
			RRName string          `json:"rrname"`
			RRType json.RawMessage `json:"rrtype"`
			Type   string          `json:"type"`
		}
		if json.Unmarshal(raw.DNS, &dns) == nil {
			recordType := dns.Type
			if len(dns.RRType) > 0 {
				var asString string
				if json.Unmarshal(dns.RRType, &asString) == nil {
					recordType = asString
				} else {
					recordType = strings.Trim(string(dns.RRType), "\"")
				}
			}
			p.DNSQuery, p.DNSRecordType = truncate(dns.RRName, MaxMetadataString), truncate(recordType, 64)
		}
	}
	if p.HTTPHost == "" && p.HTTPMethod == "" && p.HTTPPath == "" && p.TLSSNI == "" && p.TLSVersion == "" && len(p.ALPN) == 0 && p.DNSQuery == "" && p.DNSRecordType == "" && p.SSHBanner == "" {
		return nil
	}
	return p
}

func normalizeStats(raw *RawStats) *inspection.SensorCounters {
	c := &inspection.SensorCounters{}
	if v, ok := uint64Value(raw.Uptime); ok {
		c.UptimeSeconds = &v
	}
	captured := raw.Captured
	if len(captured) == 0 {
		captured = raw.Capture.KernelPackets
	}
	if v, ok := uint64Value(captured); ok {
		c.CapturedPackets = &v
	}
	drops := raw.Drops
	if len(drops) == 0 {
		drops = raw.Capture.KernelDrops
	}
	if v, ok := uint64Value(drops); ok {
		c.CaptureDrops = &v
	}
	c.SourceTimestamp, _ = ParseTimestamp(raw.Timestamp)
	return c
}

func parseALPN(raw json.RawMessage) []string {
	var values []string
	if len(raw) == 0 {
		return values
	}
	if json.Unmarshal(raw, &values) != nil {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			values = []string{value}
		}
	}
	if len(values) > MaxALPN {
		values = values[:MaxALPN]
	}
	for i := range values {
		values[i] = truncate(values[i], 128)
	}
	return values
}

func uint64Value(raw json.RawMessage) (uint64, bool) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, false
	}
	var text string
	if raw[0] == '"' {
		if json.Unmarshal(raw, &text) != nil {
			return 0, false
		}
	} else {
		text = string(raw)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	return value, err == nil
}
func intValue(raw json.RawMessage) (int, bool) {
	v, ok := uint64Value(raw)
	if !ok || v > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(v), true
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
func truncatePath(value string) string {
	value = strings.SplitN(value, "?", 2)[0]
	value = strings.SplitN(value, "#", 2)[0]
	return truncate(value, MaxHTTPPath)
}
func truncateProtocol(p *inspection.ProtocolMetadata) *inspection.ProtocolMetadata {
	if p == nil {
		return nil
	}
	c := *p
	c.HTTPHost, c.HTTPMethod, c.HTTPPath = truncate(c.HTTPHost, 128), truncate(c.HTTPMethod, 32), truncate(c.HTTPPath, 512)
	c.TLSSNI, c.TLSVersion, c.DNSQuery, c.DNSRecordType, c.SSHBanner = truncate(c.TLSSNI, 128), truncate(c.TLSVersion, 32), truncate(c.DNSQuery, 128), truncate(c.DNSRecordType, 32), truncate(c.SSHBanner, 128)
	return &c
}
