package requestworker

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection/eve"
	"github.com/kltngfw/ngfw/internal/inspection/requestpcap"
)

const (
	maxEVELineBytes    = 64 << 10
	maxEVERecords      = 4096
	maxEVEAlerts       = 128
	EVEErrorMalformed  = "GATE_EVE_MALFORMED"
	EVEErrorIncomplete = "GATE_EVE_INCOMPLETE"
	EVEErrorMismatch   = "GATE_EVE_MISMATCH"
)

type eveRecord struct {
	Timestamp    string          `json:"timestamp"`
	EventType    string          `json:"event_type"`
	PCAPFilename string          `json:"pcap_filename"`
	FlowID       json.RawMessage `json:"flow_id"`
	SrcIP        string          `json:"src_ip"`
	DestIP       string          `json:"dest_ip"`
	SrcPort      uint16          `json:"src_port"`
	DestPort     uint16          `json:"dest_port"`
	Proto        string          `json:"proto"`
	Alert        *struct {
		SignatureID json.RawMessage `json:"signature_id"`
		Signature   string          `json:"signature"`
		Category    string          `json:"category"`
		Action      string          `json:"action"`
		Severity    json.RawMessage `json:"severity"`
	} `json:"alert"`
	Flow *struct {
		State string `json:"state"`
	} `json:"flow"`
}

// NormalizeEVE accepts only job-local, matching synthetic-flow records. A
// terminal flow event is required before a zero-alert result can be COMPLETE.
// Unknown/malformed/oversized evidence never becomes a clean inspection.
func NormalizeEVE(job Result, rulesetID, rulesetHash string) domain.RequestInspectionResult {
	result := domain.RequestInspectionResult{
		RequestID: job.RequestID, Coverage: domain.RequestCoverageUnavailable,
		ErrorCode: EVEErrorMalformed, DurationMS: job.Duration.Milliseconds(),
		RulesetID: rulesetID, RulesetHash: rulesetHash,
	}
	if job.RequestID == "" || job.FlowID == 0 || job.PCAPPath == "" || len(job.EVE) == 0 || len(job.EVE) > maxEVEBytes || !bytes.HasSuffix(job.EVE, []byte("\n")) {
		return result
	}
	flow := requestpcap.SyntheticTuple(job.FlowID)
	scanner := bufio.NewScanner(bytes.NewReader(job.EVE))
	scanner.Buffer(make([]byte, 4096), maxEVELineBytes)
	terminal := false
	alerts := make([]domain.RequestAlert, 0)
	var observedFlowID uint64
	var hasFlowID bool
	for count := 0; scanner.Scan(); count++ {
		if count >= maxEVERecords || !utf8.Valid(scanner.Bytes()) {
			return result
		}
		var record eveRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.EventType == "" {
			return result
		}
		if record.EventType != "alert" && record.EventType != "flow" {
			continue
		}
		if record.PCAPFilename != "" && record.PCAPFilename != job.PCAPPath || !matchingTuple(record, flow) {
			result.ErrorCode = EVEErrorMismatch
			return result
		}
		if len(record.FlowID) != 0 && string(record.FlowID) != "null" {
			value, err := strconv.ParseUint(string(record.FlowID), 10, 64)
			if err != nil || hasFlowID && value != observedFlowID {
				result.ErrorCode = EVEErrorMismatch
				return result
			}
			hasFlowID, observedFlowID = true, value
		}
		if record.EventType == "flow" {
			if record.Flow == nil {
				return result
			}
			if strings.EqualFold(record.Flow.State, "closed") {
				terminal = true
			}
			continue
		}
		if record.Alert == nil || len(alerts) >= maxEVEAlerts {
			return result
		}
		alert, ok := normalizeAlert(record)
		if !ok {
			return result
		}
		alerts = append(alerts, alert)
	}
	if scanner.Err() != nil {
		return result
	}
	if !terminal {
		result.ErrorCode = EVEErrorIncomplete
		return result
	}
	result.Completed = true
	result.Coverage = domain.CoverageComplete
	result.ErrorCode = ""
	result.Alerts = alerts
	return result
}

func matchingTuple(record eveRecord, flow requestpcap.FlowTuple) bool {
	if !strings.EqualFold(record.Proto, "TCP") {
		return false
	}
	source, srcErr := netip.ParseAddr(record.SrcIP)
	destination, dstErr := netip.ParseAddr(record.DestIP)
	if srcErr != nil || dstErr != nil {
		return false
	}
	forward := source == flow.ClientIP && destination == flow.ServerIP && record.SrcPort == flow.ClientPort && record.DestPort == flow.ServerPort
	reverse := source == flow.ServerIP && destination == flow.ClientIP && record.SrcPort == flow.ServerPort && record.DestPort == flow.ClientPort
	return forward || reverse
}

func normalizeAlert(record eveRecord) (domain.RequestAlert, bool) {
	identifier, err := strconv.ParseUint(string(record.Alert.SignatureID), 10, 32)
	if err != nil || identifier == 0 || len(record.Alert.Signature) > 512 || len(record.Alert.Category) > 128 || len(record.Alert.Action) > 32 || len(record.Alert.Severity) > 8 {
		return domain.RequestAlert{}, false
	}
	when, err := eve.ParseTimestamp(record.Timestamp)
	if err != nil || when == nil {
		return domain.RequestAlert{}, false
	}
	alert := domain.RequestAlert{
		Detector: "suricata", SignatureID: strconv.FormatUint(identifier, 10),
		Category: record.Alert.Category, Message: record.Alert.Signature,
		Action: record.Alert.Action, Timestamp: when.Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
	if len(record.Alert.Severity) > 0 && string(record.Alert.Severity) != "null" {
		severity, err := strconv.ParseUint(string(record.Alert.Severity), 10, 8)
		if err != nil || severity < 1 || severity > 4 {
			return domain.RequestAlert{}, false
		}
		alert.Severity = strconv.FormatUint(severity, 10)
	}
	return alert, true
}
