package requestworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection/requestpcap"
)

func eveJob(records ...map[string]any) Result {
	job := Result{RequestID: "request-1", WorkerID: 0, FlowID: 19, PCAPPath: "/work/job-1/request.pcap", Duration: 22 * time.Millisecond}
	for _, record := range records {
		line, _ := json.Marshal(record)
		job.EVE = append(job.EVE, line...)
		job.EVE = append(job.EVE, '\n')
	}
	return job
}

func baseEVE(event string) map[string]any {
	flow := requestpcap.SyntheticTuple(19)
	return map[string]any{
		"timestamp": "2026-09-29T10:00:00.123456+0000", "event_type": event,
		"pcap_filename": "/work/job-1/request.pcap", "flow_id": uint64(9007199254740993),
		"src_ip": flow.ClientIP.String(), "src_port": flow.ClientPort,
		"dest_ip": flow.ServerIP.String(), "dest_port": flow.ServerPort, "proto": "TCP",
	}
}

func closedFlow() map[string]any {
	value := baseEVE("flow")
	value["flow"] = map[string]any{"state": "closed", "reason": "shutdown"}
	return value
}

func alert() map[string]any {
	value := baseEVE("alert")
	value["alert"] = map[string]any{
		"signature_id": 2012345, "signature": "lab SQLi", "category": "web-application-attack",
		"action": "blocked", "severity": 2,
	}
	return value
}

func TestNormalizeEVECleanAndMalicious(t *testing.T) {
	clean := NormalizeEVE(eveJob(closedFlow()), "rules-v1", "sha256")
	if !clean.Completed || clean.Coverage != domain.CoverageComplete || len(clean.Alerts) != 0 || clean.ErrorCode != "" || clean.RequestID != "request-1" {
		t.Fatalf("clean flow normalization failed: %#v", clean)
	}
	malicious := NormalizeEVE(eveJob(alert(), closedFlow()), "rules-v1", "sha256")
	if !malicious.Completed || malicious.Coverage != domain.CoverageComplete || len(malicious.Alerts) != 1 {
		t.Fatalf("alert normalization failed: %#v", malicious)
	}
	got := malicious.Alerts[0]
	if got.Detector != "suricata" || got.SignatureID != "2012345" || got.Action != "blocked" || got.Category != "web-application-attack" || got.Severity != "2" || got.Timestamp != "2026-09-29T10:00:00.123456Z" {
		t.Fatalf("alert evidence lost: %#v", got)
	}
	if malicious.DurationMS != 22 || malicious.RulesetID != "rules-v1" || malicious.RulesetHash != "sha256" {
		t.Fatalf("job metadata lost: %#v", malicious)
	}
}

func TestNormalizeEVERejectsStaleOrAmbiguousEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*Result){
		"missing terminal flow": func(v *Result) { *v = eveJob(alert()) },
		"empty output":          func(v *Result) { v.EVE = nil },
		"partial line":          func(v *Result) { v.EVE = []byte(`{"event_type":"flow"}`) },
		"malformed line":        func(v *Result) { v.EVE = []byte("{broken}\n") },
		"foreign PCAP": func(v *Result) {
			entry := closedFlow()
			entry["pcap_filename"] = "/old/job.pcap"
			*v = eveJob(entry)
		},
		"foreign tuple": func(v *Result) {
			entry := closedFlow()
			entry["src_port"] = 12345
			*v = eveJob(entry)
		},
		"foreign flow ID": func(v *Result) {
			entry := closedFlow()
			entry["flow_id"] = 9007199254740994
			*v = eveJob(alert(), entry)
		},
		"missing alert SID": func(v *Result) {
			entry := alert()
			entry["alert"].(map[string]any)["signature_id"] = nil
			*v = eveJob(entry, closedFlow())
		},
		"oversized output": func(v *Result) { v.EVE = bytes.Repeat([]byte("x"), maxEVEBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			job := eveJob(closedFlow())
			mutate(&job)
			result := NormalizeEVE(job, "rules-v1", "sha256")
			if result.Completed || result.Coverage != domain.RequestCoverageUnavailable || result.ErrorCode == "" || len(result.Alerts) != 0 {
				t.Fatalf("bad evidence interpreted as clean or trusted: %#v", result)
			}
		})
	}
}

func TestNormalizeEVEIgnoresOtherTypesAndAcceptsReplyDirection(t *testing.T) {
	other := baseEVE("http")
	flow := closedFlow()
	flow["pcap_filename"] = "" // flow pseudo-packets may omit the PCAP name
	flow["flow_id"] = nil
	flow["src_ip"], flow["dest_ip"] = flow["dest_ip"], flow["src_ip"]
	flow["src_port"], flow["dest_port"] = flow["dest_port"], flow["src_port"]
	result := NormalizeEVE(eveJob(other, flow), "rules-v1", "sha256")
	if !result.Completed || result.Coverage != domain.CoverageComplete {
		t.Fatalf("valid reply-direction terminal flow rejected: %#v", result)
	}
}

func TestNormalizeEVELimitsAlertsAndRecords(t *testing.T) {
	job := eveJob()
	for i := 0; i < maxEVEAlerts+1; i++ {
		job.EVE = append(job.EVE, eveJob(alert()).EVE...)
	}
	job.EVE = append(job.EVE, eveJob(closedFlow()).EVE...)
	if result := NormalizeEVE(job, "", ""); result.Completed || result.ErrorCode != EVEErrorMalformed {
		t.Fatalf("unbounded alert list accepted: %#v", result)
	}
	job = eveJob()
	for i := 0; i < maxEVERecords+1; i++ {
		job.EVE = append(job.EVE, []byte("{\"event_type\":\"http\"}\n")...)
	}
	if result := NormalizeEVE(job, "", ""); result.Completed || result.ErrorCode != EVEErrorMalformed {
		t.Fatalf("unbounded record count accepted: %#v", result)
	}
}

func FuzzNormalizeEVENoPanic(f *testing.F) {
	f.Add([]byte("{\"event_type\":\"flow\"}\n"))
	f.Add([]byte("{broken}\n"))
	f.Add([]byte(strings.Repeat("x", 1024)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2<<20 {
			t.Skip()
		}
		job := eveJob()
		job.EVE = raw
		result := NormalizeEVE(job, fmt.Sprintf("rules-%d", len(raw)), "hash")
		if result.Completed && result.Coverage != domain.CoverageComplete {
			t.Fatalf("completed result has invalid coverage: %#v", result)
		}
	})
}
