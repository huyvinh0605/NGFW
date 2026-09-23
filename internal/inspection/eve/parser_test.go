package eve

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func TestParseRepositorySuricataFixtures(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "tests", "fixtures", "suricata")
	for _, name := range []string{"alert", "flow", "http", "dns", "tls", "ssh", "stats"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(fixtureDir, name+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			line := bytes.TrimSpace(data)
			obs, err := ParseLine(line, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "fixture", Mode: domain.InspectionModeIDS, ByteStart: 0, ByteEnd: int64(len(line))})
			if err != nil {
				t.Fatal(err)
			}
			if obs.Kind != name || obs.ID == "" {
				t.Fatalf("unexpected fixture observation: %#v", obs)
			}
			switch name {
			case "alert":
				if obs.FlowID != 9007199254740993 || obs.Alert == nil || obs.Alert.SignatureAction != "allowed" || obs.Alert.PacketVerdict == nil || *obs.Alert.PacketVerdict != "drop" {
					t.Fatalf("alert action/verdict or uint64 flow ID lost: %#v", obs)
				}
			case "dns":
				if obs.Protocol == nil || obs.Protocol.DNSQuery != "example.test" || obs.Protocol.DNSRecordType != "A" {
					t.Fatalf("DNS metadata lost: %#v", obs.Protocol)
				}
			case "stats":
				if obs.Stats == nil || obs.Stats.CapturedPackets == nil || *obs.Stats.CapturedPackets != 1000 || obs.Stats.CaptureDrops == nil || *obs.Stats.CaptureDrops != 3 {
					t.Fatalf("nested Suricata stats lost: %#v", obs.Stats)
				}
			}
		})
	}
}

func TestParseLineAlertPreservesUint64AndMetadata(t *testing.T) {
	line := []byte(`{"timestamp":"2026-09-22T01:02:03.123Z","event_type":"alert","flow_id":18014398509481991,"tx_id":7,"src_ip":"192.168.10.10","src_port":50000,"dest_ip":"203.0.113.10","dest_port":443,"proto":"TCP","app_proto":"tls","alert":{"signature_id":9900100,"rev":2,"signature":"marker","category":"test","severity":1,"action":"allowed"},"verdict":{"action":"drop"},"direction":"to_server"}`)
	obs, err := ParseLine(line, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "e1", Mode: domain.InspectionModeIDS, ByteStart: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !obs.HasFlowID || obs.FlowID != 18014398509481991 || obs.Alert == nil || obs.Alert.PacketVerdict == nil || *obs.Alert.PacketVerdict != "drop" {
		t.Fatalf("unexpected observation: %#v", obs)
	}
	if obs.App.Name != "TLS" || obs.Tuple == nil || obs.Tuple.Protocol != 6 {
		t.Fatalf("missing app/tuple: %#v", obs)
	}
}

func TestParseLineUnknownAndMalformedAreTyped(t *testing.T) {
	if _, err := ParseLine([]byte(`{"event_type":"future"}`), inspection.SourcePosition{}); !errors.Is(err, inspection.ErrEVEUnknownType) {
		t.Fatalf("expected unknown type, got %v", err)
	}
	if _, err := ParseLine([]byte(`{"event_type":"alert"`), inspection.SourcePosition{}); !errors.Is(err, inspection.ErrEVEMalformed) {
		t.Fatalf("expected malformed, got %v", err)
	}
}

func TestParseLineDoesNotInventObservedTimestamp(t *testing.T) {
	obs, err := ParseLine([]byte(`{"event_type":"http","src_ip":"192.0.2.1","dest_ip":"198.51.100.2","src_port":1,"dest_port":80,"proto":"tcp","http":{"hostname":"example.test","http_method":"GET","url":"/x?secret=1"}}`), inspection.SourcePosition{})
	if err != nil {
		t.Fatal(err)
	}
	if obs.ObservedAt != nil || len(obs.MissingEvidence) == 0 || obs.Protocol.HTTPPath != "/x" {
		t.Fatalf("timestamp or URL handling incorrect: %#v", obs)
	}
}

func TestParseLineRejectsOversize(t *testing.T) {
	line := make([]byte, MaxDefaultLineBytes+1)
	if _, err := ParseLine(line, inspection.SourcePosition{}); !errors.Is(err, inspection.ErrEVETooLarge) {
		t.Fatalf("expected too large, got %v", err)
	}
}

func TestParseLineRejectsPortOverflowBeforeUint16Conversion(t *testing.T) {
	line := []byte(`{"event_type":"flow","src_ip":"192.0.2.1","dest_ip":"198.51.100.2","src_port":65536,"dest_port":443,"proto":"tcp"}`)
	obs, err := ParseLine(line, inspection.SourcePosition{})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Tuple != nil || !strings.Contains(strings.Join(obs.MissingEvidence, ","), "tuple_unavailable") {
		t.Fatalf("overflowed port became a tuple: %#v", obs)
	}
}

func TestParseLineIdentityIncludesEpochAndFileGeneration(t *testing.T) {
	line := []byte(`{"event_type":"stats"}`)
	one, err := ParseLine(line, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "one", FileGeneration: "inode-1", ByteStart: 4, ByteEnd: 30})
	if err != nil {
		t.Fatal(err)
	}
	two, err := ParseLine(line, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "two", FileGeneration: "inode-1", ByteStart: 4, ByteEnd: 30})
	if err != nil {
		t.Fatal(err)
	}
	if one.ID == "" || one.ID == two.ID {
		t.Fatalf("source identity is not epoch-stable: %q %q", one.ID, two.ID)
	}
}

func TestParseLineEnforcesConfiguredNormalizedByteLimit(t *testing.T) {
	line := []byte(`{"event_type":"http","src_ip":"192.0.2.1","dest_ip":"198.51.100.2","src_port":1,"dest_port":80,"proto":"tcp","http":{"hostname":"example.test","http_method":"GET","url":"/` + strings.Repeat("x", 4096) + `"}}`)
	if _, err := ParseLineWithLimit(line, inspection.SourcePosition{}, 256); !errors.Is(err, inspection.ErrEVETooLarge) {
		t.Fatalf("normalized byte limit error=%v", err)
	}
}
