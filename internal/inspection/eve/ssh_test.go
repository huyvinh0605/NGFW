package eve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

// The fixture was emitted by real Suricata 7.0.3 replaying synthetic SSH
// traffic captured on the appliance's LAN interface. Both discovery alerts
// and ssh records carry object-valued client/server metadata.
func TestParseRealSuricataSSHRecords(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tests", "fixtures", "suricata", "ssh-suricata7.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected discovery and SSH records, got %d", len(lines))
	}
	for _, line := range lines {
		observation, err := ParseLine(line, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "real-ssh", Mode: domain.InspectionModeIDS})
		if err != nil {
			t.Fatalf("real Suricata record rejected: %v", err)
		}
		if observation.App.Name != "SSH" || observation.App.Source != domain.ApplicationSourceSuricataAppProto || observation.App.Confidence != domain.ApplicationConfidenceHigh {
			t.Fatalf("SSH identity lost: %#v", observation.App)
		}
		if observation.Protocol == nil || observation.Protocol.SSHBanner != "SSH-2.0-NGFW_M3_schema_probe SSH-2.0-OpenSSH_9.6p1" {
			t.Fatalf("SSH metadata lost: %#v", observation.Protocol)
		}
		if observation.Tuple == nil || observation.Tuple.DstPort != 22 || observation.ObservedAt == nil {
			t.Fatalf("real SSH tuple/timestamp lost: %#v", observation)
		}
	}
}

func TestSSHMetadataShapesAndBounds(t *testing.T) {
	for _, test := range []struct {
		name, peers, want string
	}{
		{"legacy", `"client":"SSH-2.0-client","server":"SSH-2.0-server"`, "SSH-2.0-client SSH-2.0-server"},
		{"client only", `"client":{"proto_version":"2.0","software_version":"client"}`, "SSH-2.0-client"},
		{"software only", `"server":{"software_version":"server"}`, "server"},
		{"protocol only", `"client":{"proto_version":"1.99"}`, "SSH-1.99"},
		{"future fields", `"client":{"future":"value"},"server":{"proto_version":"2.0","software_version":"server","future":true}`, "SSH-2.0-server"},
		{"invalid client", `"client":{"proto_version":5},"server":{"proto_version":"2.0","software_version":"server"}`, "SSH-2.0-server"},
		{"missing", `"client":null,"server":null`, ""},
		{"wrong shape", `"client":123,"server":[]`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			line := []byte(`{"event_type":"ssh","ssh":{` + test.peers + `}}`)
			observation, err := ParseLine(line, inspection.SourcePosition{})
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if observation.Protocol != nil {
				got = observation.Protocol.SSHBanner
			}
			if got != test.want {
				t.Fatalf("banner=%q, want %q", got, test.want)
			}
		})
	}
	line := []byte(`{"event_type":"ssh","ssh":{"client":{"proto_version":"2.0","software_version":"` + strings.Repeat("ế", 800) + `"}}}`)
	observation, err := ParseLine(line, inspection.SourcePosition{})
	if err != nil || observation.Protocol == nil {
		t.Fatalf("oversize peer failed: %#v %v", observation, err)
	}
	if len(observation.Protocol.SSHBanner) > MaxMetadataString || !utf8.ValidString(observation.Protocol.SSHBanner) {
		t.Fatalf("SSH banner is unbounded or invalid UTF-8: %q", observation.Protocol.SSHBanner)
	}
}
