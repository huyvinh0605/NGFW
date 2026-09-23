package eve

import (
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func FuzzParseLine(f *testing.F) {
	f.Add([]byte(`{"timestamp":"2026-09-22T12:00:00Z","event_type":"http","flow_id":18446744073709551615,"src_ip":"192.0.2.1","src_port":50000,"dest_ip":"198.51.100.2","dest_port":80,"proto":"TCP","app_proto":"http","http":{"hostname":"fixture.test","http_method":"GET","url":"/"}}`))
	f.Add([]byte(`{"event_type":"alert","alert":{"signature_id":9900100,"signature":"marker","severity":1}}`))
	f.Add([]byte(`{"event_type":"future"}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})
	source := inspection.SourcePosition{SensorID: "fuzz", SensorEpoch: "epoch", FileGeneration: "file", Mode: domain.InspectionModeIDS}
	f.Fuzz(func(t *testing.T, line []byte) {
		if len(line) > MaxDefaultLineBytes+1 {
			return
		}
		observation, err := ParseLine(line, source)
		if err == nil {
			if observation.ID == "" || observation.Source.SensorEpoch != "epoch" {
				t.Fatalf("successful parse lost identity: %#v", observation)
			}
			if observation.Tuple != nil && !observation.Tuple.Valid() {
				t.Fatalf("successful parse returned invalid tuple: %#v", observation.Tuple)
			}
		}
	})
}
