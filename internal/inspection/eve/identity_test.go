package eve

import (
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

func TestEventIDStableAndScoped(t *testing.T) {
	s := inspection.SourcePosition{SensorID: "ids", SensorEpoch: "e1", FileGeneration: "g1", ByteStart: 1, ByteEnd: 10, Mode: domain.InspectionModeIDS}
	a := EventID(s, []byte("line"))
	b := EventID(s, []byte("line"))
	if a != b {
		t.Fatal("event id is not stable")
	}
	s.ByteStart++
	if EventID(s, []byte("line")) == a {
		t.Fatal("offset was not included")
	}
}

func TestDeduperBoundedAndTTL(t *testing.T) {
	d := NewDeduper(2, 100, time.Second)
	now := time.Unix(1, 0)
	if d.SeenOrAdd("a", now) || !d.SeenOrAdd("a", now.Add(100*time.Millisecond)) {
		t.Fatal("dedup result incorrect")
	}
	d.SeenOrAdd("b", now)
	d.SeenOrAdd("c", now)
	if d.SeenOrAdd("a", now) {
		t.Fatal("oldest record was not evicted")
	}
	if d.SeenOrAdd("b", now.Add(2*time.Second)) {
		t.Fatal("expired record was not removed")
	}
}
