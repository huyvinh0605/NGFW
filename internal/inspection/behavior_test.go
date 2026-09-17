package inspection

import (
	"testing"
	"time"
)

func TestBehaviorPortScan(t *testing.T) {
	d := NewBehaviorDetector(time.Second)
	d.PortThreshold = 3
	now := time.Now()
	var events int
	for i := 0; i < 3; i++ {
		events += len(d.Observe(now, BehaviorObservation{SourceIP: "10.0.0.2", DestinationIP: "10.0.0.10", DestinationPort: 1000 + i}))
	}
	if events == 0 {
		t.Fatal("expected port scan event")
	}
}
