package session

import (
	"testing"
	"time"
)

func TestInspectionHistoryLimitShrinksCanonicalHistoryWithoutTouchingActive(t *testing.T) {
	now := time.Now().UTC()
	s := NewRuntimeStore(RuntimeLimits{MaxClosed: 8, ClosedTTL: time.Minute})
	for i := uint32(1); i <= 5; i++ {
		record := testRecord()
		record.Identity.ID = i
		record.Identity.KernelStart = uint64(i)
		record.Identity.Original.SrcPort = uint16(50000 + i)
		record.OriginalTuple = record.Identity.Original
		value, _, err := s.Apply(record, now)
		if err != nil {
			t.Fatal(err)
		}
		if i < 5 {
			if _, closed := s.Close(value.Identity, "test", now); !closed {
				t.Fatal("close failed")
			}
		}
	}
	oldClosed := s.closed
	s.SetInspectionHistoryLimits(2, time.Second)
	if len(s.closed) != 2 || len(s.tombstones) != 2 || len(s.List()) != 1 || s.Stats().HistoryEvictions != 2 {
		t.Fatalf("canonical history not bounded, or active record affected: %+v", s.Stats())
	}
	if oldClosed[0].SessionID != "" || oldClosed[1].SessionID != "" {
		t.Fatal("evicted backing slots retain session metadata")
	}
	s.PruneClosed(now.Add(2 * time.Second))
	if len(s.closed) != 0 || len(s.tombstones) != 0 || s.Stats().HistoryExpired != 2 || len(s.List()) != 1 {
		t.Fatal("configured TTL not applied independently of live kernel identities")
	}
	s.SetInspectionHistoryLimits(0, 0)
	if s.limits.MaxClosed != 8 || s.limits.ClosedTTL != time.Minute {
		t.Fatal("M3 OFF did not restore custom M2 history limits")
	}
}
