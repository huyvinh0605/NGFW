package engine

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func threat(id string) domain.ThreatEvent {
	return domain.ThreatEvent{EventID: id, IngestedAt: time.Now().UTC(), Severity: domain.SeverityHigh, Verdict: domain.VerdictAlert, CorrelationState: domain.CorrelationUncorrelated, CaptureMode: domain.InspectionModeIDS, Application: domain.UnknownApplication()}
}

func TestSecurityEventStoreRejectedUpdateDoesNotMutateRecord(t *testing.T) {
	store := NewSecurityEventStore(10, 1024)
	if _, _, err := store.Add(threat("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateCorrelation("a", "s1", "p1", 2, domain.CorrelationCorrelated, strings.Repeat("x", 2048)); !errors.Is(err, ErrSecurityEventTooLarge) {
		t.Fatalf("expected byte limit error, got %v", err)
	}
	current, ok := store.Get("a")
	if !ok || current.SessionID != "" || current.CorrelationState != domain.CorrelationUncorrelated || current.CorrelationRevision != 0 {
		t.Fatalf("rejected update mutated stored event: %#v", current)
	}
}

func TestSecurityEventStoreCapacityDuplicateAndGap(t *testing.T) {
	store := NewSecurityEventStore(2, 1<<20)
	first, added, err := store.Add(threat("a"))
	if err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	duplicate, added, err := store.Add(threat("a"))
	if err != nil || added || duplicate.Sequence != first.Sequence {
		t.Fatalf("duplicate changed event: %#v %v", duplicate, err)
	}
	_, _, _ = store.Add(threat("b"))
	_, _, _ = store.Add(threat("c"))
	if _, ok := store.Get("a"); ok {
		t.Fatal("evicted event remains indexed")
	}
	page := store.Query(domain.SecurityQuery{AfterSequence: 0, Limit: 10})
	if page.GapFrom == 0 || len(page.Items) != 2 {
		t.Fatalf("gap/page incorrect: %#v", page)
	}
}

func TestSecurityEventStoreUpdateAndFilter(t *testing.T) {
	store := NewSecurityEventStore(10, 1<<20)
	_, _, _ = store.Add(threat("a"))
	updated, err := store.UpdateCorrelation("a", "s1", "p1", 2, domain.CorrelationCorrelated, "tuple matched")
	if err != nil || updated.CorrelationRevision != 1 {
		t.Fatalf("update failed: %#v %v", updated, err)
	}
	if got := store.Query(domain.SecurityQuery{SessionID: "s1"}); len(got.Items) != 1 {
		t.Fatalf("filter failed: %#v", got)
	}
	idempotent, err := store.UpdateCorrelation("a", "s1", "p1", 2, domain.CorrelationCorrelated, "tuple matched")
	if err != nil || idempotent.CorrelationRevision != 1 {
		t.Fatalf("idempotent correlation update changed revision: %#v %v", idempotent, err)
	}
	if _, err := store.UpdateCorrelation("missing", "", "", 0, domain.CorrelationUncorrelated, ""); !errors.Is(err, ErrSecurityEventNotFound) {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestSecurityEventStoreConcurrent(t *testing.T) {
	store := NewSecurityEventStore(1000, 4<<20)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, _ = store.Add(threat(fmt.Sprintf("%d-%d", worker, j)))
				_ = store.Query(domain.SecurityQuery{Limit: 10})
			}
		}(i)
	}
	wg.Wait()
	if store.Stats().CurrentEvents == 0 {
		t.Fatal("concurrent store lost all records")
	}
}

func TestSecurityEventStoreRingWrapKeepsIndexAndSequenceOrder(t *testing.T) {
	store := NewSecurityEventStore(3, 1<<20)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		if _, _, err := store.Add(threat(id)); err != nil {
			t.Fatal(err)
		}
	}
	page := store.Query(domain.SecurityQuery{Limit: 10})
	if len(page.Items) != 3 || page.Items[0].EventID != "c" || page.Items[1].EventID != "d" || page.Items[2].EventID != "e" {
		t.Fatalf("wrapped ring is out of order: %#v", page.Items)
	}
	for _, item := range page.Items {
		indexed, ok := store.Get(item.EventID)
		if !ok || indexed.Sequence != item.Sequence {
			t.Fatalf("ring index mismatch for %s", item.EventID)
		}
	}
}

func TestSecurityEventStoreCursorAdvancesAcrossFilteredRecordsAndResetsOnNewStream(t *testing.T) {
	store := NewSecurityEventStore(10, 1<<20)
	for _, id := range []string{"a", "b", "c"} {
		value := threat(id)
		value.SensorID = "ids"
		if id == "b" {
			value.SensorID = "ips"
		}
		if _, _, err := store.Add(value); err != nil {
			t.Fatal(err)
		}
	}
	page := store.Query(domain.SecurityQuery{SensorID: "missing", Limit: 10})
	if len(page.Items) != 0 || page.NextSequence != 3 || page.NextCursor != page.StreamID+":3" {
		t.Fatalf("filtered cursor did not advance: %#v", page)
	}
	reset := store.Query(domain.SecurityQuery{StreamID: "previous-engine", AfterSequence: 999, Limit: 1})
	if !reset.ResetRequired || !reset.Gap || len(reset.Items) != 1 || reset.NextSequence != 1 {
		t.Fatalf("new engine stream was not reset safely: %#v", reset)
	}
}
