package conntrack

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func fakeRecord(id uint32) Record {
	tuple := domain.Tuple{Family: domain.FamilyIPv4, SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: uint16(40000 + id), DstIP: netip.MustParseAddr("198.51.100.10"), DstPort: 443, Protocol: 6}
	reply := tuple.Reverse()
	return Record{Identity: domain.ConntrackIdentity{BootID: "boot", NetworkNS: "init", Zone: 1, Family: domain.FamilyIPv4, ID: id, KernelStart: uint64(id), Original: tuple}, OriginalTuple: tuple, ReplyTuple: &reply, KernelStart: time.Unix(int64(id), 0), Presence: Presence{OriginalTuple: true, ReplyTuple: true, ID: true}}
}

func TestFakeSourceGetDistinguishesAbsentFromReusedIdentity(t *testing.T) {
	source := NewFakeSource(4)
	record := fakeRecord(1)
	source.SetSnapshot(record)
	query := Identity{BootID: "boot", NetworkNS: "init", Zone: 1, Family: domain.FamilyIPv4, ID: 1, Original: record.OriginalTuple}
	got, err := source.Get(context.Background(), query)
	if err != nil || got.Identity != record.Identity {
		t.Fatalf("partial exact lookup: %+v %v", got, err)
	}
	query.ID = 2
	if _, err := source.Get(context.Background(), query); !errors.Is(err, ErrAmbiguousIdentity) {
		t.Fatalf("reused tuple should be ambiguous: %v", err)
	}
	query.Original.SrcPort++
	if _, err := source.Get(context.Background(), query); !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("absent tuple should be confirmed absent: %v", err)
	}
}

func TestFakeSourceBoundedDumpAndLifecycleEvents(t *testing.T) {
	source := NewFakeSource(4)
	if err := source.Emit(Event{Kind: EventNew, Record: fakeRecord(1)}); err != nil {
		t.Fatal(err)
	}
	if err := source.Emit(Event{Kind: EventNew, Record: fakeRecord(2)}); err != nil {
		t.Fatal(err)
	}
	result, err := source.Dump(context.Background(), DumpLimits{MaxRecords: 1, MaxBytes: 1 << 20}, func(Record) error { return nil })
	if err != ErrDumpIncomplete || result.Complete || result.Reason != "record limit" {
		t.Fatalf("bounded dump result=%+v err=%v", result, err)
	}
	if err := source.Emit(Event{Kind: EventDestroy, Record: fakeRecord(1)}); err != nil {
		t.Fatal(err)
	}
	result, err = source.Dump(context.Background(), DumpLimits{MaxRecords: 10, MaxBytes: 1 << 20}, func(Record) error { return nil })
	if err != nil || result.Records != 1 {
		t.Fatalf("lifecycle dump result=%+v err=%v", result, err)
	}
}
