package dataplane

import "testing"

func TestM2CacheMarkRoundTripAndPreserveLowBits(t *testing.T) {
	mark := CacheMark{Epoch: 12, SourceZoneSlot: 2, DestinationZoneSlot: 7}
	value, err := SetCacheMark(0x000000a5, mark)
	if err != nil {
		t.Fatal(err)
	}
	if value&0xff != 0xa5 {
		t.Fatalf("low bits changed: %#x", value)
	}
	decoded, ok := UnpackCacheMark(value)
	if !ok || decoded != mark || !CacheHit(value, mark, true) {
		t.Fatalf("decoded=%+v ok=%v", decoded, ok)
	}
	if CacheHit(value, CacheMark{Epoch: 13, SourceZoneSlot: 2, DestinationZoneSlot: 7}, true) {
		t.Fatal("stale epoch hit")
	}
	if CacheHit(value, mark, false) {
		t.Fatal("foreign mark hit")
	}
	if got := ClearCacheMark(value, false); got != value {
		t.Fatal("foreign mark was changed")
	}
	if got := ClearCacheMark(value, true); got != 0xa5 {
		t.Fatalf("clear=%#x", got)
	}
}

func TestM2CacheModeLimits(t *testing.T) {
	if !CacheModeAllowed(63, false) || CacheModeAllowed(64, false) || CacheModeAllowed(2, true) {
		t.Fatal("cache mode limits incorrect")
	}
}
