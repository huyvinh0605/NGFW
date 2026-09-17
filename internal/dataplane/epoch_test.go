package dataplane

import "testing"

func TestM2EpochAllocatorMonotonicAndCorruption(t *testing.T) {
	path := t.TempDir() + "/epoch.json"
	a, err := NewEpochAllocator(path)
	if err != nil {
		t.Fatal(err)
	}
	one, err := a.Allocate()
	if err != nil || one != 1 {
		t.Fatalf("first=%d err=%v", one, err)
	}
	b, err := NewEpochAllocator(path)
	if err != nil {
		t.Fatal(err)
	}
	two, err := b.Allocate()
	if err != nil || two != 2 {
		t.Fatalf("second=%d err=%v", two, err)
	}
}
