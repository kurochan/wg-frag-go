package state

import (
	"testing"
	"time"
)

func TestExpirySetUpdatesHeapIndexAndPrunesInOrder(t *testing.T) {
	set := newExpirySet[int](3)
	base := time.Unix(1_000, 0)
	if !set.retain(1, base.Add(time.Second)) ||
		!set.retain(2, base.Add(2*time.Second)) ||
		!set.retain(3, base.Add(3*time.Second)) {
		t.Fatal("initial retain failed")
	}
	if !set.retain(1, base.Add(500*time.Millisecond)) {
		t.Fatal("shorter update failed")
	}
	if !set.retain(1, base.Add(4*time.Second)) {
		t.Fatal("longer update failed")
	}
	set.prune(base.Add(2500 * time.Millisecond))
	if set.contains(2) {
		t.Fatal("earliest expired entry remained")
	}
	if !set.contains(3) || !set.contains(1) {
		t.Fatal("later entries were pruned early")
	}
	set.prune(base.Add(5 * time.Second))
	if len(set.entries) != 0 || len(set.index) != 0 {
		t.Fatalf("set not empty after expiry: entries=%d index=%d", len(set.entries), len(set.index))
	}
}

func TestExpirySetDoesNotEvictLiveEntryWhenFull(t *testing.T) {
	set := newExpirySet[int](1)
	base := time.Unix(1_000, 0)
	if !set.retain(1, base.Add(time.Second)) {
		t.Fatal("first retain failed")
	}
	if set.retain(2, base.Add(2*time.Second)) {
		t.Fatal("live entry was evicted")
	}
	set.prune(base.Add(time.Second))
	if !set.retain(2, base.Add(2*time.Second)) {
		t.Fatal("expired capacity was not reusable")
	}
}

func TestExpirySetStartsSmallButKeepsBound(t *testing.T) {
	set := newExpirySet[int](4096)
	if cap(set.entries) != expirySetInitialCapacity {
		t.Fatalf("initial heap capacity = %d, want %d", cap(set.entries), expirySetInitialCapacity)
	}
	if set.limit != 4096 {
		t.Fatalf("expiry limit = %d, want 4096", set.limit)
	}
}
