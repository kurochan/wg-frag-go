package reassembly

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
)

func testConfig() Config {
	return Config{Slots: 4, MaxPacketSize: 64, MaxPeers: 4, PerPeerSlots: 2, Lifetime: time.Second}
}

func testKey(peer PeerID, sequence uint32) Key {
	return Key{PeerID: peer, DataSessionID: 1, LaneID: 2, LaneSequence: sequence}
}

func testRecord(key Key, index, count uint8, offset uint16, data string) carrier.Record {
	return carrier.Record{
		Header: carrier.Header{
			FragmentIndex: index,
			FragmentCount: count,
			LaneID:        key.LaneID,
			DataSessionID: key.DataSessionID,
			LaneSequence:  key.LaneSequence,
			Offset:        offset,
		},
		Data: []byte(data),
	}
}

func mustNew(t *testing.T, config Config) *Reassembler {
	t.Helper()
	r, err := New(config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return r
}

func TestOutOfOrderCompletion(t *testing.T) {
	t.Parallel()
	r := mustNew(t, testConfig())
	key := testKey(0, 10)
	now := time.Unix(100, 0)

	result, err := r.Accept(now, key, testRecord(key, 1, 2, 3, "def"))
	if err != nil || result.Status != StatusAccepted {
		t.Fatalf("first Accept() = (%+v, %v)", result, err)
	}
	result, err = r.Accept(now.Add(time.Millisecond), key, testRecord(key, 0, 2, 0, "abc"))
	if err != nil || result.Status != StatusCompleted {
		t.Fatalf("second Accept() = (%+v, %v)", result, err)
	}
	if !bytes.Equal(result.Packet.Data, []byte("abcdef")) {
		t.Fatalf("completed data = %q", result.Packet.Data)
	}
	if cap(result.Packet.Data) != len(result.Packet.Data) {
		t.Fatalf("completed data cap = %d, want %d", cap(result.Packet.Data), len(result.Packet.Data))
	}
	if err := r.Release(result.Packet.Handle); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
}

func TestDuplicateAndConflicts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		second func(Key) carrier.Record
		want   error
		status ResultStatus
	}{
		{name: "exact duplicate", second: func(k Key) carrier.Record { return testRecord(k, 0, 2, 0, "abc") }, status: StatusDuplicate},
		{name: "same index different data", second: func(k Key) carrier.Record { return testRecord(k, 0, 2, 0, "abd") }, want: ErrFragmentConflict},
		{name: "same index different offset", second: func(k Key) carrier.Record { return testRecord(k, 0, 2, 1, "abc") }, want: ErrFragmentConflict},
		{name: "fragment count mismatch", second: func(k Key) carrier.Record { return testRecord(k, 1, 3, 3, "def") }, want: ErrFragmentCountMismatch},
		{name: "overlap", second: func(k Key) carrier.Record { return testRecord(k, 1, 2, 2, "def") }, want: ErrFragmentOverlap},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustNew(t, testConfig())
			key := testKey(0, 1)
			now := time.Unix(100, 0)
			if _, err := r.Accept(now, key, testRecord(key, 0, 2, 0, "abc")); err != nil {
				t.Fatal(err)
			}
			result, err := r.Accept(now, key, tt.second(key))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Accept() error = %v, want %v", err, tt.want)
			}
			if tt.want == nil && result.Status != tt.status {
				t.Fatalf("Accept() status = %v, want %v", result.Status, tt.status)
			}
			if tt.want != nil && r.findKey(key) >= 0 {
				t.Fatal("conflicting packet retained its slot")
			}
		})
	}
}

func TestCoverageGapDropsPacket(t *testing.T) {
	t.Parallel()
	r := mustNew(t, testConfig())
	key := testKey(0, 1)
	now := time.Unix(100, 0)
	if _, err := r.Accept(now, key, testRecord(key, 0, 2, 0, "ab")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(now, key, testRecord(key, 1, 2, 3, "cd")); !errors.Is(err, ErrCoverage) {
		t.Fatalf("Accept() error = %v, want %v", err, ErrCoverage)
	}
	if r.findKey(key) >= 0 {
		t.Fatal("gapped packet retained its slot")
	}
}

func TestInvalidRecordDropsPacket(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*carrier.Record)
		want   error
	}{
		{name: "zero count", mutate: func(r *carrier.Record) { r.Header.FragmentCount = 0 }, want: ErrInvalidFragment},
		{name: "over max count", mutate: func(r *carrier.Record) { r.Header.FragmentCount = 17 }, want: ErrInvalidFragment},
		{name: "index at count", mutate: func(r *carrier.Record) { r.Header.FragmentIndex = r.Header.FragmentCount }, want: ErrInvalidFragment},
		{name: "empty data", mutate: func(r *carrier.Record) { r.Data = nil }, want: ErrInvalidRange},
		{name: "range past max packet", mutate: func(r *carrier.Record) { r.Header.Offset = 63; r.Data = []byte("xx") }, want: ErrInvalidRange},
		{name: "key mismatch", mutate: func(r *carrier.Record) { r.Header.LaneID++ }, want: ErrKeyMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustNew(t, testConfig())
			key := testKey(0, 1)
			now := time.Unix(100, 0)
			if _, err := r.Accept(now, key, testRecord(key, 0, 2, 0, "abc")); err != nil {
				t.Fatal(err)
			}
			record := testRecord(key, 1, 2, 3, "def")
			tt.mutate(&record)
			if _, err := r.Accept(now, key, record); !errors.Is(err, tt.want) {
				t.Fatalf("Accept() error = %v, want %v", err, tt.want)
			}
			if r.findKey(key) >= 0 {
				t.Fatal("invalid packet retained its slot")
			}
		})
	}
}

func FuzzAcceptAndExpire(f *testing.F) {
	f.Add(uint8(0), uint8(1), uint16(0), uint32(1), []byte("payload"))
	f.Add(uint8(1), uint8(2), uint16(3), uint32(9), []byte("fragment"))
	f.Fuzz(func(t *testing.T, index, count uint8, offset uint16, sequence uint32, data []byte) {
		r := mustNew(t, testConfig())

		if len(data) > 64 {
			data = data[:64]
		}
		key := Key{PeerID: PeerID(index % 4), DataSessionID: 1, LaneID: count, LaneSequence: sequence}
		result, _ := r.Accept(time.Unix(0, 0), key, carrier.Record{
			Header: carrier.Header{
				FragmentIndex: index,
				FragmentCount: count,
				LaneID:        key.LaneID,
				DataSessionID: key.DataSessionID,
				LaneSequence:  key.LaneSequence,
				Offset:        offset,
			},
			Data: data,
		})
		if result.Status == StatusCompleted {
			if err := r.Release(result.Packet.Handle); err != nil {
				t.Fatalf("Release() error = %v", err)
			}
		}
		_ = r.Expire(time.Unix(2, 0))
	})
}

func TestLifetimeDoesNotExtend(t *testing.T) {
	t.Parallel()
	r := mustNew(t, testConfig())
	key := testKey(0, 1)
	t0 := time.Unix(100, 0)
	first := testRecord(key, 0, 2, 0, "abc")
	if _, err := r.Accept(t0, key, first); err != nil {
		t.Fatal(err)
	}
	if result, err := r.Accept(t0.Add(900*time.Millisecond), key, first); err != nil || result.Status != StatusDuplicate {
		t.Fatalf("duplicate Accept() = (%+v, %v)", result, err)
	}
	if got := r.Expire(t0.Add(time.Second)); got != 1 {
		t.Fatalf("Expire() = %d, want 1", got)
	}
	result, err := r.Accept(t0.Add(time.Second), key, testRecord(key, 1, 2, 3, "def"))
	if err != nil || result.Status != StatusAccepted {
		t.Fatalf("post-expiry Accept() = (%+v, %v)", result, err)
	}
}

func TestGlobalOldestEviction(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Slots = 2
	config.PerPeerSlots = 2
	r := mustNew(t, config)
	t0 := time.Unix(100, 0)
	a := testKey(0, 1)
	b := testKey(1, 1)
	c := testKey(1, 2)
	_, _ = r.Accept(t0, a, testRecord(a, 0, 2, 0, "a"))
	_, _ = r.Accept(t0.Add(time.Millisecond), b, testRecord(b, 0, 2, 0, "b"))
	result, err := r.Accept(t0.Add(2*time.Millisecond), c, testRecord(c, 0, 2, 0, "c"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Evicted || result.EvictedKey != a {
		t.Fatalf("eviction = (%v, %+v), want oldest %+v", result.Evicted, result.EvictedKey, a)
	}
	if r.findKey(a) >= 0 || r.findKey(b) < 0 || r.findKey(c) < 0 {
		t.Fatal("global eviction removed wrong slot")
	}
}

func TestPeerQuotaEvictionIsolation(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Slots = 3
	config.PerPeerSlots = 1
	r := mustNew(t, config)
	t0 := time.Unix(100, 0)
	a1 := testKey(0, 1)
	a2 := testKey(0, 2)
	b := testKey(1, 1)
	_, _ = r.Accept(t0, a1, testRecord(a1, 0, 2, 0, "a"))
	_, _ = r.Accept(t0.Add(time.Millisecond), b, testRecord(b, 0, 2, 0, "b"))
	result, err := r.Accept(t0.Add(2*time.Millisecond), a2, testRecord(a2, 0, 2, 0, "c"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Evicted || result.EvictedKey != a1 {
		t.Fatalf("eviction = (%v, %+v), want same-peer %+v", result.Evicted, result.EvictedKey, a1)
	}
	if r.findKey(a1) >= 0 || r.findKey(a2) < 0 || r.findKey(b) < 0 {
		t.Fatal("peer quota eviction crossed peer boundary")
	}
}

func TestCompletedSlotProtection(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Slots = 1
	config.PerPeerSlots = 1
	r := mustNew(t, config)
	now := time.Unix(100, 0)
	a := testKey(0, 1)
	b := testKey(1, 1)
	completed, err := r.Accept(now, a, testRecord(a, 0, 1, 0, "done"))
	if err != nil || completed.Status != StatusCompleted {
		t.Fatalf("complete Accept() = (%+v, %v)", completed, err)
	}
	if got := r.Expire(now.Add(2 * time.Second)); got != 0 {
		t.Fatalf("Expire() released %d completed slots", got)
	}
	if _, err := r.Accept(now, b, testRecord(b, 0, 2, 0, "b")); !errors.Is(err, ErrNoSlot) {
		t.Fatalf("Accept() error = %v, want %v", err, ErrNoSlot)
	}
	if err := r.Release(completed.Packet.Handle); err != nil {
		t.Fatal(err)
	}
	if result, err := r.Accept(now, b, testRecord(b, 0, 2, 0, "b")); err != nil || result.Status != StatusAccepted {
		t.Fatalf("Accept() after release = (%+v, %v)", result, err)
	}
}

func TestFreeSlotListPreservesReleaseAndGenerationSemantics(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Slots = 2
	config.PerPeerSlots = 2
	r := mustNew(t, config)
	now := time.Unix(100, 0)

	first, err := r.Accept(now, testKey(0, 1), testRecord(testKey(0, 1), 0, 1, 0, "first"))
	if err != nil || first.Status != StatusCompleted {
		t.Fatalf("first completion = (%+v, %v)", first, err)
	}
	second, err := r.Accept(now, testKey(0, 2), testRecord(testKey(0, 2), 0, 1, 0, "second"))
	if err != nil || second.Status != StatusCompleted {
		t.Fatalf("second completion = (%+v, %v)", second, err)
	}
	if r.freeHead != -1 {
		t.Fatalf("freeHead with all completed slots = %d, want -1", r.freeHead)
	}

	if err := r.Release(first.Packet.Handle); err != nil {
		t.Fatalf("Release(first) error = %v", err)
	}
	if r.freeHead != first.Packet.Handle.index {
		t.Fatalf("freeHead after Release(first) = %d, want %d", r.freeHead, first.Packet.Handle.index)
	}
	if err := r.Release(first.Packet.Handle); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("duplicate Release(first) error = %v, want %v", err, ErrInvalidHandle)
	}

	reused, err := r.Accept(now, testKey(0, 3), testRecord(testKey(0, 3), 0, 1, 0, "reused"))
	if err != nil || reused.Status != StatusCompleted {
		t.Fatalf("reused completion = (%+v, %v)", reused, err)
	}
	if reused.Packet.Handle.index != first.Packet.Handle.index {
		t.Fatalf("reused slot index = %d, want %d", reused.Packet.Handle.index, first.Packet.Handle.index)
	}
	if reused.Packet.Handle.generation == first.Packet.Handle.generation {
		t.Fatal("reused slot generation did not advance")
	}
	if err := r.Release(first.Packet.Handle); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("stale Release(first) error = %v, want %v", err, ErrInvalidHandle)
	}
	if got := r.findKey(testKey(0, 3)); got != reused.Packet.Handle.index {
		t.Fatalf("reused key index = %d, want %d", got, reused.Packet.Handle.index)
	}

	if err := r.Release(second.Packet.Handle); err != nil {
		t.Fatalf("Release(second) error = %v", err)
	}
	if err := r.Release(reused.Packet.Handle); err != nil {
		t.Fatalf("Release(reused) error = %v", err)
	}
	if r.freeHead != 0 || r.slots[0].freeNext != 1 || r.slots[1].freeNext != -1 {
		t.Fatalf("free list after all releases = head %d, nexts [%d,%d]", r.freeHead, r.slots[0].freeNext, r.slots[1].freeNext)
	}
}

func TestFreeSlotListReusesEvictedSlotWithoutScanState(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Slots = 2
	config.PerPeerSlots = 2
	r := mustNew(t, config)
	now := time.Unix(100, 0)
	a := testKey(0, 1)
	b := testKey(0, 2)
	c := testKey(0, 3)

	if _, err := r.Accept(now, a, testRecord(a, 0, 2, 0, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(now.Add(time.Millisecond), b, testRecord(b, 0, 2, 0, "b")); err != nil {
		t.Fatal(err)
	}
	result, err := r.Accept(now.Add(2*time.Millisecond), c, testRecord(c, 0, 2, 0, "c"))
	if err != nil || !result.Evicted {
		t.Fatalf("eviction Accept() = (%+v, %v)", result, err)
	}
	if r.freeHead != -1 {
		t.Fatalf("freeHead after replacement = %d, want -1", r.freeHead)
	}
	if r.findKey(a) >= 0 || r.findKey(b) < 0 || r.findKey(c) < 0 {
		t.Fatal("free-list replacement corrupted active key index")
	}
}

func TestCompletedSlotBlocksPeerQuota(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Slots = 2
	config.PerPeerSlots = 1
	r := mustNew(t, config)
	now := time.Unix(100, 0)
	completedKey := testKey(0, 1)
	nextSamePeer := testKey(0, 2)
	otherPeer := testKey(1, 1)
	completed, err := r.Accept(now, completedKey, testRecord(completedKey, 0, 1, 0, "done"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(now, nextSamePeer, testRecord(nextSamePeer, 0, 2, 0, "next")); !errors.Is(err, ErrPeerQuota) {
		t.Fatalf("same-peer Accept() error = %v, want %v", err, ErrPeerQuota)
	}
	if result, err := r.Accept(now, otherPeer, testRecord(otherPeer, 0, 2, 0, "other")); err != nil || result.Status != StatusAccepted {
		t.Fatalf("other-peer Accept() = (%+v, %v)", result, err)
	}
	if err := r.Release(completed.Packet.Handle); err != nil {
		t.Fatal(err)
	}
}

func TestPurgePeerDetachesCompletedSlot(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Slots = 2
	config.PerPeerSlots = 1
	r := mustNew(t, config)
	now := time.Unix(100, 0)
	completedKey := testKey(0, 1)
	assemblingKey := testKey(1, 1)
	completed, _ := r.Accept(now, completedKey, testRecord(completedKey, 0, 1, 0, "done"))
	_, _ = r.Accept(now, assemblingKey, testRecord(assemblingKey, 0, 2, 0, "part"))
	if got := r.PurgePeer(0); got != 1 {
		t.Fatalf("PurgePeer() = %d, want 1", got)
	}
	if r.findKey(completedKey) >= 0 {
		t.Fatal("purged completed key remains discoverable")
	}
	if !bytes.Equal(completed.Packet.Data, []byte("done")) {
		t.Fatal("purge invalidated completed data before release")
	}
	if err := r.Release(completed.Packet.Handle); err != nil {
		t.Fatal(err)
	}
	if got := r.PurgePeer(1); got != 1 {
		t.Fatalf("PurgePeer(assembling) = %d, want 1", got)
	}
}

func TestHotPathAllocations(t *testing.T) {
	config := testConfig()
	config.Slots = 1
	config.PerPeerSlots = 1
	r := mustNew(t, config)
	now := time.Unix(100, 0)
	data := []byte("packet")

	var sequence uint32

	allocs := testing.AllocsPerRun(1000, func() {
		sequence++
		key := testKey(0, sequence)
		record := carrier.Record{
			Header: carrier.Header{FragmentCount: 1, LaneID: key.LaneID, DataSessionID: key.DataSessionID, LaneSequence: key.LaneSequence},
			Data:   data,
		}
		result, err := r.Accept(now, key, record)
		if err != nil || result.Status != StatusCompleted {
			panic("unexpected Accept result")
		}
		if err := r.Release(result.Packet.Handle); err != nil {
			panic("unexpected Release result")
		}
	})
	if allocs != 0 {
		t.Fatalf("hot path allocations = %v, want 0", allocs)
	}
}

func TestKeyIndexBackshiftDeletion(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.PerPeerSlots = config.Slots
	r := mustNew(t, config)
	keys := make([]Key, 0, 3)
	bucket := -1

	for sequence := uint32(1); len(keys) < 3; sequence++ {
		key := testKey(0, sequence)
		position := r.keyPosition(key)
		if bucket < 0 {
			bucket = position
		}
		if position == bucket {
			keys = append(keys, key)
		}
	}
	now := time.Unix(100, 0)

	for _, key := range keys {
		if _, err := r.Accept(now, key, testRecord(key, 0, 2, 0, "part")); err != nil {
			t.Fatal(err)
		}
	}
	middle := r.findKey(keys[1])
	if middle < 0 {
		t.Fatal("middle collision key missing")
	}
	r.clearSlot(middle)
	if r.findKey(keys[0]) < 0 || r.findKey(keys[2]) < 0 {
		t.Fatal("backshift deletion broke a colliding key lookup")
	}
	if got := r.findKey(keys[1]); got >= 0 {
		t.Fatalf("removed collision key remains at slot %d", got)
	}
}
