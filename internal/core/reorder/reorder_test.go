package reorder

import (
	"errors"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/reassembly"
)

func testConfig() Config {
	return Config{
		Enabled:      true,
		Capacity:     3,
		MaxDelay:     10 * time.Millisecond,
		Lane:         Lane{PeerID: 1, DataSessionID: 2, LaneID: 3},
		NextSequence: 10,
	}
}

func testPacket(sequence uint32) reassembly.Packet {
	return reassembly.Packet{Key: reassembly.Key{PeerID: 1, DataSessionID: 2, LaneID: 3, LaneSequence: sequence}}
}

func mustNew(t *testing.T, config Config) *Reorderer {
	t.Helper()
	r, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDisabledDeliversArrivalOrder(t *testing.T) {
	t.Parallel()
	r := mustNew(t, Config{Enabled: false})
	out := make([]reassembly.Packet, 1)
	result, err := r.Accept(time.Time{}, testPacket(99), out)
	if err != nil || result.Status != StatusDelivered || result.Delivered != 1 || out[0].Key.LaneSequence != 99 {
		t.Fatalf("Accept() = (%+v, %v), output=%d", result, err, out[0].Key.LaneSequence)
	}
}

func TestInOrderDrainsHeldPackets(t *testing.T) {
	t.Parallel()
	r := mustNew(t, testConfig())
	out := make([]reassembly.Packet, 4)
	now := time.Unix(100, 0)
	if result, err := r.Accept(now, testPacket(11), out); err != nil || result.Status != StatusQueued {
		t.Fatalf("queue 11 = (%+v, %v)", result, err)
	}
	result, err := r.Accept(now, testPacket(10), out)
	if err != nil || result.Status != StatusDelivered || result.Delivered != 2 {
		t.Fatalf("deliver 10 = (%+v, %v)", result, err)
	}
	if out[0].Key.LaneSequence != 10 || out[1].Key.LaneSequence != 11 {
		t.Fatalf("output = %d, %d", out[0].Key.LaneSequence, out[1].Key.LaneSequence)
	}
}

func TestDelayFlushSkipsGapWithoutDroppingHeldPackets(t *testing.T) {
	t.Parallel()
	r := mustNew(t, testConfig())
	out := make([]reassembly.Packet, 4)
	now := time.Unix(100, 0)
	_, _ = r.Accept(now, testPacket(12), out)
	_, _ = r.Accept(now, testPacket(14), out)
	if delivered, err := r.Tick(now.Add(9*time.Millisecond), out); err != nil || delivered != 0 {
		t.Fatalf("early Tick() = (%d, %v)", delivered, err)
	}
	delivered, err := r.Tick(now.Add(10*time.Millisecond), out)
	if err != nil || delivered != 2 || out[0].Key.LaneSequence != 12 || out[1].Key.LaneSequence != 14 {
		t.Fatalf("flush Tick() = (%d, %v), output=%d,%d", delivered, err, out[0].Key.LaneSequence, out[1].Key.LaneSequence)
	}
}

func TestOverflowFlushesHeldAndIncoming(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Capacity = 2
	r := mustNew(t, config)
	out := make([]reassembly.Packet, 3)
	now := time.Unix(100, 0)
	_, _ = r.Accept(now, testPacket(12), out)
	_, _ = r.Accept(now, testPacket(14), out)
	result, err := r.Accept(now, testPacket(13), out)
	if err != nil || result.Status != StatusFlushed || result.Delivered != 3 {
		t.Fatalf("overflow Accept() = (%+v, %v)", result, err)
	}
	for i, want := range []uint32{12, 13, 14} {
		if out[i].Key.LaneSequence != want {
			t.Fatalf("output[%d] = %d, want %d", i, out[i].Key.LaneSequence, want)
		}
	}
}

func TestLateDuplicateAndWraparound(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.NextSequence = ^uint32(0)
	r := mustNew(t, config)
	out := make([]reassembly.Packet, 4)
	now := time.Unix(100, 0)
	result, err := r.Accept(now, testPacket(0), out)
	if err != nil || result.Status != StatusQueued {
		t.Fatalf("queue wrapped packet = (%+v, %v)", result, err)
	}
	result, err = r.Accept(now, testPacket(0), out)
	if err != nil || result.Status != StatusDuplicate {
		t.Fatalf("duplicate = (%+v, %v)", result, err)
	}
	result, err = r.Accept(now, testPacket(^uint32(0)), out)
	if err != nil || result.Delivered != 2 || out[0].Key.LaneSequence != ^uint32(0) || out[1].Key.LaneSequence != 0 {
		t.Fatalf("wrap delivery = (%+v, %v), output=%d,%d", result, err, out[0].Key.LaneSequence, out[1].Key.LaneSequence)
	}
	result, err = r.Accept(now, testPacket(^uint32(0)), out)
	if err != nil || result.Status != StatusLate {
		t.Fatalf("late = (%+v, %v)", result, err)
	}
}

func TestOutputAndLaneValidation(t *testing.T) {
	t.Parallel()
	r := mustNew(t, testConfig())
	if _, err := r.Accept(time.Time{}, testPacket(10), nil); !errors.Is(err, ErrOutputTooSmall) {
		t.Fatalf("short output error = %v", err)
	}
	wrong := testPacket(10)
	wrong.Key.LaneID++
	if _, err := r.Accept(time.Time{}, wrong, make([]reassembly.Packet, 4)); !errors.Is(err, ErrWrongLane) {
		t.Fatalf("wrong lane error = %v", err)
	}
}

func TestResetReturnsHeldPackets(t *testing.T) {
	t.Parallel()
	r := mustNew(t, testConfig())
	out := make([]reassembly.Packet, 4)
	_, _ = r.Accept(time.Unix(100, 0), testPacket(12), out)
	_, _ = r.Accept(time.Unix(100, 0), testPacket(13), out)
	if _, err := r.Reset(20, out[:1]); !errors.Is(err, ErrOutputTooSmall) {
		t.Fatalf("short reset output error = %v", err)
	}
	n, err := r.Reset(20, out)
	if err != nil || n != 2 {
		t.Fatalf("Reset() = (%d, %v)", n, err)
	}
	result, err := r.Accept(time.Unix(100, 0), testPacket(20), out)
	if err != nil || result.Delivered != 1 || out[0].Key.LaneSequence != 20 {
		t.Fatalf("post-reset Accept() = (%+v, %v), output=%d", result, err, out[0].Key.LaneSequence)
	}
}

func TestHotPathDoesNotAllocate(t *testing.T) {
	config := testConfig()
	config.Enabled = false
	r := mustNew(t, config)
	out := make([]reassembly.Packet, 1)
	packet := testPacket(1)
	allocs := testing.AllocsPerRun(1000, func() {
		result, err := r.Accept(time.Time{}, packet, out)
		if err != nil || result.Delivered != 1 {
			panic("unexpected result")
		}
	})
	if allocs != 0 {
		t.Fatalf("Accept() allocations = %v, want 0", allocs)
	}
}
