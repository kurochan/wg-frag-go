package reorder

import (
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/reassembly"
)

// BenchmarkAcceptInOrderEmptyQueue covers the common in-order path where no
// completed packets are waiting behind a gap. It guards the O(1) empty drain
// fast path independently of carrier I/O and receiver bookkeeping.
func BenchmarkAcceptInOrderEmptyQueue(b *testing.B) {
	config := testConfig()
	config.Capacity = 64
	r, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	out := make([]reassembly.Packet, config.Capacity+1)
	packet := testPacket(config.NextSequence)
	now := time.Unix(1, 0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet.Key.LaneSequence = config.NextSequence + uint32(i)
		result, err := r.Accept(now, packet, out)
		if err != nil || result.Status != StatusDelivered || result.Delivered != 1 {
			b.Fatalf("Accept() = (%+v, %v)", result, err)
		}
	}
}

// BenchmarkAcceptFragmented1500 includes the two-record reassembly immediately
// before the in-order reorder operation. It keeps the 1500-byte fragmented
// shape visible while measuring the common empty reorder queue path in context.
func BenchmarkAcceptFragmented1500(b *testing.B) {
	config := testConfig()
	config.Capacity = 64
	r, err := New(config)
	if err != nil {
		b.Fatal(err)
	}
	assembler, err := reassembly.New(reassembly.Config{
		Slots:         1,
		MaxPacketSize: 1500,
		MaxPeers:      2,
		PerPeerSlots:  1,
		Lifetime:      time.Hour,
	})
	if err != nil {
		b.Fatal(err)
	}
	part0 := make([]byte, 750)
	part1 := make([]byte, 750)
	out := make([]reassembly.Packet, config.Capacity+1)
	now := time.Unix(1, 0)

	b.ReportAllocs()
	b.ReportMetric(1500, "inner_bytes/op")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := reassembly.Key{PeerID: config.Lane.PeerID, DataSessionID: config.Lane.DataSessionID, LaneID: config.Lane.LaneID, LaneSequence: config.NextSequence + uint32(i)}
		first, err := assembler.Accept(now, key, fragmentedRecord(key, 0, 0, part0))
		if err != nil || first.Status != reassembly.StatusAccepted {
			b.Fatalf("first fragment Accept() = (%+v, %v)", first, err)
		}
		second, err := assembler.Accept(now, key, fragmentedRecord(key, 1, 750, part1))
		if err != nil || second.Status != reassembly.StatusCompleted {
			b.Fatalf("second fragment Accept() = (%+v, %v)", second, err)
		}
		result, err := r.Accept(now, second.Packet, out)
		if err != nil || result.Status != StatusDelivered || result.Delivered != 1 {
			b.Fatalf("reorder Accept() = (%+v, %v)", result, err)
		}
		if err := assembler.Release(second.Packet.Handle); err != nil {
			b.Fatalf("Release() error = %v", err)
		}
	}
}

func fragmentedRecord(key reassembly.Key, index uint8, offset uint16, data []byte) carrier.Record {
	return carrier.Record{
		Header: carrier.Header{
			FragmentIndex: index,
			FragmentCount: 2,
			LaneID:        key.LaneID,
			DataSessionID: key.DataSessionID,
			LaneSequence:  key.LaneSequence,
			Offset:        offset,
		},
		Data: data,
	}
}
