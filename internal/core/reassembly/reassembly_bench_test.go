package reassembly

import (
	"fmt"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
)

// BenchmarkAcceptFragmented1500 measures the fixed-slot path while a
// controlled number of incomplete packets occupies the front of the pool.
// Each measured operation reassembles and releases one 1500-byte packet from
// two 750-byte records. Keeping this benchmark here makes free-list regressions
// visible without involving the network or the rest of the datapath.
func BenchmarkAcceptFragmented1500(b *testing.B) {
	for _, held := range []int{0, 64, 256, 1024, 3072} {
		b.Run(fmt.Sprintf("held_%d", held), func(b *testing.B) {
			r, err := New(Config{
				Slots:         4096,
				MaxPacketSize: 1500,
				MaxPeers:      1,
				PerPeerSlots:  4096,
				Lifetime:      time.Hour,
			})
			if err != nil {
				b.Fatal(err)
			}
			now := time.Unix(1, 0)
			part0 := make([]byte, 750)
			part1 := make([]byte, 750)
			for sequence := 0; sequence < held; sequence++ {
				key := Key{PeerID: 0, DataSessionID: 1, LaneID: 0, LaneSequence: uint32(sequence)}
				if result, err := r.Accept(now, key, fragmentedRecord(key, 0, 0, part0)); err != nil || result.Status != StatusAccepted {
					b.Fatalf("setup Accept(%d) = (%+v, %v)", sequence, result, err)
				}
			}

			b.ReportAllocs()
			b.ReportMetric(1500, "inner_bytes/op")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := Key{PeerID: 0, DataSessionID: 1, LaneID: 0, LaneSequence: uint32(held + i)}
				result, err := r.Accept(now, key, fragmentedRecord(key, 0, 0, part0))
				if err != nil || result.Status != StatusAccepted {
					b.Fatalf("first Accept() = (%+v, %v)", result, err)
				}
				result, err = r.Accept(now, key, fragmentedRecord(key, 1, 750, part1))
				if err != nil || result.Status != StatusCompleted {
					b.Fatalf("second Accept() = (%+v, %v)", result, err)
				}
				if err := r.Release(result.Packet.Handle); err != nil {
					b.Fatalf("Release() error = %v", err)
				}
			}
		})
	}
}

func fragmentedRecord(key Key, index uint8, offset uint16, data []byte) carrier.Record {
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
