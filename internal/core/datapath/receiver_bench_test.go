package datapath

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

// BenchmarkReceiverFragmented1500 measures reassembly, source validation and
// ordering together, independently of encryption and platform I/O.
func BenchmarkReceiverFragmented1500(b *testing.B) {
	for _, lanes := range []int{1, 64} {
		b.Run(fmt.Sprintf("lanes=%d", lanes), func(b *testing.B) {
			r, err := NewPayloadReceiver(benchmarkReceiverConfig(256, 64))
			if err != nil {
				b.Fatal(err)
			}
			packet := make([]byte, 1500)
			packet[0] = 0x45
			binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
			copy(packet[12:16], []byte{10, 0, 0, 1})
			copy(packet[16:20], []byte{10, 0, 0, 2})
			var frames [2][]byte
			for i := range frames {
				frames[i] = make([]byte, carrier.HeaderSize+750)
				_, err := carrier.MarshalTo(frames[i], carrier.Header{
					DataSessionID: 1, FragmentCount: 2,
					FragmentIndex: uint8(i), Offset: uint16(i * 750),
				}, packet[i*750:(i+1)*750])
				if err != nil {
					b.Fatal(err)
				}
			}
			sink := benchmarkCountingSink{}
			now := time.Unix(1, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, frame := range frames {
					frame[3] = byte(i % lanes)
					binary.BigEndian.PutUint32(frame[6:10], uint32(i/lanes))
					if err := r.AcceptPayload(now, frame, &sink); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.StopTimer()
			if sink.count != b.N {
				b.Fatalf("delivered %d packets, want %d", sink.count, b.N)
			}
		})
	}
}

type benchmarkCountingSink struct{ count int }

func (s *benchmarkCountingSink) DeliverInner([]byte) error {
	s.count++
	return nil
}

type benchmarkSink struct{}

func (benchmarkSink) DeliverInner([]byte) error { return nil }

func benchmarkReceiverConfig(slots, reorderCapacity int) ReceiverConfig {
	routes, _ := peerroute.NewSnapshot([]peerroute.AllowedIP{{
		Prefix: netip.MustParsePrefix("10.0.0.0/8"),
		PeerID: 42,
	}})
	return ReceiverConfig{
		PeerID:          42,
		DataSessionID:   1,
		CarrierSource:   netip.MustParseAddr("fe80::2"),
		CarrierDest:     netip.MustParseAddr("fe80::1"),
		AllowedIPs:      routes,
		Slots:           slots,
		PerPeerSlots:    slots,
		MaxPacketSize:   1500,
		Lifetime:        time.Second,
		ReorderEnabled:  true,
		ReorderCapacity: reorderCapacity,
		ReorderMaxDelay: 10 * time.Millisecond,
	}
}

func benchmarkCarrier(lane, sequence byte, packet []byte) []byte {
	payload := make([]byte, carrier.HeaderSize+len(packet))
	_, _ = carrier.MarshalTo(payload, carrier.Header{
		FragmentCount: 1,
		DataSessionID: 1,
		LaneID:        lane,
		LaneSequence:  uint32(sequence),
	}, packet)
	outer := make([]byte, carrier.IPv6HeaderSize+len(payload))
	_, _ = carrier.MarshalEnvelopeTo(
		outer,
		netip.MustParseAddr("fe80::2"),
		netip.MustParseAddr("fe80::1"),
		payload,
	)
	return outer
}

func BenchmarkReceiverMultiLane(b *testing.B) {
	for _, lanes := range []int{1, 8, 64, 256} {
		b.Run(fmt.Sprintf("lanes=%d", lanes), func(b *testing.B) {
			r, err := NewReceiver(benchmarkReceiverConfig(256, 64))
			if err != nil {
				b.Fatal(err)
			}
			packet := make([]byte, 20)
			packet[0] = 0x45
			packet[2], packet[3] = 0, 20
			copy(packet[12:16], []byte{10, 0, 0, 1})
			copy(packet[16:20], []byte{10, 0, 0, 2})
			frames := make([][]byte, lanes)
			for lane := range frames {
				frames[lane] = benchmarkCarrier(byte(lane), 0, packet)
			}
			sink := benchmarkSink{}
			now := time.Unix(1, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lane := i % lanes
				frame := frames[lane]
				// Each lane is advanced independently; mutate only the sequence
				// field in the preallocated carrier for this benchmark.
				sequence := uint32(i / lanes)
				frame[carrier.IPv6HeaderSize+6] = byte(sequence >> 24)
				frame[carrier.IPv6HeaderSize+7] = byte(sequence >> 16)
				frame[carrier.IPv6HeaderSize+8] = byte(sequence >> 8)
				frame[carrier.IPv6HeaderSize+9] = byte(sequence)
				if err := r.AcceptCarrier(now, frame, sink); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReceiverMultiPeer(b *testing.B) {
	for _, peers := range []int{1, 2, 8} {
		b.Run(fmt.Sprintf("peers=%d", peers), func(b *testing.B) {
			receivers := make([]*Receiver, peers)
			frames := make([][]byte, peers)
			packet := make([]byte, 20)
			packet[0] = 0x45
			packet[2], packet[3] = 0, 20
			copy(packet[12:16], []byte{10, 0, 0, 1})
			copy(packet[16:20], []byte{10, 0, 0, 2})
			for i := range receivers {
				var err error
				receivers[i], err = NewReceiver(benchmarkReceiverConfig(64, 16))
				if err != nil {
					b.Fatal(err)
				}
				frames[i] = benchmarkCarrier(0, 0, packet)
			}
			sink := benchmarkSink{}
			now := time.Unix(1, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				peer := i % peers
				frame := frames[peer]
				sequence := uint32(i / peers)
				frame[carrier.IPv6HeaderSize+6] = byte(sequence >> 24)
				frame[carrier.IPv6HeaderSize+7] = byte(sequence >> 16)
				frame[carrier.IPv6HeaderSize+8] = byte(sequence >> 8)
				frame[carrier.IPv6HeaderSize+9] = byte(sequence)
				if err := receivers[peer].AcceptCarrier(now, frame, sink); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReceiverConstruction(b *testing.B) {
	for _, slots := range []int{16, 64, 256} {
		b.Run(fmt.Sprintf("slots=%d", slots), func(b *testing.B) {
			config := benchmarkReceiverConfig(slots, slots/4)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				receiver, err := NewReceiver(config)
				if err != nil {
					b.Fatal(err)
				}
				_ = receiver
			}
		})
	}
}
