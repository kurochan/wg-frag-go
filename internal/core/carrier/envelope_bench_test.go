package carrier

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
)

// BenchmarkMarshalEnvelopeToExpansion compares the former overlapping
// expansion layout with the TUN adapter's headroom layout. Both cases call
// MarshalEnvelopeTo exactly once per measured operation. Buffers and payload
// bytes are initialized before the timer; the old overlap source is
// intentionally not restored inside the loop so the benchmark measures only
// envelope marshaling and its payload move.
func BenchmarkMarshalEnvelopeToExpansion(b *testing.B) {
	for _, payloadSize := range []int{613, 1400} {
		b.Run(fmt.Sprintf("overlap_%d", payloadSize), func(b *testing.B) {
			benchmarkMarshalEnvelopeTo(b, payloadSize, false)
		})
		b.Run(fmt.Sprintf("headroom_%d", payloadSize), func(b *testing.B) {
			benchmarkMarshalEnvelopeTo(b, payloadSize, true)
		})
	}
}

func benchmarkMarshalEnvelopeTo(b *testing.B, payloadSize int, headroom bool) {
	b.Helper()
	source := netip.MustParseAddr("fe80::1")
	destination := netip.MustParseAddr("fe80::2")
	payload := bytes.Repeat([]byte{0x5a}, payloadSize)
	packet := make([]byte, IPv6HeaderSize+payloadSize)
	if headroom {
		copy(packet[IPv6HeaderSize:], payload)
	} else {
		copy(packet, payload)
	}

	b.ReportAllocs()
	b.SetBytes(int64(payloadSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var input []byte
		if headroom {
			input = packet[IPv6HeaderSize:]
		} else {
			input = packet[:payloadSize]
		}
		if _, err := MarshalEnvelopeTo(packet, source, destination, input); err != nil {
			b.Fatal(err)
		}
	}
}
