package lane

import (
	"encoding/binary"
	"errors"
	"testing"
)

func udp4(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], srcIP[:])
	copy(packet[16:20], dstIP[:])
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func vxlan(inner []byte) []byte {
	frame := make([]byte, 8+14+len(inner))
	frame[0] = 0x08 // VXLAN flags: VNI present
	frame[8+12] = 0x08
	frame[8+13] = 0x00 // EtherType IPv4
	copy(frame[8+14:], inner)
	return frame
}

func TestLaneIsStableAndFlowSensitive(t *testing.T) {
	t.Parallel()
	c, err := NewClassifier(DefaultDepth)
	if err != nil {
		t.Fatal(err)
	}
	base := udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1000, 2000, make([]byte, 32))
	first := c.Lane(base)
	if first != c.Lane(base) {
		t.Fatal("same packet must map to the same lane")
	}
	same := udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 1000, 2000, []byte{9, 9, 9})
	if c.Lane(base) != c.Lane(same) {
		t.Fatal("payload bytes beyond the flow key must not change the lane")
	}
	distinct := map[uint8]bool{}
	for port := uint16(0); port < 512; port++ {
		distinct[c.Lane(udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, port, 2000, nil))] = true
	}
	if len(distinct) < 64 {
		t.Fatalf("512 flows landed on %d lanes; hash is not spreading", len(distinct))
	}
}

func TestLaneDescendsIntoVXLAN(t *testing.T) {
	t.Parallel()
	c, err := NewClassifier(2)
	if err != nil {
		t.Fatal(err)
	}
	innerA := udp4([4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 5, 6, nil)
	innerB := udp4([4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 7, 8, nil)
	outerA := udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 4444, vxlanPort, vxlan(innerA))
	outerB := udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 4444, vxlanPort, vxlan(innerB))
	if c.Lane(outerA) == c.Lane(outerB) {
		// One in 256 honest collisions is possible; a keyed rehash with more
		// inner flows distinguishes a real parse failure.
		different := false
		for port := uint16(0); port < 64 && !different; port++ {
			inner := udp4([4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, port, 6, nil)
			different = c.Lane(udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 4444, vxlanPort, vxlan(inner))) != c.Lane(outerA)
		}
		if !different {
			t.Fatal("VXLAN inner flow does not affect the lane at depth 2")
		}
	}

	shallow, err := NewClassifier(1)
	if err != nil {
		t.Fatal(err)
	}
	if shallow.Lane(outerA) != shallow.Lane(outerB) {
		t.Fatal("depth 1 must ignore the VXLAN inner flow")
	}
}

func TestLaneFallsBackOnMalformedEncapsulation(t *testing.T) {
	t.Parallel()
	c, err := NewClassifier(4)
	if err != nil {
		t.Fatal(err)
	}
	truncated := udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 4444, vxlanPort, []byte{0x08, 0, 0, 0})
	control := udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 4444, vxlanPort, nil)
	if c.Lane(truncated) != c.Lane(control) {
		t.Fatal("malformed VXLAN payload must fall back to the outer flow key")
	}
}

func TestNewClassifierRejectsBadDepth(t *testing.T) {
	t.Parallel()

	for _, depth := range []int{0, 5, -1} {
		if _, err := NewClassifier(depth); !errors.Is(err, ErrDepth) {
			t.Fatalf("NewClassifier(%d) = %v, want ErrDepth", depth, err)
		}
	}
}

func TestLaneAllocationFree(t *testing.T) {
	c, err := NewClassifier(2)
	if err != nil {
		t.Fatal(err)
	}
	inner := udp4([4]byte{192, 168, 0, 1}, [4]byte{192, 168, 0, 2}, 5, 6, nil)
	packet := udp4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 4444, vxlanPort, vxlan(inner))
	if avg := testing.AllocsPerRun(200, func() { c.Lane(packet) }); avg != 0 {
		t.Fatalf("Lane allocates %.1f times per call", avg)
	}
}
