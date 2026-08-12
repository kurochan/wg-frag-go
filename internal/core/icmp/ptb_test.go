package icmp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func ipv4Original(src, dst [4]byte, proto byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = proto
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	copy(packet[20:], payload)
	return packet
}

func ipv6Original(src, dst [16]byte, next byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = next
	packet[7] = 64
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	copy(packet[40:], payload)
	return packet
}

// verifyChecksum recomputes the RFC 1071 sum over data; a valid checksum
// field makes the total fold to zero.
func verifyChecksum(t *testing.T, data []byte, initial uint32) {
	t.Helper()
	sum := initial
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if uint16(sum) != 0xffff {
		t.Fatalf("checksum does not verify: %#04x", uint16(sum))
	}
}

func TestBuildPacketTooBigIPv4(t *testing.T) {
	t.Parallel()
	original := ipv4Original([4]byte{10, 1, 0, 1}, [4]byte{10, 2, 0, 1}, 17, make([]byte, 1400))
	buf := make([]byte, MaxPacketTooBigSize)
	n, err := BuildPacketTooBig(buf, original, netip.MustParseAddr("10.0.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	packet := buf[:n]
	if len(packet) != 20+8+20+8 {
		t.Fatalf("length = %d, want IP + ICMP + quoted header + 8", len(packet))
	}
	if packet[9] != 1 || packet[20] != 3 || packet[21] != 4 {
		t.Fatalf("not a Fragmentation Needed message: proto=%d type=%d code=%d", packet[9], packet[20], packet[21])
	}
	if got := binary.BigEndian.Uint16(packet[26:28]); got != 1420 {
		t.Fatalf("next-hop MTU = %d, want 1420", got)
	}
	if [4]byte(packet[16:20]) != [4]byte{10, 1, 0, 1} {
		t.Fatalf("destination = %v, want original source", packet[16:20])
	}
	verifyChecksum(t, packet[:20], 0)
	var pseudo uint32
	verifyChecksum(t, packet[20:], pseudo)
}

func TestBuildPacketTooBigIPv6(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("fd00::1").As16()
	dst := netip.MustParseAddr("fd00::2").As16()
	original := ipv6Original(src, dst, 17, make([]byte, 4000))
	buf := make([]byte, MaxPacketTooBigSize)
	n, err := BuildPacketTooBig(buf, original, netip.MustParseAddr("fd00::ffff"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	packet := buf[:n]
	if len(packet) != MaxPacketTooBigSize {
		t.Fatalf("length = %d, want the IPv6 minimum MTU", len(packet))
	}
	if packet[6] != 58 || packet[40] != 2 || packet[41] != 0 {
		t.Fatalf("not a Packet Too Big message: next=%d type=%d code=%d", packet[6], packet[40], packet[41])
	}
	if got := binary.BigEndian.Uint32(packet[44:48]); got != 1420 {
		t.Fatalf("MTU = %d, want 1420", got)
	}
	if [16]byte(packet[24:40]) != src {
		t.Fatalf("destination = %x, want original source", packet[24:40])
	}
	var pseudo uint32
	for i := 8; i < 40; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	pseudo += uint32(len(packet)-40) + 58
	verifyChecksum(t, packet[40:], pseudo)
}

func TestBuildPacketTooBigSuppression(t *testing.T) {
	t.Parallel()
	v4src := netip.MustParseAddr("10.0.0.1")
	v6src := netip.MustParseAddr("fd00::ffff")
	unicast6 := netip.MustParseAddr("fd00::1").As16()
	cases := []struct {
		name     string
		original []byte
		source   netip.Addr
	}{
		{"ipv4 multicast destination", ipv4Original([4]byte{10, 1, 0, 1}, [4]byte{224, 0, 0, 1}, 17, make([]byte, 32)), v4src},
		{"ipv4 broadcast destination", ipv4Original([4]byte{10, 1, 0, 1}, [4]byte{255, 255, 255, 255}, 17, make([]byte, 32)), v4src},
		{"ipv4 icmp error original", ipv4Original([4]byte{10, 1, 0, 1}, [4]byte{10, 2, 0, 1}, 1, []byte{3, 1, 0, 0, 0, 0, 0, 0}), v4src},
		{"ipv6 multicast destination", ipv6Original(unicast6, netip.MustParseAddr("ff02::1").As16(), 17, make([]byte, 32)), v6src},
		{"ipv6 unspecified source", ipv6Original([16]byte{}, unicast6, 17, make([]byte, 32)), v6src},
		{"ipv6 icmp error original", ipv6Original(unicast6, netip.MustParseAddr("fd00::2").As16(), 58, []byte{1, 0, 0, 0, 0, 0, 0, 0}), v6src},
	}
	buf := make([]byte, MaxPacketTooBigSize)
	for _, tc := range cases {
		if _, err := BuildPacketTooBig(buf, tc.original, tc.source, 1420); !errors.Is(err, ErrSuppressed) {
			t.Errorf("%s: err = %v, want ErrSuppressed", tc.name, err)
		}
	}

	echo := ipv4Original([4]byte{10, 1, 0, 1}, [4]byte{10, 2, 0, 1}, 1, []byte{8, 0, 0, 0, 0, 0, 0, 0})
	if _, err := BuildPacketTooBig(buf, echo, v4src, 1420); err != nil {
		t.Errorf("ICMP echo request original: err = %v, want success", err)
	}
	reply := ipv6Original(unicast6, netip.MustParseAddr("fd00::2").As16(), 58, []byte{129, 0, 0, 0, 0, 0, 0, 0})
	if _, err := BuildPacketTooBig(buf, reply, v6src, 1420); err != nil {
		t.Errorf("ICMPv6 echo reply original: err = %v, want success", err)
	}
}

func TestBuildPacketTooBigFamilyMismatch(t *testing.T) {
	t.Parallel()
	buf := make([]byte, MaxPacketTooBigSize)
	v4 := ipv4Original([4]byte{10, 1, 0, 1}, [4]byte{10, 2, 0, 1}, 17, make([]byte, 32))
	if _, err := BuildPacketTooBig(buf, v4, netip.MustParseAddr("fd00::1"), 1420); !errors.Is(err, ErrBadSource) {
		t.Fatalf("v4 original with v6 source: err = %v, want ErrBadSource", err)
	}
	v6 := ipv6Original(netip.MustParseAddr("fd00::1").As16(), netip.MustParseAddr("fd00::2").As16(), 17, make([]byte, 32))
	if _, err := BuildPacketTooBig(buf, v6, netip.MustParseAddr("10.0.0.1"), 1420); !errors.Is(err, ErrBadSource) {
		t.Fatalf("v6 original with v4 source: err = %v, want ErrBadSource", err)
	}
}

func TestBuildPacketTooBigRejectsInvalidOriginalLengthAndMTU(t *testing.T) {
	t.Parallel()
	buf := make([]byte, MaxPacketTooBigSize)
	v4 := ipv4Original([4]byte{10, 1, 0, 1}, [4]byte{10, 2, 0, 1}, 17, make([]byte, 32))
	v4[2], v4[3] = 0, 19
	if _, err := BuildPacketTooBig(buf, v4, netip.MustParseAddr("10.0.0.1"), 1420); !errors.Is(err, ErrBadOriginal) {
		t.Fatalf("invalid IPv4 total length error = %v, want ErrBadOriginal", err)
	}
	v6 := ipv6Original(netip.MustParseAddr("fd00::1").As16(), netip.MustParseAddr("fd00::2").As16(), 17, make([]byte, 32))
	v6[5]++
	if _, err := BuildPacketTooBig(buf, v6, netip.MustParseAddr("fd00::ffff"), 1420); !errors.Is(err, ErrBadOriginal) {
		t.Fatalf("invalid IPv6 payload length error = %v, want ErrBadOriginal", err)
	}
	if _, err := BuildPacketTooBig(buf, v4[:20], netip.MustParseAddr("10.0.0.1"), 0); !errors.Is(err, ErrInvalidMTU) {
		t.Fatalf("invalid MTU error = %v, want ErrInvalidMTU", err)
	}
}
