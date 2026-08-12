package innerip

import (
	"errors"
	"testing"
)

func TestHasNativeFragmentIPv4(t *testing.T) {
	t.Parallel()
	normal := ipv4Packet(0)
	fragment, err := HasNativeFragment(normal)
	if err != nil || fragment {
		t.Fatalf("normal IPv4 = (%v, %v)", fragment, err)
	}
	for _, flagsOffset := range []uint16{0x2000, 0x0001, 0x3fff} {
		fragment, err := HasNativeFragment(ipv4Packet(flagsOffset))
		if err != nil || !fragment {
			t.Fatalf("IPv4 flags/offset %#x = (%v, %v)", flagsOffset, fragment, err)
		}
	}
}

func TestHasNativeFragmentIPv6(t *testing.T) {
	t.Parallel()
	normal := make([]byte, 40)
	normal[0] = 0x60
	normal[6] = 17
	fragment, err := HasNativeFragment(normal)
	if err != nil || fragment {
		t.Fatalf("normal IPv6 = (%v, %v)", fragment, err)
	}

	withFragment := make([]byte, 48)
	withFragment[0] = 0x60
	withFragment[5] = 8
	withFragment[6] = 44
	fragment, err = HasNativeFragment(withFragment)
	if err != nil || !fragment {
		t.Fatalf("fragment IPv6 = (%v, %v)", fragment, err)
	}
}

func TestHasNativeFragmentRejectsMalformedPackets(t *testing.T) {
	t.Parallel()
	if _, err := HasNativeFragment(nil); !errors.Is(err, ErrTooShort) {
		t.Fatalf("empty error = %v", err)
	}
	if _, err := HasNativeFragment([]byte{0x70}); !errors.Is(err, ErrUnsupportedIP) {
		t.Fatalf("unknown version error = %v", err)
	}
	badV4 := ipv4Packet(0)
	badV4[2] = 0
	badV4[3] = 0
	if _, err := HasNativeFragment(badV4); !errors.Is(err, ErrInvalidIPv4) {
		t.Fatalf("bad IPv4 error = %v", err)
	}
	badV6 := make([]byte, 40)
	badV6[0] = 0x60
	badV6[5] = 1
	if _, err := HasNativeFragment(badV6); !errors.Is(err, ErrInvalidIPv6) {
		t.Fatalf("bad IPv6 error = %v", err)
	}
}

func ipv4Packet(flagsOffset uint16) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = 20
	packet[6] = byte(flagsOffset >> 8)
	packet[7] = byte(flagsOffset)
	return packet
}
