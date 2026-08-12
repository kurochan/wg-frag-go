package innerip

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseIPv4BoundsDataToTotalLength(t *testing.T) {
	t.Parallel()
	packet := make([]byte, 24)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 20
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{198, 51, 100, 2})
	parsed, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 4 || parsed.Source != netip.MustParseAddr("192.0.2.1") || parsed.Destination != netip.MustParseAddr("198.51.100.2") || len(parsed.Data) != 20 || cap(parsed.Data) != 20 {
		t.Fatalf("parsed = %#v", parsed)
	}
}

func TestParseExactRejectsIPv4TrailingData(t *testing.T) {
	t.Parallel()
	packet := make([]byte, 24)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 20
	if _, err := ParseExact(packet); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("ParseExact() error = %v, want ErrTrailingData", err)
	}
}

func TestParseIPv6(t *testing.T) {
	t.Parallel()
	packet := make([]byte, 44)
	packet[0] = 0x60
	packet[4], packet[5] = 0, 4
	packet[6] = 59 // No Next Header
	copy(packet[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("2001:db8::2").AsSlice())
	parsed, err := Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 6 || parsed.Source != netip.MustParseAddr("2001:db8::1") || parsed.Destination != netip.MustParseAddr("2001:db8::2") || len(parsed.Data) != 44 || cap(parsed.Data) != 44 {
		t.Fatalf("parsed = %#v", parsed)
	}
}

func TestParseRejectsNativeFragment(t *testing.T) {
	t.Parallel()
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 20
	packet[6] = 0x20
	if _, err := Parse(packet); !errors.Is(err, ErrNativeFragment) {
		t.Fatalf("Parse() error = %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x45})
	f.Add([]byte{0x60})
	f.Add([]byte{
		0x45, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0,
		192, 0, 2, 1, 198, 51, 100, 2,
	})
	f.Add([]byte{
		0x60, 0, 0, 0, 0, 0, 59, 64,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 2,
	})

	f.Fuzz(func(t *testing.T, packet []byte) {
		parsed, err := Parse(packet)
		if err != nil {
			return
		}
		if parsed.Version != 4 && parsed.Version != 6 {
			t.Fatalf("version = %d", parsed.Version)
		}
		if !parsed.Source.IsValid() || !parsed.Destination.IsValid() {
			t.Fatalf("invalid addresses: source=%v destination=%v", parsed.Source, parsed.Destination)
		}
		if len(parsed.Data) == 0 || len(parsed.Data) > len(packet) || cap(parsed.Data) != len(parsed.Data) {
			t.Fatalf("invalid bounded payload: len=%d cap=%d input=%d", len(parsed.Data), cap(parsed.Data), len(packet))
		}
	})
}
