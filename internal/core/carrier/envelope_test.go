package carrier

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	t.Parallel()
	source := netip.MustParseAddr("fe80::1")
	destination := netip.MustParseAddr("fe80::2")
	payload := []byte{1, 2, 3}
	packet := make([]byte, IPv6HeaderSize+len(payload))

	n, err := MarshalEnvelopeTo(packet, source, destination, payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(packet) {
		t.Fatalf("MarshalEnvelopeTo() = %d, want %d", n, len(packet))
	}
	if packet[0] != 0x60 || packet[6] != CarrierNextHeader || packet[7] != carrierHopLimit {
		t.Fatalf("unexpected IPv6 fixed fields: %x", packet[:8])
	}

	envelope, err := ParseEnvelope(packet, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Source != source || envelope.Destination != destination || !bytes.Equal(envelope.Payload, payload) {
		t.Fatalf("ParseEnvelope() = %#v", envelope)
	}
	packet[IPv6HeaderSize] = 9
	if envelope.Payload[0] != 9 {
		t.Fatal("payload does not alias packet")
	}
}

func TestMarshalEnvelopeToAllowsInPlacePayloadExpansion(t *testing.T) {
	t.Parallel()
	source := netip.MustParseAddr("fe80::1")
	destination := netip.MustParseAddr("fe80::2")
	want := []byte{1, 2, 3, 4, 5}
	packet := make([]byte, IPv6HeaderSize+len(want))
	copy(packet, want)

	if _, err := MarshalEnvelopeTo(packet, source, destination, packet[:len(want)]); err != nil {
		t.Fatal(err)
	}
	envelope, err := ParseEnvelope(packet, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope.Payload, want) {
		t.Fatalf("payload = %x, want %x", envelope.Payload, want)
	}
}

func TestParseEnvelopeRejectsMalformedPackets(t *testing.T) {
	t.Parallel()
	source := netip.MustParseAddr("fe80::1")
	destination := netip.MustParseAddr("fe80::2")
	valid := make([]byte, IPv6HeaderSize+1)
	if _, err := MarshalEnvelopeTo(valid, source, destination, []byte{1}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		packet []byte
		want   error
	}{
		{name: "short", packet: valid[:IPv6HeaderSize-1], want: ErrCarrierTooShort},
		{name: "version", packet: append([]byte(nil), valid...), want: ErrCarrierVersion},
		{name: "next header", packet: append([]byte(nil), valid...), want: ErrCarrierNextHeader},
		{name: "payload length", packet: append([]byte(nil), valid...), want: ErrCarrierPayloadSize},
		{name: "source", packet: append([]byte(nil), valid...), want: ErrCarrierSource},
		{name: "destination", packet: append([]byte(nil), valid...), want: ErrCarrierDestination},
	}
	tests[1].packet[0] = 0x40
	tests[2].packet[6] = 17
	tests[3].packet[5] = 2
	tests[4].packet[23] = 3
	tests[5].packet[39] = 3

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseEnvelope(tt.packet, source, destination); !errors.Is(err, tt.want) {
				t.Fatalf("ParseEnvelope() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCarrierAddressMustBeUnscopedIPv6(t *testing.T) {
	t.Parallel()
	dst := make([]byte, IPv6HeaderSize)
	if _, err := MarshalEnvelopeTo(dst, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("fe80::1"), nil); !errors.Is(err, ErrCarrierAddress) {
		t.Fatalf("MarshalEnvelopeTo() error = %v, want ErrCarrierAddress", err)
	}
}

func FuzzParseEnvelope(f *testing.F) {
	source := netip.MustParseAddr("fe80::1")
	destination := netip.MustParseAddr("fe80::2")
	valid := make([]byte, IPv6HeaderSize+3)
	if _, err := MarshalEnvelopeTo(valid, source, destination, []byte{1, 2, 3}); err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, IPv6HeaderSize-1))

	f.Fuzz(func(t *testing.T, packet []byte) {
		envelope, err := ParseEnvelope(packet, source, destination)
		if err != nil {
			return
		}
		if envelope.Source != source || envelope.Destination != destination {
			t.Fatalf("unexpected endpoints: source=%v destination=%v", envelope.Source, envelope.Destination)
		}
		if len(packet) < IPv6HeaderSize || !bytes.Equal(envelope.Payload, packet[IPv6HeaderSize:]) {
			t.Fatal("payload is not the validated packet suffix")
		}
	})
}

func TestDecodeEnvelopeReturnsSourceForPeerLookup(t *testing.T) {
	t.Parallel()
	source := netip.MustParseAddr("fe80::2")
	local := netip.MustParseAddr("fe80::1")
	packet := make([]byte, IPv6HeaderSize+4)
	written, err := MarshalEnvelopeTo(packet, source, local, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeEnvelope(packet[:written], local)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Source != source || envelope.Destination != local {
		t.Fatalf("envelope = %+v", envelope)
	}
	globalSource := append([]byte(nil), packet[:written]...)
	globalAddress := netip.MustParseAddr("2001:db8::2").As16()
	copy(globalSource[8:24], globalAddress[:])
	if _, err := DecodeEnvelope(globalSource, local); !errors.Is(err, ErrCarrierSource) {
		t.Fatalf("global source error = %v, want ErrCarrierSource", err)
	}
	// An unexpected source is the owner's decision, not the decoder's.
	other := netip.MustParseAddr("fe80::9")
	if _, err := DecodeEnvelope(packet[:written], other); !errors.Is(err, ErrCarrierDestination) {
		t.Fatalf("wrong destination error = %v, want ErrCarrierDestination", err)
	}
}
