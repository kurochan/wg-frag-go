package carrier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	// IPv6HeaderSize is the fixed size of the hidden carrier IPv6 header.
	IPv6HeaderSize = 40
	// CarrierNextHeader is the experimental IPv6 next-header value reserved by
	// the WGF carrier protocol.
	CarrierNextHeader = 253
	carrierHopLimit   = 64
)

var (
	ErrCarrierTooShort     = errors.New("carrier: IPv6 header too short")
	ErrCarrierVersion      = errors.New("carrier: invalid IPv6 version")
	ErrCarrierNextHeader   = errors.New("carrier: invalid IPv6 next header")
	ErrCarrierPayloadSize  = errors.New("carrier: IPv6 payload length mismatch")
	ErrCarrierSource       = errors.New("carrier: unexpected IPv6 source")
	ErrCarrierDestination  = errors.New("carrier: unexpected IPv6 destination")
	ErrCarrierAddress      = errors.New("carrier: address must be unscoped IPv6")
	ErrCarrierPayloadLimit = errors.New("carrier: payload exceeds IPv6 limit")
)

// Envelope is a validated, zero-copy hidden carrier packet. Payload aliases
// the input packet and remains valid only while that packet is unchanged.
type Envelope struct {
	Source      netip.Addr
	Destination netip.Addr
	Payload     []byte
}

// MarshalEnvelopeTo writes a v1 hidden carrier IPv6 packet into dst. The
// sender always emits traffic class 0, flow label 0, next header 253, and hop
// limit 64. It does not allocate.
func MarshalEnvelopeTo(dst []byte, source, destination netip.Addr, payload []byte) (int, error) {
	if err := validateCarrierAddress(source); err != nil {
		return 0, fmt.Errorf("source: %w", err)
	}
	if err := validateCarrierAddress(destination); err != nil {
		return 0, fmt.Errorf("destination: %w", err)
	}
	if len(payload) > maxUint16 {
		return 0, ErrCarrierPayloadLimit
	}
	required := IPv6HeaderSize + len(payload)
	if len(dst) < required {
		return 0, fmt.Errorf("%w: have %d need %d", io.ErrShortBuffer, len(dst), required)
	}

	// payload may alias dst[:len(payload)] during TUN-to-WireGuard expansion.
	// Copy it before writing the IPv6 header over that source range. The TUN
	// adapter reserves this header space, so the normal path is same-address.
	copy(dst[IPv6HeaderSize:required], payload)
	// Traffic Class and Flow Label remain zero. Write the complete word so a
	// pooled caller buffer cannot leak stale header bits between packets.
	binary.BigEndian.PutUint32(dst[:4], 6<<28)
	binary.BigEndian.PutUint16(dst[4:6], uint16(len(payload)))
	dst[6] = CarrierNextHeader
	dst[7] = carrierHopLimit
	sourceBytes := source.As16()
	destinationBytes := destination.As16()

	copy(dst[8:24], sourceBytes[:])
	copy(dst[24:40], destinationBytes[:])
	return required, nil
}

// ParseEnvelope strictly validates one hidden carrier IPv6 packet. expectedSource
// and expectedDestination are the peer-derived and local-derived carrier
// addresses, respectively. Traffic Class, Flow Label, and Hop Limit are not
// admission controls so later protocol versions can use them.
func ParseEnvelope(packet []byte, expectedSource, expectedDestination netip.Addr) (Envelope, error) {
	if err := validateCarrierAddress(expectedSource); err != nil {
		return Envelope{}, fmt.Errorf("expected source: %w", err)
	}
	envelope, err := DecodeEnvelope(packet, expectedDestination)
	if err != nil {
		return Envelope{}, err
	}
	if envelope.Source != expectedSource {
		return Envelope{}, ErrCarrierSource
	}
	return envelope, nil
}

// DecodeEnvelope validates the fixed header and the local destination, then
// returns the carrier source so a multi-peer owner can resolve which peer sent
// it. The caller must still confirm the source belongs to the peer whose key
// authenticated the packet.
func DecodeEnvelope(packet []byte, expectedDestination netip.Addr) (Envelope, error) {
	if err := validateCarrierAddress(expectedDestination); err != nil {
		return Envelope{}, fmt.Errorf("expected destination: %w", err)
	}
	if len(packet) < IPv6HeaderSize {
		return Envelope{}, ErrCarrierTooShort
	}
	if packet[0]>>4 != 6 {
		return Envelope{}, ErrCarrierVersion
	}
	if packet[6] != CarrierNextHeader {
		return Envelope{}, ErrCarrierNextHeader
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLen != len(packet)-IPv6HeaderSize {
		return Envelope{}, ErrCarrierPayloadSize
	}
	source := netip.AddrFrom16([16]byte(packet[8:24]))
	if !source.IsLinkLocalUnicast() {
		return Envelope{}, ErrCarrierSource
	}
	destination := netip.AddrFrom16([16]byte(packet[24:40]))
	if destination != expectedDestination {
		return Envelope{}, ErrCarrierDestination
	}
	return Envelope{
		Source:      source,
		Destination: destination,
		Payload:     packet[IPv6HeaderSize:],
	}, nil
}

func validateCarrierAddress(address netip.Addr) error {
	if !address.Is6() || address.Zone() != "" {
		return ErrCarrierAddress
	}
	return nil
}
