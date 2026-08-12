package innerip

import (
	"errors"
	"net/netip"
)

var (
	ErrTooShort       = errors.New("inner IP packet too short")
	ErrUnsupportedIP  = errors.New("unsupported inner IP version")
	ErrInvalidIPv4    = errors.New("invalid IPv4 header")
	ErrInvalidIPv6    = errors.New("invalid IPv6 extension header")
	ErrTrailingData   = errors.New("IP datagram has trailing data")
	ErrNativeFragment = errors.New("native IP fragment is unsupported")
)

// Packet is a length-validated non-fragmented IPv4 or IPv6 datagram. Data
// aliases the caller buffer and is bounded to the IP total length.
type Packet struct {
	Version     uint8
	Source      netip.Addr
	Destination netip.Addr
	Data        []byte
}

// Parse validates the IP length, rejects native fragments, and returns the
// source/destination needed by the user AllowedIPs mirror. IPv6 jumbograms
// are deliberately unsupported in v1 because inner MTU is at most 9612.
func Parse(packet []byte) (Packet, error) {
	fragmented, err := HasNativeFragment(packet)
	if err != nil {
		return Packet{}, err
	}
	if fragmented {
		return Packet{}, ErrNativeFragment
	}

	switch packet[0] >> 4 {
	case 4:
		length := int(packet[2])<<8 | int(packet[3])
		return Packet{
			Version:     4,
			Source:      netip.AddrFrom4([4]byte(packet[12:16])),
			Destination: netip.AddrFrom4([4]byte(packet[16:20])),
			Data:        packet[:length:length],
		}, nil
	case 6:
		length := 40 + int(packet[4])<<8 + int(packet[5])
		return Packet{
			Version:     6,
			Source:      netip.AddrFrom16([16]byte(packet[8:24])),
			Destination: netip.AddrFrom16([16]byte(packet[24:40])),
			Data:        packet[:length:length],
		}, nil
	default:
		return Packet{}, ErrUnsupportedIP
	}
}

// ParseExact is Parse with a strict datagram-length check. It is used at the
// receive boundary so bytes outside an IP total length cannot be smuggled
// through the source-validation and delivery path.
func ParseExact(packet []byte) (Packet, error) {
	parsed, err := Parse(packet)
	if err != nil {
		return Packet{}, err
	}
	if len(parsed.Data) != len(packet) {
		return Packet{}, ErrTrailingData
	}
	return parsed, nil
}

// HasNativeFragment reports whether packet is an already-fragmented IPv4 or
// IPv6 datagram. WGF v1 rejects these packets rather than nesting native IP
// fragmentation inside its bounded record reassembly.
func HasNativeFragment(packet []byte) (bool, error) {
	if len(packet) == 0 {
		return false, ErrTooShort
	}

	switch packet[0] >> 4 {
	case 4:
		return ipv4Fragmented(packet)
	case 6:
		return ipv6Fragmented(packet)
	default:
		return false, ErrUnsupportedIP
	}
}

func ipv4Fragmented(packet []byte) (bool, error) {
	if len(packet) < 20 {
		return false, ErrTooShort
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return false, ErrInvalidIPv4
	}
	totalLen := int(packet[2])<<8 | int(packet[3])
	if totalLen < headerLen || totalLen > len(packet) {
		return false, ErrInvalidIPv4
	}
	flagsOffset := uint16(packet[6])<<8 | uint16(packet[7])
	return flagsOffset&0x2000 != 0 || flagsOffset&0x1fff != 0, nil
}

func ipv6Fragmented(packet []byte) (bool, error) {
	if len(packet) < 40 {
		return false, ErrTooShort
	}
	payloadLen := int(packet[4])<<8 | int(packet[5])
	if len(packet) != 40+payloadLen {
		return false, ErrInvalidIPv6
	}

	next := packet[6]
	offset := 40

	for extensions := 0; extensions < 4; extensions++ {
		switch next {
		case 44: // Fragment Header
			if offset+8 > len(packet) {
				return false, ErrInvalidIPv6
			}
			return true, nil
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if offset+2 > len(packet) {
				return false, ErrInvalidIPv6
			}
			next = packet[offset]
			headerLen := (int(packet[offset+1]) + 1) * 8
			if headerLen < 8 || offset+headerLen > len(packet) {
				return false, ErrInvalidIPv6
			}
			offset += headerLen
		case 51: // Authentication Header
			if offset+2 > len(packet) {
				return false, ErrInvalidIPv6
			}
			next = packet[offset]
			headerLen := (int(packet[offset+1]) + 2) * 4
			if headerLen < 8 || offset+headerLen > len(packet) {
				return false, ErrInvalidIPv6
			}
			offset += headerLen
		default:
			return false, nil
		}
	}
	return false, ErrInvalidIPv6
}
