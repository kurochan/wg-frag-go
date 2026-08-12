// Package icmp builds the Packet Too Big errors returned to inner senders
// whose packets exceed a peer's advertised receive MTU.
package icmp

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

// MaxPacketTooBigSize bounds every generated message: an ICMPv6 error must
// fit the IPv6 minimum link MTU, and the IPv4 variant is always smaller.
const MaxPacketTooBigSize = 1280

var (
	ErrShortBuffer = errors.New("icmp: buffer too small")
	ErrSuppressed  = errors.New("icmp: no error may be generated for this packet")
	ErrBadOriginal = errors.New("icmp: original packet is not a valid IP packet")
	ErrBadSource   = errors.New("icmp: source address family does not match original")
	// ErrInvalidMTU reports a peer MTU outside the v1 inner-MTU range.
	ErrInvalidMTU = errors.New("icmp: advertised MTU is outside the v1 range")
)

// BuildPacketTooBig writes an IPv4 Fragmentation Needed or ICMPv6 Packet Too
// Big message for original into buf and returns its length. source becomes
// the outer IP source; mtu is the peer's advertised inner MTU. Suppression
// (RFC 1122 / RFC 4443: ICMP errors, multicast/broadcast destinations, and
// invalid source addresses) returns ErrSuppressed so callers can count silent
// drops separately.
func BuildPacketTooBig(buf, original []byte, source netip.Addr, mtu int) (int, error) {
	if len(original) == 0 {
		return 0, ErrBadOriginal
	}
	if mtu < limits.MinInnerMTU || mtu > limits.MaxInnerMTU {
		return 0, ErrInvalidMTU
	}

	switch original[0] >> 4 {
	case 4:
		if !source.Is4() || source.Zone() != "" {
			return 0, ErrBadSource
		}
		return buildIPv4(buf, original, source, mtu)
	case 6:
		if !source.Is6() || source.Is4In6() || source.Zone() != "" {
			return 0, ErrBadSource
		}
		return buildIPv6(buf, original, source, mtu)
	default:
		return 0, ErrBadOriginal
	}
}

func buildIPv4(buf, original []byte, source netip.Addr, mtu int) (int, error) {
	if len(original) < 20 {
		return 0, ErrBadOriginal
	}
	headerLen := int(original[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(original) {
		return 0, ErrBadOriginal
	}
	totalLen := int(binary.BigEndian.Uint16(original[2:4]))
	if totalLen < headerLen || totalLen > len(original) {
		return 0, ErrBadOriginal
	}
	original = original[:totalLen]
	if suppressIPv4(original, headerLen) {
		return 0, ErrSuppressed
	}
	quote := headerLen + 8
	if quote > len(original) {
		quote = len(original)
	}
	total := 20 + 8 + quote
	if total > len(buf) {
		return 0, ErrShortBuffer
	}
	ip := buf[:20]
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	binary.BigEndian.PutUint32(ip[4:8], 0)
	ip[8] = 64
	ip[9] = 1 // ICMP
	binary.BigEndian.PutUint16(ip[10:12], 0)
	src := source.As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], original[12:16])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip, 0))

	msg := buf[20:total]
	msg[0] = 3 // Destination Unreachable
	msg[1] = 4 // Fragmentation Needed and DF set
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint16(msg[4:6], 0)
	binary.BigEndian.PutUint16(msg[6:8], uint16(mtu))
	copy(msg[8:], original[:quote])
	binary.BigEndian.PutUint16(msg[2:4], checksum(msg, 0))
	return total, nil
}

func buildIPv6(buf, original []byte, source netip.Addr, mtu int) (int, error) {
	if len(original) < 40 {
		return 0, ErrBadOriginal
	}
	payloadLen := int(binary.BigEndian.Uint16(original[4:6]))
	if payloadLen != len(original)-40 {
		return 0, ErrBadOriginal
	}
	if suppressIPv6(original) {
		return 0, ErrSuppressed
	}
	quote := len(original)
	if maxSize := MaxPacketTooBigSize - 40 - 8; quote > maxSize {
		quote = maxSize
	}
	total := 40 + 8 + quote
	if total > len(buf) {
		return 0, ErrShortBuffer
	}
	ip := buf[:40]
	ip[0] = 0x60
	ip[1], ip[2], ip[3] = 0, 0, 0
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+quote))
	ip[6] = 58 // ICMPv6
	ip[7] = 64
	src := source.As16()
	copy(ip[8:24], src[:])
	copy(ip[24:40], original[8:24])

	msg := buf[40:total]
	msg[0] = 2 // Packet Too Big
	msg[1] = 0
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], uint32(mtu))
	copy(msg[8:], original[:quote])

	var pseudo uint32
	for i := 8; i < 40; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	pseudo += uint32(len(msg)) + 58
	binary.BigEndian.PutUint16(msg[2:4], checksum(msg, pseudo))
	return total, nil
}

func suppressIPv4(original []byte, headerLen int) bool {
	src := netip.AddrFrom4([4]byte(original[12:16]))
	dst := netip.AddrFrom4([4]byte(original[16:20]))

	if !src.IsGlobalUnicast() && !src.IsPrivate() && !src.IsLinkLocalUnicast() {
		return true
	}
	if dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	if original[9] == 1 && headerLen < len(original) {
		switch original[headerLen] {
		case 3, 4, 5, 11, 12: // ICMP error messages
			return true
		}
	}
	return false
}

func suppressIPv6(original []byte) bool {
	src := netip.AddrFrom16([16]byte(original[8:24]))
	dst := netip.AddrFrom16([16]byte(original[24:40]))

	if src.IsUnspecified() || src.IsMulticast() {
		return true
	}
	if dst.IsMulticast() {
		return true
	}
	next := original[6]
	offset := 40
	// The walk mirrors innerip's bounded extension-header scan.
	for extensions := 0; extensions < 4; extensions++ {
		switch next {
		case 58: // ICMPv6
			// Error messages have the high type bit clear.
			return offset >= len(original) || original[offset] < 128
		case 0, 43, 60:
			if offset+2 > len(original) {
				return true
			}
			next = original[offset]
			headerLen := (int(original[offset+1]) + 1) * 8
			if offset+headerLen > len(original) {
				return true
			}
			offset += headerLen
		case 51:
			if offset+2 > len(original) {
				return true
			}
			next = original[offset]
			headerLen := (int(original[offset+1]) + 2) * 4
			if offset+headerLen > len(original) {
				return true
			}
			offset += headerLen
		default:
			return false
		}
	}
	return true
}

// checksum is the RFC 1071 internet checksum with an initial partial sum.
func checksum(data []byte, initial uint32) uint16 {
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
	return ^uint16(sum)
}
