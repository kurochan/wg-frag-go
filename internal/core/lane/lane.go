// Package lane classifies inner packets into wire lanes: the data-plane
// domains that share packet ordering, packing, reassembly, and reorder.
package lane

import (
	"encoding/binary"
	"errors"
	"hash/maphash"
)

// Lanes is the wire lane count, fixed by protocol v1 independently of the
// local worker count.
const Lanes = 256

const (
	DefaultDepth = 1
	MaxDepth     = 4

	vxlanPort = 4789
)

var ErrDepth = errors.New("lane: recursion depth must be in 1..4")

// Classifier derives a wire lane from a flow hash over the outermost IP
// 5-tuple, optionally extending it with each known encapsulated flow tuple.
// The hash key is random per process, so lane assignment is not externally
// predictable; parse failures fall back to the outermost flow key rather than
// dropping.
type Classifier struct {
	seed  maphash.Seed
	depth int
}

// NewClassifier builds a classifier that unwraps known encapsulations
// (VXLAN) up to depth levels below the outermost inner packet.
func NewClassifier(depth int) (*Classifier, error) {
	if depth < 1 || depth > MaxDepth {
		return nil, ErrDepth
	}
	return &Classifier{seed: maphash.MakeSeed(), depth: depth}, nil
}

// Lane returns the wire lane for one validated non-fragmented inner packet.
func (c *Classifier) Lane(packet []byte) uint8 {
	var hash maphash.Hash

	hash.SetSeed(c.seed)
	writeFlow(&hash, packet, c.depth)
	return uint8(hash.Sum64())
}

// writeFlow feeds one packet's 5-tuple into hash, then recurses into a known
// encapsulation payload. Anything malformed or unknown keeps what was already
// hashed, which is at worst the outermost flow key.
func writeFlow(hash *maphash.Hash, packet []byte, depth int) {
	transport, payload, ok := writeAddresses(hash, packet)
	if !ok {
		return
	}

	var ports []byte

	switch transport {
	case 6, 17, 132: // TCP, UDP, SCTP
		if len(payload) < 4 {
			return
		}
		ports = payload[:4]
		_, _ = hash.Write(ports)
	default:
		return
	}
	if depth <= 1 || transport != 17 || binary.BigEndian.Uint16(ports[2:4]) != vxlanPort {
		return
	}
	inner, ok := vxlanInner(payload)
	if !ok {
		return
	}
	writeFlow(hash, inner, depth-1)
}

// writeAddresses hashes the IP addresses and returns the transport protocol
// and its payload.
func writeAddresses(hash *maphash.Hash, packet []byte) (byte, []byte, bool) {
	if len(packet) == 0 {
		return 0, nil, false
	}

	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return 0, nil, false
		}
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen < 20 || headerLen > len(packet) {
			return 0, nil, false
		}
		_, _ = hash.Write(packet[12:20])
		_ = hash.WriteByte(packet[9])
		return packet[9], packet[headerLen:], true
	case 6:
		if len(packet) < 40 {
			return 0, nil, false
		}
		_, _ = hash.Write(packet[8:40])
		next := packet[6]
		offset := 40

		for extensions := 0; extensions < 4; extensions++ {
			switch next {
			case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
				if offset+2 > len(packet) {
					return 0, nil, false
				}
				headerLen := (int(packet[offset+1]) + 1) * 8
				if offset+headerLen > len(packet) {
					return 0, nil, false
				}
				next = packet[offset]
				offset += headerLen
			case 51: // Authentication Header
				if offset+2 > len(packet) {
					return 0, nil, false
				}
				headerLen := (int(packet[offset+1]) + 2) * 4
				if offset+headerLen > len(packet) {
					return 0, nil, false
				}
				next = packet[offset]
				offset += headerLen
			default:
				_ = hash.WriteByte(next)
				return next, packet[offset:], true
			}
		}
		return 0, nil, false
	default:
		return 0, nil, false
	}
}

// vxlanInner unwraps a VXLAN frame (UDP payload) down to its inner IP packet.
func vxlanInner(udp []byte) ([]byte, bool) {
	// UDP header 8 + VXLAN header 8 + Ethernet header 14.
	if len(udp) < 8+8+14 {
		return nil, false
	}
	frame := udp[16:]
	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[14:]
	if etherType == 0x8100 { // single VLAN tag
		if len(frame) < 18 {
			return nil, false
		}
		etherType = binary.BigEndian.Uint16(frame[16:18])
		payload = frame[18:]
	}

	switch etherType {
	case 0x0800, 0x86dd:
		return payload, true
	default:
		return nil, false
	}
}
