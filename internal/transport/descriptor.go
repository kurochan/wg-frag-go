package transport

import (
	"net/netip"

	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

// PeerID is the authenticated logical peer identity used at the transport
// boundary. It aliases the core routing identity so adapters do not need a
// lossy conversion at the hot-path call site.
type PeerID = peerroute.PeerID

// TXDescriptor describes one carrier payload produced by the shim. Payload
// is caller-owned storage supplied before the read. Length is set to the
// number of bytes written; bytes after Length are not part of the descriptor.
// The buffer is borrowed only for the duration of the read call and must not
// be retained by an adapter after it returns.
type TXDescriptor struct {
	PeerID         PeerID
	Payload        []byte
	Length         int
	PathGeneration uint64
}

// RXDescriptor describes one authenticated carrier payload delivered to the
// shim. Payload and Length are borrowed synchronously from the caller. The
// adapter must complete authentication and peer attribution before filling
// PeerID; the shim does not infer identity from an endpoint or payload.
type RXDescriptor struct {
	PeerID         PeerID
	Payload        []byte
	Length         int
	PathGeneration uint64
}

// TXBatch and RXBatch are aliases for caller-owned descriptor arrays. Aliases
// (rather than wrapper structs) keep the API compatible with fixed arrays and
// avoid a batch allocation at the call boundary.
type TXBatch = []TXDescriptor
type RXBatch = []RXDescriptor

// PathEventKind identifies a transport observation that the shim may use for
// PMTU or path-state bookkeeping. Transport-specific handshake and NAT state
// do not cross this boundary.
type PathEventKind uint8

const (
	PathEventUnknown PathEventKind = iota
	PathEventMessageTooLarge
)

// OuterFamily identifies the address family of the transport path.
type OuterFamily uint8

const (
	OuterFamilyUnknown OuterFamily = iota
	OuterFamilyIPv4
	OuterFamilyIPv6
)

// PathEvent reports a transport-level path observation. Optional values are
// guarded by their *Known fields; zero values are otherwise meaningful only as
// unknown. Err is transport-provided context and must not be retained by the
// shim after event handling returns.
type PathEvent struct {
	Kind              PathEventKind
	Err               error
	Family            OuterFamily
	DatagramSize      int
	DatagramSizeKnown bool
	Endpoint          netip.AddrPort
	EndpointKnown     bool
}

// Bytes returns the borrowed bytes described by d. It returns nil for an
// invalid length instead of slicing, allowing callers to reject a malformed
// descriptor without a panic.
func (d TXDescriptor) Bytes() []byte {
	return descriptorBytes(d.Payload, d.Length)
}

// Bytes returns the borrowed bytes described by d.
func (d RXDescriptor) Bytes() []byte {
	return descriptorBytes(d.Payload, d.Length)
}

func descriptorBytes(payload []byte, length int) []byte {
	if length < 0 || length > len(payload) {
		return nil
	}
	return payload[:length]
}
