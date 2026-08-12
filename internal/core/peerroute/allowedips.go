package peerroute

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
)

var (
	// ErrInvalidAllowedIP is returned when an AllowedIPs entry has an invalid
	// or IPv4-mapped IPv6 prefix.
	ErrInvalidAllowedIP = errors.New("peerroute: invalid AllowedIPs prefix")

	// ErrDuplicateAllowedIP is returned when two entries normalize to the same
	// prefix. Exact prefix ownership must be unambiguous.
	ErrDuplicateAllowedIP = errors.New("peerroute: duplicate AllowedIPs prefix")

	// ErrTooManyAllowedIPs is returned before a trie node index would overflow.
	ErrTooManyAllowedIPs = errors.New("peerroute: too many AllowedIPs trie nodes")
)

// PeerID is a dense, process-local peer identifier. Zero is a valid peer ID.
type PeerID uint32

// AllowedIP assigns one user-visible IP prefix to a peer.
type AllowedIP struct {
	Prefix netip.Prefix
	PeerID PeerID
}

// DuplicateAllowedIPError identifies two entries that normalize to the same
// prefix.
type DuplicateAllowedIPError struct {
	Prefix      netip.Prefix
	FirstIndex  int
	SecondIndex int
	FirstPeer   PeerID
	SecondPeer  PeerID
}

func (e *DuplicateAllowedIPError) Error() string {
	return fmt.Sprintf(
		"%v %s at indexes %d (peer %d) and %d (peer %d)",
		ErrDuplicateAllowedIP,
		e.Prefix,
		e.FirstIndex,
		e.FirstPeer,
		e.SecondIndex,
		e.SecondPeer,
	)
}

// Unwrap supports errors.Is(err, ErrDuplicateAllowedIP).
func (e *DuplicateAllowedIPError) Unwrap() error { return ErrDuplicateAllowedIP }

// InvalidAllowedIPError identifies an invalid entry by input index.
type InvalidAllowedIPError struct {
	Index  int
	Prefix netip.Prefix
}

func (e *InvalidAllowedIPError) Error() string {
	return fmt.Sprintf("%v at index %d: %s", ErrInvalidAllowedIP, e.Index, e.Prefix)
}

// Unwrap supports errors.Is(err, ErrInvalidAllowedIP).
func (e *InvalidAllowedIPError) Unwrap() error { return ErrInvalidAllowedIP }

type routeNode struct {
	// Children store node index + 1. Zero means absent.
	children [2]uint32
	peerID   PeerID
	hasPeer  bool
}

type routeTrie struct {
	nodes []routeNode
}

// Snapshot is an immutable user AllowedIPs routing and source-validation
// table. Build a complete replacement with NewSnapshot and publish its pointer
// atomically; never mutate a live snapshot.
//
// LookupPeer performs global longest-prefix matching. ValidateSource uses the
// same global lookup and accepts a source only when the winning peer matches
// the authenticated carrier peer. This prevents a less-specific peer from
// spoofing a prefix assigned more specifically to another peer.
type Snapshot struct {
	v4      routeTrie
	v6      routeTrie
	entries int
}

// NewSnapshot validates every entry and builds immutable IPv4 and IPv6 tries.
// Valid prefixes are normalized with Prefix.Masked. Two inputs that normalize
// to the same prefix are rejected, even when they name the same peer.
func NewSnapshot(allowed []AllowedIP) (*Snapshot, error) {
	snapshot := &Snapshot{
		v4: routeTrie{nodes: []routeNode{{}}},
		v6: routeTrie{nodes: []routeNode{{}}},
	}

	type owner struct {
		index int
		peer  PeerID
	}
	seen := make(map[netip.Prefix]owner, len(allowed))

	for index, entry := range allowed {
		if !validAllowedPrefix(entry.Prefix) {
			return nil, &InvalidAllowedIPError{Index: index, Prefix: entry.Prefix}
		}
		prefix := entry.Prefix.Masked()

		if first, ok := seen[prefix]; ok {
			return nil, &DuplicateAllowedIPError{
				Prefix:      prefix,
				FirstIndex:  first.index,
				SecondIndex: index,
				FirstPeer:   first.peer,
				SecondPeer:  entry.PeerID,
			}
		}
		seen[prefix] = owner{index: index, peer: entry.PeerID}

		trie := &snapshot.v6
		if prefix.Addr().Is4() {
			trie = &snapshot.v4
		}

		if err := trie.insert(prefix, entry.PeerID); err != nil {
			return nil, fmt.Errorf("AllowedIPs index %d: %w", index, err)
		}
	}
	snapshot.entries = len(allowed)

	return snapshot, nil
}

// Len returns the number of prefixes in the snapshot.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}

	return s.entries
}

// LookupPeer returns the owner of the longest prefix containing address.
// Invalid, scoped, and IPv4-mapped IPv6 addresses fail closed.
func (s *Snapshot) LookupPeer(address netip.Addr) (PeerID, bool) {
	if s == nil || !validLookupAddress(address) {
		return 0, false
	}

	if address.Is4() {
		return s.v4.lookup4(address.As4())
	}

	return s.v6.lookup6(address.As16())
}

// ValidateSource reports whether source's global longest-prefix owner is the
// authenticated peer. Unknown and invalid sources fail closed.
func (s *Snapshot) ValidateSource(peer PeerID, source netip.Addr) bool {
	owner, ok := s.LookupPeer(source)
	return ok && owner == peer
}

func validAllowedPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}
	address := prefix.Addr()
	return address.IsValid() && address.Zone() == "" && !address.Is4In6()
}

func validLookupAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && !address.Is4In6()
}

func (t *routeTrie) insert(prefix netip.Prefix, peer PeerID) error {
	address := prefix.Addr()
	nodeIndex := uint32(0)

	if address.Is4() {
		bits := address.As4()
		for depth := 0; depth < prefix.Bits(); depth++ {
			child, err := t.child(nodeIndex, addressBit4(bits, depth))
			if err != nil {
				return err
			}
			nodeIndex = child
		}
	} else {
		bits := address.As16()
		for depth := 0; depth < prefix.Bits(); depth++ {
			child, err := t.child(nodeIndex, addressBit16(bits, depth))
			if err != nil {
				return err
			}
			nodeIndex = child
		}
	}

	t.nodes[nodeIndex].peerID = peer
	t.nodes[nodeIndex].hasPeer = true
	return nil
}

func (t *routeTrie) child(parent uint32, bit uint8) (uint32, error) {
	encoded := t.nodes[parent].children[bit]
	if encoded != 0 {
		return encoded - 1, nil
	}

	if uint64(len(t.nodes)) >= uint64(math.MaxUint32) {
		return 0, ErrTooManyAllowedIPs
	}

	index := uint32(len(t.nodes))
	t.nodes = append(t.nodes, routeNode{})
	t.nodes[parent].children[bit] = index + 1
	return index, nil
}

func (t routeTrie) lookup4(address [4]byte) (PeerID, bool) {
	if len(t.nodes) == 0 {
		return 0, false
	}

	nodeIndex := uint32(0)
	bestPeer := t.nodes[0].peerID
	found := t.nodes[0].hasPeer

	for depth := 0; depth < 32; depth++ {
		encoded := t.nodes[nodeIndex].children[addressBit4(address, depth)]
		if encoded == 0 {
			break
		}
		nodeIndex = encoded - 1
		node := t.nodes[nodeIndex]
		if node.hasPeer {
			bestPeer = node.peerID
			found = true
		}
	}
	return bestPeer, found
}

func (t routeTrie) lookup6(address [16]byte) (PeerID, bool) {
	if len(t.nodes) == 0 {
		return 0, false
	}
	nodeIndex := uint32(0)
	bestPeer := t.nodes[0].peerID
	found := t.nodes[0].hasPeer

	for depth := 0; depth < 128; depth++ {
		encoded := t.nodes[nodeIndex].children[addressBit16(address, depth)]
		if encoded == 0 {
			break
		}
		nodeIndex = encoded - 1
		node := t.nodes[nodeIndex]

		if node.hasPeer {
			bestPeer = node.peerID
			found = true
		}
	}
	return bestPeer, found
}

func addressBit4(address [4]byte, depth int) uint8 {
	return address[depth/8] >> (7 - uint(depth%8)) & 1
}

func addressBit16(address [16]byte, depth int) uint8 {
	return address[depth/8] >> (7 - uint(depth%8)) & 1
}
