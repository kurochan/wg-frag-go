package peerroute

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/crypto/blake2s"
)

const (
	// PublicKeySize is the size in bytes of a WireGuard static public key.
	PublicKeySize = 32

	carrierAddressDomain = "wg-frag/carrier-address/v1:"
)

var (
	// ErrInvalidPublicKey is returned when a public key is not exactly 32
	// bytes or is the all-zero value.
	ErrInvalidPublicKey = errors.New("invalid WireGuard public key")

	// ErrNoPublicKeys is returned when collision checking is requested without
	// the local public key and peer public keys.
	ErrNoPublicKeys = errors.New("no WireGuard public keys")
)

// AddressCollisionError reports two entries that derive the same hidden
// carrier address. Index zero is conventionally the local public key and
// subsequent indexes are peer public keys.
type AddressCollisionError struct {
	Address     netip.Addr
	FirstIndex  int
	SecondIndex int
}

func (e *AddressCollisionError) Error() string {
	return fmt.Sprintf(
		"carrier address collision at %s between public key indexes %d and %d",
		e.Address,
		e.FirstIndex,
		e.SecondIndex,
	)
}

// DeriveCarrierAddress derives a hidden IPv6 link-local carrier address from
// a raw WireGuard static public key.
//
// The address IID is the first eight bytes, in network byte order, of:
//
//	BLAKE2s-256("wg-frag/carrier-address/v1:" || publicKey)
func DeriveCarrierAddress(publicKey []byte) (netip.Addr, error) {
	if len(publicKey) != PublicKeySize || isAllZero(publicKey) {
		return netip.Addr{}, ErrInvalidPublicKey
	}

	var input [len(carrierAddressDomain) + PublicKeySize]byte

	copy(input[:], carrierAddressDomain)
	copy(input[len(carrierAddressDomain):], publicKey)
	digest := blake2s.Sum256(input[:])

	var address [16]byte
	address[0] = 0xfe
	address[1] = 0x80
	copy(address[8:], digest[:8])
	return netip.AddrFrom16(address), nil
}

// DeriveUniqueCarrierAddresses derives addresses for the local public key and
// every peer public key, failing closed if any input is invalid or two entries
// derive the same address. Index zero is conventionally the local public key.
// Returned addresses preserve input order.
func DeriveUniqueCarrierAddresses(publicKeys [][]byte) ([]netip.Addr, error) {
	if len(publicKeys) == 0 {
		return nil, ErrNoPublicKeys
	}

	addresses := make([]netip.Addr, len(publicKeys))
	seen := make(map[netip.Addr]int, len(publicKeys))

	for index, publicKey := range publicKeys {
		address, err := DeriveCarrierAddress(publicKey)
		if err != nil {
			return nil, fmt.Errorf("public key index %d: %w", index, err)
		}
		if firstIndex, ok := seen[address]; ok {
			return nil, &AddressCollisionError{
				Address:     address,
				FirstIndex:  firstIndex,
				SecondIndex: index,
			}
		}
		seen[address] = index
		addresses[index] = address
	}
	return addresses, nil
}

func isAllZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
