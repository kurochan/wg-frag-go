package peerroute

import (
	"errors"
	"net/netip"
	"testing"
)

func TestDeriveCarrierAddressKnownVector(t *testing.T) {
	t.Parallel()
	publicKey := make([]byte, PublicKeySize)
	for index := range publicKey {
		publicKey[index] = byte(index)
	}

	got, err := DeriveCarrierAddress(publicKey)
	if err != nil {
		t.Fatalf("DeriveCarrierAddress() error = %v", err)
	}
	want := netip.MustParseAddr("fe80::756d:3e88:8ba:489b")
	if got != want {
		t.Fatalf("DeriveCarrierAddress() = %s, want %s", got, want)
	}
	if !got.Is6() || !got.IsLinkLocalUnicast() {
		t.Fatalf("DeriveCarrierAddress() = %s, want IPv6 link-local unicast", got)
	}
}

func TestDeriveCarrierAddressRejectsInvalidKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "nil", key: nil},
		{name: "short", key: make([]byte, PublicKeySize-1)},
		{name: "long", key: make([]byte, PublicKeySize+1)},
		{name: "all zero", key: make([]byte, PublicKeySize)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DeriveCarrierAddress(test.key)
			if !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("DeriveCarrierAddress() error = %v, want ErrInvalidPublicKey", err)
			}
			if got.IsValid() {
				t.Fatalf("DeriveCarrierAddress() = %s, want invalid address", got)
			}
		})
	}
}

func TestDeriveUniqueCarrierAddresses(t *testing.T) {
	t.Parallel()
	local := testPublicKey(1)
	peerA := testPublicKey(2)
	peerB := testPublicKey(3)

	addresses, err := DeriveUniqueCarrierAddresses([][]byte{local, peerA, peerB})
	if err != nil {
		t.Fatalf("DeriveUniqueCarrierAddresses() error = %v", err)
	}
	if len(addresses) != 3 {
		t.Fatalf("len(addresses) = %d, want 3", len(addresses))
	}
	for first := range addresses {
		for second := first + 1; second < len(addresses); second++ {
			if addresses[first] == addresses[second] {
				t.Fatalf("addresses[%d] and addresses[%d] collide at %s", first, second, addresses[first])
			}
		}
	}
}

func TestDeriveUniqueCarrierAddressesRejectsCollision(t *testing.T) {
	t.Parallel()
	duplicate := testPublicKey(7)

	addresses, err := DeriveUniqueCarrierAddresses([][]byte{
		duplicate,
		testPublicKey(2),
		append([]byte(nil), duplicate...), // peer duplicates the local key
	})
	if addresses != nil {
		t.Fatalf("DeriveUniqueCarrierAddresses() addresses = %v, want nil", addresses)
	}

	var collision *AddressCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("DeriveUniqueCarrierAddresses() error = %v, want AddressCollisionError", err)
	}
	if collision.FirstIndex != 0 || collision.SecondIndex != 2 {
		t.Fatalf(
			"AddressCollisionError indexes = (%d, %d), want (0, 2)",
			collision.FirstIndex,
			collision.SecondIndex,
		)
	}
	want, deriveErr := DeriveCarrierAddress(duplicate)
	if deriveErr != nil {
		t.Fatalf("DeriveCarrierAddress() error = %v", deriveErr)
	}
	if collision.Address != want {
		t.Fatalf("AddressCollisionError address = %s, want %s", collision.Address, want)
	}
}

func TestDeriveUniqueCarrierAddressesRejectsEmptyInput(t *testing.T) {
	t.Parallel()
	addresses, err := DeriveUniqueCarrierAddresses(nil)
	if !errors.Is(err, ErrNoPublicKeys) {
		t.Fatalf("DeriveUniqueCarrierAddresses() error = %v, want ErrNoPublicKeys", err)
	}
	if addresses != nil {
		t.Fatalf("DeriveUniqueCarrierAddresses() addresses = %v, want nil", addresses)
	}
}

func testPublicKey(seed byte) []byte {
	publicKey := make([]byte, PublicKeySize)
	for index := range publicKey {
		publicKey[index] = seed + byte(index)
	}
	return publicKey
}
