package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/curve25519"
)

var (
	errKeyArguments = errors.New("key command accepts no arguments")
	errInvalidKey   = errors.New("invalid WireGuard private key")
)

func genkey(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errKeyArguments
	}

	key, err := generatePrivateKey(rand.Reader)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(key[:]))

	return err
}

// genpsk emits raw random bytes: preshared keys are symmetric secrets, so
// Curve25519 clamping must not be applied.
func genpsk(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errKeyArguments
	}

	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return err
	}

	_, err := fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(key[:]))

	return err
}

func pubkey(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) != 0 {
		return errKeyArguments
	}
	encoded, err := io.ReadAll(io.LimitReader(stdin, 128))
	if err != nil {
		return err
	}

	private, err := decodePrivateKey(string(encoded))
	if err != nil {
		return err
	}

	public, err := derivePublicKey(private)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(public[:]))

	return err
}

func generatePrivateKey(source io.Reader) ([32]byte, error) {
	var key [32]byte
	if _, err := io.ReadFull(source, key[:]); err != nil {
		return [32]byte{}, err
	}

	clampPrivateKey(&key)

	return key, nil
}

func decodePrivateKey(encoded string) ([32]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, errInvalidKey
	}

	var key [32]byte

	copy(key[:], decoded)

	if isAllZero(key[:]) {
		return [32]byte{}, errInvalidKey
	}
	return key, nil
}

func derivePublicKey(private [32]byte) ([32]byte, error) {
	var base [32]byte

	base[0] = 9

	value, err := curve25519.X25519(private[:], base[:])
	if err != nil || len(value) != 32 {
		return [32]byte{}, errInvalidKey
	}

	var public [32]byte

	copy(public[:], value)

	return public, nil
}

func clampPrivateKey(key *[32]byte) {
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
}

func isAllZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
