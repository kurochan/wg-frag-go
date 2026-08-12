// Package limits contains wire-format invariants shared by the OS-independent core.
package limits

import "fmt"

const (
	DataHeaderSize = 12
	MaxFragments   = 16

	MinInnerMTU     = 1280
	DefaultInnerMTU = 1500
	MaxInnerMTU     = 9612

	DefaultCarrierPayload = 613
	DefaultMinPackData    = 128
)

// MinCarrierPayload returns the smallest carrier payload that can carry an
// inner packet of mtu bytes in at most MaxFragments records.
func MinCarrierPayload(mtu int) int {
	return (mtu+MaxFragments-1)/MaxFragments + DataHeaderSize
}

// ValidateInnerMTU rejects values outside the v1 user-facing MTU range.
func ValidateInnerMTU(mtu int) error {
	if mtu < MinInnerMTU || mtu > MaxInnerMTU {
		return fmt.Errorf("inner MTU %d is outside v1 range %d..%d", mtu, MinInnerMTU, MaxInnerMTU)
	}
	return nil
}

// ValidateMinCarrierPayload rejects a DPLPMTUD BASE that cannot carry mtu in
// MaxFragments records or is below the protocol BASE.
func ValidateMinCarrierPayload(mtu, payload int) error {
	if err := ValidateInnerMTU(mtu); err != nil {
		return err
	}
	minimum := max(DefaultCarrierPayload, MinCarrierPayload(mtu))
	if payload < minimum {
		return fmt.Errorf("carrier payload %d is below required minimum %d for MTU %d", payload, minimum, mtu)
	}
	return nil
}
