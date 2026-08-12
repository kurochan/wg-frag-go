package datapath

import (
	"errors"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/innerip"
	"github.com/kurochan/wg-frag-go/internal/core/reassembly"
)

// carrierDropErrors are per-carrier or per-packet rejections.
var carrierDropErrors = []error{
	carrier.ErrCarrierTooShort,
	carrier.ErrCarrierVersion,
	carrier.ErrCarrierNextHeader,
	carrier.ErrCarrierPayloadSize,
	carrier.ErrCarrierSource,
	carrier.ErrCarrierDestination,
	carrier.ErrCarrierPayloadLimit,
	carrier.ErrHeaderTooShort,
	carrier.ErrRecordTruncated,
	carrier.ErrInvalidRecordLength,
	carrier.ErrInvalidFragment,
	carrier.ErrInvalidDataSessionID,
	carrier.ErrInvalidRange,
	ErrDataSession,
	innerip.ErrTooShort,
	innerip.ErrUnsupportedIP,
	innerip.ErrInvalidIPv4,
	innerip.ErrInvalidIPv6,
	innerip.ErrNativeFragment,
	reassembly.ErrInvalidKey,
	reassembly.ErrKeyMismatch,
	reassembly.ErrInvalidFragment,
	reassembly.ErrInvalidRange,
	reassembly.ErrFragmentCountMismatch,
	reassembly.ErrFragmentConflict,
	reassembly.ErrFragmentOverlap,
	reassembly.ErrCoverage,
	reassembly.ErrPeerQuota,
	reassembly.ErrNoSlot,
	reassembly.ErrCompletedPacketConflict,
}

// IsCarrierDrop reports a per-carrier or per-packet rejection.
func IsCarrierDrop(err error) bool {
	for _, drop := range carrierDropErrors {
		if errors.Is(err, drop) {
			return true
		}
	}
	return false
}
