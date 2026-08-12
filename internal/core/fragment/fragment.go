package fragment

import (
	"errors"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
	"github.com/kurochan/wg-frag-go/internal/core/packing"
)

var (
	ErrPacketSize       = errors.New("fragment: packet size is outside the v1 range")
	ErrDataSessionID    = errors.New("fragment: data session ID must be non-zero")
	ErrCarrierPayload   = errors.New("fragment: carrier payload is out of range")
	ErrCarrierRemaining = errors.New("fragment: carrier remaining capacity is out of range")
	ErrMinPack          = errors.New("fragment: min-pack must be positive")
	ErrTooManyFragments = errors.New("fragment: packet requires more than 16 fragments")
	ErrOutputTooShort   = errors.New("fragment: output descriptor slice is too short")
)

// Metadata is copied into every generated DATA record header.
type Metadata struct {
	DataSessionID uint16
	LaneID        uint8
	LaneSequence  uint32
}

// Options describes the current carrier and packing policy. CarrierRemaining
// includes space needed by the first record header.
type Options struct {
	CarrierPayload   int
	CarrierRemaining int
	MinPack          int
}

// Fragment is a zero-copy descriptor for one DATA record. Data aliases the
// input packet and has capacity limited to its own fragment.
type Fragment struct {
	Header carrier.Header
	Data   []byte
}

// Result is backed by the caller-provided descriptor slice. StartInTail is
// false when the current carrier must be flushed before the first fragment.
type Result struct {
	Fragments   []Fragment
	StartInTail bool
}

// Split generates DATA record headers and zero-copy fragment descriptors in
// output. It does not copy packet bytes or allocate on a valid hot path.
func Split(packet []byte, metadata Metadata, options Options, output []Fragment) (Result, error) {
	if len(packet) < 1 || len(packet) > limits.MaxInnerMTU {
		return Result{}, ErrPacketSize
	}
	if metadata.DataSessionID == 0 {
		return Result{}, ErrDataSessionID
	}
	if options.CarrierPayload <= carrier.HeaderSize || options.CarrierPayload > 1<<16-1 {
		return Result{}, ErrCarrierPayload
	}
	if options.CarrierRemaining < 0 || options.CarrierRemaining > options.CarrierPayload {
		return Result{}, ErrCarrierRemaining
	}
	if options.MinPack < 1 {
		return Result{}, ErrMinPack
	}

	plan, err := packing.MakePlan(
		len(packet),
		options.CarrierPayload,
		options.CarrierRemaining,
		options.MinPack,
	)
	if err != nil {
		return Result{}, ErrTooManyFragments
	}
	if plan.Fragments < 1 || plan.Fragments > limits.MaxFragments {
		return Result{}, ErrTooManyFragments
	}
	if len(output) < plan.Fragments {
		return Result{}, ErrOutputTooShort
	}

	fullData := options.CarrierPayload - carrier.HeaderSize
	offset := 0

	for i := 0; i < plan.Fragments; i++ {
		capacity := fullData
		if i == 0 && plan.StartInTail {
			capacity = plan.FirstData
		}
		dataLen := min(capacity, len(packet)-offset)
		end := offset + dataLen
		output[i] = Fragment{
			Header: carrier.Header{
				FragmentIndex: uint8(i),
				FragmentCount: uint8(plan.Fragments),
				LaneID:        metadata.LaneID,
				DataSessionID: metadata.DataSessionID,
				LaneSequence:  metadata.LaneSequence,
				Offset:        uint16(offset),
			},
			Data: packet[offset:end:end],
		}
		offset = end
	}

	if offset != len(packet) {
		return Result{}, ErrTooManyFragments
	}
	return Result{Fragments: output[:plan.Fragments], StartInTail: plan.StartInTail}, nil
}
