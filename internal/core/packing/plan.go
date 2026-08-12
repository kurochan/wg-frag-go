// Package packing decides whether a packet may start in a partially filled
// carrier without exceeding the v1 fragment limit.
package packing

import (
	"fmt"

	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

// Plan is the bounded-fragment decision for one inner packet. FirstData is
// zero only when the current carrier must be flushed before this packet starts.
type Plan struct {
	StartInTail bool
	Fragments   int
	FirstData   int
}

// MakePlan determines whether packetLen bytes can start in the unoccupied tail
// of the current carrier. remaining is the remaining carrier payload capacity,
// including a possible record header. If tail placement would use too many
// fragments, the result starts from a fresh carrier instead.
func MakePlan(packetLen, carrierPayload, remaining, minPack int) (Plan, error) {
	if packetLen < 1 {
		return Plan{}, fmt.Errorf("packet length must be positive: %d", packetLen)
	}
	if carrierPayload <= limits.DataHeaderSize {
		return Plan{}, fmt.Errorf("carrier payload %d cannot contain a data record", carrierPayload)
	}
	if remaining < 0 || remaining > carrierPayload {
		return Plan{}, fmt.Errorf("remaining capacity %d is outside 0..%d", remaining, carrierPayload)
	}
	if minPack < 1 {
		return Plan{}, fmt.Errorf("min-pack must be positive: %d", minPack)
	}

	fullData := carrierPayload - limits.DataHeaderSize
	tailData := remaining - limits.DataHeaderSize
	if tailData >= minPack {
		first := min(packetLen, tailData)
		fragments := 1 + ceilDiv(packetLen-first, fullData)
		if fragments <= limits.MaxFragments {
			return Plan{StartInTail: true, Fragments: fragments, FirstData: first}, nil
		}
	}

	fragments := ceilDiv(packetLen, fullData)
	if fragments > limits.MaxFragments {
		return Plan{}, fmt.Errorf(
			"packet length %d requires %d fragments at carrier payload %d",
			packetLen,
			fragments,
			carrierPayload,
		)
	}
	return Plan{Fragments: fragments}, nil
}

func ceilDiv(n, d int) int {
	if n <= 0 {
		return 0
	}
	return (n + d - 1) / d
}
