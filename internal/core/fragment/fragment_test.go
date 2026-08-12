package fragment

import (
	"errors"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
	"github.com/kurochan/wg-frag-go/internal/core/packing"
)

var testMetadata = Metadata{DataSessionID: 7, LaneID: 3, LaneSequence: 99}

func TestSplit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		packetLen     int
		remaining     int
		wantTail      bool
		wantFragments int
		wantFirstData int
	}{
		{name: "one byte fresh", packetLen: 1, remaining: 0, wantFragments: 1, wantFirstData: 1},
		{name: "eligible tail", packetLen: 1000, remaining: 200, wantTail: true, wantFragments: 3, wantFirstData: 188},
		{name: "tail would make seventeen", packetLen: limits.MaxInnerMTU, remaining: 140, wantFragments: 16, wantFirstData: 601},
		{name: "maximum packet full tail", packetLen: limits.MaxInnerMTU, remaining: limits.DefaultCarrierPayload, wantTail: true, wantFragments: 16, wantFirstData: 601},
	}

	packet := make([]byte, limits.MaxInnerMTU)
	for i := range packet {
		packet[i] = byte(i)
	}
	output := make([]Fragment, limits.MaxFragments)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Split(packet[:tt.packetLen], testMetadata, Options{
				CarrierPayload:   limits.DefaultCarrierPayload,
				CarrierRemaining: tt.remaining,
				MinPack:          limits.DefaultMinPackData,
			}, output)
			if err != nil {
				t.Fatalf("Split() error = %v", err)
			}
			if result.StartInTail != tt.wantTail || len(result.Fragments) != tt.wantFragments {
				t.Fatalf("Split() = tail:%v fragments:%d", result.StartInTail, len(result.Fragments))
			}
			if len(result.Fragments[0].Data) != tt.wantFirstData {
				t.Fatalf("first data = %d, want %d", len(result.Fragments[0].Data), tt.wantFirstData)
			}
			assertFragments(t, packet[:tt.packetLen], result.Fragments)
		})
	}
}

func TestSplitRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	validOptions := Options{CarrierPayload: limits.DefaultCarrierPayload, CarrierRemaining: 0, MinPack: limits.DefaultMinPackData}
	tests := []struct {
		name     string
		packet   []byte
		metadata Metadata
		options  Options
		output   []Fragment
		want     error
	}{
		{name: "empty packet", metadata: testMetadata, options: validOptions, output: make([]Fragment, 16), want: ErrPacketSize},
		{name: "oversize packet", packet: make([]byte, limits.MaxInnerMTU+1), metadata: testMetadata, options: validOptions, output: make([]Fragment, 16), want: ErrPacketSize},
		{name: "zero session", packet: []byte{1}, options: validOptions, output: make([]Fragment, 16), want: ErrDataSessionID},
		{name: "short carrier", packet: []byte{1}, metadata: testMetadata, options: Options{CarrierPayload: carrier.HeaderSize, MinPack: 1}, output: make([]Fragment, 16), want: ErrCarrierPayload},
		{name: "carrier beyond u16", packet: []byte{1}, metadata: testMetadata, options: Options{CarrierPayload: 1 << 16, MinPack: 1}, output: make([]Fragment, 16), want: ErrCarrierPayload},
		{name: "negative remaining", packet: []byte{1}, metadata: testMetadata, options: Options{CarrierPayload: 613, CarrierRemaining: -1, MinPack: 1}, output: make([]Fragment, 16), want: ErrCarrierRemaining},
		{name: "remaining past payload", packet: []byte{1}, metadata: testMetadata, options: Options{CarrierPayload: 613, CarrierRemaining: 614, MinPack: 1}, output: make([]Fragment, 16), want: ErrCarrierRemaining},
		{name: "zero min-pack", packet: []byte{1}, metadata: testMetadata, options: Options{CarrierPayload: 613}, output: make([]Fragment, 16), want: ErrMinPack},
		{name: "too many fragments", packet: make([]byte, limits.MaxInnerMTU), metadata: testMetadata, options: Options{CarrierPayload: 13, MinPack: 1}, output: make([]Fragment, 16), want: ErrTooManyFragments},
		{name: "short output", packet: make([]byte, 1000), metadata: testMetadata, options: validOptions, output: make([]Fragment, 1), want: ErrOutputTooShort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Split(tt.packet, tt.metadata, tt.options, tt.output); !errors.Is(err, tt.want) {
				t.Fatalf("Split() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSplitAllV1PacketLengthsAndTails(t *testing.T) {
	t.Parallel()
	packet := make([]byte, limits.MaxInnerMTU)
	for i := range packet {
		packet[i] = byte(i*31 + 7)
	}
	output := make([]Fragment, limits.MaxFragments)
	options := Options{CarrierPayload: limits.DefaultCarrierPayload, MinPack: limits.DefaultMinPackData}

	for packetLen := 1; packetLen <= limits.MaxInnerMTU; packetLen++ {
		for remaining := 0; remaining <= options.CarrierPayload; remaining++ {
			options.CarrierRemaining = remaining
			wantPlan, err := packing.MakePlan(packetLen, options.CarrierPayload, remaining, options.MinPack)
			if err != nil {
				t.Fatalf("MakePlan(packet=%d remaining=%d): %v", packetLen, remaining, err)
			}
			result, err := Split(packet[:packetLen], testMetadata, options, output)
			if err != nil {
				t.Fatalf("Split(packet=%d remaining=%d): %v", packetLen, remaining, err)
			}
			if result.StartInTail != wantPlan.StartInTail || len(result.Fragments) != wantPlan.Fragments {
				t.Fatalf("packet=%d remaining=%d: got tail:%v fragments:%d, want %+v", packetLen, remaining, result.StartInTail, len(result.Fragments), wantPlan)
			}
			if result.StartInTail && len(result.Fragments[0].Data) != wantPlan.FirstData {
				t.Fatalf("packet=%d remaining=%d: first data=%d, want %d", packetLen, remaining, len(result.Fragments[0].Data), wantPlan.FirstData)
			}
			assertFragments(t, packet[:packetLen], result.Fragments)
		}
	}
}

func TestSplitAllocations(t *testing.T) {
	packet := make([]byte, limits.MaxInnerMTU)
	output := make([]Fragment, limits.MaxFragments)
	options := Options{
		CarrierPayload:   limits.DefaultCarrierPayload,
		CarrierRemaining: 140,
		MinPack:          limits.DefaultMinPackData,
	}
	allocs := testing.AllocsPerRun(1000, func() {
		result, err := Split(packet, testMetadata, options, output)
		if err != nil || len(result.Fragments) != limits.MaxFragments || result.StartInTail {
			panic("unexpected Split result")
		}
	})
	if allocs != 0 {
		t.Fatalf("Split allocations = %v, want 0", allocs)
	}
}

func assertFragments(t *testing.T, packet []byte, fragments []Fragment) {
	if len(fragments) < 1 || len(fragments) > limits.MaxFragments {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	offset := 0

	for i, fragment := range fragments {
		header := fragment.Header
		if int(header.FragmentIndex) != i || int(header.FragmentCount) != len(fragments) {
			t.Fatalf("fragment %d header index/count = %d/%d", i, header.FragmentIndex, header.FragmentCount)
		}
		if header.DataSessionID != testMetadata.DataSessionID || header.LaneID != testMetadata.LaneID || header.LaneSequence != testMetadata.LaneSequence {
			t.Fatalf("fragment %d metadata = %+v", i, header)
		}
		if int(header.Offset) != offset || len(fragment.Data) < 1 {
			t.Fatalf("fragment %d offset/data = %d/%d, want offset %d", i, header.Offset, len(fragment.Data), offset)
		}
		end := offset + len(fragment.Data)
		if end > len(packet) || &fragment.Data[0] != &packet[offset] {
			t.Fatalf("fragment %d does not alias expected packet range", i)
		}
		if cap(fragment.Data) != len(fragment.Data) {
			t.Fatalf("fragment %d cap = %d, want %d", i, cap(fragment.Data), len(fragment.Data))
		}
		offset = end
	}
	if offset != len(packet) {
		t.Fatalf("coverage ends at %d, want %d", offset, len(packet))
	}
}
