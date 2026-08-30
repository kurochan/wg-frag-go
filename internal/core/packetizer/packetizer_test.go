package packetizer

import (
	"bytes"
	"errors"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/fragment"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

type collector struct{ payloads [][]byte }

func (c *collector) EmitCarrier(payload []byte) error {
	c.payloads = append(c.payloads, append([]byte(nil), payload...))
	return nil
}

type failedEmitter struct{ err error }

func (e failedEmitter) EmitCarrier([]byte) error { return e.err }

func TestPacketizerPacksPacketsIntoOneCarrier(t *testing.T) {
	t.Parallel()

	var p Packetizer
	collector := &collector{}
	if err := p.Init(make([]byte, limits.DefaultCarrierPayload), Config{CarrierPayload: limits.DefaultCarrierPayload, MinPack: limits.DefaultMinPackData}, collector); err != nil {
		t.Fatal(err)
	}
	one := bytes.Repeat([]byte{0x11}, 100)
	two := bytes.Repeat([]byte{0x22}, 200)
	meta := fragment.Metadata{DataSessionID: 1, LaneID: 7, LaneSequence: 9}
	if err := p.Add(one, meta); err != nil {
		t.Fatal(err)
	}

	meta.LaneSequence++
	if err := p.Add(two, meta); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(collector.payloads) != 1 {
		t.Fatalf("payload count = %d, want 1", len(collector.payloads))
	}

	var got []carrier.Record
	if err := carrier.Parse(collector.payloads[0], func(record carrier.Record) error {
		got = append(got, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0].Data, one) || !bytes.Equal(got[1].Data, two) {
		t.Fatalf("records = %#v", got)
	}
	if got[0].Header.LaneSequence != 9 || got[1].Header.LaneSequence != 10 {
		t.Fatalf("sequences = %d, %d", got[0].Header.LaneSequence, got[1].Header.LaneSequence)
	}
}

func TestPacketizerFlushesBeforeFragmentLimitWouldBeExceeded(t *testing.T) {
	t.Parallel()

	const carrierPayload = limits.DefaultCarrierPayload
	var p Packetizer
	collector := &collector{}
	if err := p.Init(make([]byte, carrierPayload), Config{CarrierPayload: carrierPayload, MinPack: limits.DefaultMinPackData}, collector); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(bytes.Repeat([]byte{1}, 500), fragment.Metadata{DataSessionID: 1}); err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{2}, limits.MaxInnerMTU)
	if err := p.Add(packet, fragment.Metadata{DataSessionID: 1, LaneSequence: 1}); err != nil {
		t.Fatal(err)
	}
	if len(collector.payloads) != limits.MaxFragments {
		t.Fatalf("flushes = %d, want %d", len(collector.payloads), limits.MaxFragments)
	}
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}

	var fragments int

	for _, payload := range collector.payloads {
		if err := carrier.Parse(payload, func(record carrier.Record) error {
			if record.Header.LaneSequence == 1 {
				fragments++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if fragments != limits.MaxFragments {
		t.Fatalf("fragments = %d, want %d", fragments, limits.MaxFragments)
	}
}

func TestPacketizerFailedFlushRetainsPayload(t *testing.T) {
	t.Parallel()
	var p Packetizer
	collector := &collector{}
	errEmit := errors.New("emit failed")
	if err := p.Init(make([]byte, 64), Config{CarrierPayload: 64, MinPack: 1}, failedEmitter{err: errEmit}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add([]byte{1, 2, 3}, fragment.Metadata{DataSessionID: 1}); err != nil {
		t.Fatal(err)
	}
	want := p.Len()
	if err := p.Flush(); !errors.Is(err, errEmit) {
		t.Fatalf("flush error = %v", err)
	}
	if p.Len() != want {
		t.Fatalf("pending payload = %d, want %d", p.Len(), want)
	}
	p.emitter = collector
	if err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(collector.payloads) != 1 {
		t.Fatalf("payload count = %d", len(collector.payloads))
	}
}

func TestPacketizerHotPathDoesNotAllocate(t *testing.T) {
	var p Packetizer
	emitter := failedEmitter{err: errors.New("must not flush")}
	if err := p.Init(make([]byte, limits.DefaultCarrierPayload), Config{CarrierPayload: limits.DefaultCarrierPayload, MinPack: limits.DefaultMinPackData}, emitter); err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{1}, 100)
	if allocs := testing.AllocsPerRun(1000, func() {
		p.used = 0
		if err := p.Add(packet, fragment.Metadata{DataSessionID: 1}); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("allocations = %f, want 0", allocs)
	}
}

func TestPacketizerDoesNotRetainInputDescriptors(t *testing.T) {
	t.Parallel()
	var p Packetizer
	emitter := failedEmitter{err: errors.New("must not flush")}
	if err := p.Init(make([]byte, limits.DefaultCarrierPayload), Config{CarrierPayload: limits.DefaultCarrierPayload, MinPack: limits.DefaultMinPackData}, emitter); err != nil {
		t.Fatal(err)
	}
	packet := bytes.Repeat([]byte{1}, 100)
	if err := p.Add(packet, fragment.Metadata{DataSessionID: 1}); err != nil {
		t.Fatal(err)
	}
	for i, frag := range p.frags {
		if frag.Data != nil {
			t.Fatalf("fragment descriptor %d retained input data", i)
		}
	}
}

func TestPacketizerClearsDescriptorsAfterPreFlushFailure(t *testing.T) {
	t.Parallel()
	var p Packetizer
	errEmit := errors.New("emit failed")
	if err := p.Init(make([]byte, limits.DefaultCarrierPayload), Config{CarrierPayload: limits.DefaultCarrierPayload, MinPack: limits.DefaultMinPackData}, failedEmitter{err: errEmit}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(bytes.Repeat([]byte{1}, 500), fragment.Metadata{DataSessionID: 1}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(bytes.Repeat([]byte{2}, limits.MaxInnerMTU), fragment.Metadata{DataSessionID: 1, LaneSequence: 1}); !errors.Is(err, errEmit) {
		t.Fatalf("pre-flush error = %v, want %v", err, errEmit)
	}
	for i, frag := range p.frags {
		if frag.Data != nil {
			t.Fatalf("fragment descriptor %d retained input data", i)
		}
	}
}
