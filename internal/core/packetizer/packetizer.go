package packetizer

import (
	"errors"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/fragment"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

var (
	ErrCarrierPayload = errors.New("packetizer: invalid carrier payload")
	ErrMinPack        = errors.New("packetizer: min-pack must be positive")
	ErrEmitter        = errors.New("packetizer: emitter is nil")
	ErrUninitialized  = errors.New("packetizer: packetizer is not initialized")
)

// Config is the local packing policy. It is deliberately not carried on the
// wire; both peers parse a concatenation of self-delimiting DATA records.
type Config struct {
	CarrierPayload int
	MinPack        int
}

// Emitter synchronously consumes a carrier payload. The passed slice aliases
// the buffer supplied to Init and is invalid after EmitCarrier returns.
//
// An implementation that must enqueue the payload instead of immediately
// transmitting it owns the surrounding buffer lifecycle and should swap to a
// different initialized Packetizer before returning.
type Emitter interface {
	EmitCarrier(payload []byte) error
}

// Packetizer packs complete DATA records into a single caller-owned carrier
// buffer. Its hot path does not allocate. It is single-owner and not safe for
// concurrent use.
type Packetizer struct {
	buffer  []byte
	used    int
	config  Config
	emitter Emitter
	frags   [limits.MaxFragments]fragment.Fragment
	valid   bool
}

// Init prepares p to use buffer. buffer must remain exclusively owned by p
// until every emitted payload has been synchronously consumed.
func (p *Packetizer) Init(buffer []byte, config Config, emitter Emitter) error {
	if config.CarrierPayload <= carrier.HeaderSize ||
		config.CarrierPayload > 1<<16-1 ||
		len(buffer) < config.CarrierPayload {
		return ErrCarrierPayload
	}
	if config.MinPack < 1 {
		return ErrMinPack
	}
	if emitter == nil {
		return ErrEmitter
	}
	p.buffer = buffer[:config.CarrierPayload]
	p.used = 0
	p.config = config
	p.emitter = emitter
	p.valid = true

	return nil
}

// Len returns the pending carrier payload length.
func (p *Packetizer) Len() int { return p.used }

// Reset discards the carrier currently being built. It is used by an owner
// that drops a whole batch after emission failed; a failed Flush deliberately
// keeps its buffer for retry, so continuing with Add would otherwise resend
// the dropped carrier on the next batch.
func (p *Packetizer) Reset() {
	p.used = 0
	p.clearFragments()
}

// Add packs packet using metadata. It flushes only when a DATA record cannot
// fit in the current carrier, or when starting in its tail would exceed the
// 16-fragment wire bound. Calling Flush after the TUN queue is drained
// implements the no-packing-timer rule.
func (p *Packetizer) Add(packet []byte, metadata fragment.Metadata) error {
	if !p.valid {
		return ErrUninitialized
	}

	result, err := fragment.Split(packet, metadata, fragment.Options{
		CarrierPayload:   p.config.CarrierPayload,
		CarrierRemaining: len(p.buffer) - p.used,
		MinPack:          p.config.MinPack,
	}, p.frags[:])
	if err != nil {
		p.clearFragments()
		return err
	}
	if !result.StartInTail && p.used != 0 {
		if err := p.Flush(); err != nil {
			p.clearFragments()
			return err
		}
		result, err = fragment.Split(packet, metadata, fragment.Options{
			CarrierPayload:   p.config.CarrierPayload,
			CarrierRemaining: len(p.buffer),
			MinPack:          p.config.MinPack,
		}, p.frags[:])
		if err != nil {
			p.clearFragments()
			return err
		}
	}

	for i := range result.Fragments {
		frag := &result.Fragments[i]
		if len(p.buffer)-p.used < carrier.HeaderSize+len(frag.Data) {
			if err := p.Flush(); err != nil {
				p.clearFragments()

				return err
			}
		}
		written, err := carrier.MarshalTo(p.buffer[p.used:], frag.Header, frag.Data)
		if err != nil {
			p.clearFragments()
			return err
		}
		p.used += written
		// The descriptor is only needed until its record has been copied. Clear
		// the alias immediately so a large caller-owned packet is not retained
		// by the fixed descriptor array while the carrier waits for Flush.
		frag.Data = nil
	}

	return nil
}

// Flush emits the current carrier, if any. A failed emission leaves the
// carrier intact so the caller may retry or account for the failure.
func (p *Packetizer) Flush() error {
	if !p.valid {
		return ErrUninitialized
	}
	if p.used == 0 {
		return nil
	}
	if err := p.emitter.EmitCarrier(p.buffer[:p.used]); err != nil {
		return err
	}
	p.used = 0
	return nil
}

func (p *Packetizer) clearFragments() {
	for i := range p.frags {
		p.frags[i].Data = nil
	}
}
