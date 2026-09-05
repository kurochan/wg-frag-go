package reorder

import (
	"errors"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/reassembly"
)

const halfSequenceSpace = uint32(1 << 31)

var (
	ErrInvalidConfig  = errors.New("reorder: invalid config")
	ErrWrongLane      = errors.New("reorder: packet belongs to another lane")
	ErrOutputTooSmall = errors.New("reorder: output buffer is too small")
)

// Lane identifies the lane state owned by one Reorderer.
type Lane struct {
	PeerID        reassembly.PeerID
	DataSessionID uint16
	LaneID        uint8
}

// Config controls one bounded reorder queue. Disabled mode emits packets in
// arrival order and deliberately performs no sequence-based drops.
type Config struct {
	Enabled      bool
	Capacity     int
	MaxDelay     time.Duration
	Lane         Lane
	NextSequence uint32
}

// Status describes what Accept did with its input packet.
type Status uint8

const (
	StatusDelivered Status = iota + 1
	StatusQueued
	StatusDuplicate
	StatusLate
	StatusFlushed
)

// Result reports the number of output packets written by an operation.
type Result struct {
	Status    Status
	Delivered int
}

type entry struct {
	used   bool
	packet reassembly.Packet
}

// Reorderer is single-owner. It has no locks and does not release packet
// handles; its caller owns delivery and must Release each delivered packet.
type Reorderer struct {
	config       Config
	next         uint32
	entries      []entry
	count        int
	gapStartedAt time.Time
}

// New preallocates the fixed queue. Enabled queues require a strictly
// positive capacity and delay. Capacity must remain below half the u32 space.
func New(config Config) (*Reorderer, error) {
	if !config.Enabled {
		return &Reorderer{config: config, next: config.NextSequence}, nil
	}
	if config.Capacity <= 0 ||
		uint64(config.Capacity) >= uint64(halfSequenceSpace) ||
		config.MaxDelay <= 0 ||
		config.Lane.DataSessionID == 0 {
		return nil, ErrInvalidConfig
	}
	return &Reorderer{
		config:  config,
		next:    config.NextSequence,
		entries: make([]entry, config.Capacity),
	}, nil
}

// Reset returns all held descriptors to dropped before changing the expected
// sequence. The caller must Release every returned packet handle. This keeps a
// session reset from leaking protected reassembly slots.
func (r *Reorderer) Reset(nextSequence uint32, dropped []reassembly.Packet) (int, error) {
	if len(dropped) < r.count {
		return 0, ErrOutputTooSmall
	}
	n := 0

	for i := range r.entries {
		if r.entries[i].used {
			dropped[n] = r.entries[i].packet
			n++
		}
		r.entries[i] = entry{}
	}
	r.count = 0
	r.next = nextSequence
	r.gapStartedAt = time.Time{}
	return n, nil
}

// Accept handles one completed packet. out must have length for at least
// Capacity+1 packets when enabled, because overflow may flush held packets and
// the input packet together without dropping completed data.
func (r *Reorderer) Accept(now time.Time, packet reassembly.Packet, out []reassembly.Packet) (Result, error) {
	if !r.matchesLane(packet) {
		return Result{}, ErrWrongLane
	}
	if !r.config.Enabled {
		if len(out) < 1 {
			return Result{}, ErrOutputTooSmall
		}
		out[0] = packet
		return Result{Status: StatusDelivered, Delivered: 1}, nil
	}
	if len(out) < len(r.entries)+1 {
		return Result{}, ErrOutputTooSmall
	}

	sequence := packet.Key.LaneSequence
	if sequence == r.next {
		out[0] = packet
		r.next++
		n := 1 + r.drainContiguous(out[1:])
		if r.count == 0 {
			r.gapStartedAt = time.Time{}
		}
		return Result{Status: StatusDelivered, Delivered: n}, nil
	}
	if !aheadOf(sequence, r.next) {
		return Result{Status: StatusLate}, nil
	}
	if r.contains(sequence) {
		return Result{Status: StatusDuplicate}, nil
	}
	if r.count == len(r.entries) {
		n := r.flushIncluding(packet, out)
		return Result{Status: StatusFlushed, Delivered: n}, nil
	}

	r.insert(packet)
	if r.count == 1 {
		r.gapStartedAt = now
	}
	return Result{Status: StatusQueued}, nil
}

// Tick flushes a pending gap once its maximum wait has elapsed. out must have
// length for Capacity packets. It returns zero when no flush is due.
func (r *Reorderer) Tick(now time.Time, out []reassembly.Packet) (int, error) {
	if !r.config.Enabled || r.count == 0 || now.Before(r.gapStartedAt.Add(r.config.MaxDelay)) {
		return 0, nil
	}
	if len(out) < len(r.entries) {
		return 0, ErrOutputTooSmall
	}
	return r.flush(out), nil
}

// Pending reports the number of completed packets held behind a sequence gap.
func (r *Reorderer) Pending() int { return r.count }

// GapStartedAt reports when the current gap began. The zero value means no
// packets are pending.
func (r *Reorderer) GapStartedAt() time.Time { return r.gapStartedAt }

// WouldQueue reports whether a packet with sequence would be retained behind
// the current gap. It lets a receiver-wide budget flush only when accepting a
// packet would consume another completed slot.
func (r *Reorderer) WouldQueue(sequence uint32) bool {
	if !r.config.Enabled || sequence == r.next || !aheadOf(sequence, r.next) || r.contains(sequence) {
		return false
	}
	return r.count < len(r.entries)
}

// Flush releases all packets currently held behind a gap. It is used when a
// receiver-wide reorder budget is exhausted; callers must deliver and release
// every returned packet.
func (r *Reorderer) Flush(out []reassembly.Packet) (int, error) {
	if !r.config.Enabled || r.count == 0 {
		return 0, nil
	}
	if len(out) < len(r.entries) {
		return 0, ErrOutputTooSmall
	}
	return r.flush(out), nil
}

// FlushIncluding flushes held packets together with packet, in sequence order.
// It is used when a receiver-wide budget is full and the incoming packet
// belongs to this lane; accepting it after a flush could otherwise classify it
// as late and discard it.
func (r *Reorderer) FlushIncluding(packet reassembly.Packet, out []reassembly.Packet) (int, error) {
	if !r.config.Enabled {
		if len(out) < 1 {
			return 0, ErrOutputTooSmall
		}
		out[0] = packet
		return 1, nil
	}
	if !r.matchesLane(packet) {
		return 0, ErrWrongLane
	}
	if len(out) < len(r.entries)+1 {
		return 0, ErrOutputTooSmall
	}
	return r.flushIncluding(packet, out), nil
}

func (r *Reorderer) matchesLane(packet reassembly.Packet) bool {
	if !r.config.Enabled {
		return true
	}
	key := packet.Key
	return key.PeerID == r.config.Lane.PeerID &&
		key.DataSessionID == r.config.Lane.DataSessionID &&
		key.LaneID == r.config.Lane.LaneID
}

func (r *Reorderer) insert(packet reassembly.Packet) {
	for i := range r.entries {
		if !r.entries[i].used {
			r.entries[i] = entry{used: true, packet: packet}
			r.count++
			return
		}
	}
}

func (r *Reorderer) contains(sequence uint32) bool {
	for i := range r.entries {
		if r.entries[i].used && r.entries[i].packet.Key.LaneSequence == sequence {
			return true
		}
	}
	return false
}

func (r *Reorderer) drainContiguous(out []reassembly.Packet) int {
	if r.count == 0 {
		return 0
	}

	n := 0

	for {
		index := -1

		for i := range r.entries {
			if r.entries[i].used && r.entries[i].packet.Key.LaneSequence == r.next {
				index = i

				break
			}
		}
		if index < 0 {
			return n
		}
		out[n] = r.entries[index].packet
		r.entries[index] = entry{}
		r.count--
		r.next++
		n++
	}
}

func (r *Reorderer) flush(out []reassembly.Packet) int {
	n := 0

	for r.count > 0 {
		index := r.closestAhead()
		out[n] = r.entries[index].packet
		r.next = out[n].Key.LaneSequence + 1
		r.entries[index] = entry{}
		r.count--
		n++
	}
	r.gapStartedAt = time.Time{}
	return n
}

func (r *Reorderer) flushIncluding(packet reassembly.Packet, out []reassembly.Packet) int {
	n := 0

	virtual := &packet
	for r.count > 0 || virtual != nil {
		index := r.closestAhead()
		bestIsVirtual := false
		if virtual != nil &&
			(index < 0 ||
				virtual.Key.LaneSequence-r.next <
					r.entries[index].packet.Key.LaneSequence-r.next) {
			bestIsVirtual = true
		}
		if bestIsVirtual {
			out[n] = *virtual
			virtual = nil
		} else {
			out[n] = r.entries[index].packet
			r.entries[index] = entry{}
			r.count--
		}
		r.next = out[n].Key.LaneSequence + 1
		n++
	}
	r.gapStartedAt = time.Time{}
	return n
}

func (r *Reorderer) closestAhead() int {
	best := -1

	for i := range r.entries {
		if !r.entries[i].used {
			continue
		}
		if best < 0 ||
			r.entries[i].packet.Key.LaneSequence-r.next <
				r.entries[best].packet.Key.LaneSequence-r.next {
			best = i
		}
	}
	return best
}

func aheadOf(sequence, expected uint32) bool {
	delta := sequence - expected
	return delta != 0 && delta < halfSequenceSpace
}
