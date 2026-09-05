package reassembly

import (
	"bytes"
	"errors"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
)

const maxFragments = 16

var (
	ErrInvalidConfig           = errors.New("reassembly: invalid config")
	ErrInvalidPeer             = errors.New("reassembly: peer ID is out of range")
	ErrInvalidKey              = errors.New("reassembly: invalid key")
	ErrKeyMismatch             = errors.New("reassembly: record does not match key")
	ErrInvalidFragment         = errors.New("reassembly: invalid fragment index or count")
	ErrInvalidRange            = errors.New("reassembly: invalid fragment byte range")
	ErrFragmentCountMismatch   = errors.New("reassembly: fragment count mismatch")
	ErrFragmentConflict        = errors.New("reassembly: fragment index conflicts with prior data")
	ErrFragmentOverlap         = errors.New("reassembly: fragment byte ranges overlap")
	ErrCoverage                = errors.New("reassembly: completed fragments do not provide contiguous coverage")
	ErrPeerQuota               = errors.New("reassembly: peer quota is occupied by completed packets")
	ErrNoSlot                  = errors.New("reassembly: no evictable slot available")
	ErrInvalidHandle           = errors.New("reassembly: invalid or stale slot handle")
	ErrCompletedPacketConflict = errors.New("reassembly: conflicting fragment arrived after completion")
)

// PeerID is a dense, process-local peer identifier. Valid values are in the
// range [0, Config.MaxPeers).
type PeerID uint32

// Key uniquely identifies one fragmented inner packet.
type Key struct {
	PeerID        PeerID
	DataSessionID uint16
	LaneID        uint8
	LaneSequence  uint32
}

// Config controls fixed-capacity memory allocated by New.
type Config struct {
	Slots         int
	MaxPacketSize int
	MaxPeers      int
	PerPeerSlots  int
	Lifetime      time.Duration
}

// ResultStatus describes a successful Accept operation.
type ResultStatus uint8

const (
	StatusAccepted ResultStatus = iota + 1
	StatusDuplicate
	StatusCompleted
)

// SlotHandle identifies a completed slot. Its fields are intentionally hidden;
// callers obtain it from Packet and return it to Release.
type SlotHandle struct {
	index      int
	generation uint64
}

// Packet is a completed inner packet. Data aliases fixed slot storage and is
// valid only until Handle is passed to Release. Its capacity equals its length.
type Packet struct {
	Handle SlotHandle
	Key    Key
	Data   []byte
}

// Result contains the outcome of Accept. Packet is populated only for
// StatusCompleted. Evicted reports pressure eviction performed for a new key.
type Result struct {
	Status     ResultStatus
	Packet     Packet
	Evicted    bool
	EvictedKey Key
}

type slotState uint8

const (
	slotFree slotState = iota
	slotAssembling
	slotCompleted
)

type slot struct {
	state      slotState
	detached   bool
	counted    bool
	freeNext   int
	generation uint64
	born       uint64
	key        Key
	firstSeen  time.Time
	count      uint8
	present    uint16
	offsets    [maxFragments]uint16
	lengths    [maxFragments]uint16
	packetLen  int
	buf        []byte
}

// Reassembler owns all reassembly slots. It is not safe for concurrent use;
// callers should keep each instance under a single worker's ownership.
type Reassembler struct {
	config     Config
	slots      []slot
	storage    []byte
	peerCounts []uint32
	// keySlots is a fixed open-address index from an active packet key to its
	// slot index plus one. Zero is empty. Its capacity is at least twice Slots,
	// so key lookup avoids allocations and a linear scan of active slots. Free
	// slots are tracked by the fixed list below.
	keySlots []int
	keyMask  uint64
	freeHead int
	nextBorn uint64
}

// New validates config and preallocates every slot buffer and peer counter.
func New(config Config) (*Reassembler, error) {
	maxInt := int(^uint(0) >> 1)
	if config.Slots <= 0 || config.MaxPacketSize <= 0 || config.MaxPacketSize > 1<<16-1 ||
		config.MaxPeers <= 0 || config.PerPeerSlots <= 0 || config.PerPeerSlots > config.Slots ||
		config.Lifetime <= 0 || config.Slots > maxInt/config.MaxPacketSize {
		return nil, ErrInvalidConfig
	}
	keySlots, err := keyIndexSize(config.Slots)
	if err != nil {
		return nil, ErrInvalidConfig
	}

	r := &Reassembler{
		config:     config,
		slots:      make([]slot, config.Slots),
		storage:    make([]byte, config.Slots*config.MaxPacketSize),
		peerCounts: make([]uint32, config.MaxPeers),
		keySlots:   make([]int, keySlots),
		keyMask:    uint64(keySlots - 1),
	}
	for i := range r.slots {
		start := i * config.MaxPacketSize
		end := start + config.MaxPacketSize
		r.slots[i].buf = r.storage[start:end:end]
		r.slots[i].freeNext = i + 1
	}
	r.slots[len(r.slots)-1].freeNext = -1

	return r, nil
}

// Accept adds one fragment. It copies fragment data directly into fixed slot
// storage. A slot's expiry remains based on its first accepted fragment.
func (r *Reassembler) Accept(now time.Time, key Key, record carrier.Record) (Result, error) {
	if err := r.validateKey(key); err != nil {
		return Result{}, err
	}

	if err := r.validateRecord(key, record); err != nil {
		r.dropAssemblingKey(key)

		return Result{}, err
	}

	index := r.findKey(key)
	if index >= 0 {
		s := &r.slots[index]
		if s.state == slotAssembling && r.expired(s, now) {
			r.clearSlot(index)
			index = -1
		}
	}

	result := Result{}

	if index < 0 {
		var evicted Key

		var didEvict bool
		index, evicted, didEvict = r.allocateSlot(now, key, record.Header.FragmentCount)
		if index < 0 {
			if int(r.peerCounts[int(key.PeerID)]) >= r.config.PerPeerSlots {
				return Result{}, ErrPeerQuota
			}
			return Result{}, ErrNoSlot
		}
		result.Evicted = didEvict
		result.EvictedKey = evicted
	}

	s := &r.slots[index]
	if s.count != record.Header.FragmentCount {
		return r.conflict(index, ErrFragmentCountMismatch)
	}

	fragmentIndex := int(record.Header.FragmentIndex)
	bit := uint16(1) << fragmentIndex
	start := int(record.Header.Offset)
	end := start + len(record.Data)

	if s.present&bit != 0 {
		if int(s.offsets[fragmentIndex]) == start && int(s.lengths[fragmentIndex]) == len(record.Data) &&
			bytes.Equal(s.buf[start:end], record.Data) {
			result.Status = StatusDuplicate
			return result, nil
		}
		return r.conflict(index, ErrFragmentConflict)
	}

	for i := 0; i < int(s.count); i++ {
		if s.present&(uint16(1)<<i) == 0 {
			continue
		}
		otherStart := int(s.offsets[i])
		otherEnd := otherStart + int(s.lengths[i])
		if start < otherEnd && otherStart < end {
			return r.conflict(index, ErrFragmentOverlap)
		}
	}

	copy(s.buf[start:end], record.Data)
	s.offsets[fragmentIndex] = record.Header.Offset
	s.lengths[fragmentIndex] = uint16(len(record.Data))
	s.present |= bit

	expected := uint16(1<<s.count) - 1
	if s.present != expected {
		result.Status = StatusAccepted
		return result, nil
	}

	packetLen, ok := contiguousLength(s)
	if !ok {
		return r.conflict(index, ErrCoverage)
	}
	s.state = slotCompleted
	s.packetLen = packetLen
	result.Status = StatusCompleted
	result.Packet = Packet{
		Handle: SlotHandle{index: index, generation: s.generation},
		Key:    s.key,
		Data:   s.buf[:packetLen:packetLen],
	}

	return result, nil
}

// Expire releases assembling slots whose first-fragment lifetime has elapsed.
// Completed slots are never expired.
func (r *Reassembler) Expire(now time.Time) int {
	expired := 0

	for i := range r.slots {
		s := &r.slots[i]
		if s.state == slotAssembling && r.expired(s, now) {
			r.clearSlot(i)

			expired++
		}
	}
	return expired
}

// PurgePeer removes all assembling state for peer. Completed packets are
// detached from key lookup and peer quota, but their storage remains protected
// until the caller releases their handles.
func (r *Reassembler) PurgePeer(peer PeerID) int {
	if uint64(peer) >= uint64(r.config.MaxPeers) {
		return 0
	}

	purged := 0
	for i := range r.slots {
		s := &r.slots[i]
		if s.state == slotFree || s.key.PeerID != peer || s.detached {
			continue
		}

		purged++

		if s.state == slotCompleted {
			s.detached = true
			r.removeKey(s.key)
			r.uncount(s)

			continue
		}

		r.clearSlot(i)
	}
	return purged
}

// Release returns a completed slot to the free pool. Stale and duplicate
// handles are rejected.
func (r *Reassembler) Release(handle SlotHandle) error {
	if handle.index < 0 || handle.index >= len(r.slots) {
		return ErrInvalidHandle
	}

	s := &r.slots[handle.index]
	if s.state != slotCompleted || s.generation != handle.generation {
		return ErrInvalidHandle
	}

	r.clearSlot(handle.index)
	return nil
}

func (r *Reassembler) validateKey(key Key) error {
	if uint64(key.PeerID) >= uint64(r.config.MaxPeers) {
		return ErrInvalidPeer
	}
	if key.DataSessionID == 0 {
		return ErrInvalidKey
	}
	return nil
}

func (r *Reassembler) validateRecord(key Key, record carrier.Record) error {
	h := record.Header
	if h.DataSessionID != key.DataSessionID || h.LaneID != key.LaneID || h.LaneSequence != key.LaneSequence {
		return ErrKeyMismatch
	}
	if h.FragmentCount < 1 || h.FragmentCount > maxFragments || h.FragmentIndex >= h.FragmentCount {
		return ErrInvalidFragment
	}

	if len(record.Data) < 1 || len(record.Data) > r.config.MaxPacketSize {
		return ErrInvalidRange
	}
	start := int(h.Offset)
	if start > r.config.MaxPacketSize-len(record.Data) {
		return ErrInvalidRange
	}
	return nil
}

func (r *Reassembler) findKey(key Key) int {
	for position, probes := r.keyPosition(key), 0; probes < len(r.keySlots); probes++ {
		entry := r.keySlots[position]
		if entry == 0 {
			return -1
		}

		index := entry - 1
		s := &r.slots[index]
		if !s.detached && s.state != slotFree && s.key == key {
			return index
		}
		position = (position + 1) & int(r.keyMask)
	}
	return -1
}

func (r *Reassembler) allocateSlot(now time.Time, key Key, count uint8) (int, Key, bool) {
	if int(r.peerCounts[int(key.PeerID)]) >= r.config.PerPeerSlots {
		oldest := r.oldestAssembling(key.PeerID, true)
		if oldest < 0 {
			return -1, Key{}, false
		}
		return r.replaceSlot(oldest, now, key, count)
	}

	if index := r.takeFreeSlot(); index >= 0 {
		r.startSlot(index, now, key, count)
		return index, Key{}, false
	}

	oldest := r.oldestAssembling(0, false)
	if oldest < 0 {
		return -1, Key{}, false
	}
	return r.replaceSlot(oldest, now, key, count)
}

func (r *Reassembler) replaceSlot(index int, now time.Time, key Key, count uint8) (int, Key, bool) {
	evicted := r.slots[index].key
	r.clearSlot(index)
	if got := r.takeFreeSlot(); got != index {
		panic("reassembly: evicted slot missing from free list")
	}
	r.startSlot(index, now, key, count)
	return index, evicted, true
}

// takeFreeSlot removes and returns one slot from the fixed free list. A
// negative result means all slots are active or detached completed packets.
func (r *Reassembler) takeFreeSlot() int {
	index := r.freeHead
	if index < 0 {
		return -1
	}

	s := &r.slots[index]
	if s.state != slotFree {
		panic("reassembly: non-free slot in free list")
	}
	r.freeHead = s.freeNext
	s.freeNext = -1
	return index
}

func (r *Reassembler) startSlot(index int, now time.Time, key Key, count uint8) {
	s := &r.slots[index]
	buf := s.buf
	generation := s.generation + 1
	r.nextBorn++
	*s = slot{
		state:      slotAssembling,
		counted:    true,
		generation: generation,
		born:       r.nextBorn,
		key:        key,
		firstSeen:  now,
		count:      count,
		buf:        buf[:r.config.MaxPacketSize:r.config.MaxPacketSize],
	}
	r.peerCounts[int(key.PeerID)]++
	r.insertKey(index)
}

func (r *Reassembler) clearSlot(index int) {
	s := &r.slots[index]
	if s.state == slotFree {
		return
	}
	if !s.detached {
		r.removeKey(s.key)
	}

	r.uncount(s)
	buf := s.buf
	generation := s.generation
	*s = slot{
		generation: generation,
		buf:        buf[:r.config.MaxPacketSize:r.config.MaxPacketSize],
		freeNext:   r.freeHead,
	}
	r.freeHead = index
}

func keyIndexSize(slots int) (int, error) {
	maxInt := int(^uint(0) >> 1)
	if slots > maxInt/2 {
		return 0, ErrInvalidConfig
	}
	want := slots * 2
	size := 1

	for size < want {
		if size > maxInt/2 {
			return 0, ErrInvalidConfig
		}
		size <<= 1
	}
	return size, nil
}

func (r *Reassembler) keyPosition(key Key) int {
	return int(hashKey(key) & r.keyMask)
}

func hashKey(key Key) uint64 {
	// SplitMix64 finalization gives a stable, inexpensive distribution for the
	// small wire key while preserving the fixed-memory data-path contract.
	x := uint64(key.PeerID)<<40 | uint64(key.DataSessionID)<<24 | uint64(key.LaneID)<<16
	x ^= uint64(key.LaneSequence)
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func (r *Reassembler) insertKey(index int) {
	key := r.slots[index].key

	for position, probes := r.keyPosition(key), 0; probes < len(r.keySlots); probes++ {
		if r.keySlots[position] == 0 {
			r.keySlots[position] = index + 1
			return
		}

		position = (position + 1) & int(r.keyMask)
	}
	// keySlots has at least twice as many entries as slots, so a full index is
	// unreachable unless a future invariant is broken. Keep failure local
	// rather than silently losing a reassembly key.
	panic("reassembly: key index exhausted")
}

func (r *Reassembler) removeKey(key Key) {
	position := r.keyPosition(key)
	for probes := 0; probes < len(r.keySlots); probes++ {
		entry := r.keySlots[position]
		if entry == 0 {
			return
		}
		index := entry - 1
		if r.slots[index].key == key {
			r.deleteKeyPosition(position)
			return
		}
		position = (position + 1) & int(r.keyMask)
	}
}

func (r *Reassembler) deleteKeyPosition(position int) {
	// Backshift deletion keeps probe chains intact and avoids tombstones, whose
	// accumulation would otherwise reintroduce a long lookup after sustained
	// traffic.
	r.keySlots[position] = 0
	for next := (position + 1) & int(r.keyMask); r.keySlots[next] != 0; next = (next + 1) & int(r.keyMask) {
		entry := r.keySlots[next]
		home := r.keyPosition(r.slots[entry-1].key)

		if keyDistance(home, next, int(r.keyMask)) > keyDistance(home, position, int(r.keyMask)) {
			r.keySlots[position] = entry
			r.keySlots[next] = 0
			position = next
		}
	}
}

func keyDistance(from, to, mask int) int { return (to - from) & mask }

func (r *Reassembler) uncount(s *slot) {
	if !s.counted {
		return
	}
	peer := int(s.key.PeerID)
	if r.peerCounts[peer] > 0 {
		r.peerCounts[peer]--
	}
	s.counted = false
}

func (r *Reassembler) dropAssemblingKey(key Key) {
	index := r.findKey(key)
	if index >= 0 && r.slots[index].state == slotAssembling {
		r.clearSlot(index)
	}
}

func (r *Reassembler) conflict(index int, err error) (Result, error) {
	if r.slots[index].state == slotCompleted {
		return Result{}, ErrCompletedPacketConflict
	}
	r.clearSlot(index)
	return Result{}, err
}

func (r *Reassembler) expired(s *slot, now time.Time) bool {
	return !now.Before(s.firstSeen.Add(r.config.Lifetime))
}

func (r *Reassembler) oldestAssembling(peer PeerID, samePeer bool) int {
	oldest := -1

	for i := range r.slots {
		s := &r.slots[i]
		if s.state != slotAssembling || (samePeer && s.key.PeerID != peer) {
			continue
		}
		if oldest < 0 || s.firstSeen.Before(r.slots[oldest].firstSeen) ||
			(s.firstSeen.Equal(r.slots[oldest].firstSeen) && s.born < r.slots[oldest].born) {
			oldest = i
		}
	}
	return oldest
}

func contiguousLength(s *slot) (int, bool) {
	next := 0
	used := uint16(0)

	for n := 0; n < int(s.count); n++ {
		found := -1

		for i := 0; i < int(s.count); i++ {
			bit := uint16(1) << i
			if used&bit == 0 && int(s.offsets[i]) == next {
				found = i
				used |= bit

				break
			}
		}

		if found < 0 {
			return 0, false
		}

		next += int(s.lengths[found])
	}
	return next, true
}
