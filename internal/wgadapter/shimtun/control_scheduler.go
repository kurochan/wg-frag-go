package shimtun

// This file contains the interface-wide outbound CONTROL scheduler.  The
// scheduler deliberately owns descriptors rather than wire bytes: a padded
// MtuProbe is represented by its decoded message and target frame length and
// is materialised only when it is selected for transmission.

import (
	"errors"
	"math"
	"time"

	corecontrol "github.com/kurochan/wg-frag-go/internal/core/control"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	wirev1 "github.com/kurochan/wg-frag-go/proto/wire/v1"
	"google.golang.org/protobuf/proto"
)

const (
	controlDescriptorCapacity = 16
	controlExploratoryLimit   = 8
	controlPeerRate           = 32.0
	controlPeerBurst          = 8.0
	controlGlobalRate         = 128.0
	controlGlobalBurst        = 16.0
)

type controlClass uint8

const (
	controlCritical controlClass = iota
	controlExploratory
)

type controlKind uint8

const (
	controlKindUnknown controlKind = iota
	controlKindHello
	controlKindHelloAck
	controlKindReset
	controlKindResetAck
	controlKindPeerMTU
	controlKindPeerMTUAck
	controlKindPing
	controlKindPong
	controlKindStateSync
	controlKindProbe
	controlKindProbeAck
)

type controlDescriptor struct {
	peer       peerroute.PeerID
	class      controlClass
	kind       controlKind
	messageID  uint64
	replyTo    uint64
	epoch      uint64
	message    *wirev1.Control
	targetSize int // non-zero only for MtuProbe; padding is generated at dequeue.
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (b *tokenBucket) refill(now time.Time, rate, burst float64) {
	if b.last.IsZero() {
		b.last = now
		b.tokens = burst
		return
	}
	if now.Before(b.last) {
		return
	}
	b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
}

func (b *tokenBucket) available() bool { return b.tokens >= 1 }
func (b *tokenBucket) take()           { b.tokens-- }

// controlScheduler is called with Device.txMu held.  descriptors is a fixed
// ring; no descriptor enqueue can allocate or grow it.
type controlScheduler struct {
	descriptors []controlDescriptor
	head        int
	count       int
	exploratory int

	peerOrder    []peerroute.PeerID
	rrIndex      int
	peerRate     map[peerroute.PeerID]*tokenBucket
	global       tokenBucket
	controlBurst int
}

func newControlScheduler(capacity int, peers []peerroute.PeerID) *controlScheduler {
	if capacity <= 0 || capacity > controlDescriptorCapacity {
		capacity = controlDescriptorCapacity
	}
	order := append([]peerroute.PeerID(nil), peers...)

	s := &controlScheduler{
		descriptors: make([]controlDescriptor, capacity),
		peerOrder:   order,
		peerRate:    make(map[peerroute.PeerID]*tokenBucket, len(order)),
	}
	for _, id := range order {
		s.peerRate[id] = &tokenBucket{tokens: controlPeerBurst}
	}
	s.global.tokens = controlGlobalBurst
	return s
}

func (s *controlScheduler) updatePeers(peers []peerroute.PeerID) {
	for offset := 0; offset < s.count; {
		index := (s.head + offset) % len(s.descriptors)
		active := false
		for _, id := range peers {
			if s.descriptors[index].peer == id {
				active = true

				break
			}
		}
		if !active {
			s.remove(index)

			continue
		}

		offset++
	}
	s.peerOrder = append(s.peerOrder[:0], peers...)
	for id := range s.peerRate {
		active := false
		for _, peer := range peers {
			if id == peer {
				active = true

				break
			}
		}
		if !active {
			delete(s.peerRate, id)
		}
	}
	for _, id := range peers {
		if s.peerRate[id] == nil {
			s.peerRate[id] = &tokenBucket{tokens: controlPeerBurst}
		}
	}
	if len(s.peerOrder) == 0 {
		s.rrIndex = 0
	} else if s.rrIndex >= len(s.peerOrder) {
		s.rrIndex %= len(s.peerOrder)
	}
}

// removePeer drops every queued descriptor for peer. Reconfiguration calls
// this before publishing a replacement peer with the same ID; otherwise an
// old CONTROL frame could be delivered to the new cryptographic session.
func (s *controlScheduler) removePeer(peer peerroute.PeerID) int {
	removed := 0

	for offset := 0; offset < s.count; {
		index := (s.head + offset) % len(s.descriptors)
		if s.descriptors[index].peer != peer {
			offset++
			continue
		}
		s.remove(index)

		removed++
	}
	return removed
}

func (s *controlScheduler) enqueue(
	peer peerroute.PeerID,
	frame []byte,
	codec corecontrol.Codec,
) (dropped, evicted, coalesced bool, err error) {
	payload, err := codec.Parse(frame)
	if err != nil {
		return false, false, false, err
	}
	message := new(wirev1.Control)
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(payload, message); err != nil {
		return false, false, false, err
	}
	class, kind := classifyControl(message)
	desc := controlDescriptor{
		peer:      peer,
		class:     class,
		kind:      kind,
		messageID: message.GetMessageId(),
		replyTo:   message.GetReplyTo(),
		epoch:     message.GetControlEpoch(),
		message:   message,
	}
	if kind == controlKindProbe {
		desc.targetSize = len(frame)
		// Padding is attacker-controlled and potentially almost a carrier MTU.
		// Do not retain it in the descriptor ring.
		message.ClearPadding()
	}

	if class == controlExploratory && s.exploratory >= controlExploratoryLimit {
		return true, false, false, nil
	}
	if class == controlCritical {
		if index := s.sameCritical(desc); index >= 0 {
			s.descriptors[index] = desc
			return false, false, true, nil
		}
		if s.countForPeer(peer) >= s.peerAdmissionLimit() {
			if index := s.oldestExploratoryForPeer(peer); index >= 0 {
				s.remove(index)
				evicted = true
			} else {
				return true, false, false, nil
			}
		}
	}
	if s.count == len(s.descriptors) {
		if class == controlCritical {
			if index := s.oldestExploratory(); index >= 0 {
				s.remove(index)
				evicted = true
			} else {
				return true, false, false, nil
			}
		} else {
			return true, false, false, nil
		}
	}
	index := (s.head + s.count) % len(s.descriptors)
	s.descriptors[index] = desc
	s.count++
	if class == controlExploratory {
		s.exploratory++
	}
	return false, evicted, false, nil
}

func (s *controlScheduler) oldestExploratory() int {
	for offset := 0; offset < s.count; offset++ {
		index := (s.head + offset) % len(s.descriptors)
		if s.descriptors[index].class == controlExploratory {
			return index
		}
	}
	return -1
}

func (s *controlScheduler) oldestExploratoryForPeer(peer peerroute.PeerID) int {
	for offset := 0; offset < s.count; offset++ {
		index := (s.head + offset) % len(s.descriptors)
		if s.descriptors[index].peer == peer && s.descriptors[index].class == controlExploratory {
			return index
		}
	}
	return -1
}

func (s *controlScheduler) sameCritical(want controlDescriptor) int {
	for offset := 0; offset < s.count; offset++ {
		index := (s.head + offset) % len(s.descriptors)
		desc := s.descriptors[index]
		if desc.class == controlCritical && desc.peer == want.peer && desc.kind == want.kind &&
			desc.epoch == want.epoch && desc.messageID == want.messageID && desc.replyTo == want.replyTo {
			return index
		}
	}
	return -1
}

func (s *controlScheduler) countForPeer(peer peerroute.PeerID) int {
	count := 0
	for offset := 0; offset < s.count; offset++ {
		if s.descriptors[(s.head+offset)%len(s.descriptors)].peer == peer {
			count++
		}
	}
	return count
}

func (s *controlScheduler) peerAdmissionLimit() int {
	peers := len(s.peerOrder)
	if peers < 1 {
		peers = 1
	}
	limit := len(s.descriptors) / peers
	if limit < 1 {
		return 1
	}
	return limit
}

// remove deletes one ring entry while preserving FIFO order for all entries
// around it.  The ring is only 16 entries, so the bounded copy is preferable
// to a second queue or an allocation.
func (s *controlScheduler) remove(index int) {
	if s.count == 0 {
		return
	}
	if s.descriptors[index].class == controlExploratory {
		s.exploratory--
	}

	for index != (s.head+s.count-1)%len(s.descriptors) {
		next := (index + 1) % len(s.descriptors)
		s.descriptors[index] = s.descriptors[next]
		index = next
	}
	s.descriptors[index] = controlDescriptor{}
	s.count--
}

func (s *controlScheduler) pop(index int) controlDescriptor {
	desc := s.descriptors[index]
	if index == s.head {
		if desc.class == controlExploratory {
			s.exploratory--
		}
		s.descriptors[index] = controlDescriptor{}
		s.head = (s.head + 1) % len(s.descriptors)
	} else {
		s.remove(index)
		return desc
	}

	s.count--
	return desc
}

// choose returns one eligible descriptor and its ring slot.  It enforces both
// token buckets and peer round-robin.  No tokens are consumed when no peer is
// eligible, allowing the caller to service DATA or wait without dropping the
// descriptor.
func (s *controlScheduler) choose(now time.Time) (controlDescriptor, int, bool) {
	if s.count == 0 {
		return controlDescriptor{}, 0, false
	}
	s.global.refill(now, controlGlobalRate, controlGlobalBurst)
	if !s.global.available() {
		return controlDescriptor{}, 0, false
	}
	if len(s.peerOrder) == 0 {
		return controlDescriptor{}, 0, false
	}

	for step := 0; step < len(s.peerOrder); step++ {
		rank := (s.rrIndex + step) % len(s.peerOrder)
		peer := s.peerOrder[rank]
		bucket := s.peerRate[peer]
		if bucket == nil {
			bucket = &tokenBucket{tokens: controlPeerBurst}
			s.peerRate[peer] = bucket
		}
		bucket.refill(now, controlPeerRate, controlPeerBurst)
		if !bucket.available() {
			continue
		}

		for offset := 0; offset < s.count; offset++ {
			index := (s.head + offset) % len(s.descriptors)
			if s.descriptors[index].peer != peer {
				continue
			}
			bucket.take()
			s.global.take()
			s.rrIndex = (rank + 1) % len(s.peerOrder)
			return s.descriptors[index], index, true
		}
	}
	return controlDescriptor{}, 0, false
}

// refund puts tokens back when the caller cannot copy the selected carrier
// into its user buffer. The descriptor remains queued and can be retried with
// a larger buffer without an artificial rate-limit penalty.
func (s *controlScheduler) refund(peer peerroute.PeerID) {
	if bucket := s.peerRate[peer]; bucket != nil {
		bucket.tokens = math.Min(controlPeerBurst, bucket.tokens+1)
	}
	s.global.tokens = math.Min(controlGlobalBurst, s.global.tokens+1)
}

func classifyControl(message *wirev1.Control) (controlClass, controlKind) {
	if message == nil {
		return controlCritical, controlKindUnknown
	}

	switch {
	case message.GetMtuProbe() != nil:
		return controlExploratory, controlKindProbe
	case message.GetMtuProbeAck() != nil:
		return controlCritical, controlKindProbeAck
	case message.GetCapabilitiesHello() != nil:
		return controlCritical, controlKindHello
	case message.GetCapabilitiesAck() != nil:
		return controlCritical, controlKindHelloAck
	case message.GetResetSequence() != nil:
		return controlCritical, controlKindReset
	case message.GetResetSequenceAck() != nil:
		return controlCritical, controlKindResetAck
	case message.GetPeerMtu() != nil:
		return controlCritical, controlKindPeerMTU
	case message.GetPeerMtuAck() != nil:
		return controlCritical, controlKindPeerMTUAck
	case message.GetPing() != nil:
		return controlCritical, controlKindPing
	case message.GetPong() != nil:
		return controlCritical, controlKindPong
	case message.GetStateSyncRequired() != nil:
		return controlCritical, controlKindStateSync
	default:
		return controlCritical, controlKindUnknown
	}
}

// materializeControl emits one complete frame. It uses the same deterministic
// protobuf encoding as Engine, and keeps the original probe target length.
func materializeControl(desc controlDescriptor, dst []byte, codec corecontrol.Codec) (int, error) {
	if desc.message == nil {
		return 0, errors.New("shimtun: empty CONTROL descriptor")
	}
	message := desc.message
	if desc.targetSize != 0 {
		if desc.targetSize > codec.MaxFrameSize() || desc.targetSize < corecontrol.HeaderSize+1 {
			return 0, corecontrol.ErrFrameTooLarge
		}
		message = proto.Clone(message).(*wirev1.Control)
		paddingLen := desc.targetSize - corecontrol.HeaderSize - proto.Size(message)
		if paddingLen < 0 {
			return 0, corecontrol.ErrFrameTooLarge
		}
		matched := false

		for attempts := 0; attempts < 8 && paddingLen >= 0; attempts++ {
			message.SetPadding(make([]byte, paddingLen))
			got := corecontrol.HeaderSize + proto.Size(message)
			if got == desc.targetSize {
				matched = true

				break
			}
			paddingLen += desc.targetSize - got
		}
		if !matched {
			return 0, corecontrol.ErrFrameTooLarge
		}
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return 0, err
	}
	if desc.targetSize != 0 {
		// A varint boundary can make the requested size unrepresentable. The
		// original Engine only emits representable frames, but retain a strict
		// check here so a malformed descriptor never overruns the fixed slot.
		if got := corecontrol.HeaderSize + len(payload); got != desc.targetSize {
			return 0, corecontrol.ErrFrameTooLarge
		}
	}
	return codec.MarshalTo(dst, payload)
}
