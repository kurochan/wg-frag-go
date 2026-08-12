package datapath

import (
	"errors"
	"net/netip"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/fragment"
	"github.com/kurochan/wg-frag-go/internal/core/innerip"
	"github.com/kurochan/wg-frag-go/internal/core/lane"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
	"github.com/kurochan/wg-frag-go/internal/core/packetizer"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

var (
	ErrInvalidSenderConfig = errors.New("datapath: invalid sender config")
	ErrPeerMTU             = errors.New("datapath: inner packet exceeds remote PeerMTU")
	ErrInnerDest           = errors.New("datapath: inner destination is not routed to peer")
	ErrLaneWrap            = errors.New("datapath: lane sequence wrapped; admission paused")
)

// CarrierSink synchronously consumes one complete synthetic IPv6 carrier. The
// slice aliases Sender's fixed output buffer and is invalid on return.
type CarrierSink interface {
	DeliverCarrier(packet []byte) error
}

// PayloadSink synchronously consumes one complete carrier payload. The slice
// aliases Sender's fixed output buffer and is invalid on return. PeerID is the
// logical destination selected by the shim; no endpoint or synthetic IP
// header is part of this callback.
type PayloadSink interface {
	DeliverPayload(peer peerroute.PeerID, payload []byte) error
}

// SenderConfig configures one TX peer.
type SenderConfig struct {
	DataSessionID uint16
	LaneID        uint8
	// CarrierSource and CarrierDest form the synthetic envelope emitted by
	// NewSender. NewPayloadSender ignores them.
	CarrierSource  netip.Addr
	CarrierDest    netip.Addr
	CarrierPayload int
	MinPack        int
	RemotePeerMTU  int
	// AllowedIPs selects this peer by destination. Nil disables the check.
	PeerID     peerroute.PeerID
	AllowedIPs *peerroute.Snapshot
	// Classifier selects a wire lane per inner packet. Nil keeps every packet
	// on the fixed LaneID, which small tests rely on.
	Classifier *lane.Classifier
	// InitialSequences continues each lane across a controlled carrier payload
	// replacement. A session reset intentionally leaves it nil.
	InitialSequences *[lane.Lanes]uint32
	// InitialWrapBlocks continues wrap-pause deadlines alongside
	// InitialSequences, so a replacement cannot lift an active pause.
	InitialWrapBlocks *[lane.Lanes]int64
	// SequenceReuseLifetime pauses a lane after its u32 sequence wraps, so a
	// reused (session, lane, sequence) reassembly key cannot collide with
	// fragments still alive on the receiver. Use the peer's advertised
	// reassembly lifetime; zero selects the protocol maximum.
	SequenceReuseLifetime time.Duration
}

// Sender packs inner packets into DATA records and wraps each flushed payload
// in the hidden IPv6 carrier envelope. It is single-owner and allocation-free
// after construction.
type Sender struct {
	config      SenderConfig
	sink        CarrierSink
	payloadSink PayloadSink
	packetizer  packetizer.Packetizer
	payload     []byte
	outer       []byte
	// sequences is per wire lane; without a classifier only LaneID advances.
	sequences [lane.Lanes]uint32
	// wrapBlocks holds per-lane admission-pause deadlines in unix nanoseconds;
	// zero means the lane is open.
	wrapBlocks [lane.Lanes]int64
	reuseWait  time.Duration
}

// NewSender creates a bounded sender. The payload and outer buffers are fixed
// at the negotiated payload size; a PMTU increase requires controlled sender
// replacement rather than hot-path allocation.
func NewSender(config SenderConfig, sink CarrierSink) (*Sender, error) {
	return newSender(config, sink, nil, true)
}

// NewPayloadSender creates a sender whose callback contains only the logical
// peer ID and carrier payload. CarrierSource and CarrierDest are ignored;
// synthetic envelope encoding belongs to a transport adapter.
func NewPayloadSender(config SenderConfig, sink PayloadSink) (*Sender, error) {
	return newSender(config, nil, sink, false)
}

func newSender(config SenderConfig, sink CarrierSink, payloadSink PayloadSink, synthetic bool) (*Sender, error) {
	if config.DataSessionID == 0 || config.CarrierPayload <= carrier.HeaderSize ||
		config.CarrierPayload > 1<<16-1-carrier.IPv6HeaderSize || config.MinPack < 1 ||
		limits.ValidateInnerMTU(config.RemotePeerMTU) != nil || (synthetic &&
		(!config.CarrierSource.Is6() || !config.CarrierSource.IsLinkLocalUnicast() ||
			!config.CarrierDest.Is6() || !config.CarrierDest.IsLinkLocalUnicast())) ||
		(synthetic && sink == nil) || (!synthetic && payloadSink == nil) {
		return nil, ErrInvalidSenderConfig
	}
	sender := &Sender{
		config:      config,
		sink:        sink,
		payloadSink: payloadSink,
		payload:     make([]byte, config.CarrierPayload),
		reuseWait:   config.SequenceReuseLifetime,
	}
	if synthetic {
		sender.outer = make([]byte, carrier.IPv6HeaderSize+config.CarrierPayload)
	}
	if sender.reuseWait <= 0 {
		// Protocol maximum reassembly lifetime (CapabilitiesHello range).
		sender.reuseWait = 60 * time.Second
	}
	if config.InitialSequences != nil {
		sender.sequences = *config.InitialSequences
	}
	if config.InitialWrapBlocks != nil {
		sender.wrapBlocks = *config.InitialWrapBlocks
	}
	if err := sender.packetizer.Init(sender.payload, packetizer.Config{
		CarrierPayload: config.CarrierPayload,
		MinPack:        config.MinPack,
	}, sender); err != nil {
		return nil, err
	}
	return sender, nil
}

// Add validates an inner non-fragmented IP packet then packs it. It does not
// start a timer; callers invoke Flush when their TUN queue has been drained.
func (s *Sender) Add(packet []byte) error {
	parsed, err := innerip.Parse(packet)
	if err != nil {
		return err
	}
	if s.config.AllowedIPs != nil {
		peer, ok := s.config.AllowedIPs.LookupPeer(parsed.Destination)
		if !ok || peer != s.config.PeerID {
			return ErrInnerDest
		}
	}
	if len(parsed.Data) > s.config.RemotePeerMTU {
		return ErrPeerMTU
	}
	laneID := s.config.LaneID
	if s.config.Classifier != nil {
		laneID = s.config.Classifier.Lane(parsed.Data)
	}
	if blocked := s.wrapBlocks[laneID]; blocked != 0 {
		if time.Now().UnixNano() < blocked {
			return ErrLaneWrap
		}
		s.wrapBlocks[laneID] = 0
	}
	if err := s.packetizer.Add(parsed.Data, fragment.Metadata{
		DataSessionID: s.config.DataSessionID,
		LaneID:        laneID,
		LaneSequence:  s.sequences[laneID],
	}); err != nil {
		return err
	}

	s.sequences[laneID]++
	// The next sequence on this lane would reuse a value from the previous
	// cycle; the youngest of those was used just now, so pausing one full
	// lifetime keeps every reuse at least a lifetime apart.
	if s.sequences[laneID] == 0 {
		s.wrapBlocks[laneID] = time.Now().Add(s.reuseWait).UnixNano()
	}
	return nil
}

// Flush immediately emits the current partial carrier, if any.
func (s *Sender) Flush() error { return s.packetizer.Flush() }

// ResetPending discards a carrier whose emission failed after the owner chose
// to drop the surrounding native batch. The next packet starts a fresh carrier.
func (s *Sender) ResetPending() { s.packetizer.Reset() }

// Sequences snapshots every lane's next sequence. It is read only during a
// cold replacement while the owner has stopped normal Add calls.
func (s *Sender) Sequences() [lane.Lanes]uint32 { return s.sequences }

// WrapBlocks snapshots per-lane admission-pause deadlines for the same cold
// replacement as Sequences.
func (s *Sender) WrapBlocks() [lane.Lanes]int64 { return s.wrapBlocks }

// SetAllowedIPs replaces the egress routing snapshot after a configuration
// change. Like Sequences, it may only run while the owner is stopped.
func (s *Sender) SetAllowedIPs(routes *peerroute.Snapshot) { s.config.AllowedIPs = routes }

// EmitCarrier implements packetizer.Emitter. It is intentionally
// synchronous, so the reusable output buffer cannot be retained by a queue.
func (s *Sender) EmitCarrier(payload []byte) error {
	if s.payloadSink != nil {
		return s.payloadSink.DeliverPayload(s.config.PeerID, payload)
	}
	written, err := carrier.MarshalEnvelopeTo(s.outer, s.config.CarrierSource, s.config.CarrierDest, payload)
	if err != nil {
		return err
	}
	return s.sink.DeliverCarrier(s.outer[:written])
}
