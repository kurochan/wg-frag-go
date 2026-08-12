package datapath

import (
	"errors"
	"net/netip"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/innerip"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/core/reassembly"
	"github.com/kurochan/wg-frag-go/internal/core/reorder"
)

var (
	ErrInvalidConfig = errors.New("datapath: invalid receiver config")
	ErrDataSession   = errors.New("datapath: DATA session is not current")
)

// Sink synchronously receives a reconstructed, source-validated inner packet.
// packet aliases a fixed reassembly slot and becomes invalid when DeliverInner
// returns. It must not be retained by an implementation.
type Sink interface {
	DeliverInner(packet []byte) error
}

// ReceiverConfig configures a single authenticated carrier peer. Session changes
// require a new Receiver so old reassembly/reorder state cannot bleed across
// ResetSequence.
type ReceiverConfig struct {
	PeerID        peerroute.PeerID
	DataSessionID uint16
	// CarrierSource and CarrierDest identify the synthetic envelope accepted by
	// AcceptCarrier. NewPayloadReceiver leaves envelope validation to its adapter.
	CarrierSource netip.Addr
	CarrierDest   netip.Addr
	AllowedIPs    *peerroute.Snapshot

	Slots         int
	PerPeerSlots  int
	MaxPacketSize int
	Lifetime      time.Duration

	ReorderEnabled  bool
	ReorderCapacity int
	// ReorderBudget is the receiver-wide number of completed packets that may
	// wait in lane reorder. Zero derives Slots-1, preserving one slot for an
	// incomplete packet.
	ReorderBudget   int
	ReorderMaxDelay time.Duration
}

// ReceiverDrops counts per-packet policy drops.
type ReceiverDrops struct {
	SourceSpoof    uint64
	NativeFragment uint64
	InnerInvalid   uint64
}

// Receiver is a single-owner inbound DATA pipeline. All bounded storage is
// allocated by NewReceiver; AcceptCarrier and Tick do not allocate.
type Receiver struct {
	config        ReceiverConfig
	payloadOnly   bool
	reassembly    *reassembly.Reassembler
	reorders      [256]*reorder.Reorderer
	delivered     []reassembly.Packet
	reorderHeld   int
	reorderBudget int
	drops         ReceiverDrops

	unknownSession uint16
}

// TakeUnknownSession reports and clears the most recent non-current DATA
// session seen on the wire. Recovering from a peer restart needs the observed
// value, which the drop itself does not carry.
func (r *Receiver) TakeUnknownSession() (uint16, bool) {
	session := r.unknownSession
	r.unknownSession = 0
	return session, session != 0
}

// Drops returns cumulative policy-drop counters.
func (r *Receiver) Drops() ReceiverDrops { return r.drops }

// SetAllowedIPs replaces the source-validation snapshot after a configuration
// change. It may only run while the owner goroutine is stopped.
func (r *Receiver) SetAllowedIPs(routes *peerroute.Snapshot) { r.config.AllowedIPs = routes }

// NewReceiver prepares fixed reassembly and per-lane reorder state.
func NewReceiver(config ReceiverConfig) (*Receiver, error) {
	return newConfiguredReceiver(config, false)
}

// NewPayloadReceiver creates a receiver for an already authenticated logical
// peer. CarrierSource and CarrierDest are ignored; synthetic envelope
// verification belongs to a transport adapter.
func NewPayloadReceiver(config ReceiverConfig) (*Receiver, error) {
	return newConfiguredReceiver(config, true)
}

func newConfiguredReceiver(config ReceiverConfig, payloadOnly bool) (*Receiver, error) {
	if config.DataSessionID == 0 || (!payloadOnly &&
		(!config.CarrierSource.Is6() || !config.CarrierSource.IsLinkLocalUnicast() ||
			!config.CarrierDest.Is6() || !config.CarrierDest.IsLinkLocalUnicast())) ||
		config.AllowedIPs == nil || config.Slots <= 0 || config.PerPeerSlots <= 0 ||
		config.MaxPacketSize < limits.MinInnerMTU || config.MaxPacketSize > limits.MaxInnerMTU || config.Lifetime <= 0 ||
		(config.ReorderEnabled && (config.ReorderCapacity <= 0 || config.ReorderMaxDelay <= 0)) {
		return nil, ErrInvalidConfig
	}
	if config.ReorderEnabled {
		if config.ReorderBudget == 0 {
			config.ReorderBudget = config.Slots - 1
		}
		if config.ReorderBudget <= 0 || config.ReorderBudget >= config.Slots {
			return nil, ErrInvalidConfig
		}
	}
	reassembler, err := reassembly.New(reassembly.Config{
		Slots:         config.Slots,
		MaxPacketSize: config.MaxPacketSize,
		MaxPeers:      1,
		PerPeerSlots:  config.PerPeerSlots,
		Lifetime:      config.Lifetime,
	})
	if err != nil {
		return nil, err
	}
	receiver := &Receiver{
		config:        config,
		payloadOnly:   payloadOnly,
		reassembly:    reassembler,
		reorderBudget: config.ReorderBudget,
	}
	outputSize := 1
	if config.ReorderEnabled {
		outputSize = config.ReorderCapacity + 1
	}
	receiver.delivered = make([]reassembly.Packet, outputSize)
	for lane := range receiver.reorders {
		r, err := reorder.New(reorder.Config{
			Enabled:      config.ReorderEnabled,
			Capacity:     config.ReorderCapacity,
			MaxDelay:     config.ReorderMaxDelay,
			Lane:         reorder.Lane{PeerID: 0, DataSessionID: config.DataSessionID, LaneID: uint8(lane)},
			NextSequence: 0,
		})
		if err != nil {
			return nil, err
		}
		receiver.reorders[lane] = r
	}
	return receiver, nil
}

// AcceptCarrier parses one authenticated hidden IPv6 carrier. It validates the
// expected carrier endpoints, session, IP source ownership, and releases every
// completed slot after synchronous delivery.
func (r *Receiver) AcceptCarrier(now time.Time, outer []byte, sink Sink) error {
	envelope, err := carrier.ParseEnvelope(outer, r.config.CarrierSource, r.config.CarrierDest)
	if err != nil {
		return err
	}
	return r.acceptPayload(now, envelope.Payload, sink)
}

// AcceptPayload accepts one carrier payload after the transport has
// authenticated it and resolved its logical peer. The payload aliases the
// caller buffer and is consumed synchronously.
func (r *Receiver) AcceptPayload(now time.Time, payload []byte, sink Sink) error {
	return r.acceptPayload(now, payload, sink)
}

func (r *Receiver) acceptPayload(now time.Time, payload []byte, sink Sink) error {
	return carrier.Parse(payload, func(record carrier.Record) error {
		if record.Header.DataSessionID != r.config.DataSessionID {
			r.unknownSession = record.Header.DataSessionID
			return ErrDataSession
		}
		key := reassembly.Key{
			PeerID:        0,
			DataSessionID: record.Header.DataSessionID,
			LaneID:        record.Header.LaneID,
			LaneSequence:  record.Header.LaneSequence,
		}
		result, err := r.reassembly.Accept(now, key, record)
		if err != nil || result.Status != reassembly.StatusCompleted {
			return err
		}
		laneReorderer := r.reorders[result.Packet.Key.LaneID]
		if r.config.ReorderEnabled && r.reorderHeld >= r.reorderBudget &&
			laneReorderer.WouldQueue(result.Packet.Key.LaneSequence) {
			oldest := r.oldestReorderLane()
			if oldest < 0 {
				_ = r.reassembly.Release(result.Packet.Handle)
				return errors.New("datapath: reorder budget accounting mismatch")
			}
			if oldest == int(result.Packet.Key.LaneID) {
				n, err := laneReorderer.FlushIncluding(result.Packet, r.delivered)
				if err != nil {
					_ = r.reassembly.Release(result.Packet.Handle)
					return err
				}
				r.reorderHeld -= n - 1
				return r.deliver(n, sink)
			}
			if err := r.flushOldestReorder(sink); err != nil {
				_ = r.reassembly.Release(result.Packet.Handle)
				return err
			}
		}
		ordered, err := laneReorderer.Accept(now, result.Packet, r.delivered)
		if err != nil {
			_ = r.reassembly.Release(result.Packet.Handle)
			return err
		}
		switch ordered.Status {
		case reorder.StatusLate, reorder.StatusDuplicate:
			return r.reassembly.Release(result.Packet.Handle)
		case reorder.StatusQueued:
			r.reorderHeld++
		case reorder.StatusDelivered, reorder.StatusFlushed:
			r.reorderHeld -= ordered.Delivered - 1
		}
		return r.deliver(ordered.Delivered, sink)
	})
}

// Tick expires incomplete reassembly slots and flushes reorder gaps that have
// waited for their configured maximum. It returns the count of expired slots.
func (r *Receiver) Tick(now time.Time, sink Sink) (int, error) {
	expired := r.reassembly.Expire(now)
	for _, reorderer := range r.reorders {
		n, err := reorderer.Tick(now, r.delivered)
		if err != nil {
			return expired, err
		}
		r.reorderHeld -= n
		if err := r.deliver(n, sink); err != nil {
			return expired, err
		}
	}
	return expired, nil
}

func (r *Receiver) flushOldestReorder(sink Sink) error {
	oldest := r.oldestReorderLane()
	if oldest < 0 {
		return errors.New("datapath: reorder budget accounting mismatch")
	}
	n, err := r.reorders[oldest].Flush(r.delivered)
	if err != nil {
		return err
	}
	r.reorderHeld -= n
	return r.deliver(n, sink)
}

func (r *Receiver) oldestReorderLane() int {
	oldest := -1
	oldestAt := time.Time{}
	for lane, reorderer := range r.reorders {
		started := reorderer.GapStartedAt()
		if reorderer.Pending() == 0 || (oldest >= 0 && !started.Before(oldestAt)) {
			continue
		}
		oldest = lane
		oldestAt = started
	}
	return oldest
}

func (r *Receiver) deliver(count int, sink Sink) error {
	var firstErr error

	for i := 0; i < count; i++ {
		packet := r.delivered[i]
		r.delivered[i] = reassembly.Packet{}

		parsed, err := innerip.ParseExact(packet.Data)
		switch {
		case errors.Is(err, innerip.ErrNativeFragment):
			// Per-packet policy drops do not stop the flush.
			r.drops.NativeFragment++
		case err != nil:
			r.drops.InnerInvalid++
		case !r.config.AllowedIPs.ValidateSource(r.config.PeerID, parsed.Source):
			r.drops.SourceSpoof++
		case firstErr == nil && sink != nil:
			if err := sink.DeliverInner(parsed.Data); err != nil {
				firstErr = err
			}
		}
		if releaseErr := r.reassembly.Release(packet.Handle); releaseErr != nil && firstErr == nil {
			firstErr = releaseErr
		}
	}
	return firstErr
}
