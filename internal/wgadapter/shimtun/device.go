package shimtun

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/control"
	"github.com/kurochan/wg-frag-go/internal/core/datapath"
	"github.com/kurochan/wg-frag-go/internal/core/icmp"
	"github.com/kurochan/wg-frag-go/internal/core/innerip"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/transport"
	"golang.zx2c4.com/wireguard/tun"
)

// SyntheticMTU is the MTU exposed to wireguard-go. The shim enforces the
// configured inner MTU and negotiated carrier payload below this boundary.
const SyntheticMTU = 65503

// DefaultPreconfirmQueueSize bounds inner packets accepted before the CONTROL
// gate opens. Overflow drops the oldest packet, as this shim has no retry.
const DefaultPreconfirmQueueSize = 8

const (
	controlIngressPeerRate    = 64.0
	controlIngressPeerBurst   = 8.0
	controlIngressGlobalRate  = 256.0
	controlIngressGlobalBurst = 32.0
)

// activeCarrierQueueSlots caps the DATA ring by the amount of work one
// native read can produce. CarrierQueueSize remains the caller's upper
// bound, while the maximum fragment count across peers sizes two worst-case
// batches plus every peer's preconfirm backlog. This keeps PMTU growth from
// multiplying an unnecessarily large slot count by a near-64 KiB buffer.
func activeCarrierQueueSlots(configured, fragments, batch, peerCount int) int {
	if configured <= 0 {
		return 1
	}
	maxInt := int(^uint(0) >> 1)
	if fragments < 1 {
		fragments = 1
	}
	pending := maxInt
	if peerCount >= 0 && peerCount <= maxInt/DefaultPreconfirmQueueSize {
		pending = peerCount * DefaultPreconfirmQueueSize
	}
	packets := maxInt
	if batch >= 0 && batch <= (maxInt-pending)/2 {
		packets = batch*2 + pending
	}
	worstSlots := maxInt
	if packets <= maxInt/fragments {
		worstSlots = packets * fragments
	}
	if configured > worstSlots {
		return worstSlots
	}
	return configured
}

func carrierFragmentCount(carrierSize, innerMTU int) int {
	recordPayload := carrierSize - carrier.IPv6HeaderSize - limits.DataHeaderSize
	fragments := limits.MaxFragments
	if recordPayload > 0 {
		fragments = (innerMTU + recordPayload - 1) / recordPayload
		if fragments < 1 {
			fragments = 1
		}
		if fragments > limits.MaxFragments {
			fragments = limits.MaxFragments
		}
	}
	return fragments
}

func carrierFragmentCountForPayload(payload, innerMTU int) int {
	return carrierFragmentCount(carrier.IPv6HeaderSize+payload, innerMTU)
}

func activePeerCount(peers []*peerState) int {
	count := 0
	for _, peer := range peers {
		if peer != nil {
			count++
		}
	}
	return count
}

func maxPeerFragments(peers []*peerState) int {
	maxFragments := 1
	for _, peer := range peers {
		if peer != nil && peer.dataFragments > maxFragments {
			maxFragments = peer.dataFragments
		}
	}
	return maxFragments
}

func maxPeerCarrierSize(peers []*peerState) int {
	maxSize := 0
	for _, peer := range peers {
		if peer != nil && peer.dataCarrierSize > maxSize {
			maxSize = peer.dataCarrierSize
		}
	}
	return maxSize
}

// Errors returned by Device configuration and packet I/O.
var (
	ErrInvalidConfig    = errors.New("shimtun: invalid config")
	ErrPeerNotFound     = errors.New("shimtun: peer not found")
	ErrClosed           = errors.New("shimtun: device is closed")
	ErrCarrierQueueFull = errors.New("shimtun: carrier queue is full")
	ErrControlSink      = errors.New("shimtun: CONTROL frame received without a sink")
	ErrDataNotReady     = errors.New("shimtun: DATA received before CONTROL gate opened")
	ErrShortBuffer      = errors.New("shimtun: caller buffer is too short")
	ErrReadInterrupted  = errors.New("shimtun: payload read interrupted")
	ErrShortNativeWrite = errors.New("shimtun: native TUN accepted fewer packets than requested")
)

// ControlSink synchronously consumes one validated CONTROL frame, including
// its marker and protocol version. frame aliases the wireguard-go input buffer
// and must not be retained. Implementations must not re-enter Device.Write.
type ControlSink interface {
	DeliverControl(peer peerroute.PeerID, frame []byte) error
}

// SessionSink is an optional ControlSink extension notified of authenticated
// DATA from a session this side never accepted.
type SessionSink interface {
	ReportUnknownDataSession(peer peerroute.PeerID, sessionID uint16) error
}

// PeerConfig is one peer's initial data plane. Carrier endpoints are from the
// local perspective in Sender and from the remote perspective in Receiver.
type PeerConfig struct {
	Sender   datapath.SenderConfig
	Receiver datapath.ReceiverConfig
}

// Config describes the adapter. Peers are indexed by peerroute.PeerID, which
// must match the routing snapshot the senders validate against.
type Config struct {
	Native      tun.Device
	Peers       []PeerConfig
	ControlSink ControlSink
	// CarrierQueueSize is the upper bound for DATA carrier slots. The active
	// ring may be smaller when the negotiated carrier payload makes a native
	// batch require fewer slots.
	CarrierQueueSize int
	// ControlQueueSize is retained for config compatibility; the interface-wide
	// scheduler normalizes it to its fixed 16-entry descriptor ring.
	ControlQueueSize int
	// MaxCarrierPayload bounds CONTROL probes and future negotiated DATA
	// carriers. Zero uses the largest initial Sender payload.
	MaxCarrierPayload    int
	DataInitiallyEnabled bool
	// NativeWriteOffset reserves a platform TUN write header before an inner
	// packet. Linux NativeTun with IFF_VNET_HDR requires 10; zero is used by
	// headerless test and future platform devices.
	NativeWriteOffset  int
	ExpirationInterval time.Duration
}

// Stats is a point-in-time snapshot. Every queue and reassembly structure is
// independently bounded; these counters do not retain packet data.
type Stats struct {
	TXCarriers                     uint64
	TXPacketDrops                  uint64
	TXNativeFragmentDrops          uint64
	TXRouteDrops                   uint64
	TXPeerMTUDrops                 uint64
	TXPTBSent                      uint64
	RXDataCarriers                 uint64
	RXInnerDelivered               uint64
	RXPacketRejects                uint64
	RXNativeFragmentDrops          uint64
	RXSourceSpoofDrops             uint64
	RXNativeWriteDrops             uint64
	CarrierQueueOverflows          uint64
	ControlQueueDrops              uint64
	ControlExploratoryEvictions    uint64
	ControlCoalesces               uint64
	ControlRateSuppressionEpisodes uint64
	ControlMaterializationDrops    uint64
	ControlIngressRateLimited      uint64
	PreconfirmDrops                uint64
	ReassemblyExpirations          uint64
}

// peerState holds one peer's data plane. RX is serialized by its own rxMu.
type peerState struct {
	id              peerroute.PeerID
	sender          *datapath.Sender
	txSession       uint16
	txDest          netip.Addr
	rxSource        netip.Addr
	remoteMTU       int // advertised peer inner MTU, quoted in Packet Too Big
	dataFragments   int
	dataCarrierSize int
	controlIngress  tokenBucket

	dataEnabled atomic.Bool

	pendingData  []byte
	pendingLens  []int
	pendingHead  int
	pendingCount int

	rxMu      sync.Mutex
	receiver  *datapath.Receiver
	rxSession uint16
	dropsBase datapath.ReceiverDrops
	sink      datapath.Sink
	// Fixed slab for completed inner packets.
	deliverStorage []byte
	deliverBufs    [][]byte
	deliverCount   int
}

// peerTable is the immutable peer set. Readers load it once per operation;
// Reconfigure publishes a replacement while txMu is held, so a removed peer
// finishes at most the RX batch already in flight under its own lock.
type peerTable struct {
	// peers is indexed by peerroute.PeerID; removed peers leave nil holes so
	// surviving IDs stay valid in every routing snapshot.
	peers []*peerState
	// byCarrier resolves an authenticated carrier source to its peer, so a
	// peer can never be charged for another peer's records.
	byCarrier map[netip.Addr]peerroute.PeerID
	routes    *peerroute.Snapshot
}

// Device implements tun.Device. readNative owns TX; each peer's RX state is
// protected by peerState.rxMu. No path holds two peer RX locks at once.
type Device struct {
	native tun.Device
	table  atomic.Pointer[peerTable]
	batch  int

	carrierSize          int // active DATA carrier size, protected by txMu
	dataStride           int // current DATA queue slot size, protected by txMu
	dataFragments        int // maximum DATA fragments per inner packet, protected by txMu
	queueLimit           int // configured maximum DATA queue slots
	controlStride        int // fixed CONTROL queue slot size, including hidden IPv6 header
	innerMTU             int
	txSource             netip.Addr
	rxDest               netip.Addr
	control              control.Codec
	controlSink          ControlSink
	controlSched         *controlScheduler
	controlIngressMu     sync.Mutex
	controlIngressGlobal tokenBucket
	txMu                 sync.Mutex
	queueData            []byte
	queueLens            []int
	queuePeers           []peerroute.PeerID
	queueHead            int
	queueCount           int
	controlData          []byte
	controlLens          []int
	controlHead          int
	controlCount         int
	payloadStride        int // carrier payload bytes in each DATA slot
	txFatal              error
	readStorage          []byte
	readBufs             [][]byte
	readSizes            []int
	queueReady           chan struct{}
	queueDrained         chan struct{}
	readInterrupt        chan struct{}
	nativeWriteMu        sync.Mutex

	// The next Write consumes a flush failure raised by expireLoop.
	rxAsyncErr        atomic.Pointer[error]
	nativeWriteOffset int

	// PTB state, including the write header staging buffers, is owned by the
	// single readNative goroutine.
	writeBufs    [1][]byte
	writeStorage []byte
	ptbStorage   []byte
	ptbTokens    int
	ptbRefill    time.Time

	events   chan tun.Event
	stop     chan struct{}
	done     sync.WaitGroup
	closed   atomic.Bool
	once     sync.Once
	closeErr error

	txPacketDrops                  atomic.Uint64
	txCarriers                     atomic.Uint64
	txNativeFragmentDrops          atomic.Uint64
	txRouteDrops                   atomic.Uint64
	txPeerMTUDrops                 atomic.Uint64
	txPTBSent                      atomic.Uint64
	rxDataCarriers                 atomic.Uint64
	rxInnerDelivered               atomic.Uint64
	rxPacketRejects                atomic.Uint64
	rxNativeWriteDrops             atomic.Uint64
	carrierQueueOverflows          atomic.Uint64
	controlQueueDrops              atomic.Uint64
	controlExploratoryEvictions    atomic.Uint64
	controlCoalesces               atomic.Uint64
	controlRateSuppressionEpisodes atomic.Uint64
	controlMaterializationDrops    atomic.Uint64
	controlIngressRateLimited      atomic.Uint64
	preconfirmDrops                atomic.Uint64
	reassemblyExpirations          atomic.Uint64
	retiredSourceSpoofDrops        atomic.Uint64
	retiredNativeFragmentDrops     atomic.Uint64
	retiredInnerInvalidDrops       atomic.Uint64
	controlSuppressionActive       bool
}

// New validates all cross-layer invariants and preallocates bounded hot-path
// storage before starting background event and expiration forwarding.
//
//nolint:cyclop // Construction validates and sizes all fixed buffers before publication.
func New(config Config) (*Device, error) {
	if config.Native == nil || len(config.Peers) == 0 || config.CarrierQueueSize <= 0 || config.ControlQueueSize <= 0 ||
		config.NativeWriteOffset < 0 || config.ExpirationInterval <= 0 {
		return nil, ErrInvalidConfig
	}
	batch := config.Native.BatchSize()
	if batch <= 0 {
		return nil, ErrInvalidConfig
	}
	nativeMTU, err := config.Native.MTU()
	if err != nil || limits.ValidateInnerMTU(nativeMTU) != nil || config.NativeWriteOffset > nativeMTU {
		return nil, ErrInvalidConfig
	}
	maxInt := int(^uint(0) >> 1)
	if batch > maxInt/nativeMTU || config.NativeWriteOffset+nativeMTU > maxInt/batch {
		return nil, ErrInvalidConfig
	}
	maxCarrierPayload := config.MaxCarrierPayload
	// A zero carrier address selects the transport-neutral mode. In that mode
	// peer authentication and synthetic envelope handling belong to the
	// adapter, so all peers must leave both address fields unset.
	syntheticEnvelope := config.Peers[0].Sender.CarrierSource.IsValid() ||
		config.Peers[0].Sender.CarrierDest.IsValid() ||
		config.Peers[0].Receiver.CarrierSource.IsValid() ||
		config.Peers[0].Receiver.CarrierDest.IsValid()
	for _, peer := range config.Peers {
		if config.ExpirationInterval > peer.Receiver.Lifetime || peer.Receiver.MaxPacketSize != nativeMTU ||
			limits.ValidateMinCarrierPayload(peer.Sender.RemotePeerMTU, peer.Sender.CarrierPayload) != nil {
			return nil, ErrInvalidConfig
		}
		if syntheticEnvelope && (peer.Sender.CarrierSource != peer.Receiver.CarrierDest ||
			peer.Sender.CarrierDest != peer.Receiver.CarrierSource ||
			peer.Sender.CarrierSource != config.Peers[0].Sender.CarrierSource) {
			return nil, ErrInvalidConfig
		}
		if syntheticEnvelope && (!peer.Sender.CarrierSource.Is6() || !peer.Sender.CarrierSource.IsLinkLocalUnicast() ||
			!peer.Sender.CarrierDest.Is6() || !peer.Sender.CarrierDest.IsLinkLocalUnicast()) {
			return nil, ErrInvalidConfig
		}
		if !syntheticEnvelope && (peer.Sender.CarrierSource.IsValid() || peer.Sender.CarrierDest.IsValid() ||
			peer.Receiver.CarrierSource.IsValid() || peer.Receiver.CarrierDest.IsValid()) {
			return nil, ErrInvalidConfig
		}
		if maxCarrierPayload < peer.Sender.CarrierPayload {
			maxCarrierPayload = peer.Sender.CarrierPayload
		}
	}
	if maxCarrierPayload > 1<<16-1-carrier.IPv6HeaderSize {
		return nil, ErrInvalidConfig
	}
	controlCodec, err := control.NewCodec(maxCarrierPayload)
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}

	largestCarrier := carrier.IPv6HeaderSize + config.Peers[0].Sender.CarrierPayload
	maxFragments := 1
	for _, peer := range config.Peers {
		if size := carrier.IPv6HeaderSize + peer.Sender.CarrierPayload; size > largestCarrier {
			largestCarrier = size
		}
		if fragments := carrierFragmentCountForPayload(peer.Sender.CarrierPayload, nativeMTU); fragments > maxFragments {
			maxFragments = fragments
		}
	}
	queueSlots := activeCarrierQueueSlots(config.CarrierQueueSize, maxFragments, batch, len(config.Peers))
	if queueSlots <= 0 || largestCarrier > maxInt/queueSlots {
		return nil, ErrInvalidConfig
	}
	controlCapacity := controlDescriptorCapacity
	d := &Device{
		native:            config.Native,
		batch:             batch,
		nativeWriteOffset: config.NativeWriteOffset,
		carrierSize:       largestCarrier,
		dataStride:        largestCarrier,
		dataFragments:     maxFragments,
		controlStride:     carrier.IPv6HeaderSize + maxCarrierPayload,
		innerMTU:          nativeMTU,
		txSource:          config.Peers[0].Sender.CarrierSource,
		rxDest:            config.Peers[0].Receiver.CarrierDest,
		queueLimit:        config.CarrierQueueSize,
		control:           controlCodec,
		controlSink:       config.ControlSink,
		queueLens:         make([]int, queueSlots),
		queuePeers:        make([]peerroute.PeerID, queueSlots),
		controlLens:       make([]int, controlDescriptorCapacity),
		readStorage:       make([]byte, batch*nativeMTU),
		readBufs:          make([][]byte, batch),
		readSizes:         make([]int, batch),
		queueReady:        make(chan struct{}, 1),
		queueDrained:      make(chan struct{}, 1),
		readInterrupt:     make(chan struct{}, 1),
		events:            make(chan tun.Event, batch),
		stop:              make(chan struct{}),
	}
	d.payloadStride = largestCarrier - carrier.IPv6HeaderSize

	peerOrder := make([]peerroute.PeerID, len(config.Peers))
	for i := range peerOrder {
		peerOrder[i] = peerroute.PeerID(i)
	}
	// CONTROL scheduling is interface-wide and always fixed at 16 entries;
	// ControlQueueSize remains an accepted compatibility knob but is normalized
	// here so peer count and oversized configuration cannot grow this ring.
	d.controlSched = newControlScheduler(controlCapacity, peerOrder)
	d.queueData = make([]byte, d.dataStride*len(d.queueLens))
	d.controlData = make([]byte, d.controlStride*controlCapacity)
	if config.NativeWriteOffset != 0 {
		d.writeStorage = make([]byte, config.NativeWriteOffset+nativeMTU)
	}
	d.ptbStorage = make([]byte, icmp.MaxPacketTooBigSize)

	d.ptbTokens = ptbTokenBucketSize
	for i := range d.readBufs {
		start := i * nativeMTU
		d.readBufs[i] = d.readStorage[start : start+nativeMTU]
	}

	table := &peerTable{
		peers:     make([]*peerState, len(config.Peers)),
		byCarrier: make(map[netip.Addr]peerroute.PeerID, len(config.Peers)),
		routes:    config.Peers[0].Sender.AllowedIPs,
	}
	for i, peerConfig := range config.Peers {
		id := peerroute.PeerID(i)
		if peerConfig.Sender.PeerID != id || peerConfig.Receiver.PeerID != id {
			return nil, ErrInvalidConfig
		}
		if syntheticEnvelope {
			if _, duplicate := table.byCarrier[peerConfig.Receiver.CarrierSource]; duplicate {
				return nil, ErrInvalidConfig
			}
		}
		peer, err := d.newPeerState(id, peerConfig)
		if err != nil {
			return nil, err
		}
		peer.dataEnabled.Store(config.DataInitiallyEnabled)
		table.peers[i] = peer
		if syntheticEnvelope {
			table.byCarrier[peer.rxSource] = id
		}
	}
	d.table.Store(table)

	d.done.Add(3)
	go d.readNative()
	go d.forwardEvents()
	go d.expireLoop(config.ExpirationInterval)
	return d, nil
}

// newPeerState builds one peer's data plane with DATA disabled. The caller
// decides the initial gate and publishes the peer into a table.
func (d *Device) newPeerState(id peerroute.PeerID, config PeerConfig) (*peerState, error) {
	peer := &peerState{
		id:              id,
		txSession:       config.Sender.DataSessionID,
		rxSession:       config.Receiver.DataSessionID,
		txDest:          config.Sender.CarrierDest,
		rxSource:        config.Receiver.CarrierSource,
		remoteMTU:       config.Sender.RemotePeerMTU,
		dataFragments:   carrierFragmentCountForPayload(config.Sender.CarrierPayload, d.innerMTU),
		dataCarrierSize: carrier.IPv6HeaderSize + config.Sender.CarrierPayload,
		pendingLens:     make([]int, DefaultPreconfirmQueueSize),
		pendingData:     make([]byte, d.innerMTU*DefaultPreconfirmQueueSize),
		deliverStorage:  make([]byte, d.batch*(d.nativeWriteOffset+d.innerMTU)),
		deliverBufs:     make([][]byte, 0, d.batch),
	}
	peer.sink = peerDeliverySink{device: d, peer: peer}
	var err error
	if peer.sender, err = datapath.NewPayloadSender(config.Sender, senderQueueSink{device: d}); err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	if peer.receiver, err = datapath.NewPayloadReceiver(config.Receiver); err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	return peer, nil
}

// validatePeerConfig mirrors the per-peer invariants New enforces, so a
// runtime reconfiguration cannot introduce a peer New would have rejected.
func (d *Device) validatePeerConfig(id peerroute.PeerID, config PeerConfig) error {
	if config.Sender.PeerID != id || config.Receiver.PeerID != id ||
		config.Sender.CarrierSource != d.txSource || config.Receiver.CarrierDest != d.rxDest ||
		config.Sender.CarrierDest != config.Receiver.CarrierSource ||
		config.Receiver.MaxPacketSize != d.innerMTU ||
		config.Sender.CarrierPayload+carrier.IPv6HeaderSize > d.controlStride ||
		limits.ValidateMinCarrierPayload(config.Sender.RemotePeerMTU, config.Sender.CarrierPayload) != nil {
		return ErrInvalidConfig
	}
	return nil
}

// growDataQueueLocked expands the DATA ring without losing carriers already
// queued. The caller holds txMu; queue slots are copied in FIFO order into the
// new fixed slab, so no producer can observe a partially published ring.
func (d *Device) growDataQueueLocked(slots int) {
	if slots <= len(d.queueLens) {
		return
	}
	data := make([]byte, d.dataStride*slots)
	lens := make([]int, slots)
	peers := make([]peerroute.PeerID, slots)

	for i := 0; i < d.queueCount; i++ {
		oldIndex := (d.queueHead + i) % len(d.queueLens)
		start := oldIndex * d.dataStride
		length := d.queueLens[oldIndex]
		newStart := i * d.dataStride
		copy(data[newStart:newStart+length], d.queueData[start:start+length])
		lens[i] = length
		peers[i] = d.queuePeers[oldIndex]
	}
	d.queueData = data
	d.queueLens = lens
	d.queuePeers = peers
	d.queueHead = 0
}

// Reconfigure atomically publishes a new peer set. Surviving peers keep their
// IDs, sessions, and reassembly state; only their routing snapshots are
// swapped. Removed IDs become nil holes whose reassembly, reorder, and MTU
// state are dropped with the peerState. Added IDs must be unoccupied.
func (d *Device) Reconfigure(
	added map[peerroute.PeerID]PeerConfig,
	removed []peerroute.PeerID,
	routes *peerroute.Snapshot,
) error {
	if d.closed.Load() {
		return ErrClosed
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.closed.Load() {
		return ErrClosed
	}
	current := d.table.Load()
	occupied := func(id peerroute.PeerID, in []*peerState) bool {
		return uint64(id) < uint64(len(in)) && in[int(id)] != nil
	}
	width := len(current.peers)
	for id, config := range added {
		if err := d.validatePeerConfig(id, config); err != nil {
			return err
		}
		if uint64(id) >= uint64(width) {
			if uint64(id) >= uint64(^uint(0)>>1) {
				return ErrInvalidConfig
			}
			width = int(id) + 1
		}
	}
	next := &peerTable{
		peers:     make([]*peerState, width),
		byCarrier: make(map[netip.Addr]peerroute.PeerID, width),
		routes:    routes,
	}
	copy(next.peers, current.peers)
	// Removals free their slots first, so one call can replace a peer in place.
	for _, id := range removed {
		if !occupied(id, next.peers) {
			return ErrInvalidConfig
		}
		next.peers[int(id)] = nil
	}
	for id, config := range added {
		if occupied(id, next.peers) {
			return ErrInvalidConfig
		}
		// Egress selection and per-peer validation must observe the same
		// interface-wide routing snapshot.
		if routes != nil {
			config.Sender.AllowedIPs = routes
			config.Receiver.AllowedIPs = routes
		}
		peer, err := d.newPeerState(id, config)
		if err != nil {
			return err
		}
		next.peers[int(id)] = peer
	}
	for _, peer := range next.peers {
		if peer == nil {
			continue
		}
		if d.txSource.IsValid() {
			if _, duplicate := next.byCarrier[peer.rxSource]; duplicate {
				return ErrInvalidConfig
			}
			next.byCarrier[peer.rxSource] = peer.id
		}
	}

	for _, config := range added {
		// Runtime peers join at the current carrier size. A later negotiated
		// InstallDataPlane transition owns queue resizing and session gating.
		if config.Sender.CarrierPayload+carrier.IPv6HeaderSize > d.dataStride {
			return ErrInvalidConfig
		}
	}
	for _, peer := range next.peers {
		if peer == nil {
			continue
		}
		if _, isNew := added[peer.id]; isNew {
			continue
		}
		peer.sender.SetAllowedIPs(routes)
		peer.rxMu.Lock()
		peer.receiver.SetAllowedIPs(routes)
		peer.rxMu.Unlock()
	}
	if fragments := maxPeerFragments(next.peers); fragments > d.dataFragments {
		d.dataFragments = fragments
	}
	if slots := activeCarrierQueueSlots(
		d.queueLimit,
		d.dataFragments,
		d.batch,
		activePeerCount(next.peers),
	); slots > len(d.queueLens) {
		d.growDataQueueLocked(slots)
	}
	for _, id := range removed {
		d.retirePeerDropsLocked(current.peers[int(id)])
		d.purgeDataPeerLocked(id)
		d.controlSched.removePeer(id)
	}
	// A blocked native reader may be waiting for queueDrained because the ring
	// was full before this reconfiguration freed slots.
	d.notifyDrained()
	d.table.Store(next)

	peerOrder := make([]peerroute.PeerID, 0, len(next.peers))
	for id, peer := range next.peers {
		if peer != nil {
			peerOrder = append(peerOrder, peerroute.PeerID(id))
		}
	}
	d.controlSched.updatePeers(peerOrder)
	d.controlHead = d.controlSched.head
	d.controlCount = d.controlSched.count
	return nil
}

// purgeDataPeerLocked removes queued DATA carriers for a peer while txMu is
// held. Compaction preserves FIFO order for surviving peers and prevents a
// reused PeerID from inheriting the removed peer's payloads.
func (d *Device) purgeDataPeerLocked(peer peerroute.PeerID) {
	kept := 0

	for offset := 0; offset < d.queueCount; offset++ {
		oldIndex := (d.queueHead + offset) % len(d.queueLens)
		if d.queuePeers[oldIndex] == peer {
			continue
		}
		newIndex := (d.queueHead + kept) % len(d.queueLens)
		if newIndex != oldIndex {
			oldStart := oldIndex * d.dataStride
			newStart := newIndex * d.dataStride
			copy(d.queueData[newStart:newStart+d.queueLens[oldIndex]], d.queueData[oldStart:oldStart+d.queueLens[oldIndex]])
		}
		d.queueLens[newIndex] = d.queueLens[oldIndex]
		d.queuePeers[newIndex] = d.queuePeers[oldIndex]
		kept++
	}

	for offset := kept; offset < d.queueCount; offset++ {
		index := (d.queueHead + offset) % len(d.queueLens)
		d.queueLens[index] = 0
		d.queuePeers[index] = 0
	}
	d.queueCount = kept
}

// retirePeerDropsLocked preserves receiver counters when a peer leaves the
// published table. The peer receive lock is held while reading its session
// counters so an in-flight reassembly update cannot be lost.
func (d *Device) retirePeerDropsLocked(peer *peerState) {
	if peer == nil {
		return
	}
	peer.rxMu.Lock()
	drops := peer.dropsBase
	if peer.receiver != nil {
		current := peer.receiver.Drops()
		drops.SourceSpoof += current.SourceSpoof
		drops.NativeFragment += current.NativeFragment
		drops.InnerInvalid += current.InnerInvalid
	}
	peer.rxMu.Unlock()
	d.retiredSourceSpoofDrops.Add(drops.SourceSpoof)
	d.retiredNativeFragmentDrops.Add(drops.NativeFragment)
	d.retiredInnerInvalidDrops.Add(drops.InnerInvalid)
}

// peerFor resolves a peer index supplied by the control plane.
func (d *Device) peerFor(id peerroute.PeerID) (*peerState, bool) {
	peers := d.table.Load().peers
	if uint64(id) >= uint64(len(peers)) {
		return nil, false
	}
	peer := peers[int(id)]
	if peer == nil {
		return nil, false
	}
	return peer, true
}

// anyDataEnabled reports whether at least one peer accepts DATA, which is what
// the producer waits on before reading the shared native TUN.
func (d *Device) anyDataEnabled() bool {
	for _, peer := range d.table.Load().peers {
		if peer != nil && peer.dataEnabled.Load() {
			return true
		}
	}
	return false
}

// InstallDataPlane atomically replaces one peer's independent local TX and
// remote RX DATA sessions after a verified ResetSequence exchange. Queued DATA
// is discarded: the shared ring interleaves every peer's carriers, so it cannot
// be replayed selectively, and a cold session transition loses at most one
// batch that the inner protocol already tolerates.
func (d *Device) InstallDataPlane(
	id peerroute.PeerID,
	senderConfig datapath.SenderConfig,
	receiverConfig datapath.ReceiverConfig,
) error {
	if d.closed.Load() || senderConfig.DataSessionID == 0 || receiverConfig.DataSessionID == 0 ||
		senderConfig.PeerID != id || receiverConfig.PeerID != id ||
		senderConfig.CarrierSource != d.txSource || receiverConfig.CarrierDest != d.rxDest ||
		senderConfig.CarrierPayload+carrier.IPv6HeaderSize > d.controlStride {
		return ErrInvalidConfig
	}
	nativeMTU, err := d.native.MTU()
	if err != nil || receiverConfig.MaxPacketSize != nativeMTU ||
		limits.ValidateMinCarrierPayload(senderConfig.RemotePeerMTU, senderConfig.CarrierPayload) != nil {
		return ErrInvalidConfig
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.closed.Load() {
		return ErrClosed
	}
	peer, ok := d.peerFor(id)
	if !ok {
		return errors.Join(ErrPeerNotFound, ErrInvalidConfig)
	}
	if senderConfig.CarrierDest != peer.txDest || receiverConfig.CarrierSource != peer.rxSource {
		return ErrInvalidConfig
	}
	peer.rxMu.Lock()
	defer peer.rxMu.Unlock()
	sameTXSession := peer.txSession == senderConfig.DataSessionID
	sameRXSession := peer.rxSession == receiverConfig.DataSessionID
	if sameTXSession {
		sequences := peer.sender.Sequences()
		wrapBlocks := peer.sender.WrapBlocks()
		senderConfig.InitialSequences = &sequences
		senderConfig.InitialWrapBlocks = &wrapBlocks
	}
	// Cold control-plane transition: allocate the fixed sender buffers while
	// both owners are stopped so the TUN hot path never allocates.
	replacementSender, err := datapath.NewPayloadSender(senderConfig, senderQueueSink{device: d})
	if err != nil {
		return errors.Join(ErrInvalidConfig, err)
	}
	var replacementReceiver *datapath.Receiver
	if !sameRXSession {
		if replacementReceiver, err = datapath.NewPayloadReceiver(receiverConfig); err != nil {
			return errors.Join(ErrInvalidConfig, err)
		}
	}
	peer.sender = replacementSender
	if !sameRXSession {
		retired := peer.receiver.Drops()
		peer.dropsBase.SourceSpoof += retired.SourceSpoof
		peer.dropsBase.NativeFragment += retired.NativeFragment
		peer.dropsBase.InnerInvalid += retired.InnerInvalid
		peer.receiver = replacementReceiver
		peer.rxSession = receiverConfig.DataSessionID
	}
	peer.txSession = senderConfig.DataSessionID
	peer.remoteMTU = senderConfig.RemotePeerMTU
	peer.dataFragments = carrierFragmentCountForPayload(senderConfig.CarrierPayload, d.innerMTU)
	peer.dataCarrierSize = senderConfig.CarrierPayload + carrier.IPv6HeaderSize
	peers := d.table.Load().peers
	d.dataFragments = maxPeerFragments(peers)
	activeCarrierSize := maxPeerCarrierSize(peers)
	activeSlots := activeCarrierQueueSlots(d.queueLimit, d.dataFragments, d.batch, activePeerCount(peers))
	if activeSlots <= 0 || activeCarrierSize <= 0 || activeCarrierSize > int(^uint(0)>>1)/activeSlots {
		return ErrInvalidConfig
	}
	if activeCarrierSize != d.dataStride || activeSlots != len(d.queueLens) {
		d.queueLens = make([]int, activeSlots)
		d.queuePeers = make([]peerroute.PeerID, activeSlots)
		d.queueData = make([]byte, activeCarrierSize*activeSlots)
		d.dataStride = activeCarrierSize
		d.payloadStride = activeCarrierSize - carrier.IPv6HeaderSize
		d.carrierSize = activeCarrierSize
	}
	d.queueHead = 0
	d.queueCount = 0
	clear(d.queueLens)
	d.notifyDrained()
	return nil
}

// ResetTransportErrors clears interface-wide transport failures at the end of
// a successful configuration transaction. Peer data-plane installation is
// deliberately not allowed to clear these shared errors independently.
func (d *Device) ResetTransportErrors() {
	d.txMu.Lock()
	d.txFatal = nil
	d.txMu.Unlock()
	d.rxAsyncErr.Store(nil)
}

// SetDataEnabled closes or opens one peer's CONTROL DATA gate. While closed,
// the native reader retains only a fixed number of that peer's most-recent
// inner packets. On opening, those packets are immediately packetized with the
// installed local session; no timer is introduced for packing.
func (d *Device) SetDataEnabled(id peerroute.PeerID, enabled bool) error {
	if d.closed.Load() {
		return ErrClosed
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.closed.Load() {
		return ErrClosed
	}
	peer, ok := d.peerFor(id)
	if !ok {
		return errors.Join(ErrPeerNotFound, ErrInvalidConfig)
	}
	if !enabled {
		peer.dataEnabled.Store(false)
		peer.pendingHead = 0
		peer.pendingCount = 0
		clear(peer.pendingLens)
		d.notifyDrained()
		return nil
	}
	if peer.dataEnabled.Load() {
		return nil
	}
	peer.dataEnabled.Store(true)
	startCount := d.queueCount
	pendingCount := peer.pendingCount
	if err := d.flushPendingLocked(peer); err != nil {
		if errors.Is(err, ErrCarrierQueueFull) {
			// Opening a gate can race with another producer filling the
			// bounded carrier ring. Roll back this peer's partial batch and
			// drop the retained packets; ordinary backpressure must not make
			// wireguard-go tear down the whole device.
			d.rollbackDataLocked(startCount)
			peer.sender.ResetPending()
			d.preconfirmDrops.Add(uint64(pendingCount))
			d.notifyQueue()
			return nil
		}
		peer.dataEnabled.Store(false)
		d.txFatal = err
		d.notifyQueue()
		return err
	}
	d.notifyQueue()
	return nil
}

// File delegates to the native TUN. wireguard-go does not use this for packet
// I/O, but callers may use it for platform-specific inspection.
func (d *Device) File() *os.File { return d.native.File() }

func (d *Device) Name() (string, error) { return d.native.Name() }

// MTU is wireguard-go's synthetic plaintext ceiling, not the native inner MTU.
func (d *Device) MTU() (int, error) { return SyntheticMTU, nil }

func (d *Device) Events() <-chan tun.Event { return d.events }

func (d *Device) BatchSize() int { return d.batch }

// Read drains CONTROL before DATA and otherwise waits for either fixed ring.
// Native reads run independently, so idle inner traffic cannot block CONTROL.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < 0 || len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, ErrShortBuffer
	}

	for {
		d.txMu.Lock()
		if d.controlSched.count != 0 || d.queueCount != 0 {
			n, err := d.drainCarriersLocked(bufs, sizes, offset)
			pending := d.controlSched.count != 0 || d.queueCount != 0
			d.txMu.Unlock()
			d.notifyDrained()
			if err != nil || n != 0 || !pending {
				return n, err
			}
			// Both rings can remain non-empty when a token bucket is empty.
			// Avoid a zero-result busy loop while retaining normal close/wake
			// behavior for callers of tun.Device.Read.
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-timer.C:
			case <-d.stop:
				if !timer.Stop() {
					<-timer.C
				}
				return 0, ErrClosed
			}
			continue
		}
		if d.txFatal != nil {
			err := d.txFatal
			d.txMu.Unlock()
			return 0, err
		}
		d.txMu.Unlock()

		select {
		case <-d.queueReady:
		case <-d.stop:
			return 0, ErrClosed
		}
	}
}

// ReadPayloads drains transport-neutral carrier payloads. Each descriptor's
// Payload is caller-owned output storage; only [:Length] is written. The
// descriptors and buffers are borrowed for the synchronous call and are not
// retained. CONTROL is returned as a payload too, with its logical peer ID.
func (d *Device) ReadPayloads(batch transport.TXBatch) (int, error) {
	if len(batch) == 0 {
		return 0, ErrShortBuffer
	}
	for i := range batch {
		batch[i].Length = 0
	}

	for {
		d.txMu.Lock()
		if d.controlSched.count != 0 || d.queueCount != 0 {
			n, err := d.drainPayloadsLocked(batch)
			pending := d.controlSched.count != 0 || d.queueCount != 0
			d.txMu.Unlock()
			d.notifyDrained()
			if err != nil || n != 0 || !pending {
				return n, err
			}
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-timer.C:
			case <-d.readInterrupt:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return 0, ErrReadInterrupted
			case <-d.stop:
				if !timer.Stop() {
					<-timer.C
				}
				return 0, ErrClosed
			}
			continue
		}
		if d.txFatal != nil {
			err := d.txFatal
			d.txMu.Unlock()
			return 0, err
		}
		d.txMu.Unlock()

		select {
		case <-d.queueReady:
		case <-d.readInterrupt:
			return 0, ErrReadInterrupted
		case <-d.stop:
			return 0, ErrClosed
		}
	}
}

// InterruptPayloadRead wakes one idle ReadPayloads call. It is used only by a
// cold transport reconfiguration so the adapter can switch its peer mapping
// without waiting for unrelated native traffic.
func (d *Device) InterruptPayloadRead() {
	if d == nil || d.closed.Load() {
		return
	}

	select {
	case d.readInterrupt <- struct{}{}:
	default:
	}
}

func (d *Device) drainPayloadsLocked(batch transport.TXBatch) (int, error) {
	n := 0
	for n < len(batch) {
		if d.controlSched.count != 0 && (d.controlSched.controlBurst < 4 || d.queueCount == 0) {
			desc, index, ok := d.controlSched.choose(time.Now())
			if ok {
				d.controlSuppressionActive = false
				peer, exists := d.peerFor(desc.peer)
				if !exists {
					d.controlSched.pop(index)
					d.controlHead = d.controlSched.head
					d.controlCount = d.controlSched.count
					continue
				}
				frameLen, err := materializeControl(desc, batch[n].Payload, d.control)
				if err != nil {
					if errors.Is(err, control.ErrShortBuffer) {
						d.controlSched.refund(desc.peer)
						return n, ErrShortBuffer
					}
					d.controlSched.pop(index)
					d.controlMaterializationDrops.Add(1)
					d.controlHead = d.controlSched.head
					d.controlCount = d.controlSched.count
					continue
				}
				if frameLen > len(batch[n].Payload) {
					d.controlSched.refund(desc.peer)
					return n, ErrShortBuffer
				}
				batch[n].PeerID = peer.id
				batch[n].Length = frameLen

				d.controlSched.pop(index)
				d.controlHead = d.controlSched.head
				d.controlCount = d.controlSched.count
				d.controlSched.controlBurst++
				n++
				continue
			}
			d.noteControlSuppressionLocked(true)
		} else if d.controlSched.count == 0 || d.controlSched.controlBurst >= 4 {
			d.noteControlSuppressionLocked(false)
		}
		if d.queueCount != 0 {
			length := d.queueLens[d.queueHead]
			if length > len(batch[n].Payload) {
				return n, ErrShortBuffer
			}
			start := d.queueHead * d.dataStride
			copy(batch[n].Payload[:length], d.queueData[start:start+length])
			batch[n].PeerID = d.queuePeers[d.queueHead]
			batch[n].Length = length
			d.queueLens[d.queueHead] = 0
			d.queuePeers[d.queueHead] = 0
			d.queueHead = (d.queueHead + 1) % len(d.queueLens)
			d.queueCount--
			d.controlSched.controlBurst = 0
			n++
			continue
		}

		break
	}
	if d.controlSched.count == 0 {
		d.noteControlSuppressionLocked(false)
	}
	return n, nil
}

// EnqueueControl validates and wraps one complete CONTROL frame, then appends
// it to a dedicated bounded ring. CONTROL remains enqueueable while the DATA
// ring is full and is always drained first. A full ring is a counted drop, not
// an error: every CONTROL exchange is retried by its engine, so failing the
// caller would tear down a session that recovers on its own.
func (d *Device) EnqueueControl(id peerroute.PeerID, frame []byte) error {
	if d.closed.Load() {
		return ErrClosed
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.closed.Load() {
		return ErrClosed
	}
	if _, ok := d.peerFor(id); !ok {
		return errors.Join(ErrPeerNotFound, ErrInvalidConfig)
	}
	dropped, evicted, coalesced, err := d.controlSched.enqueue(id, frame, d.control)
	if err != nil {
		return err
	}
	if dropped {
		d.controlQueueDrops.Add(1)
	}
	if evicted {
		d.controlExploratoryEvictions.Add(1)
	}
	if coalesced {
		d.controlCoalesces.Add(1)
	}
	d.controlHead = d.controlSched.head
	d.controlCount = d.controlSched.count
	d.notifyQueue()
	return nil
}

func (d *Device) enqueuePayloadLocked(peer peerroute.PeerID, packet []byte) error {
	if d.queueCount == len(d.queueLens) {
		d.carrierQueueOverflows.Add(1)
		return ErrCarrierQueueFull
	}
	if len(packet) > d.payloadStride {
		return ErrShortBuffer
	}
	index := (d.queueHead + d.queueCount) % len(d.queueLens)
	start := index * d.dataStride
	copy(d.queueData[start:start+len(packet)], packet)
	d.queueLens[index] = len(packet)
	d.queuePeers[index] = peer
	d.queueCount++
	d.txCarriers.Add(1)
	return nil
}

func (d *Device) drainCarriersLocked(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for n < len(bufs) {
		// CONTROL gets bounded priority, but four consecutive CONTROL
		// services must yield one pending DATA carrier.
		//nolint:nestif // CONTROL/DATA arbitration and bounded refund handling are one transaction.
		if d.controlSched.count != 0 && (d.controlSched.controlBurst < 4 || d.queueCount == 0) {
			desc, index, ok := d.controlSched.choose(time.Now())
			if ok {
				d.controlSuppressionActive = false
				peer, exists := d.peerFor(desc.peer)
				if !exists {
					d.controlSched.pop(index)
					d.controlHead = d.controlSched.head
					d.controlCount = d.controlSched.count
					continue
				}
				start := index * d.controlStride
				payload := d.controlData[start+carrier.IPv6HeaderSize : start+d.controlStride]
				frameLen, err := materializeControl(desc, payload, d.control)
				if err != nil {
					if errors.Is(err, control.ErrShortBuffer) {
						d.controlSched.refund(desc.peer)
						return n, ErrShortBuffer
					}
					d.controlSched.pop(index)
					d.controlMaterializationDrops.Add(1)
					d.controlHead = d.controlSched.head
					d.controlCount = d.controlSched.count
					continue
				}
				length, err := carrier.MarshalEnvelopeTo(
					d.controlData[start:start+d.controlStride],
					d.txSource,
					peer.txDest,
					payload[:frameLen],
				)
				if err != nil {
					return n, err
				}
				if offset > len(bufs[n]) || length > len(bufs[n])-offset {
					d.controlSched.refund(desc.peer)
					return n, ErrShortBuffer
				}
				copy(bufs[n][offset:offset+length], d.controlData[start:start+length])
				sizes[n] = length
				d.controlLens[index] = 0
				d.controlSched.pop(index)
				d.controlHead = d.controlSched.head
				d.controlCount = d.controlSched.count
				d.controlSched.controlBurst++
				n++
				continue
			}
			// No token available. DATA may still make progress below;
			// otherwise Read waits briefly for the next bucket refill.
			d.noteControlSuppressionLocked(true)
		} else if d.controlSched.count == 0 || d.controlSched.controlBurst >= 4 {
			d.noteControlSuppressionLocked(false)
		}
		if d.queueCount != 0 {
			payloadLength := d.queueLens[d.queueHead]
			peer, ok := d.peerFor(d.queuePeers[d.queueHead])
			if !ok {
				d.queueLens[d.queueHead] = 0
				d.queueHead = (d.queueHead + 1) % len(d.queueLens)
				d.queueCount--
				continue
			}
			if offset > len(bufs[n]) || carrier.IPv6HeaderSize+payloadLength > len(bufs[n])-offset {
				return n, ErrShortBuffer
			}
			start := d.queueHead * d.dataStride
			length, err := carrier.MarshalEnvelopeTo(
				bufs[n][offset:],
				d.txSource,
				peer.txDest,
				d.queueData[start:start+payloadLength],
			)
			if err != nil {
				return n, err
			}
			sizes[n] = length
			d.queueLens[d.queueHead] = 0
			d.queuePeers[d.queueHead] = 0
			d.queueHead = (d.queueHead + 1) % len(d.queueLens)
			d.queueCount--
			d.controlSched.controlBurst = 0
			n++
			continue
		}

		break
	}
	if d.controlSched.count == 0 {
		d.noteControlSuppressionLocked(false)
	}
	return n, nil
}

func (d *Device) noteControlSuppressionLocked(blocked bool) {
	if blocked {
		if !d.controlSuppressionActive {
			d.controlRateSuppressionEpisodes.Add(1)
			d.controlSuppressionActive = true
		}
		return
	}
	d.controlSuppressionActive = false
}

func (d *Device) notifyQueue() {
	select {
	case d.queueReady <- struct{}{}:
	default:
	}
}

// readNative is the sole owner of readBufs, readSizes, and Sender. It holds
// txMu while building one complete native batch, making publication atomic.
func (d *Device) readNative() {
	defer d.done.Done()

	for {
		if !d.waitForCarrierSpace() {
			return
		}
		n, readErr := d.native.Read(d.readBufs, d.readSizes, 0)
		if d.closed.Load() {
			return
		}
		if n < 0 || n > len(d.readBufs) || n > len(d.readSizes) {
			d.setTXFatal(ErrShortBuffer)
			return
		}
		if n != 0 && !d.processNativeBatch(n) {
			return
		}
		if readErr != nil && !errors.Is(readErr, tun.ErrTooManySegments) {
			d.setTXFatal(readErr)
			return
		}
	}
}

// waitForCarrierSpace blocks until a worst-case native batch fits in the DATA
// ring; returning an overflow error would make wireguard-go close the device.
func (d *Device) waitForCarrierSpace() bool {
	for {
		d.txMu.Lock()
		free := len(d.queueLens) - d.queueCount
		pending := 0
		for _, peer := range d.table.Load().peers {
			if peer == nil {
				continue
			}
			if pending > int(^uint(0)>>1)-peer.pendingCount {
				pending = int(^uint(0) >> 1)

				break
			}
			pending += peer.pendingCount
		}
		needPackets := d.batch
		if pending > int(^uint(0)>>1)-needPackets {
			needPackets = int(^uint(0) >> 1)
		} else {
			needPackets += pending
		}
		fragments := d.dataFragments
		need := int(^uint(0) >> 1)
		if needPackets <= need/fragments {
			need = needPackets * fragments
		}
		// A caller may intentionally configure a smaller ring than the
		// worst-case batch. Admission cannot wait for more slots than exist;
		// processNativeBatch will account and drop that batch instead.
		if need > len(d.queueLens) {
			need = len(d.queueLens)
		}
		if need < 1 {
			need = 1
		}
		d.txMu.Unlock()
		if free >= need || !d.anyDataEnabled() {
			return true
		}

		select {
		case <-d.queueDrained:
		case <-d.stop:
			return false
		}
	}
}

func (d *Device) notifyDrained() {
	select {
	case d.queueDrained <- struct{}{}:
	default:
	}
}

func (d *Device) processNativeBatch(n int) bool {
	d.txMu.Lock()
	table := d.table.Load()
	startCount := d.queueCount
	for _, peer := range table.peers {
		if peer == nil || !peer.dataEnabled.Load() {
			continue
		}
		if err := d.flushPendingLocked(peer); err != nil {
			if d.dropBatchLocked(startCount, err) {
				return true
			}
			d.txFatal = err
			d.txMu.Unlock()
			d.notifyQueue()
			return false
		}
	}

	for i := 0; i < n; i++ {
		size := d.readSizes[i]
		if size < 0 || size > len(d.readBufs[i]) {
			d.rollbackDataLocked(startCount)
			d.txFatal = ErrShortBuffer
			d.txMu.Unlock()
			d.notifyQueue()
			return false
		}
		packet := d.readBufs[i][:size]
		peer, err := routePacket(table, packet)
		if err != nil {
			d.dropTXPacket(err, packet, 0)
			continue
		}
		if !peer.dataEnabled.Load() {
			d.enqueuePendingLocked(peer, packet)
			continue
		}
		if err := peer.sender.Add(packet); err != nil {
			if isPacketError(err) {
				d.dropTXPacket(err, packet, peer.remoteMTU)
				continue
			}
			if d.dropBatchLocked(startCount, err) {
				return true
			}
			d.txFatal = err
			d.txMu.Unlock()
			d.notifyQueue()
			return false
		}
	}
	for _, peer := range table.peers {
		if peer == nil || !peer.dataEnabled.Load() {
			continue
		}
		if err := peer.sender.Flush(); err != nil {
			if d.dropBatchLocked(startCount, err) {
				return true
			}
			d.txFatal = err
			d.txMu.Unlock()
			d.notifyQueue()
			return false
		}
	}
	published := d.queueCount != startCount
	d.txMu.Unlock()
	if published {
		d.notifyQueue()
	}
	return true
}

// routePacket selects the peer that owns an inner packet's destination.
// Egress selection is a global longest-prefix match over every peer's user
// AllowedIPs, so a less specific peer cannot capture another peer's traffic.
func routePacket(table *peerTable, packet []byte) (*peerState, error) {
	parsed, err := innerip.Parse(packet)
	if err != nil {
		return nil, err
	}
	if table.routes == nil {
		// A nil snapshot is the single-peer compatibility mode. Reconfigure can
		// remove slot zero, so use the sole survivor rather than assuming its ID.
		var fallback *peerState
		for _, peer := range table.peers {
			if peer == nil {
				continue
			}
			if fallback != nil {
				return nil, datapath.ErrInnerDest
			}
			fallback = peer
		}
		if fallback != nil {
			return fallback, nil
		}
		return nil, datapath.ErrInnerDest
	}
	id, ok := table.routes.LookupPeer(parsed.Destination)
	if !ok || uint64(id) >= uint64(len(table.peers)) || table.peers[int(id)] == nil {
		return nil, datapath.ErrInnerDest
	}
	return table.peers[int(id)], nil
}

func (d *Device) enqueuePendingLocked(peer *peerState, packet []byte) {
	if peer.pendingCount == len(peer.pendingLens) {
		peer.pendingLens[peer.pendingHead] = 0
		peer.pendingHead = (peer.pendingHead + 1) % len(peer.pendingLens)
		peer.pendingCount--

		d.preconfirmDrops.Add(1)
	}
	index := (peer.pendingHead + peer.pendingCount) % len(peer.pendingLens)
	start := index * d.innerMTU
	copy(peer.pendingData[start:start+len(packet)], packet)
	peer.pendingLens[index] = len(packet)
	peer.pendingCount++
}

func (d *Device) flushPendingLocked(peer *peerState) error {
	for peer.pendingCount != 0 {
		index := peer.pendingHead
		length := peer.pendingLens[index]
		start := index * d.innerMTU
		packet := peer.pendingData[start : start+length]
		peer.pendingLens[index] = 0
		peer.pendingHead = (peer.pendingHead + 1) % len(peer.pendingLens)
		peer.pendingCount--
		if err := peer.sender.Add(packet); err != nil {
			if isPacketError(err) {
				d.dropTXPacket(err, packet, peer.remoteMTU)
				continue
			}
			return err
		}
	}
	return peer.sender.Flush()
}

// dropTXPacket counts one undeliverable inner packet and answers an oversize
// one with Packet Too Big. Zero remoteMTU marks call sites where no peer was
// resolved and an MTU error therefore cannot occur.
func (d *Device) dropTXPacket(err error, packet []byte, remoteMTU int) {
	d.txPacketDrops.Add(1)
	if errors.Is(err, innerip.ErrNativeFragment) {
		d.txNativeFragmentDrops.Add(1)
	}
	if errors.Is(err, datapath.ErrInnerDest) {
		d.txRouteDrops.Add(1)
	}
	if errors.Is(err, datapath.ErrPeerMTU) {
		d.txPeerMTUDrops.Add(1)
		d.emitPacketTooBig(packet, remoteMTU)
	}
}

// ptbTokenBucketSize caps the Packet Too Big rate at bucket size per second,
// so a bulk sender cannot turn the shim into an ICMP amplifier.
const ptbTokenBucketSize = 16

// emitPacketTooBig answers an oversize inner packet on the native TUN. The
// message is sourced from the original destination: a source address local to
// the injected kernel is discarded as a martian, and the destination is what
// the far host would use, so it also works in route-only configurations. It
// is called only from readNative.
func (d *Device) emitPacketTooBig(packet []byte, remoteMTU int) {
	if remoteMTU <= 0 || len(packet) == 0 {
		return
	}
	now := time.Now()
	if elapsed := now.Sub(d.ptbRefill); elapsed >= time.Second {
		d.ptbTokens = ptbTokenBucketSize
		d.ptbRefill = now
	}
	if d.ptbTokens == 0 {
		return
	}
	source, ok := ptbSourceFor(packet)
	if !ok {
		return
	}
	n, err := icmp.BuildPacketTooBig(d.ptbStorage, packet, source, remoteMTU)
	if err != nil {
		return
	}

	d.ptbTokens--
	written, err := d.writeNative(d.ptbStorage[:n])
	if err == nil && written {
		d.txPTBSent.Add(1)
	}
}

// ptbSourceFor extracts the original destination address.
func ptbSourceFor(packet []byte) (netip.Addr, bool) {
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[16:20])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[24:40])), true
	default:
		return netip.Addr{}, false
	}
}

// dropBatchLocked discards a batch that lost a race with a full ring without
// turning ordinary backpressure into a fatal wireguard-go Read error.
func (d *Device) dropBatchLocked(startCount int, err error) bool {
	if !errors.Is(err, ErrCarrierQueueFull) {
		return false
	}
	d.rollbackDataLocked(startCount)
	for _, peer := range d.table.Load().peers {
		if peer != nil {
			peer.sender.ResetPending()
		}
	}
	d.txMu.Unlock()
	d.notifyQueue()
	return true
}

func (d *Device) rollbackDataLocked(wantCount int) {
	for d.queueCount > wantCount {
		index := (d.queueHead + d.queueCount - 1) % len(d.queueLens)
		d.queueLens[index] = 0
		d.queuePeers[index] = 0
		d.queueCount--
	}
}

func (d *Device) setTXFatal(err error) {
	d.txMu.Lock()
	if d.txFatal == nil {
		d.txFatal = err
	}
	d.txMu.Unlock()
	d.notifyQueue()
}

// senderQueueSink is called only by readNative while txMu is held.
type senderQueueSink struct{ device *Device }

func (s senderQueueSink) DeliverCarrier(packet []byte) error {
	for _, peer := range s.device.table.Load().peers {
		if peer == nil {
			continue
		}
		envelope, err := carrier.ParseEnvelope(packet, s.device.txSource, peer.txDest)
		if err == nil {
			return s.device.enqueuePayloadLocked(peer.id, envelope.Payload)
		}
	}
	return carrier.ErrCarrierDestination
}

// DeliverPayload is the transport-neutral TX boundary. The callback is
// synchronous and aliases Sender's fixed packetizer buffer.
func (s senderQueueSink) DeliverPayload(peer peerroute.PeerID, payload []byte) error {
	return s.device.enqueuePayloadLocked(peer, payload)
}

// writeTouches tracks a small fixed chunk of peers touched by one Write call.
// The chunk is flushed before a fifth distinct peer is added, so Write never
// allocates even if one batch contains carriers from many peers.
type writeTouches struct {
	peers [4]*peerState
	count int
}

func (t *writeTouches) has(peer *peerState) bool {
	for i := 0; i < t.count; i++ {
		if t.peers[i] == peer {
			return true
		}
	}
	return false
}

func (t *writeTouches) add(peer *peerState) {
	if t.has(peer) {
		return
	}
	if t.count == len(t.peers) {
		panic("shimtun: write touch chunk is full")
	}
	t.peers[t.count] = peer
	t.count++
}

func (t *writeTouches) reset() {
	clear(t.peers[:t.count])
	t.count = 0
}

// Write accepts authenticated synthetic carriers from wireguard-go and writes
// every completed inner packet synchronously to the native TUN. It holds only
// the resolved peer's rxMu, so wireguard-go's per-peer sequential receiver
// goroutines reassemble concurrently.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	if d.closed.Load() {
		return 0, ErrClosed
	}
	if offset < 0 {
		return 0, ErrShortBuffer
	}
	var now time.Time
	var touched writeTouches
	for i, buffer := range bufs {
		if offset > len(buffer) {
			return i, d.failWrite(&touched, ErrShortBuffer)
		}
		packet := buffer[offset:]
		peer, handled, err := d.acceptControl(packet)
		if err != nil {
			d.recordReceiveError(err)
			// A malformed carrier or CONTROL frame from an authenticated peer,
			// and a transiently full CONTROL ring, must not suppress the
			// unrelated packets wireguard-go decrypted into the same batch.
			if errors.Is(err, ErrClosed) || errors.Is(err, ErrControlSink) {
				return i, d.failWrite(&touched, err)
			}
			continue
		}
		if handled {
			continue
		}

		peer.rxMu.Lock()
		accepted := false
		if d.closed.Load() {
			peer.rxMu.Unlock()
			return i, ErrClosed
		}
		if !peer.dataEnabled.Load() {
			err = ErrDataNotReady
		} else if asyncErr := d.rxAsyncErr.Swap(nil); asyncErr != nil {
			err = *asyncErr
		} else {
			if now.IsZero() {
				now = time.Now()
			}
			d.rxDataCarriers.Add(1)
			accepted = true
			err = peer.receiver.AcceptCarrier(now, packet, peer.sink)
		}
		peer.rxMu.Unlock()
		if accepted && !touched.has(peer) && touched.count == len(touched.peers) {
			// flushTouched takes the same per-peer locks, so call it after the
			// current peer's lock is released.
			if flushErr := d.flushTouched(&touched); flushErr != nil {
				peer.rxMu.Lock()
				currentErr := d.flushInnerLocked(peer)
				peer.rxMu.Unlock()
				if currentErr != nil {
					return i, currentErr
				}
				return i, flushErr
			}
			touched.reset()
		}
		if accepted {
			touched.add(peer)
		}
		if err != nil {
			d.recordReceiveError(err)
			if errors.Is(err, datapath.ErrDataSession) {
				if syncErr := d.reportUnknownSession(peer); syncErr != nil {
					return i, d.failWrite(&touched, syncErr)
				}
			}
			if datapath.IsCarrierDrop(err) || errors.Is(err, ErrDataNotReady) {
				continue
			}
			return i, d.failWrite(&touched, err)
		}
	}
	if err := d.flushTouched(&touched); err != nil {
		return len(bufs), err
	}
	return len(bufs), nil
}

// WritePayloads ingests authenticated transport payloads. PeerID must already
// have been established by the transport adapter; this method never derives
// identity from payload bytes or endpoints. Payload buffers are borrowed only
// for this synchronous call and are not retained.
func (d *Device) WritePayloads(batch transport.RXBatch) (int, error) {
	if d.closed.Load() {
		return 0, ErrClosed
	}
	var now time.Time
	var touched writeTouches
	for i := range batch {
		desc := &batch[i]
		if desc.Length < 0 || desc.Length > len(desc.Payload) {
			return i, d.failWrite(&touched, ErrShortBuffer)
		}
		peer, ok := d.peerFor(desc.PeerID)
		if !ok {
			d.recordReceiveError(carrier.ErrCarrierSource)
			continue
		}
		payload := desc.Payload[:desc.Length]
		if len(payload) >= 2 && binary.BigEndian.Uint16(payload[:2]) == control.Marker {
			if _, err := d.control.Parse(payload); err != nil {
				d.recordReceiveError(err)
				continue
			}
			if !d.allowControlIngress(peer, time.Now()) {
				d.recordReceiveError(ErrCarrierQueueFull)
				continue
			}
			if d.controlSink == nil {
				return i, d.failWrite(&touched, ErrControlSink)
			}
			if err := d.controlSink.DeliverControl(peer.id, payload); err != nil {
				d.recordReceiveError(err)
				if errors.Is(err, ErrClosed) || errors.Is(err, ErrControlSink) {
					return i, d.failWrite(&touched, err)
				}
			}
			continue
		}

		peer.rxMu.Lock()
		accepted := false
		var err error
		if d.closed.Load() {
			peer.rxMu.Unlock()
			return i, d.failWrite(&touched, ErrClosed)
		}
		if !peer.dataEnabled.Load() {
			err = ErrDataNotReady
		} else if asyncErr := d.rxAsyncErr.Swap(nil); asyncErr != nil {
			err = *asyncErr
		} else {
			if now.IsZero() {
				now = time.Now()
			}
			d.rxDataCarriers.Add(1)
			accepted = true
			err = peer.receiver.AcceptPayload(now, payload, peer.sink)
		}
		peer.rxMu.Unlock()
		if accepted && !touched.has(peer) && touched.count == len(touched.peers) {
			if flushErr := d.flushTouched(&touched); flushErr != nil {
				peer.rxMu.Lock()
				currentErr := d.flushInnerLocked(peer)
				peer.rxMu.Unlock()
				if currentErr != nil {
					return i, currentErr
				}
				return i, flushErr
			}
			touched.reset()
		}
		if accepted {
			touched.add(peer)
		}
		if err != nil {
			d.recordReceiveError(err)
			if errors.Is(err, datapath.ErrDataSession) {
				if syncErr := d.reportUnknownSession(peer); syncErr != nil {
					return i, d.failWrite(&touched, syncErr)
				}
			}
			if datapath.IsCarrierDrop(err) || errors.Is(err, ErrDataNotReady) {
				continue
			}
			return i, d.failWrite(&touched, err)
		}
	}
	if err := d.flushTouched(&touched); err != nil {
		return len(batch), err
	}
	return len(batch), nil
}

// flushTouched writes every touched peer's delivery slab to the native TUN.
func (d *Device) flushTouched(touched *writeTouches) error {
	var firstErr error
	for _, peer := range touched.peers[:touched.count] {
		if peer == nil {
			continue
		}
		peer.rxMu.Lock()
		err := d.flushInnerLocked(peer)
		peer.rxMu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// failWrite flushes packets already completed by this batch before Write
// unwinds with err; a native flush failure takes precedence.
func (d *Device) failWrite(touched *writeTouches, err error) error {
	if flushErr := d.flushTouched(touched); flushErr != nil {
		return flushErr
	}
	return err
}

// acceptControl resolves the sending peer from the authenticated carrier
// source, then dispatches CONTROL without the DATA reassembly lock so the sink
// may install a new DATA session in response to ResetSequence.
func (d *Device) acceptControl(packet []byte) (*peerState, bool, error) {
	envelope, err := carrier.DecodeEnvelope(packet, d.rxDest)
	if err != nil {
		return nil, false, err
	}
	table := d.table.Load()
	id, known := table.byCarrier[envelope.Source]
	if !known || int(id) >= len(table.peers) || table.peers[id] == nil {
		return nil, false, carrier.ErrCarrierSource
	}
	peer := table.peers[id]
	if len(envelope.Payload) >= 2 && binary.BigEndian.Uint16(envelope.Payload[:2]) == control.Marker {
		if _, err := d.control.Parse(envelope.Payload); err != nil {
			return peer, true, err
		}
		if !d.allowControlIngress(peer, time.Now()) {
			d.recordReceiveError(ErrCarrierQueueFull)
			return peer, true, nil
		}
		if d.controlSink == nil {
			return peer, true, ErrControlSink
		}
		return peer, true, d.controlSink.DeliverControl(peer.id, envelope.Payload)
	}
	if !peer.dataEnabled.Load() {
		return peer, false, ErrDataNotReady
	}
	return peer, false, nil
}

// allowControlIngress bounds authenticated CONTROL parsing per peer and for
// the interface before protobuf decoding. DATA never takes this lock.
func (d *Device) allowControlIngress(peer *peerState, now time.Time) bool {
	d.controlIngressMu.Lock()
	defer d.controlIngressMu.Unlock()
	d.controlIngressGlobal.refill(now, controlIngressGlobalRate, controlIngressGlobalBurst)
	peer.controlIngress.refill(now, controlIngressPeerRate, controlIngressPeerBurst)
	if !d.controlIngressGlobal.available() || !peer.controlIngress.available() {
		d.controlIngressRateLimited.Add(1)
		return false
	}
	d.controlIngressGlobal.take()
	peer.controlIngress.take()
	return true
}

func (d *Device) reportUnknownSession(peer *peerState) error {
	sink, ok := d.controlSink.(SessionSink)
	if !ok {
		return nil
	}
	peer.rxMu.Lock()
	session, seen := peer.receiver.TakeUnknownSession()
	peer.rxMu.Unlock()
	if !seen {
		return nil
	}
	return sink.ReportUnknownDataSession(peer.id, session)
}

func (d *Device) recordReceiveError(err error) {
	d.rxPacketRejects.Add(1)
}

// RecordTransportDrop accounts for a carrier rejected by an adapter before a
// transport-neutral payload can be delivered. The reason is deliberately not
// retained because it may contain adapter-specific endpoint state.
func (d *Device) RecordTransportDrop() {
	d.recordReceiveError(ErrShortBuffer)
}

// peerDeliverySink routes Receiver completions into the owning peer's slab.
// It is built once per peerState, so the hot path converts no interfaces.
type peerDeliverySink struct {
	device *Device
	peer   *peerState
}

// DeliverInner consumes Receiver's reusable reassembly slot synchronously by
// copying it into the peer's delivery slab. The batch is written to the native
// TUN when the surrounding Write or expiration tick completes, or when the
// slab fills. Callers hold the peer's rxMu.
func (s peerDeliverySink) DeliverInner(packet []byte) error {
	d, peer := s.device, s.peer
	offset := d.nativeWriteOffset
	stride := offset + d.innerMTU
	if len(packet) > d.innerMTU {
		return ErrShortBuffer
	}
	if peer.deliverCount == d.batch {
		if err := d.flushInnerLocked(peer); err != nil {
			return err
		}
	}
	start := peer.deliverCount * stride
	clear(peer.deliverStorage[start : start+offset])
	copy(peer.deliverStorage[start+offset:], packet)
	peer.deliverBufs = append(peer.deliverBufs, peer.deliverStorage[start:start+offset+len(packet):start+stride])
	peer.deliverCount++
	return nil
}

// flushInnerLocked writes one peer's delivery slab as one native TUN batch.
// Callers hold that peer's rxMu; nativeWriteMu serializes the platform call.
// A full native queue drops the batch as counted drops.
func (d *Device) flushInnerLocked(peer *peerState) error {
	if peer.deliverCount == 0 {
		return nil
	}
	count := peer.deliverCount

	d.nativeWriteMu.Lock()
	_, err := d.native.Write(peer.deliverBufs[:count], d.nativeWriteOffset)
	d.nativeWriteMu.Unlock()
	peer.deliverBufs = peer.deliverBufs[:0]
	peer.deliverCount = 0
	if err != nil {
		// NativeTun joins per-buffer errors and a full queue charges the whole
		// batch as drops.
		if errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOMEM) {
			d.rxNativeWriteDrops.Add(uint64(count))
			return nil
		}
		return err
	}
	// The numeric result is not a per-packet success signal: NativeTun's GRO
	// legally coalesces same-flow buffers and returns fewer bytes than the
	// slab submitted, so only the error return may fail the batch.
	d.rxInnerDelivered.Add(uint64(count))
	return nil
}

// writeNative writes one inner packet to the native TUN. Only readNative calls
// it, so the reusable write header storage needs no lock.
func (d *Device) writeNative(packet []byte) (bool, error) {
	offset := d.nativeWriteOffset
	if offset == 0 {
		d.writeBufs[0] = packet
	} else {
		if len(packet) > len(d.writeStorage)-offset {
			return false, ErrShortBuffer
		}
		clear(d.writeStorage[:offset])
		copy(d.writeStorage[offset:], packet)
		d.writeBufs[0] = d.writeStorage[:offset+len(packet)]
	}
	d.nativeWriteMu.Lock()
	n, err := d.native.Write(d.writeBufs[:], offset)
	d.nativeWriteMu.Unlock()
	d.writeBufs[0] = nil
	if err != nil {
		if errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOMEM) {
			d.rxNativeWriteDrops.Add(1)
			return false, nil
		}
		return false, err
	}
	// NativeTun with IFF_VNET_HDR returns bytes; other devices return packets.
	if n != 1 && n < offset+len(packet) {
		return false, ErrShortNativeWrite
	}
	return true, nil
}

func (d *Device) Stats() Stats {
	var drops datapath.ReceiverDrops
	drops.SourceSpoof = d.retiredSourceSpoofDrops.Load()
	drops.NativeFragment = d.retiredNativeFragmentDrops.Load()
	drops.InnerInvalid = d.retiredInnerInvalidDrops.Load()
	for _, peer := range d.table.Load().peers {
		if peer == nil {
			continue
		}
		peer.rxMu.Lock()
		drops.SourceSpoof += peer.dropsBase.SourceSpoof
		drops.NativeFragment += peer.dropsBase.NativeFragment
		drops.InnerInvalid += peer.dropsBase.InnerInvalid
		if peer.receiver != nil {
			current := peer.receiver.Drops()
			drops.SourceSpoof += current.SourceSpoof
			drops.NativeFragment += current.NativeFragment
			drops.InnerInvalid += current.InnerInvalid
		}
		peer.rxMu.Unlock()
	}
	return Stats{
		TXCarriers:                     d.txCarriers.Load(),
		TXPacketDrops:                  d.txPacketDrops.Load(),
		TXNativeFragmentDrops:          d.txNativeFragmentDrops.Load(),
		TXRouteDrops:                   d.txRouteDrops.Load(),
		TXPeerMTUDrops:                 d.txPeerMTUDrops.Load(),
		TXPTBSent:                      d.txPTBSent.Load(),
		RXDataCarriers:                 d.rxDataCarriers.Load(),
		RXInnerDelivered:               d.rxInnerDelivered.Load(),
		RXPacketRejects:                d.rxPacketRejects.Load() + drops.SourceSpoof + drops.NativeFragment + drops.InnerInvalid,
		RXNativeFragmentDrops:          drops.NativeFragment,
		RXSourceSpoofDrops:             drops.SourceSpoof,
		RXNativeWriteDrops:             d.rxNativeWriteDrops.Load(),
		CarrierQueueOverflows:          d.carrierQueueOverflows.Load(),
		ControlQueueDrops:              d.controlQueueDrops.Load(),
		ControlExploratoryEvictions:    d.controlExploratoryEvictions.Load(),
		ControlCoalesces:               d.controlCoalesces.Load(),
		ControlRateSuppressionEpisodes: d.controlRateSuppressionEpisodes.Load(),
		ControlMaterializationDrops:    d.controlMaterializationDrops.Load(),
		ControlIngressRateLimited:      d.controlIngressRateLimited.Load(),
		PreconfirmDrops:                d.preconfirmDrops.Load(),
		ReassemblyExpirations:          d.reassemblyExpirations.Load(),
	}
}

func (d *Device) Close() error {
	d.once.Do(func() {
		d.closed.Store(true)
		close(d.stop)
		d.closeErr = d.native.Close()
		d.done.Wait()
		close(d.events)
	})
	return d.closeErr
}

func (d *Device) forwardEvents() {
	defer d.done.Done()

	for {
		select {
		case <-d.stop:
			return
		case event, ok := <-d.native.Events():
			if !ok {
				return
			}
			filtered := event &^ tun.EventMTUUpdate
			if filtered == 0 {
				continue
			}

			select {
			case d.events <- filtered:
			case <-d.stop:
				return
			}
		}
	}
}

func (d *Device) expireLoop(interval time.Duration) {
	defer d.done.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stop:
			return
		case now := <-ticker.C:
			for _, peer := range d.table.Load().peers {
				if peer == nil || d.closed.Load() {
					continue
				}
				peer.rxMu.Lock()
				expired, err := peer.receiver.Tick(now, peer.sink)
				d.reassemblyExpirations.Add(uint64(expired))
				if err != nil {
					// Policy drops from a reorder flush are not sticky failures.
					if datapath.IsCarrierDrop(err) {
						d.recordReceiveError(err)
					} else {
						d.rxAsyncErr.CompareAndSwap(nil, &err)
					}
				}
				if err := d.flushInnerLocked(peer); err != nil {
					d.rxAsyncErr.CompareAndSwap(nil, &err)
				}
				peer.rxMu.Unlock()
			}
		}
	}
}

func isPacketError(err error) bool {
	return errors.Is(err, innerip.ErrTooShort) || errors.Is(err, innerip.ErrUnsupportedIP) ||
		errors.Is(err, innerip.ErrInvalidIPv4) || errors.Is(err, innerip.ErrInvalidIPv6) ||
		errors.Is(err, innerip.ErrNativeFragment) || errors.Is(err, datapath.ErrPeerMTU) ||
		errors.Is(err, datapath.ErrInnerDest) || errors.Is(err, datapath.ErrLaneWrap)
}

var _ tun.Device = (*Device)(nil)
var _ datapath.Sink = peerDeliverySink{}
var _ datapath.CarrierSink = senderQueueSink{}
var _ datapath.PayloadSink = senderQueueSink{}
