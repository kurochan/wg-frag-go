package wgadapter

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/transport"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
	"golang.zx2c4.com/wireguard/tun"
)

// ErrWireGuardTUNConfig indicates an invalid hidden carrier mapping.
var ErrWireGuardTUNConfig = errors.New("wgadapter: invalid WireGuard TUN configuration")

// maxCarrierTableEntries bounds the slice used for process-local peer IDs.
// IDs are normally dense, but a stale sparse ID must not turn a malformed
// plan into an unbounded allocation.
const maxCarrierTableEntries = 1 << 16

// WireGuardTUN adapts transport-neutral shim carrier payloads to the
// synthetic IPv6 packets that wireguard-go exchanges with its tun.Device.
// It is the only owner of the hidden carrier address representation.
type WireGuardTUN struct {
	shim *shimtun.Device

	peers atomic.Pointer[wireGuardCarrierTable]

	txMu   sync.Mutex
	rxMu   sync.RWMutex
	config struct {
		transactionMu sync.Mutex
		stateMu       sync.Mutex
		done          chan struct{}
	}
	txDesc []transport.TXDescriptor
	rxPool sync.Pool
}

type wireGuardCarrierTable struct {
	local    netip.Addr
	byPeer   []netip.Addr
	bySource map[netip.Addr]peerroute.PeerID
}

type wireGuardRXBatch struct {
	descriptors []transport.RXDescriptor
	indices     []int
}

// NewWireGuardTUN creates a tun.Device facade for one shim and its current
// WireGuard peer plan. The caller must update it with Reconfigure after an
// accepted runtime peer update.
func NewWireGuardTUN(shim *shimtun.Device, plan Plan) (*WireGuardTUN, error) {
	if shim == nil || shim.BatchSize() <= 0 {
		return nil, ErrWireGuardTUNConfig
	}
	table, err := newWireGuardCarrierTable(plan)
	if err != nil {
		return nil, err
	}
	device := &WireGuardTUN{
		shim:   shim,
		txDesc: make([]transport.TXDescriptor, shim.BatchSize()),
	}
	device.peers.Store(table)
	device.rxPool.New = func() any {
		return &wireGuardRXBatch{
			descriptors: make([]transport.RXDescriptor, shim.BatchSize()),
			indices:     make([]int, shim.BatchSize()),
		}
	}
	return device, nil
}

func newWireGuardCarrierTable(plan Plan) (*wireGuardCarrierTable, error) {
	if !plan.LocalCarrier.Is6() || plan.LocalCarrier.Zone() != "" || !plan.LocalCarrier.IsLinkLocalUnicast() {
		return nil, ErrWireGuardTUNConfig
	}
	maxID := -1
	for _, peer := range plan.Peers {
		if !peer.Carrier.Is6() || peer.Carrier.Zone() != "" || !peer.Carrier.IsLinkLocalUnicast() {
			return nil, ErrWireGuardTUNConfig
		}
		if peer.Carrier == plan.LocalCarrier || uint64(peer.ID) >= maxCarrierTableEntries {
			return nil, ErrWireGuardTUNConfig
		}
		if int(peer.ID) > maxID {
			maxID = int(peer.ID)
		}
	}
	if maxID < 0 {
		return nil, ErrWireGuardTUNConfig
	}
	table := &wireGuardCarrierTable{
		local:    plan.LocalCarrier,
		byPeer:   make([]netip.Addr, maxID+1),
		bySource: make(map[netip.Addr]peerroute.PeerID, len(plan.Peers)),
	}
	for _, peer := range plan.Peers {
		if _, duplicate := table.bySource[peer.Carrier]; duplicate || table.byPeer[peer.ID].IsValid() {
			return nil, ErrWireGuardTUNConfig
		}
		table.byPeer[peer.ID] = peer.Carrier
		table.bySource[peer.Carrier] = peer.ID
	}
	return table, nil
}

func (d *WireGuardTUN) initialized() bool {
	return d != nil && d.shim != nil && d.peers.Load() != nil
}

// Reconfigure atomically publishes carrier peer mapping. Callers that also
// replace shim peers must use ReconfigureWithShim.
func (d *WireGuardTUN) Reconfigure(plan Plan) error {
	if !d.initialized() {
		return ErrWireGuardTUNConfig
	}
	table, err := newWireGuardCarrierTable(plan)
	if err != nil {
		return err
	}
	finish := d.beginReconfigure()

	defer finish()
	d.txMu.Lock()
	defer d.txMu.Unlock()
	d.rxMu.Lock()
	defer d.rxMu.Unlock()
	d.peers.Store(table)
	return nil
}

// ReconfigureWithShim publishes plan's hidden carrier mapping with a shim
// update while TUN read and write calls are excluded from the transition.
func (d *WireGuardTUN) ReconfigureWithShim(plan Plan, updateShim func() error) error {
	if !d.initialized() || updateShim == nil {
		return ErrWireGuardTUNConfig
	}
	table, err := newWireGuardCarrierTable(plan)
	if err != nil {
		return err
	}
	finish := d.beginReconfigure()

	defer finish()
	d.txMu.Lock()
	defer d.txMu.Unlock()
	d.rxMu.Lock()
	defer d.rxMu.Unlock()
	if err := updateShim(); err != nil {
		return err
	}
	d.shim.ResetTransportErrors()
	d.peers.Store(table)
	return nil
}

func (d *WireGuardTUN) beginReconfigure() func() {
	d.config.transactionMu.Lock()
	d.config.stateMu.Lock()
	done := make(chan struct{})
	d.config.done = done
	d.config.stateMu.Unlock()
	d.shim.InterruptPayloadRead()
	return func() {
		d.config.stateMu.Lock()
		close(done)
		d.config.done = nil
		d.config.stateMu.Unlock()
		d.config.transactionMu.Unlock()
	}
}

func (d *WireGuardTUN) waitForReconfigure() {
	d.config.stateMu.Lock()
	done := d.config.done
	d.config.stateMu.Unlock()
	if done != nil {
		<-done
	}
}

func (d *WireGuardTUN) File() *os.File {
	if d == nil || d.shim == nil {
		return nil
	}
	return d.shim.File()
}

func (d *WireGuardTUN) Name() (string, error) {
	if d == nil || d.shim == nil {
		return "", ErrWireGuardTUNConfig
	}
	return d.shim.Name()
}

func (d *WireGuardTUN) MTU() (int, error) {
	if d == nil || d.shim == nil {
		return 0, ErrWireGuardTUNConfig
	}
	return d.shim.MTU()
}

func (d *WireGuardTUN) Events() <-chan tun.Event {
	if d == nil || d.shim == nil {
		return nil
	}
	return d.shim.Events()
}

func (d *WireGuardTUN) BatchSize() int {
	if d == nil || d.shim == nil {
		return 0
	}
	return d.shim.BatchSize()
}

func (d *WireGuardTUN) Close() error {
	if d == nil || d.shim == nil {
		return ErrWireGuardTUNConfig
	}
	return d.shim.Close()
}

// Read turns shim payload descriptors into hidden IPv6 packets for
// wireguard-go. The output buffers belong to wireguard-go and no descriptor
// is retained after this call.
func (d *WireGuardTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if !d.initialized() {
		return 0, ErrWireGuardTUNConfig
	}
	if offset < 0 || len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, shimtun.ErrShortBuffer
	}
	// wireguard-go uses the maximum of the Bind and TUN batch sizes. A
	// configurable UDP Bind may therefore pass more buffers than this shim's
	// native TUN batch. Return a bounded prefix; the caller reuses the full
	// slice and subsequent reads drain any remaining queued packets. The full
	// input length is still checked above so the caller's sizes slice satisfies
	// the tun.Device contract.
	readBufs := bufs
	if len(readBufs) > len(d.txDesc) {
		readBufs = readBufs[:len(d.txDesc)]
	}
	// Validate every destination before publishing any descriptor. A short
	// buffer must not leave a borrowed slice in txDesc after Read returns.
	for i := range readBufs {
		if offset > len(readBufs[i]) || carrier.IPv6HeaderSize > len(readBufs[i])-offset {
			return 0, shimtun.ErrShortBuffer
		}
	}

	for {
		d.txMu.Lock()
		for i := range readBufs {
			// Leave room for the synthetic IPv6 header. The shim writes the
			// payload directly where MarshalEnvelopeTo will find it, avoiding a
			// second payload-sized move on every carrier.
			d.txDesc[i] = transport.TXDescriptor{Payload: readBufs[i][offset+carrier.IPv6HeaderSize:]}
		}
		n, err := d.shim.ReadPayloads(d.txDesc[:len(readBufs)])
		if errors.Is(err, shimtun.ErrReadInterrupted) {
			clear(d.txDesc[:len(readBufs)])
			d.txMu.Unlock()
			d.waitForReconfigure()

			continue
		}
		if err != nil {
			clear(d.txDesc[:len(readBufs)])
			d.txMu.Unlock()
			return n, err
		}
		table := d.peers.Load()
		for i := 0; i < n; i++ {
			descriptor := d.txDesc[i]
			payload := descriptor.Bytes()
			if payload == nil || int(descriptor.PeerID) >= len(table.byPeer) {
				clear(d.txDesc[:len(readBufs)])
				d.txMu.Unlock()
				return i, ErrWireGuardTUNConfig
			}
			destination := table.byPeer[descriptor.PeerID]
			if !destination.IsValid() {
				clear(d.txDesc[:len(readBufs)])
				d.txMu.Unlock()
				return i, ErrWireGuardTUNConfig
			}
			length, marshalErr := carrier.MarshalEnvelopeTo(readBufs[i][offset:], table.local, destination, payload)
			if marshalErr != nil {
				clear(d.txDesc[:len(readBufs)])
				d.txMu.Unlock()
				return i, fmt.Errorf("encode synthetic carrier: %w", marshalErr)
			}
			sizes[i] = length
		}
		clear(d.txDesc[:len(readBufs)])
		d.txMu.Unlock()
		return n, nil
	}
}

// Write validates the synthetic IPv6 representation after WireGuard has
// decrypted and AllowedIPs-checked it, then gives authenticated payloads to
// the shim. Malformed or unmapped carriers are dropped without affecting the
// rest of the decrypted batch.
func (d *WireGuardTUN) Write(bufs [][]byte, offset int) (int, error) {
	if !d.initialized() {
		return 0, ErrWireGuardTUNConfig
	}
	if offset < 0 {
		return 0, shimtun.ErrShortBuffer
	}
	d.rxMu.RLock()
	defer d.rxMu.RUnlock()
	batch, ok := d.rxPool.Get().(*wireGuardRXBatch)
	if !ok || batch == nil {
		return 0, ErrWireGuardTUNConfig
	}

	defer func() {
		clear(batch.descriptors)
		d.rxPool.Put(batch)
	}()

	table := d.peers.Load()

	for start := 0; start < len(bufs); {
		end := start + len(batch.descriptors)
		if end > len(bufs) {
			end = len(bufs)
		}
		count := 0

		for i := start; i < end; i++ {
			if offset > len(bufs[i]) {
				return i, shimtun.ErrShortBuffer
			}
			envelope, err := carrier.DecodeEnvelope(bufs[i][offset:], table.local)
			if err != nil {
				d.shim.RecordTransportDrop()

				continue
			}
			peer, known := table.bySource[envelope.Source]
			if !known {
				d.shim.RecordTransportDrop()
				continue
			}
			batch.descriptors[count] = transport.RXDescriptor{
				PeerID:  peer,
				Payload: envelope.Payload,
				Length:  len(envelope.Payload),
			}
			batch.indices[count] = i
			count++
		}
		if count != 0 {
			n, err := d.shim.WritePayloads(batch.descriptors[:count])
			if err != nil {
				if n < count {
					return batch.indices[n], err
				}
				return end, err
			}
		}
		start = end
	}
	return len(bufs), nil
}

var _ tun.Device = (*WireGuardTUN)(nil)
