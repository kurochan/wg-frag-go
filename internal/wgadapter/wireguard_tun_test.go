package wgadapter

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/datapath"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
	"golang.zx2c4.com/wireguard/tun"
)

const wireGuardTestBatchSize = 16

func TestWireGuardCarrierTableUsesLogicalPeerIDs(t *testing.T) {
	t.Parallel()
	local := netip.MustParseAddr("fe80::1")
	first := netip.MustParseAddr("fe80::2")
	third := netip.MustParseAddr("fe80::4")
	table, err := newWireGuardCarrierTable(Plan{
		LocalCarrier: local,
		Peers: []PeerPlan{
			{ID: peerroute.PeerID(0), Carrier: first},
			{ID: peerroute.PeerID(2), Carrier: third},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if table.local != local || table.byPeer[0] != first || table.byPeer[2] != third {
		t.Fatalf("carrier table = %#v", table)
	}
	if got, ok := table.bySource[third]; !ok || got != 2 {
		t.Fatalf("source mapping = (%d, %t), want (2, true)", got, ok)
	}
}

func TestWireGuardCarrierTableRejectsDuplicateCarrier(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("fe80::2")
	_, err := newWireGuardCarrierTable(Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers: []PeerPlan{
			{ID: 0, Carrier: addr},
			{ID: 1, Carrier: addr},
		},
	})
	if err == nil {
		t.Fatal("newWireGuardCarrierTable accepted duplicate carrier")
	}
}

func TestWireGuardCarrierTableRejectsLocalAndHugePeer(t *testing.T) {
	t.Parallel()
	local := netip.MustParseAddr("fe80::1")
	tests := []struct {
		name string
		peer PeerPlan
	}{
		{name: "local carrier", peer: PeerPlan{ID: 0, Carrier: local}},
		{name: "sparse id", peer: PeerPlan{ID: peerroute.PeerID(maxCarrierTableEntries), Carrier: netip.MustParseAddr("fe80::2")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := newWireGuardCarrierTable(Plan{LocalCarrier: local, Peers: []PeerPlan{test.peer}})
			if !errors.Is(err, ErrWireGuardTUNConfig) {
				t.Fatalf("newWireGuardCarrierTable() error = %v, want ErrWireGuardTUNConfig", err)
			}
		})
	}
}

func TestWireGuardTUNZeroValueIsSafe(t *testing.T) {
	t.Parallel()
	var device WireGuardTUN
	if device.File() != nil || device.Events() != nil || device.BatchSize() != 0 {
		t.Fatal("zero WireGuardTUN exposed a live facade")
	}
	if _, err := device.Name(); !errors.Is(err, ErrWireGuardTUNConfig) {
		t.Fatalf("Name() error = %v, want ErrWireGuardTUNConfig", err)
	}
	if _, err := device.MTU(); !errors.Is(err, ErrWireGuardTUNConfig) {
		t.Fatalf("MTU() error = %v, want ErrWireGuardTUNConfig", err)
	}
	if err := device.Close(); !errors.Is(err, ErrWireGuardTUNConfig) {
		t.Fatalf("Close() error = %v, want ErrWireGuardTUNConfig", err)
	}
	if _, err := device.Read(nil, nil, 0); !errors.Is(err, ErrWireGuardTUNConfig) {
		t.Fatalf("Read() error = %v, want ErrWireGuardTUNConfig", err)
	}
	if _, err := device.Write(nil, 0); !errors.Is(err, ErrWireGuardTUNConfig) {
		t.Fatalf("Write() error = %v, want ErrWireGuardTUNConfig", err)
	}
	if err := device.Reconfigure(Plan{}); !errors.Is(err, ErrWireGuardTUNConfig) {
		t.Fatalf("Reconfigure() error = %v, want ErrWireGuardTUNConfig", err)
	}
	var nilDevice *WireGuardTUN
	if nilDevice.File() != nil || nilDevice.Events() != nil || nilDevice.BatchSize() != 0 {
		t.Fatal("nil WireGuardTUN exposed a live facade")
	}
	if _, err := nilDevice.Read(nil, nil, 0); !errors.Is(err, ErrWireGuardTUNConfig) {
		t.Fatalf("nil Read() error = %v, want ErrWireGuardTUNConfig", err)
	}
}

func TestWireGuardTUNReadWriteBoundaryUsesOffsetAndContinuesBadBatch(t *testing.T) {
	t.Parallel()
	inner := testWireGuardIPv4Packet()
	native := newWireGuardTestTUN(1500, [][]byte{inner})
	shim := newWireGuardTestShim(t, native)
	device, err := NewWireGuardTUN(shim, Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers:        []PeerPlan{{ID: 0, Carrier: netip.MustParseAddr("fe80::2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	const offset = 7
	buffer := make([]byte, offset+2048)
	for i := 0; i < offset; i++ {
		buffer[i] = 0xa5
	}
	sizes := []int{0}
	count, err := device.Read([][]byte{buffer}, sizes, offset)
	if err != nil || count != 1 {
		t.Fatalf("Read() = (%d, %v), want (1, nil)", count, err)
	}
	if !bytes.Equal(buffer[:offset], bytes.Repeat([]byte{0xa5}, offset)) {
		t.Fatal("Read() modified the caller's prefix before offset")
	}
	if sizes[0] <= carrier.IPv6HeaderSize {
		t.Fatalf("synthetic envelope size = %d, want header and payload", sizes[0])
	}
	if !bytes.Equal(buffer[offset:offset+4], []byte{0x60, 0, 0, 0}) {
		t.Fatalf("synthetic IPv6 first word = %x, want 60000000", buffer[offset:offset+4])
	}
	forward, err := carrier.ParseEnvelope(buffer[offset:offset+sizes[0]], netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2"))
	if err != nil {
		t.Fatalf("ParseEnvelope(forward) = %v", err)
	}
	if err := carrier.Parse(forward.Payload, func(record carrier.Record) error { return nil }); err != nil {
		t.Fatalf("carrier.Parse(forward payload) = %v", err)
	}

	// The same adapter receives the opposite direction: the peer source is
	// authenticated by WireGuard and the local destination is checked here.
	reverse := make([]byte, carrier.IPv6HeaderSize+len(forward.Payload))
	reverseSize, err := carrier.MarshalEnvelopeTo(reverse, netip.MustParseAddr("fe80::2"), netip.MustParseAddr("fe80::1"), forward.Payload)
	if err != nil {
		t.Fatal(err)
	}
	badVersion := append([]byte(nil), reverse[:reverseSize]...)
	badVersion[0] = 0x40
	unknownSource := make([]byte, reverseSize)
	if _, err := carrier.MarshalEnvelopeTo(unknownSource, netip.MustParseAddr("fe80::9"), netip.MustParseAddr("fe80::1"), forward.Payload); err != nil {
		t.Fatal(err)
	}
	batchSize := device.BatchSize()
	batch := make([][]byte, batchSize+1)
	batch[0] = badVersion
	batch[1] = unknownSource

	batch[2] = append([]byte(nil), reverse[:reverseSize]...)
	for i := 3; i < len(batch); i++ {
		batch[i] = append([]byte(nil), badVersion...)
	}
	if written, err := device.Write(batch, 0); err != nil || written != len(batch) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", written, err, len(batch))
	}
	if got := native.written(); len(got) != 1 || !bytes.Equal(got[0], inner) {
		t.Fatalf("native writes = %d, want one original packet", len(got))
	}
	if rejects := shim.Stats().RXPacketRejects; rejects < 2 {
		t.Fatalf("RXPacketRejects = %d, want at least malformed and unknown-source drops", rejects)
	}
}

func TestWireGuardTUNReadValidatesEnvelopeHeadroomBeforeDescriptors(t *testing.T) {
	t.Parallel()
	native := newWireGuardTestTUN(1500)
	shim := newWireGuardTestShim(t, native)
	device, err := NewWireGuardTUN(shim, Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers:        []PeerPlan{{ID: 0, Carrier: netip.MustParseAddr("fe80::2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	bufs := [][]byte{
		make([]byte, carrier.IPv6HeaderSize+100),
		make([]byte, carrier.IPv6HeaderSize-1),
	}
	if _, err := device.Read(bufs, []int{0, 0}, 0); !errors.Is(err, shimtun.ErrShortBuffer) {
		t.Fatalf("Read() error = %v, want ErrShortBuffer", err)
	}
	for i, descriptor := range device.txDesc {
		if descriptor.Payload != nil || descriptor.Length != 0 || descriptor.PeerID != 0 {
			t.Fatalf("txDesc[%d] published after short buffer: %#v", i, descriptor)
		}
	}
}

func TestWireGuardTUNReadBoundsOversizedCallerBatch(t *testing.T) {
	t.Parallel()
	const innerLength = 600
	innerBatch := make([][]byte, wireGuardTestBatchSize)
	for i := range innerBatch {
		inner := make([]byte, innerLength)
		inner[0] = 0x45
		inner[2] = byte(innerLength >> 8)
		inner[3] = byte(innerLength & 0xff)
		copy(inner[12:16], []byte{10, 0, 0, 1})
		copy(inner[16:20], []byte{10, 0, 0, 2})
		innerBatch[i] = inner
	}
	native := newWireGuardTestTUN(1500, innerBatch)
	shim := newWireGuardTestShim(t, native)
	device, err := NewWireGuardTUN(shim, Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers:        []PeerPlan{{ID: 0, Carrier: netip.MustParseAddr("fe80::2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })

	const offset = 5
	batchSize := device.BatchSize()
	bufs := make([][]byte, batchSize+1)
	sizes := make([]int, len(bufs))
	for i := range bufs {
		bufs[i] = make([]byte, offset+2048)
		for j := range bufs[i] {
			bufs[i][j] = 0xa5
		}
	}
	const extraSize = 0x1357
	sizes[len(sizes)-1] = extraSize
	extraBefore := append([]byte(nil), bufs[len(bufs)-1]...)

	count, err := device.Read(bufs, sizes, offset)
	if err != nil || count != batchSize {
		t.Fatalf("Read() = (%d, %v), want (%d, nil)", count, err, batchSize)
	}
	if sizes[len(sizes)-1] != extraSize {
		t.Fatalf("oversized batch tail size = %d, want %d", sizes[len(sizes)-1], extraSize)
	}
	if !bytes.Equal(bufs[len(bufs)-1], extraBefore) {
		t.Fatal("Read() modified the caller buffer beyond the shim batch")
	}
	if sizes[0] <= carrier.IPv6HeaderSize {
		t.Fatalf("synthetic envelope size = %d, want header and payload", sizes[0])
	}
}

func TestWireGuardTUNReconfigureWithShimPublishesOnlySuccessfulTransactions(t *testing.T) {
	t.Parallel()
	native := newWireGuardTestTUN(1500)
	shim := newWireGuardTestShim(t, native)
	device, err := NewWireGuardTUN(shim, Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers:        []PeerPlan{{ID: 0, Carrier: netip.MustParseAddr("fe80::2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	next := Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers:        []PeerPlan{{ID: 0, Carrier: netip.MustParseAddr("fe80::3")}},
	}
	want := errors.New("shim update failed")
	if err := device.ReconfigureWithShim(next, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("ReconfigureWithShim() error = %v, want %v", err, want)
	}
	if got := device.peers.Load().byPeer[0]; got != netip.MustParseAddr("fe80::2") {
		t.Fatalf("carrier after failed transaction = %v, want fe80::2", got)
	}
	if err := device.ReconfigureWithShim(next, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := device.peers.Load().byPeer[0]; got != netip.MustParseAddr("fe80::3") {
		t.Fatalf("carrier after transaction = %v, want fe80::3", got)
	}
}

func TestWireGuardTUNReconfigureInterruptsIdleRead(t *testing.T) {
	t.Parallel()
	native := newWireGuardTestTUN(1500)
	shim := newWireGuardTestShim(t, native)
	device, err := NewWireGuardTUN(shim, Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers:        []PeerPlan{{ID: 0, Carrier: netip.MustParseAddr("fe80::2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	readResult := make(chan error, 1)

	go func() {
		_, err := device.Read([][]byte{make([]byte, 2048)}, []int{0}, 0)
		readResult <- err
	}()

	updated := Plan{
		LocalCarrier: netip.MustParseAddr("fe80::1"),
		Peers:        []PeerPlan{{ID: 0, Carrier: netip.MustParseAddr("fe80::3")}},
	}
	reconfigured := make(chan error, 1)

	go func() { reconfigured <- device.ReconfigureWithShim(updated, func() error { return nil }) }()
	select {
	case err := <-reconfigured:
		if err != nil {
			t.Fatalf("ReconfigureWithShim() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReconfigureWithShim blocked behind idle Read")
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readResult:
		if !errors.Is(err, shimtun.ErrClosed) {
			t.Fatalf("Read() error = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle Read did not exit on Close")
	}
}

type wireGuardTestTUN struct {
	mu       sync.Mutex
	mtu      int
	read     [][][]byte
	readAt   int
	writes   [][]byte
	closed   bool
	wake     chan struct{}
	closeOne sync.Once
	events   chan tun.Event
}

func newWireGuardTestTUN(mtu int, batches ...[][]byte) *wireGuardTestTUN {
	return &wireGuardTestTUN{mtu: mtu, read: batches, wake: make(chan struct{}), events: make(chan tun.Event)}
}

func (f *wireGuardTestTUN) File() *os.File { return nil }

func (f *wireGuardTestTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		f.mu.Lock()
		if f.readAt < len(f.read) {
			batch := f.read[f.readAt]
			f.readAt++
			f.mu.Unlock()
			if len(batch) > len(bufs) || len(batch) > len(sizes) {
				return 0, io.ErrShortBuffer
			}
			for i, packet := range batch {
				if offset < 0 || offset > len(bufs[i]) || len(packet) > len(bufs[i])-offset {
					return 0, io.ErrShortBuffer
				}
				copy(bufs[i][offset:], packet)
				sizes[i] = len(packet)
			}
			return len(batch), nil
		}
		closed := f.closed
		wake := f.wake
		f.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-wake
	}
}

func (f *wireGuardTestTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, buffer := range bufs {
		if offset < 0 || offset > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		f.writes = append(f.writes, append([]byte(nil), buffer[offset:]...))
	}
	return len(bufs), nil
}

func (f *wireGuardTestTUN) MTU() (int, error)        { return f.mtu, nil }
func (f *wireGuardTestTUN) Name() (string, error)    { return "wg-test", nil }
func (f *wireGuardTestTUN) Events() <-chan tun.Event { return f.events }
func (f *wireGuardTestTUN) BatchSize() int           { return wireGuardTestBatchSize }
func (f *wireGuardTestTUN) Close() error {
	f.closeOne.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.wake)
		close(f.events)
	})
	return nil
}

func (f *wireGuardTestTUN) written() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([][]byte, len(f.writes))
	for i := range f.writes {
		result[i] = append([]byte(nil), f.writes[i]...)
	}
	return result
}

func newWireGuardTestShim(t *testing.T, native tun.Device) *shimtun.Device {
	t.Helper()
	routes, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 0}})
	if err != nil {
		t.Fatal(err)
	}
	shim, err := shimtun.New(shimtun.Config{
		Native: native,
		Peers: []shimtun.PeerConfig{{
			Sender: datapath.SenderConfig{
				DataSessionID:  1,
				CarrierPayload: 613,
				MinPack:        128,
				RemotePeerMTU:  1500,
				PeerID:         0,
				AllowedIPs:     routes,
			},
			Receiver: datapath.ReceiverConfig{
				PeerID:        0,
				DataSessionID: 1,
				AllowedIPs:    routes,
				Slots:         8,
				PerPeerSlots:  8,
				MaxPacketSize: 1500,
				Lifetime:      time.Second,
			},
		}},
		CarrierQueueSize:     64,
		ControlQueueSize:     8,
		DataInitiallyEnabled: true,
		ExpirationInterval:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return shim
}

func testWireGuardIPv4Packet() []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 20
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	return packet
}
