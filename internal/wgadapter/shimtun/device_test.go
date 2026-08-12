package shimtun

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
	"github.com/kurochan/wg-frag-go/internal/core/control"
	"github.com/kurochan/wg-frag-go/internal/core/datapath"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/transport"
	"golang.zx2c4.com/wireguard/tun"
)

const testBatchSize = 16

type fakeTUN struct {
	mu          sync.Mutex
	name        string
	mtu         int
	batchSize   int
	events      chan tun.Event
	readWake    chan struct{}
	readBatches [][][]byte
	readErrors  []error
	readIndex   int
	writes      [][]byte
	closed      bool
	closeOnce   sync.Once
}

type captureControlSink struct {
	frames [][]byte
}

func (s *captureControlSink) DeliverControl(_ peerroute.PeerID, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return nil
}

type errorControlSink struct{ err error }

func (s errorControlSink) DeliverControl(peerroute.PeerID, []byte) error { return s.err }

func newFakeTUN(name string, mtu int, batches ...[][]byte) *fakeTUN {
	return &fakeTUN{
		name:        name,
		mtu:         mtu,
		batchSize:   testBatchSize,
		events:      make(chan tun.Event, 8),
		readWake:    make(chan struct{}, 1),
		readBatches: batches,
	}
}

func (f *fakeTUN) File() *os.File { return nil }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var batch [][]byte
	var readErr error
	for {
		f.mu.Lock()
		if f.readIndex < len(f.readBatches) {
			index := f.readIndex
			batch = f.readBatches[index]
			if index < len(f.readErrors) {
				readErr = f.readErrors[index]
			}
			f.readIndex++
			f.mu.Unlock()

			break
		}
		closed := f.closed
		wake := f.readWake
		f.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-wake
	}
	if len(batch) > len(bufs) || len(batch) > len(sizes) {
		return 0, io.ErrShortBuffer
	}
	for i, packet := range batch {
		if offset > len(bufs[i]) || len(packet) > len(bufs[i])-offset {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[i][offset:], packet)
		sizes[i] = len(packet)
	}
	return len(batch), readErr
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, buffer := range bufs {
		if offset > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		f.writes = append(f.writes, append([]byte(nil), buffer[offset:]...))
	}
	return len(bufs), nil
}

func (f *fakeTUN) MTU() (int, error)        { return f.mtu, nil }
func (f *fakeTUN) Name() (string, error)    { return f.name, nil }
func (f *fakeTUN) Events() <-chan tun.Event { return f.events }
func (f *fakeTUN) BatchSize() int           { return f.batchSize }
func (f *fakeTUN) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.readWake)
		close(f.events)
	})
	return nil
}

// appendBatch schedules another native read after construction, so tests can
// interleave reads with reconfiguration.
func (f *fakeTUN) appendBatch(batch [][]byte) {
	f.mu.Lock()
	f.readBatches = append(f.readBatches, batch)
	f.mu.Unlock()
	select {
	case f.readWake <- struct{}{}:
	default:
	}
}

func (f *fakeTUN) written() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([][]byte, len(f.writes))
	for i := range f.writes {
		result[i] = append([]byte(nil), f.writes[i]...)
	}
	return result
}

func TestRoundTripPacksNativeBatch(t *testing.T) {
	t.Parallel()
	first := ipv4Packet(10, 0, 80)
	second := ipv4Packet(10, 1, 80)
	aNative := newFakeTUN("a", 1500, [][]byte{first, second})
	bNative := newFakeTUN("b", 1500)
	a := newPairDevice(t, aNative, true, 64)
	b := newPairDevice(t, bNative, false, 64)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	carriers, sizes, n, err := readCarriers(a)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("Read() carrier count = %d, want 1 packed carrier", n)
	}
	if written, err := b.Write(sized(carriers, sizes, n), 0); err != nil || written != 1 {
		t.Fatalf("Write() = (%d, %v), want (1, nil)", written, err)
	}
	got := bNative.written()
	if len(got) != 2 || !bytes.Equal(got[0], first) || !bytes.Equal(got[1], second) {
		t.Fatalf("restored packets = %d, want original batch", len(got))
	}
}

func TestRoundTripFragmentsLargePacket(t *testing.T) {
	t.Parallel()
	packet := ipv4Packet(10, 0, 1500)
	aNative := newFakeTUN("a", 1500, [][]byte{packet})
	bNative := newFakeTUN("b", 1500)
	a := newPairDevice(t, aNative, true, 64)
	b := newPairDevice(t, bNative, false, 64)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	carriers, sizes, n, err := readCarriers(a)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("Read() carrier count = %d, want 3", n)
	}
	if written, err := b.Write(sized(carriers, sizes, n), 0); err != nil || written != 3 {
		t.Fatalf("Write() = (%d, %v), want (3, nil)", written, err)
	}
	got := bNative.written()
	if len(got) != 1 || !bytes.Equal(got[0], packet) {
		t.Fatalf("restored packets = %d, want one original packet", len(got))
	}
}

func TestPayloadBoundaryRoundTripUsesLogicalPeerAndBorrowedBuffers(t *testing.T) {
	t.Parallel()
	inner := ipv4Packet(10, 0, 80)
	aNative := newFakeTUN("a", 1500, [][]byte{inner})
	bNative := newFakeTUN("b", 1500)
	a := newPairDevice(t, aNative, true, 64)
	b := newPairDevice(t, bNative, false, 64)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	tx := make(transport.TXBatch, testBatchSize)
	for i := range tx {
		tx[i].Payload = make([]byte, 2048)
	}
	n, err := a.ReadPayloads(tx)
	if err != nil || n != 1 {
		t.Fatalf("ReadPayloads() = (%d, %v), want (1, nil)", n, err)
	}
	if tx[0].PeerID != 0 || tx[0].Length == 0 {
		t.Fatalf("TX descriptor = %+v, want peer 0 and payload", tx[0])
	}
	// The payload boundary excludes the synthetic IPv6 header. A DATA record
	// starts with its two-byte record length, not IPv6 version 6.
	if tx[0].Payload[0] == 6<<4 {
		t.Fatal("payload descriptor unexpectedly contains a synthetic IPv6 header")
	}

	if wrote, err := b.WritePayloads(transport.RXBatch{{
		PeerID:  0,
		Payload: tx[0].Payload,
		Length:  tx[0].Length,
	}}); err != nil || wrote != 1 {
		t.Fatalf("WritePayloads() = (%d, %v), want (1, nil)", wrote, err)
	}
	// WritePayloads consumes the caller buffer synchronously; mutating it after
	// return cannot alter the packet already delivered to the native TUN.
	clear(tx[0].Payload[:tx[0].Length])
	got := bNative.written()
	if len(got) != 1 || !bytes.Equal(got[0], inner) {
		t.Fatalf("native writes = %d, want original inner packet", len(got))
	}
}

func TestPayloadBoundaryRejectsDescriptorLengthWithoutRetainingBuffer(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })
	payload := make([]byte, 4)
	if n, err := d.WritePayloads(transport.RXBatch{{PeerID: 0, Payload: payload, Length: len(payload) + 1}}); !errors.Is(err, ErrShortBuffer) || n != 0 {
		t.Fatalf("WritePayloads() = (%d, %v), want (0, ErrShortBuffer)", n, err)
	}
}

func TestInterruptPayloadReadUnblocksIdlePayloadRead(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("test", 1500)
	d := newPairDevice(t, native, true, 16)
	t.Cleanup(func() { _ = d.Close() })

	result := make(chan error, 1)
	go func() {
		batch := []transport.TXDescriptor{{Payload: make([]byte, 1024)}}
		_, err := d.ReadPayloads(batch)
		result <- err
	}()
	d.InterruptPayloadRead()
	select {
	case err := <-result:
		if !errors.Is(err, ErrReadInterrupted) {
			t.Fatalf("ReadPayloads() error = %v, want ErrReadInterrupted", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPayloads did not unblock")
	}
}

func TestPayloadBoundaryRejectsUnknownPeerWithoutPanic(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })

	batch := transport.RXBatch{{PeerID: ^transport.PeerID(0), Payload: []byte{1}, Length: 1}}
	if got, err := d.WritePayloads(batch); err != nil || got != 1 {
		t.Fatalf("WritePayloads() = (%d, %v), want (1, nil)", got, err)
	}
}

func TestReadPayloadsKeepsControlOnShortOutputBuffer(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })

	codec, err := control.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 32)
	n, err := codec.MarshalTo(frame, []byte{0x08, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	frame = frame[:n]
	if err := d.EnqueueControl(0, frame); err != nil {
		t.Fatal(err)
	}

	short := transport.TXBatch{{Payload: make([]byte, len(frame)-1)}}
	if got, err := d.ReadPayloads(short); !errors.Is(err, ErrShortBuffer) || got != 0 {
		t.Fatalf("short ReadPayloads() = (%d, %v), want (0, ErrShortBuffer)", got, err)
	}
	full := transport.TXBatch{{Payload: make([]byte, len(frame))}}
	if got, err := d.ReadPayloads(full); err != nil || got != 1 {
		t.Fatalf("retry ReadPayloads() = (%d, %v), want (1, nil)", got, err)
	}
	if !bytes.Equal(full[0].Payload[:full[0].Length], frame) {
		t.Fatalf("retry payload = %x, want %x", full[0].Payload[:full[0].Length], frame)
	}
}

func TestPayloadModeAllowsUnsetCarrierAddresses(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500, [][]byte{ipv4Packet(10, 0, 80)})
	config := pairConfig(t, native, true, 64)
	config.Peers[0].Sender.CarrierSource = netip.Addr{}
	config.Peers[0].Sender.CarrierDest = netip.Addr{}
	config.Peers[0].Receiver.CarrierSource = netip.Addr{}
	config.Peers[0].Receiver.CarrierDest = netip.Addr{}
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	batch := transport.TXBatch{{Payload: make([]byte, 2048)}}
	if n, err := d.ReadPayloads(batch); err != nil || n != 1 || batch[0].PeerID != 0 {
		t.Fatalf("ReadPayloads() = (%d, %v), descriptor=%+v", n, err, batch[0])
	}
}

func TestReadDropsNativeFragmentAndContinuesBatch(t *testing.T) {
	t.Parallel()
	fragmented := ipv4Packet(10, 0, 80)
	fragmented[6] = 0x20
	valid := ipv4Packet(10, 1, 80)
	native := newFakeTUN("a", 1500, [][]byte{fragmented, valid})
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })

	_, _, n, err := readCarriers(d)
	if err != nil || n != 1 {
		t.Fatalf("Read() = (%d, %v), want one valid carrier", n, err)
	}
	stats := d.Stats()
	if stats.TXPacketDrops != 1 || stats.TXNativeFragmentDrops != 1 {
		t.Fatalf("Stats() = %+v", stats)
	}
}

func TestWriteRejectsSpoofedInnerSource(t *testing.T) {
	t.Parallel()
	spoofed := ipv4Packet(99, 0, 80)
	spoofed[12] = 11
	aNative := newFakeTUN("a", 1500, [][]byte{spoofed})
	bNative := newFakeTUN("b", 1500)
	a := newPairDevice(t, aNative, true, 64)
	b := newPairDevice(t, bNative, false, 64)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	carriers, sizes, n, err := readCarriers(a)
	if err != nil {
		t.Fatal(err)
	}
	// A spoofed inner source is a counted drop; the Write batch succeeds so
	// wireguard-go never discards unrelated packets from the same batch.
	if wrote, err := b.Write(sized(carriers, sizes, n), 0); err != nil || wrote != n {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", wrote, err, n)
	}
	if len(bNative.written()) != 0 {
		t.Fatal("spoofed packet reached native TUN")
	}
	if stats := b.Stats(); stats.RXPacketRejects != 1 || stats.RXSourceSpoofDrops != 1 {
		t.Fatalf("Stats() = %+v", stats)
	}
}

func TestWriteContinuesBatchAfterCarrierPolicyDrop(t *testing.T) {
	t.Parallel()
	valid := ipv4Packet(10, 7, 80)
	aNative := newFakeTUN("a", 1500, [][]byte{valid})
	bNative := newFakeTUN("b", 1500)
	a := newPairDevice(t, aNative, true, 64)
	b := newPairDevice(t, bNative, false, 64)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	carriers, sizes, n, err := readCarriers(a)
	if err != nil || n != 1 {
		t.Fatalf("readCarriers() = (%d, %v)", n, err)
	}
	good := carriers[0][:sizes[0]]
	// Corrupt the data session ID: an authenticated peer sending a
	// non-current session must cost exactly one carrier, not the batch.
	bad := append([]byte(nil), good...)
	bad[44] ^= 0x55
	wrote, err := b.Write([][]byte{bad, good}, 0)
	if err != nil || wrote != 2 {
		t.Fatalf("Write() = (%d, %v), want (2, nil)", wrote, err)
	}
	written := bNative.written()
	if len(written) != 1 || !bytes.Equal(written[0], valid) {
		t.Fatalf("native writes = %d, want the valid packet delivered", len(written))
	}
	if stats := b.Stats(); stats.RXPacketRejects == 0 {
		t.Fatalf("Stats() = %+v, want the bad carrier counted", stats)
	}
}

func TestMTUAndEventsHideNativeMTUChanges(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })

	if mtu, err := d.MTU(); err != nil || mtu != SyntheticMTU {
		t.Fatalf("MTU() = (%d, %v), want (%d, nil)", mtu, err, SyntheticMTU)
	}
	native.events <- tun.EventMTUUpdate
	native.events <- tun.EventMTUUpdate | tun.EventUp
	select {
	case event := <-d.Events():
		if event != tun.EventUp {
			t.Fatalf("event = %v, want EventUp", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for filtered event")
	}
}

func TestDeliverInnerHonorsNativeWriteOffset(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := pairConfig(t, native, true, 64)
	config.NativeWriteOffset = 10
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	packet := ipv4Packet(10, 0, 80)
	peer, ok := d.peerFor(0)
	if !ok {
		t.Fatal("peer 0 missing")
	}
	if got, want := cap(peer.deliverBufs), d.batch; got != want {
		t.Fatalf("deliver buffer cap = %d, want %d", got, want)
	}
	peer.rxMu.Lock()
	err = peer.sink.DeliverInner(packet)
	if err == nil {
		if len(peer.deliverBufs) != 1 {
			t.Fatalf("delivery buffers = %d, want 1", len(peer.deliverBufs))
		}
		// The inner slice capacity must stop at its fixed slab stride; GRO
		// must not append into the next packet's storage.
		if got, want := cap(peer.deliverBufs[0]), d.nativeWriteOffset+d.innerMTU; got != want {
			t.Fatalf("delivery buffer capacity = %d, want %d", got, want)
		}
	}
	peer.rxMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Delivery is batched; the expiration tick flushes an idle slab.
	waitFor(t, func() bool { return len(native.written()) == 1 })
	got := native.written()
	if !bytes.Equal(got[0], packet) {
		t.Fatalf("native packet = %x, want %x", got, packet)
	}
}

func TestTooManySegmentsDoesNotCloseDeviceAfterBatch(t *testing.T) {
	t.Parallel()
	packet := ipv4Packet(10, 0, 80)
	native := newFakeTUN("a", 1500, [][]byte{packet})
	native.readErrors = []error{tun.ErrTooManySegments}
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })
	if _, _, n, err := readCarriers(d); err != nil || n == 0 {
		t.Fatalf("Read() = (%d, %v), want batch despite segment warning", n, err)
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.txFatal != nil {
		t.Fatalf("tx fatal = %v, want nil", d.txFatal)
	}
}

func TestPeerOperationsReportPeerNotFoundAfterRemoval(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })
	if err := d.Reconfigure(nil, []peerroute.PeerID{0}, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDataEnabled(0, false); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("SetDataEnabled() error = %v, want ErrPeerNotFound", err)
	}
	if err := d.EnqueueControl(0, []byte{0, 0}); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("EnqueueControl() error = %v, want ErrPeerNotFound", err)
	}
}

func TestControlQueueOverflowDropsWithoutFailing(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := pairConfig(t, native, true, 64)
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	codec, err := control.NewCodec(config.Peers[0].Sender.CarrierPayload)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < controlDescriptorCapacity+2; i++ {
		frame := make([]byte, 32)
		n, err := codec.MarshalTo(frame, []byte{0x08, byte(i + 1)})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.EnqueueControl(0, frame[:n]); err != nil {
			t.Fatalf("EnqueueControl() #%d: %v", i, err)
		}
	}
	if got := d.Stats().ControlQueueDrops; got != 2 {
		t.Fatalf("ControlQueueDrops = %d, want 2", got)
	}
}

func TestControlUsesValidatedEnvelopeAndFixedCarrierQueue(t *testing.T) {
	t.Parallel()
	aNative := newFakeTUN("a", 1500)
	bNative := newFakeTUN("b", 1500)
	aConfig := pairConfig(t, aNative, true, 64)
	bConfig := pairConfig(t, bNative, false, 64)
	sink := &captureControlSink{}
	bConfig.ControlSink = sink
	a, err := New(aConfig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(bConfig)
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	codec, err := control.NewCodec(aConfig.Peers[0].Sender.CarrierPayload)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 32)
	n, err := codec.MarshalTo(frame, []byte{0x08, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	frame = frame[:n]
	if err := a.EnqueueControl(0, frame); err != nil {
		t.Fatal(err)
	}
	carriers, sizes, count, err := readCarriers(a)
	if err != nil || count != 1 {
		t.Fatalf("Read() = (%d, %v), want one CONTROL carrier", count, err)
	}
	if written, err := b.Write(sized(carriers, sizes, count), 0); err != nil || written != 1 {
		t.Fatalf("Write() = (%d, %v), want (1, nil)", written, err)
	}
	if len(sink.frames) != 1 || !bytes.Equal(sink.frames[0], frame) {
		t.Fatalf("CONTROL frames = %x, want %x", sink.frames, frame)
	}
	if len(bNative.written()) != 0 {
		t.Fatal("CONTROL frame reached native TUN")
	}
	if err := a.EnqueueControl(0, []byte{0, 0, 99, 1}); !errors.Is(err, control.ErrUnsupportedVersion) {
		t.Fatalf("invalid CONTROL error = %v", err)
	}
}

func TestControlIngressRateLimit(t *testing.T) {
	t.Parallel()
	aNative := newFakeTUN("a", 1500)
	bNative := newFakeTUN("b", 1500)
	aConfig := pairConfig(t, aNative, true, 64)
	bConfig := pairConfig(t, bNative, false, 64)
	sink := &captureControlSink{}
	bConfig.ControlSink = sink
	a, err := New(aConfig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(bConfig)
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	codec, err := control.NewCodec(aConfig.Peers[0].Sender.CarrierPayload)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 32)
	n, err := codec.MarshalTo(frame, []byte{0x08, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnqueueControl(0, frame[:n]); err != nil {
		t.Fatal(err)
	}
	carriers, sizes, count, err := readCarriers(a)
	if err != nil || count != 1 {
		t.Fatalf("Read() = (%d, %v), want one CONTROL carrier", count, err)
	}
	carrier := sized(carriers, sizes, count)
	for range int(controlIngressPeerBurst) + 3 {
		if written, err := b.Write(carrier, 0); err != nil || written != 1 {
			t.Fatalf("Write() = (%d, %v), want (1, nil)", written, err)
		}
	}
	if got := len(sink.frames); got != int(controlIngressPeerBurst) {
		t.Fatalf("delivered CONTROL frames = %d, want %d", got, int(controlIngressPeerBurst))
	}
	if got := b.Stats().ControlIngressRateLimited; got != 3 {
		t.Fatalf("ControlIngressRateLimited = %d, want 3", got)
	}
}

func TestWriteReturnsControlQueueFull(t *testing.T) {
	t.Parallel()
	aNative := newFakeTUN("a", 1500)
	bNative := newFakeTUN("b", 1500)
	aConfig := pairConfig(t, aNative, true, 64)
	bConfig := pairConfig(t, bNative, false, 64)
	bConfig.ControlSink = errorControlSink{err: ErrCarrierQueueFull}
	a, err := New(aConfig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(bConfig)
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	codec, err := control.NewCodec(aConfig.Peers[0].Sender.CarrierPayload)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 32)
	n, err := codec.MarshalTo(frame, []byte{0x08, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnqueueControl(0, frame[:n]); err != nil {
		t.Fatal(err)
	}
	carriers, sizes, count, err := readCarriers(a)
	if err != nil || count != 1 {
		t.Fatalf("Read() = (%d, %v), want one CONTROL carrier", count, err)
	}
	// A full CONTROL ring is transient backpressure that CONTROL retry
	// recovers from. Reporting it would make wireguard-go close the device,
	// so the frame is dropped and the batch continues.
	if wrote, err := b.Write(sized(carriers, sizes, count), 0); err != nil || wrote != count {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", wrote, err, count)
	}
	if stats := b.Stats(); stats.RXPacketRejects == 0 {
		t.Fatalf("Stats() = %+v, want the dropped CONTROL counted", stats)
	}
}

func TestControlWakesIdleReadAndPrecedesFullDataRing(t *testing.T) {
	t.Parallel()
	packet := ipv4Packet(10, 0, 80)
	native := newFakeTUN("a", 1500, [][]byte{packet})
	config := pairConfig(t, native, true, 1)
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	waitFor(t, func() bool {
		d.txMu.Lock()
		defer d.txMu.Unlock()
		return d.queueCount == 1
	})
	codec, err := control.NewCodec(config.Peers[0].Sender.CarrierPayload)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 16)
	n, err := codec.MarshalTo(frame, []byte{0x08, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnqueueControl(0, frame[:n]); err != nil {
		t.Fatalf("EnqueueControl() with full DATA ring: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		count, err := d.Read(bufs, sizes, 0)
		if err == nil && count != 1 {
			err = errors.New("unexpected carrier count")
		}
		if err == nil {
			envelope, parseErr := carrier.ParseEnvelope(bufs[0][:sizes[0]], config.Peers[0].Sender.CarrierSource, config.Peers[0].Sender.CarrierDest)
			if parseErr != nil {
				err = parseErr
			} else if len(envelope.Payload) < 2 || envelope.Payload[0] != 0 || envelope.Payload[1] != 0 {
				err = errors.New("DATA carrier was returned before CONTROL")
			}
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle Read was not woken by CONTROL")
	}
}

func TestCarrierQueueOverflowDropsBatchAndKeepsDeviceOpen(t *testing.T) {
	t.Parallel()
	oversized := make([][]byte, 8)
	for i := range oversized {
		oversized[i] = ipv4Packet(10, byte(i), 1500)
	}
	survivor := ipv4Packet(10, 9, 80)
	native := newFakeTUN("a", 1500, oversized, [][]byte{survivor})
	d := newPairDevice(t, native, true, 1)
	t.Cleanup(func() { _ = d.Close() })

	bufs, sizes, n, err := readCarriers(d)
	if err != nil {
		t.Fatalf("Read() error = %v, want the device to survive a full ring", err)
	}
	if n == 0 {
		t.Fatal("Read() returned no carrier after the overflow")
	}
	if len(bufs[0][:sizes[0]]) == 0 {
		t.Fatal("Read() returned an empty carrier")
	}
	if d.queueCount != 0 || len(d.queueData) != d.dataStride {
		t.Fatalf("bounded queue = (count %d, bytes %d)", d.queueCount, len(d.queueData))
	}
	if stats := d.Stats(); stats.CarrierQueueOverflows == 0 {
		t.Fatalf("Stats() = %+v, want the overflow counted", stats)
	}
}

func TestCloseIsIdempotentAndClosesEvents(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	d := newPairDevice(t, native, true, 64)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-d.Events():
		if ok {
			t.Fatal("Events() remains open")
		}
	case <-time.After(time.Second):
		t.Fatal("Events() was not closed")
	}
	bufs, sizes := carrierBuffers()
	if _, err := d.Read(bufs, sizes, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Read() error = %v, want ErrClosed", err)
	}
	if _, err := d.Write(nil, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write() error = %v, want ErrClosed", err)
	}
}

func TestNewFailsClosedOnCrossLayerMismatch(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1400)
	config := pairConfig(t, native, true, 64)
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New() MTU mismatch error = %v", err)
	}

	native.mtu = 1500
	config.Peers[0].Sender.CarrierDest = netip.MustParseAddr("fe80::dead")
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New() endpoint mismatch error = %v", err)
	}
}

func TestNewRejectsNativeWriteOffsetPastMTU(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := pairConfig(t, native, true, 64)
	config.NativeWriteOffset = 1501
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
	}
}

func TestActiveCarrierQueueSlotsScaleWithCarrierPayload(t *testing.T) {
	t.Parallel()
	const (
		configured = 4096
		batch      = 128
		innerMTU   = 1500
	)
	const peers = 1
	small := activeCarrierQueueSlots(configured, carrierFragmentCountForPayload(613, innerMTU), batch, peers)
	large := activeCarrierQueueSlots(configured, carrierFragmentCountForPayload(65495, innerMTU), batch, peers)
	if small != batch*2*3+peers*DefaultPreconfirmQueueSize*3 {
		t.Fatalf("small-payload active slots = %d, want %d", small, batch*2*3+peers*DefaultPreconfirmQueueSize*3)
	}
	if large != batch*2+peers*DefaultPreconfirmQueueSize {
		t.Fatalf("large-payload active slots = %d, want %d", large, batch*2+peers*DefaultPreconfirmQueueSize)
	}
	if large >= small || small >= configured {
		t.Fatalf("active slots did not shrink: small=%d large=%d configured=%d", small, large, configured)
	}
}

func TestInstallDataPlaneResizesQueueForCarrierPayload(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := pairConfig(t, native, true, 4096)
	config.MaxCarrierPayload = 65495
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	sender := config.Peers[0].Sender
	sender.DataSessionID = 2
	sender.CarrierPayload = 65495
	receiver := config.Peers[0].Receiver
	receiver.DataSessionID = 2
	if err := d.InstallDataPlane(0, sender, receiver); err != nil {
		t.Fatal(err)
	}
	if got, want := len(d.queueLens), d.batch*2+DefaultPreconfirmQueueSize; got != want {
		t.Fatalf("large-payload active queue slots = %d, want %d", got, want)
	}
	if got, want := len(d.queueData), (carrier.IPv6HeaderSize+65495)*(d.batch*2+DefaultPreconfirmQueueSize); got != want {
		t.Fatalf("large-payload queue bytes = %d, want %d", got, want)
	}

	sender.DataSessionID = 3
	sender.CarrierPayload = 613
	receiver.DataSessionID = 3
	if err := d.InstallDataPlane(0, sender, receiver); err != nil {
		t.Fatal(err)
	}
	wantSlots := (d.batch*2 + DefaultPreconfirmQueueSize) * 3
	if got := len(d.queueLens); got != wantSlots {
		t.Fatalf("BASE active queue slots = %d, want %d", got, wantSlots)
	}
	if got, want := len(d.queueData), (carrier.IPv6HeaderSize+613)*wantSlots; got != want {
		t.Fatalf("BASE queue bytes after PMTU reset = %d, want %d", got, want)
	}
}

func TestInstallDataPlaneUsesIndependentDirectionalSessions(t *testing.T) {
	t.Parallel()
	aNative := newFakeTUN("a", 1500, [][]byte{ipv4Packet(10, 0, 80)})
	bNative := newFakeTUN("b", 1500)
	aConfig := pairConfig(t, aNative, true, 64)
	bConfig := pairConfig(t, bNative, false, 64)
	aConfig.Peers[0].Sender.DataSessionID, aConfig.Peers[0].Receiver.DataSessionID = 101, 202
	bConfig.Peers[0].Sender.DataSessionID, bConfig.Peers[0].Receiver.DataSessionID = 202, 101
	a, err := New(aConfig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(bConfig)
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	carriers, sizes, n, err := readCarriers(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write(sized(carriers, sizes, n), 0); err != nil {
		t.Fatal(err)
	}
	if got := bNative.written(); len(got) != 1 {
		t.Fatalf("restored packet count = %d, want 1", len(got))
	}

	replacementSender := aConfig.Peers[0].Sender
	replacementReceiver := aConfig.Peers[0].Receiver
	replacementSender.DataSessionID = 303
	replacementReceiver.DataSessionID = 404
	if err := a.InstallDataPlane(0, replacementSender, replacementReceiver); err != nil {
		t.Fatal(err)
	}
}

func TestInstallDataPlaneCanIncreaseActiveCarrierWithinFixedMaximum(t *testing.T) {
	t.Parallel()
	packet := ipv4Packet(10, 0, 1500)
	native := newFakeTUN("a", 1500, [][]byte{packet})
	config := pairConfig(t, native, true, 4)
	config.MaxCarrierPayload = 1400
	config.DataInitiallyEnabled = false
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if got, want := len(d.queueData), (carrier.IPv6HeaderSize+613)*4; got != want {
		t.Fatalf("initial DATA queue bytes = %d, want %d", got, want)
	}
	if got, want := len(d.controlData), (carrier.IPv6HeaderSize+1400)*controlDescriptorCapacity; got != want {
		t.Fatalf("CONTROL descriptor ring bytes = %d, want %d", got, want)
	}
	if got := len(d.controlLens); got != controlDescriptorCapacity {
		t.Fatalf("CONTROL descriptor ring slots = %d, want %d", got, controlDescriptorCapacity)
	}

	replacementSender := config.Peers[0].Sender
	replacementSender.CarrierPayload = 1400
	replacementReceiver := config.Peers[0].Receiver
	if err := d.InstallDataPlane(0, replacementSender, replacementReceiver); err != nil {
		t.Fatal(err)
	}
	if got, want := d.carrierSize, carrier.IPv6HeaderSize+1400; got != want {
		t.Fatalf("active carrier size = %d, want %d", got, want)
	}
	if got, want := d.dataStride, carrier.IPv6HeaderSize+1400; got != want {
		t.Fatalf("DATA stride = %d, want %d", got, want)
	}
	if got, want := d.controlStride, carrier.IPv6HeaderSize+1400; got != want {
		t.Fatalf("CONTROL stride = %d, want %d", got, want)
	}
	if err := d.SetDataEnabled(0, true); err != nil {
		t.Fatal(err)
	}
	_, _, count, err := readCarriers(d)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("1400-byte carrier count = %d, want 2", count)
	}
}

func TestInstallDataPlanePayloadIncreaseKeepsSequenceAndDropsQueuedCarriers(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := pairConfig(t, native, true, 4)
	config.MaxCarrierPayload = 1400
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	d.txMu.Lock()
	err = d.table.Load().peers[0].sender.Add(ipv4Packet(10, 0, 80))
	if err == nil {
		err = d.table.Load().peers[0].sender.Flush()
	}
	d.txMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	replacementSender := config.Peers[0].Sender
	replacementSender.CarrierPayload = 1400
	if err := d.InstallDataPlane(0, replacementSender, config.Peers[0].Receiver); err != nil {
		t.Fatal(err)
	}

	d.txMu.Lock()
	defer d.txMu.Unlock()
	// The lane sequence survives a payload-only replacement, so the peer does
	// not see a sequence gap.
	if got := d.table.Load().peers[0].sender.Sequences()[0]; got != 1 {
		t.Fatalf("next lane sequence = %d, want 1", got)
	}
	// Queued carriers do not: the shared ring interleaves every peer, so a
	// cold transition cannot replay one peer's entries selectively.
	if d.queueHead != 0 || d.queueCount != 0 {
		t.Fatalf("queue state = head=%d count=%d, want empty", d.queueHead, d.queueCount)
	}
	if d.dataStride != 1400+carrier.IPv6HeaderSize {
		t.Fatalf("dataStride = %d, want the larger carrier", d.dataStride)
	}
}

func TestControlGateBuffersThenFlushesNewestPackets(t *testing.T) {
	t.Parallel()
	packets := make([][]byte, DefaultPreconfirmQueueSize+2)
	for i := range packets {
		packets[i] = ipv4Packet(10, byte(i), 80)
	}
	native := newFakeTUN("a", 1500, packets)
	config := pairConfig(t, native, true, 64)
	config.DataInitiallyEnabled = false
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	waitFor(t, func() bool {
		d.txMu.Lock()
		defer d.txMu.Unlock()
		return d.table.Load().peers[0].pendingCount == DefaultPreconfirmQueueSize
	})
	if got := d.Stats().PreconfirmDrops; got != 2 {
		t.Fatalf("PreconfirmDrops = %d, want 2", got)
	}
	if err := d.SetDataEnabled(0, true); err != nil {
		t.Fatal(err)
	}
	_, _, n, err := readCarriers(d)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("gate opening emitted no DATA carrier")
	}
}

func TestControlGateQueueFullDropsPendingWithoutFatal(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	d := newPairDevice(t, native, true, 64)
	t.Cleanup(func() { _ = d.Close() })

	if err := d.SetDataEnabled(0, false); err != nil {
		t.Fatal(err)
	}
	d.txMu.Lock()
	peer := d.table.Load().peers[0]
	d.enqueuePendingLocked(peer, ipv4Packet(10, 0, 80))
	d.queueCount = len(d.queueLens)
	d.txMu.Unlock()

	if err := d.SetDataEnabled(0, true); err != nil {
		t.Fatalf("SetDataEnabled() = %v, want backpressure drop without error", err)
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.txFatal != nil {
		t.Fatalf("txFatal = %v, want nil", d.txFatal)
	}
	if !peer.dataEnabled.Load() {
		t.Fatal("peer DATA gate remained closed after queue pressure")
	}
	if peer.pendingCount != 0 {
		t.Fatalf("pendingCount = %d, want dropped", peer.pendingCount)
	}
	d.queueCount = 0
}

func TestResetTransportErrorsClearsInterfaceState(t *testing.T) {
	t.Parallel()
	d := newPairDevice(t, newFakeTUN("a", 1500), true, 64)
	t.Cleanup(func() { _ = d.Close() })

	d.txMu.Lock()
	d.txFatal = ErrShortBuffer
	d.txMu.Unlock()
	err := errors.New("queued receive failure")
	d.rxAsyncErr.Store(&err)

	d.ResetTransportErrors()

	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.txFatal != nil {
		t.Fatalf("txFatal = %v, want nil", d.txFatal)
	}
	if got := d.rxAsyncErr.Load(); got != nil {
		t.Fatalf("rxAsyncErr = %v, want nil", *got)
	}
}

func newPairDevice(t *testing.T, native tun.Device, sideA bool, queueSize int) *Device {
	t.Helper()
	d, err := New(pairConfig(t, native, sideA, queueSize))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func pairConfig(t *testing.T, native tun.Device, sideA bool, queueSize int) Config {
	t.Helper()
	local := netip.MustParseAddr("fe80::a")
	remote := netip.MustParseAddr("fe80::b")
	var allowedPrefix netip.Prefix
	if sideA {
		allowedPrefix = netip.MustParsePrefix("10.2.0.0/16")
	} else {
		local, remote = remote, local
		allowedPrefix = netip.MustParsePrefix("10.0.0.0/16")
	}
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: allowedPrefix, PeerID: 0}})
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Native: native,
		Peers: []PeerConfig{{
			Sender: datapath.SenderConfig{
				DataSessionID:  1,
				CarrierSource:  local,
				CarrierDest:    remote,
				CarrierPayload: 613,
				MinPack:        128,
				RemotePeerMTU:  1500,
			},
			Receiver: datapath.ReceiverConfig{
				PeerID:        0,
				DataSessionID: 1,
				CarrierSource: remote,
				CarrierDest:   local,
				AllowedIPs:    allowed,
				Slots:         32,
				PerPeerSlots:  32,
				MaxPacketSize: 1500,
				Lifetime:      time.Second,
			},
		}},
		CarrierQueueSize:     queueSize,
		ControlQueueSize:     8,
		DataInitiallyEnabled: true,
		ExpirationInterval:   100 * time.Millisecond,
	}
}

func readCarriers(d *Device) ([][]byte, []int, int, error) {
	bufs, sizes := carrierBuffers()
	n, err := d.Read(bufs, sizes, 0)
	return bufs, sizes, n, err
}

func carrierBuffers() ([][]byte, []int) {
	bufs := make([][]byte, testBatchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	return bufs, make([]int, testBatchSize)
}

func sized(bufs [][]byte, sizes []int, n int) [][]byte {
	for i := 0; i < n; i++ {
		bufs[i] = bufs[i][:sizes[i]]
	}
	return bufs[:n]
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not satisfied")
		}
		time.Sleep(time.Millisecond)
	}
}

func ipv4Packet(sourceLast, marker byte, size int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	packet[2], packet[3] = byte(size>>8), byte(size)
	copy(packet[12:16], []byte{10, 0, 0, sourceLast})
	copy(packet[16:20], []byte{192, 0, 2, marker})
	for i := 20; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet
}

var _ tun.Device = (*fakeTUN)(nil)
