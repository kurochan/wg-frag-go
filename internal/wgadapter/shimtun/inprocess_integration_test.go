package shimtun

import (
	"bytes"
	"sort"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/transport"
)

// inProcessCarrierLink is a deterministic test-only authenticated-carrier
// transport. It exercises the payload boundary without synthetic envelopes,
// sockets, namespaces, or wall-clock network scheduling.
type inProcessCarrierLink struct {
	destination *Device
	now         time.Duration
	queued      []scheduledCarrier
}

type scheduledCarrier struct {
	peer   transport.PeerID
	packet []byte
	due    time.Duration
	order  int
}

func (l *inProcessCarrierLink) enqueue(after time.Duration, peer transport.PeerID, payload []byte) {
	l.queued = append(l.queued, scheduledCarrier{
		peer:   peer,
		packet: append([]byte(nil), payload...),
		due:    l.now + after,
		order:  len(l.queued),
	})
}

func (l *inProcessCarrierLink) advance(by time.Duration) error {
	l.now += by
	ready := make([]scheduledCarrier, 0, len(l.queued))
	pending := l.queued[:0]
	for _, carrier := range l.queued {
		if carrier.due <= l.now {
			ready = append(ready, carrier)
		} else {
			pending = append(pending, carrier)
		}
	}
	l.queued = pending
	sort.SliceStable(ready, func(i, j int) bool {
		if ready[i].due == ready[j].due {
			return ready[i].order < ready[j].order
		}
		return ready[i].due < ready[j].due
	})
	if len(ready) == 0 {
		return nil
	}
	packets := make([]transport.RXDescriptor, len(ready))
	for i := range ready {
		packets[i] = transport.RXDescriptor{
			PeerID:  ready[i].peer,
			Payload: ready[i].packet,
			Length:  len(ready[i].packet),
		}
	}
	n, err := l.destination.WritePayloads(packets)
	if err != nil {
		return err
	}
	if n != len(packets) {
		return ErrShortNativeWrite
	}
	return nil
}

func TestInProcessCarrierLinkBidirectional(t *testing.T) {
	t.Parallel()
	aPacket := ipv4Packet(10, 0, 600)
	bPacket := ipv4Packet(10, 1, 600)
	// side A only accepts 10.2.0.0/16 from side B.
	bPacket[13] = 2
	aNative := newFakeTUN("a", 1500, [][]byte{aPacket})
	bNative := newFakeTUN("b", 1500, [][]byte{bPacket})
	a := newPairDevice(t, aNative, true, 16)
	b := newPairDevice(t, bNative, false, 16)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	aCarriers, aCount, err := readPayloads(a)
	if err != nil {
		t.Fatal(err)
	}
	bCarriers, bCount, err := readPayloads(b)
	if err != nil {
		t.Fatal(err)
	}
	if aCount != 1 || bCount != 1 {
		t.Fatalf("carrier counts = a:%d b:%d, want one each", aCount, bCount)
	}

	aToB := &inProcessCarrierLink{destination: b}
	bToA := &inProcessCarrierLink{destination: a}
	aToB.enqueue(0, aCarriers[0].PeerID, aCarriers[0].Bytes())
	bToA.enqueue(0, bCarriers[0].PeerID, bCarriers[0].Bytes())
	if err := aToB.advance(0); err != nil {
		t.Fatal(err)
	}
	if err := bToA.advance(0); err != nil {
		t.Fatal(err)
	}
	if got := bNative.written(); len(got) != 1 || !bytes.Equal(got[0], aPacket) {
		t.Fatalf("B received %#v, want A packet", got)
	}
	if got := aNative.written(); len(got) != 1 || !bytes.Equal(got[0], bPacket) {
		t.Fatalf("A received %#v, want B packet", got)
	}
}

func TestInProcessCarrierLinkDelaysAndReordersPackets(t *testing.T) {
	t.Parallel()
	first := ipv4Packet(10, 0, 600)
	second := ipv4Packet(10, 1, 600)
	aNative := newFakeTUN("a", 1500, [][]byte{first, second})
	bNative := newFakeTUN("b", 1500)
	aConfig := pairConfig(t, aNative, true, 16)
	bConfig := pairConfig(t, bNative, false, 16)
	bConfig.Peers[0].Receiver.ReorderEnabled = true
	bConfig.Peers[0].Receiver.ReorderCapacity = 4
	bConfig.Peers[0].Receiver.ReorderMaxDelay = 10 * time.Millisecond
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

	carriers, count, err := readPayloads(a)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("carrier count = %d, want 2", count)
	}

	link := &inProcessCarrierLink{destination: b}
	// Carrier 1 arrives first. Its complete packet must remain in the reorder
	// queue until delayed carrier 0 arrives.
	link.enqueue(0, carriers[1].PeerID, carriers[1].Bytes())
	link.enqueue(5*time.Millisecond, carriers[0].PeerID, carriers[0].Bytes())
	if err := link.advance(0); err != nil {
		t.Fatal(err)
	}
	if got := bNative.written(); len(got) != 0 {
		t.Fatalf("future packet delivered before delayed predecessor: %#v", got)
	}
	if err := link.advance(5 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	got := bNative.written()
	if len(got) != 2 || !bytes.Equal(got[0], first) || !bytes.Equal(got[1], second) {
		t.Fatalf("reordered output = %#v, want original order", got)
	}
}

func TestInProcessCarrierLinkReassemblesReverseFragments(t *testing.T) {
	t.Parallel()
	packet := ipv4Packet(10, 0, 1500)
	aNative := newFakeTUN("a", 1500, [][]byte{packet})
	bNative := newFakeTUN("b", 1500)
	a := newPairDevice(t, aNative, true, 16)
	b := newPairDevice(t, bNative, false, 16)
	t.Cleanup(func() { _ = a.Close() })
	t.Cleanup(func() { _ = b.Close() })

	carriers, count, err := readPayloads(a)
	if err != nil {
		t.Fatal(err)
	}
	if count < 2 {
		t.Fatalf("fragmented carrier count = %d, want at least 2", count)
	}
	link := &inProcessCarrierLink{destination: b}
	for i := count - 1; i >= 0; i-- {
		link.enqueue(0, carriers[i].PeerID, carriers[i].Bytes())
	}
	if err := link.advance(0); err != nil {
		t.Fatal(err)
	}
	if got := bNative.written(); len(got) != 1 || !bytes.Equal(got[0], packet) {
		t.Fatalf("reverse-fragment output = %#v, want original packet", got)
	}
}

func TestInProcessCarrierLinkDropsFragmentAndExpiresReassembly(t *testing.T) {
	t.Parallel()
	packet := ipv4Packet(10, 0, 1500)
	aNative := newFakeTUN("a", 1500, [][]byte{packet})
	bNative := newFakeTUN("b", 1500)
	aConfig := pairConfig(t, aNative, true, 16)
	bConfig := pairConfig(t, bNative, false, 16)
	aConfig.Peers[0].Receiver.Lifetime = 100 * time.Millisecond
	bConfig.Peers[0].Receiver.Lifetime = 100 * time.Millisecond
	aConfig.ExpirationInterval = time.Millisecond
	bConfig.ExpirationInterval = time.Millisecond
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

	carriers, count, err := readPayloads(a)
	if err != nil {
		t.Fatal(err)
	}
	if count < 3 {
		t.Fatalf("fragmented carrier count = %d, want at least 3", count)
	}
	link := &inProcessCarrierLink{destination: b}
	for i := 0; i < count-1; i++ { // intentionally drop the final fragment
		link.enqueue(0, carriers[i].PeerID, carriers[i].Bytes())
	}
	if err := link.advance(0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return b.Stats().ReassemblyExpirations == 1 })
	if got := bNative.written(); len(got) != 0 {
		t.Fatalf("dropped fragment produced inner output: %#v", got)
	}
}

func readPayloads(d *Device) ([]transport.TXDescriptor, int, error) {
	batch := make([]transport.TXDescriptor, testBatchSize)
	for i := range batch {
		batch[i].Payload = make([]byte, 2048)
	}
	n, err := d.ReadPayloads(batch)
	return batch[:n], n, err
}
