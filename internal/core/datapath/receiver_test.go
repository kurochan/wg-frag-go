package datapath

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

type captureSink struct{ packets [][]byte }

func (s *captureSink) DeliverInner(packet []byte) error {
	s.packets = append(s.packets, append([]byte(nil), packet...))
	return nil
}

type discardSink struct{}

func (discardSink) DeliverInner([]byte) error { return nil }

type carrierCollector struct{ carriers [][]byte }

func (s *carrierCollector) DeliverCarrier(packet []byte) error {
	s.carriers = append(s.carriers, append([]byte(nil), packet...))
	return nil
}

type payloadCollector struct {
	peer     peerroute.PeerID
	payloads [][]byte
}

func (s *payloadCollector) DeliverPayload(peer peerroute.PeerID, payload []byte) error {
	s.peer = peer
	s.payloads = append(s.payloads, append([]byte(nil), payload...))
	return nil
}

func TestPayloadSenderReceiverUsesLogicalPeerWithoutSyntheticEnvelope(t *testing.T) {
	t.Parallel()
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), PeerID: 42},
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), PeerID: 42},
	})
	if err != nil {
		t.Fatal(err)
	}
	carriers := &payloadCollector{}
	sender, err := NewPayloadSender(SenderConfig{
		DataSessionID:  1,
		CarrierPayload: 613,
		MinPack:        128,
		RemotePeerMTU:  1500,
		PeerID:         42,
		AllowedIPs:     allowed,
	}, carriers)
	if err != nil {
		t.Fatal(err)
	}
	packet := ipv4Packet(10, 0)
	if err := sender.Add(packet); err != nil {
		t.Fatal(err)
	}
	if err := sender.Flush(); err != nil {
		t.Fatal(err)
	}
	if carriers.peer != 42 || len(carriers.payloads) != 1 {
		t.Fatalf("payload callback = peer %d, count %d", carriers.peer, len(carriers.payloads))
	}
	if carriers.payloads[0][0] == 6<<4 {
		t.Fatal("payload callback included synthetic IPv6 header")
	}

	receiver, err := NewPayloadReceiver(ReceiverConfig{
		PeerID:        42,
		DataSessionID: 1,
		AllowedIPs:    allowed,
		Slots:         2,
		PerPeerSlots:  2,
		MaxPacketSize: 1500,
		Lifetime:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	if err := receiver.AcceptPayload(time.Unix(1, 0), carriers.payloads[0], sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 1 || !bytes.Equal(sink.packets[0], packet) {
		t.Fatalf("delivered = %#v", sink.packets)
	}
}

func TestSenderReceiverRoundTripPacksDifferentPackets(t *testing.T) {
	t.Parallel()
	carriers := &carrierCollector{}
	sender, err := NewSender(SenderConfig{
		DataSessionID:  1,
		CarrierSource:  netip.MustParseAddr("fe80::2"),
		CarrierDest:    netip.MustParseAddr("fe80::1"),
		CarrierPayload: 613,
		MinPack:        128,
		RemotePeerMTU:  1500,
	}, carriers)
	if err != nil {
		t.Fatal(err)
	}
	first := ipv4Packet(10, 0)
	second := ipv4Packet(10, 1)
	if err := sender.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := sender.Add(second); err != nil {
		t.Fatal(err)
	}
	if err := sender.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(carriers.carriers) != 1 {
		t.Fatalf("carrier count = %d, want 1", len(carriers.carriers))
	}

	receiver := newReceiver(t, false)
	sink := &captureSink{}
	if err := receiver.AcceptCarrier(time.Unix(1, 0), carriers.carriers[0], sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 2 || !bytes.Equal(sink.packets[0], first) || !bytes.Equal(sink.packets[1], second) {
		t.Fatalf("delivered = %#v", sink.packets)
	}
}

func TestSenderRejectsRemotePeerMTUOverrun(t *testing.T) {
	t.Parallel()
	carriers := &carrierCollector{}
	sender, err := NewSender(SenderConfig{
		DataSessionID:  1,
		CarrierSource:  netip.MustParseAddr("fe80::2"),
		CarrierDest:    netip.MustParseAddr("fe80::1"),
		CarrierPayload: 613,
		MinPack:        128,
		RemotePeerMTU:  1280,
	}, carriers)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1281)
	packet[0] = 0x45
	packet[2], packet[3] = 5, 1
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{192, 0, 2, 1})
	if err := sender.Add(packet); !errors.Is(err, ErrPeerMTU) {
		t.Fatalf("Add() error = %v, want ErrPeerMTU", err)
	}
	if len(carriers.carriers) != 0 {
		t.Fatal("oversized packet emitted a carrier")
	}
}

func TestReceiverReordersAndValidatesSource(t *testing.T) {
	t.Parallel()
	r := newReceiver(t, true)
	now := time.Unix(1, 0)
	sink := &captureSink{}
	zero := ipv4Packet(10, 0)
	one := ipv4Packet(10, 1)
	if err := r.AcceptCarrier(now, outer(t, 1, one), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 0 {
		t.Fatal("future sequence was delivered")
	}
	if err := r.AcceptCarrier(now, outer(t, 0, zero), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 2 || !bytes.Equal(sink.packets[0], zero) || !bytes.Equal(sink.packets[1], one) {
		t.Fatalf("delivered = %#v", sink.packets)
	}
}

func TestReceiverReorderDeadlineIsIndependentOfReassemblyExpiration(t *testing.T) {
	t.Parallel()
	r := newReceiver(t, true)
	now := time.Unix(1, 0)
	sink := &captureSink{}
	if err := r.AcceptCarrier(now, outer(t, 1, ipv4Packet(10, 1)), sink); err != nil {
		t.Fatal(err)
	}
	wantDeadline := now.Add(10 * time.Millisecond)
	if got := r.NextReorderDeadline(); !got.Equal(wantDeadline) {
		t.Fatalf("NextReorderDeadline() = %v, want %v", got, wantDeadline)
	}
	if expired := r.ExpireReassembly(wantDeadline); expired != 0 {
		t.Fatalf("ExpireReassembly() = %d, want 0", expired)
	}
	if err := r.TickReorder(wantDeadline.Add(-time.Nanosecond), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 0 {
		t.Fatalf("reorder delivered before deadline: %d packets", len(sink.packets))
	}
	if err := r.TickReorder(wantDeadline, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 1 {
		t.Fatalf("reorder delivered at deadline = %d, want 1", len(sink.packets))
	}
	if got := r.NextReorderDeadline(); !got.IsZero() {
		t.Fatalf("NextReorderDeadline() after flush = %v, want zero", got)
	}
}

func TestReceiverReorderDeadlineTracksOlderTimestampOnAnotherLane(t *testing.T) {
	t.Parallel()
	r := newReceiver(t, true)
	later := time.Unix(20, 0)
	earlier := time.Unix(10, 0)
	if err := r.AcceptCarrier(later, outerLane(t, 0, 1, ipv4Packet(10, 1)), discardSink{}); err != nil {
		t.Fatal(err)
	}
	if err := r.AcceptCarrier(earlier, outerLane(t, 1, 1, ipv4Packet(10, 2)), discardSink{}); err != nil {
		t.Fatal(err)
	}
	want := earlier.Add(10 * time.Millisecond)
	if got := r.NextReorderDeadline(); !got.Equal(want) {
		t.Fatalf("NextReorderDeadline() = %v, want %v", got, want)
	}
}

func TestReceiverReorderBudgetIsSharedAcrossLanes(t *testing.T) {
	t.Parallel()
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/24"), PeerID: 42}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReceiver(ReceiverConfig{
		PeerID:          42,
		DataSessionID:   1,
		CarrierSource:   netip.MustParseAddr("fe80::2"),
		CarrierDest:     netip.MustParseAddr("fe80::1"),
		AllowedIPs:      allowed,
		Slots:           3,
		PerPeerSlots:    3,
		MaxPacketSize:   1500,
		Lifetime:        time.Second,
		ReorderEnabled:  true,
		ReorderCapacity: 4,
		ReorderBudget:   2,
		ReorderMaxDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	now := time.Unix(1, 0)
	for lane := byte(0); lane < 3; lane++ {
		if err := r.AcceptCarrier(now, outerLane(t, lane, 1, ipv4Packet(10, lane)), sink); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.packets) != 1 {
		t.Fatalf("packets delivered before Tick = %d, want oldest lane flush", len(sink.packets))
	}
	if _, err := r.Tick(now.Add(20*time.Millisecond), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 3 {
		t.Fatalf("packets delivered after Tick = %d, want 3", len(sink.packets))
	}
}

func TestReceiverReorderBudgetFlushesIncomingPacketOnItsLane(t *testing.T) {
	t.Parallel()
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/24"), PeerID: 42}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReceiver(ReceiverConfig{
		PeerID:          42,
		DataSessionID:   1,
		CarrierSource:   netip.MustParseAddr("fe80::2"),
		CarrierDest:     netip.MustParseAddr("fe80::1"),
		AllowedIPs:      allowed,
		Slots:           4,
		PerPeerSlots:    4,
		MaxPacketSize:   1500,
		Lifetime:        time.Second,
		ReorderEnabled:  true,
		ReorderCapacity: 4,
		ReorderBudget:   2,
		ReorderMaxDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	now := time.Unix(1, 0)
	for sequence := uint32(1); sequence <= 3; sequence++ {
		if err := r.AcceptCarrier(now, outerLane(t, 0, sequence, ipv4Packet(10, byte(sequence))), sink); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.packets) != 3 {
		t.Fatalf("packets delivered = %d, want incoming lane flush", len(sink.packets))
	}
}

func TestReceiverReorderBudgetSameLaneKeepsIncomingPacket(t *testing.T) {
	t.Parallel()
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/24"), PeerID: 42}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReceiver(ReceiverConfig{
		PeerID:          42,
		DataSessionID:   1,
		CarrierSource:   netip.MustParseAddr("fe80::2"),
		CarrierDest:     netip.MustParseAddr("fe80::1"),
		AllowedIPs:      allowed,
		Slots:           3,
		PerPeerSlots:    3,
		MaxPacketSize:   1500,
		Lifetime:        time.Second,
		ReorderEnabled:  true,
		ReorderCapacity: 4,
		ReorderBudget:   2,
		ReorderMaxDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	now := time.Unix(1, 0)
	packets := [][]byte{ipv4Packet(10, 1), ipv4Packet(10, 2), ipv4Packet(10, 3)}
	for sequence := uint32(2); sequence <= 3; sequence++ {
		if err := r.AcceptCarrier(now, outerLane(t, 0, sequence, packets[sequence-1]), sink); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.AcceptCarrier(now, outerLane(t, 0, 1, packets[0]), sink); err != nil {
		t.Fatal(err)
	}
	for _, packet := range sink.packets {
		if bytes.Equal(packet, packets[0]) {
			return
		}
	}
	t.Fatal("incoming same-lane packet was dropped")
}

func TestReceiverDropsSpoofedInnerSourceAndReleasesSlot(t *testing.T) {
	t.Parallel()
	r := newReceiver(t, false)
	now := time.Unix(1, 0)
	spoofed := ipv4Packet(11, 0)
	spoofed[14] = 1
	// A spoofed reconstructed source is a counted per-packet drop, not an
	// error: it must not abort the carrier, the batch, or a reorder flush.
	if err := r.AcceptCarrier(now, outer(t, 0, spoofed), discardSink{}); err != nil {
		t.Fatalf("spoofed packet error = %v, want counted drop", err)
	}
	if drops := r.Drops(); drops.SourceSpoof != 1 {
		t.Fatalf("Drops() = %+v, want SourceSpoof=1", drops)
	}
	// The rejected completed slot must have been released, allowing another
	// packet with the only configured slot to complete immediately.
	sink := &captureSink{}
	valid := ipv4Packet(10, 1)
	if err := r.AcceptCarrier(now, outer(t, 1, valid), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 1 || !bytes.Equal(sink.packets[0], valid) {
		t.Fatalf("delivered = %#v", sink.packets)
	}
}

func TestReceiverDropsNativeFragments(t *testing.T) {
	t.Parallel()
	r := newReceiver(t, false)
	packet := ipv4Packet(10, 0)
	packet[6] = 0x20
	if err := r.AcceptCarrier(time.Unix(1, 0), outer(t, 0, packet), discardSink{}); err != nil {
		t.Fatalf("fragment error = %v, want counted drop", err)
	}
	if drops := r.Drops(); drops.NativeFragment != 1 {
		t.Fatalf("Drops() = %+v, want NativeFragment=1", drops)
	}
}

func TestReceiverTickGapFlushDropsSpoofedPacketWithoutError(t *testing.T) {
	t.Parallel()
	r := newReceiver(t, true)
	now := time.Unix(1, 0)
	spoofed := ipv4Packet(11, 1)
	spoofed[14] = 1
	// The future sequence waits in the reorder queue until Tick flushes it.
	if err := r.AcceptCarrier(now, outer(t, 1, spoofed), discardSink{}); err != nil {
		t.Fatal(err)
	}
	expired, err := r.Tick(now.Add(20*time.Millisecond), discardSink{})
	if err != nil || expired != 0 {
		t.Fatalf("Tick() = (%d, %v), want (0, nil)", expired, err)
	}
	if drops := r.Drops(); drops.SourceSpoof != 1 {
		t.Fatalf("Drops() = %+v, want SourceSpoof=1", drops)
	}
	// Later in-order traffic still flows.
	sink := &captureSink{}
	valid := ipv4Packet(10, 2)
	if err := r.AcceptCarrier(now.Add(30*time.Millisecond), outer(t, 2, valid), sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 1 || !bytes.Equal(sink.packets[0], valid) {
		t.Fatalf("delivered = %#v", sink.packets)
	}
}

func TestSenderDropsInnerDestinationNotRoutedToPeer(t *testing.T) {
	t.Parallel()
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), PeerID: 42},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), PeerID: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	carriers := &carrierCollector{}
	sender, err := NewSender(SenderConfig{
		DataSessionID:  1,
		CarrierSource:  netip.MustParseAddr("fe80::2"),
		CarrierDest:    netip.MustParseAddr("fe80::1"),
		CarrierPayload: 613,
		MinPack:        128,
		RemotePeerMTU:  1500,
		PeerID:         42,
		AllowedIPs:     allowed,
	}, carriers)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Add(ipv4Packet(10, 1)); err != nil {
		t.Fatalf("routed destination error = %v", err)
	}
	otherPeer := ipv4Packet(10, 1)
	copy(otherPeer[16:20], []byte{198, 51, 100, 1})
	if err := sender.Add(otherPeer); !errors.Is(err, ErrInnerDest) {
		t.Fatalf("other-peer destination error = %v, want ErrInnerDest", err)
	}
	unrouted := ipv4Packet(10, 1)
	copy(unrouted[16:20], []byte{203, 0, 113, 1})
	if err := sender.Add(unrouted); !errors.Is(err, ErrInnerDest) {
		t.Fatalf("unrouted destination error = %v, want ErrInnerDest", err)
	}
	if err := sender.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(carriers.carriers) != 1 {
		t.Fatalf("carrier count = %d, want only the routed packet", len(carriers.carriers))
	}
}

func TestReceiverTickExpiresIncompletePacket(t *testing.T) {
	t.Parallel()
	r := newReceiver(t, false)
	packet := ipv4Packet(10, 0)
	record := carrier.Header{FragmentCount: 2, DataSessionID: 1, LaneSequence: 0}
	if err := r.AcceptCarrier(time.Unix(1, 0), outerRecord(t, record, packet[:10]), discardSink{}); err != nil {
		t.Fatal(err)
	}
	expired, err := r.Tick(time.Unix(3, 0), discardSink{})
	if err != nil || expired != 1 {
		t.Fatalf("Tick() = (%d, %v), want (1, nil)", expired, err)
	}
}

func TestReceiverHotPathDoesNotAllocateForIncompleteRecord(t *testing.T) {
	r := newReceiver(t, false)
	packet := ipv4Packet(10, 0)
	inputs := make([][]byte, 64)
	for i := range inputs {
		record := carrier.Header{FragmentCount: 2, DataSessionID: 1, LaneSequence: uint32(i)}
		inputs[i] = outerRecord(t, record, packet[:10])
	}
	now := time.Unix(1, 0)
	next := 0
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := r.AcceptCarrier(now, inputs[next%len(inputs)], discardSink{}); err != nil {
			t.Fatal(err)
		}

		next++
	}); allocs != 0 {
		t.Fatalf("AcceptCarrier() allocations = %f, want 0", allocs)
	}
}

func FuzzReceiverAcceptCarrier(f *testing.F) {
	packet := ipv4Packet(10, 0)
	payload := make([]byte, carrier.HeaderSize+len(packet))
	if _, err := carrier.MarshalTo(payload, carrier.Header{FragmentCount: 1, DataSessionID: 1}, packet); err != nil {
		f.Fatal(err)
	}
	outer := make([]byte, carrier.IPv6HeaderSize+len(payload))
	if _, err := carrier.MarshalEnvelopeTo(outer, netip.MustParseAddr("fe80::2"), netip.MustParseAddr("fe80::1"), payload); err != nil {
		f.Fatal(err)
	}
	f.Add(outer)
	f.Add([]byte{})
	f.Add(make([]byte, carrier.IPv6HeaderSize))

	f.Fuzz(func(t *testing.T, outer []byte) {
		receiver := newReceiver(t, true)
		now := time.Unix(1, 0)
		_ = receiver.AcceptCarrier(now, outer, discardSink{})
		// A syntactically valid but semantically unauthorized packet may be
		// deferred by reorder and rejected only at Tick. Both paths must remain
		// safe for arbitrary authenticated-carrier bytes.
		_, _ = receiver.Tick(now.Add(2*time.Second), discardSink{})
	})
}

func newReceiver(t *testing.T, reorderEnabled bool) *Receiver {
	t.Helper()
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/24"), PeerID: 42}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReceiver(ReceiverConfig{
		PeerID:          42,
		DataSessionID:   1,
		CarrierSource:   netip.MustParseAddr("fe80::2"),
		CarrierDest:     netip.MustParseAddr("fe80::1"),
		AllowedIPs:      allowed,
		Slots:           slotCount(reorderEnabled),
		PerPeerSlots:    slotCount(reorderEnabled),
		MaxPacketSize:   1500,
		Lifetime:        time.Second,
		ReorderEnabled:  reorderEnabled,
		ReorderCapacity: 4,
		ReorderMaxDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func slotCount(reorderEnabled bool) int {
	if reorderEnabled {
		return 2
	}
	return 1
}

func outer(t *testing.T, sequence uint32, packet []byte) []byte {
	t.Helper()
	return outerRecord(t, carrier.Header{FragmentCount: 1, DataSessionID: 1, LaneSequence: sequence}, packet)
}

func outerLane(t *testing.T, lane byte, sequence uint32, packet []byte) []byte {
	t.Helper()
	return outerRecord(t, carrier.Header{FragmentCount: 1, DataSessionID: 1, LaneID: lane, LaneSequence: sequence}, packet)
}

func outerRecord(t *testing.T, header carrier.Header, packet []byte) []byte {
	t.Helper()
	payload := make([]byte, carrier.HeaderSize+len(packet))
	if _, err := carrier.MarshalTo(payload, header, packet); err != nil {
		t.Fatal(err)
	}
	outer := make([]byte, carrier.IPv6HeaderSize+len(payload))
	if _, err := carrier.MarshalEnvelopeTo(outer, netip.MustParseAddr("fe80::2"), netip.MustParseAddr("fe80::1"), payload); err != nil {
		t.Fatal(err)
	}
	return outer
}

func ipv4Packet(sourceLast, marker byte) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 20
	copy(packet[12:16], []byte{10, 0, 0, sourceLast})
	copy(packet[16:20], []byte{192, 0, 2, marker})
	return packet
}
