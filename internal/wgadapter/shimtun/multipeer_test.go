package shimtun

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/control"
	"github.com/kurochan/wg-frag-go/internal/core/datapath"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/transport"
)

// twoPeerConfig builds one shim serving two peers whose user prefixes differ,
// so egress selection and ingress attribution are both observable.
func twoPeerConfig(t *testing.T, native *fakeTUN) Config {
	t.Helper()
	local := netip.MustParseAddr("fe80::a")
	remotes := []netip.Addr{netip.MustParseAddr("fe80::b"), netip.MustParseAddr("fe80::c")}
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), PeerID: 0},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), PeerID: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	peers := make([]PeerConfig, 2)
	metricsIDs := []string{"peer-a", "peer-b"}
	for i := range peers {
		id := peerroute.PeerID(i)
		peers[i] = PeerConfig{
			MetricsID: metricsIDs[i],
			OwnerKey:  [32]byte{byte(i + 1)},
			Sender: datapath.SenderConfig{
				DataSessionID:  1,
				CarrierSource:  local,
				CarrierDest:    remotes[i],
				CarrierPayload: 613,
				MinPack:        128,
				RemotePeerMTU:  1500,
				PeerID:         id,
				AllowedIPs:     allowed,
			},
			Receiver: datapath.ReceiverConfig{
				PeerID:        id,
				DataSessionID: 1,
				CarrierSource: remotes[i],
				CarrierDest:   local,
				AllowedIPs:    allowed,
				Slots:         32,
				PerPeerSlots:  16,
				MaxPacketSize: 1500,
				Lifetime:      time.Second,
			},
		}
	}
	return Config{
		Native:               native,
		Peers:                peers,
		CarrierQueueSize:     64,
		ControlQueueSize:     8,
		DataInitiallyEnabled: true,
		ExpirationInterval:   100 * time.Millisecond,
	}
}

func TestEgressSelectsPeerByLongestPrefixMatch(t *testing.T) {
	t.Parallel()
	toFirst := ipv4Packet(10, 0, 80)
	copy(toFirst[16:20], []byte{192, 0, 2, 5})
	toSecond := ipv4Packet(10, 0, 80)
	copy(toSecond[16:20], []byte{198, 51, 100, 5})
	unrouted := ipv4Packet(10, 0, 80)
	copy(unrouted[16:20], []byte{203, 0, 113, 5})

	native := newFakeTUN("a", 1500, [][]byte{toFirst, toSecond, unrouted})
	d, err := New(twoPeerConfig(t, native))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	carriers, sizes, n, err := readCarriers(d)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("carrier count = %d, want one per routed peer", n)
	}
	// Each carrier must be addressed to the peer that owns its destination.
	destinations := map[netip.Addr]bool{}
	for i := 0; i < n; i++ {
		destinations[netip.AddrFrom16([16]byte(carriers[i][24:40]))] = true
	}
	for _, want := range []string{"fe80::b", "fe80::c"} {
		if !destinations[netip.MustParseAddr(want)] {
			t.Fatalf("no carrier addressed to %s: %v", want, destinations)
		}
	}
	if stats := d.Stats(); stats.TXRouteDrops != 1 {
		t.Fatalf("Stats() = %+v, want the unrouted packet counted", stats)
	}
	_ = sizes
}

func TestStatsIncludesPeerPMTUState(t *testing.T) {
	t.Parallel()
	d, err := New(twoPeerConfig(t, newFakeTUN("a", 1500)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.SetPeerPMTUState(1, [32]byte{2}, 1400, true); err != nil {
		t.Fatal(err)
	}
	stats := d.PeerStats()
	if len(stats) != 2 {
		t.Fatalf("PeerStats() = %#v, want two peers", stats)
	}
	if got := stats[1]; got.ID != 1 || got.MetricsID != "peer-b" || got.CarrierPayload != 1400 || !got.PMTUSearching || !got.DataForwardingEnabled {
		t.Fatalf("PeerStats()[1] = %#v", got)
	}
	if err := d.SetPeerPMTUState(2, [32]byte{}, 0, false); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("SetPeerPMTUState unknown = %v, want ErrPeerNotFound", err)
	}
	if err := d.SetPeerPMTUState(peerroute.PeerID(^uint32(0)), [32]byte{}, 0, false); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("SetPeerPMTUState maximum ID = %v, want ErrPeerNotFound", err)
	}
}

func TestStalePeerStateCannotUpdateReplacement(t *testing.T) {
	t.Parallel()
	config := twoPeerConfig(t, newFakeTUN("a", 1500))
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	replacement := config.Peers[1]
	replacement.MetricsID = "replacement"
	replacement.OwnerKey = [32]byte{9}
	if err := d.Reconfigure(map[peerroute.PeerID]PeerConfig{1: replacement}, []peerroute.PeerID{1}, config.Peers[0].Sender.AllowedIPs); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPeerPMTUState(1, config.Peers[1].OwnerKey, 1400, true); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("stale SetPeerPMTUState = %v, want ErrPeerNotFound", err)
	}
	if err := d.SetPeerMetricsID(1, config.Peers[1].OwnerKey, "stale"); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("stale SetPeerMetricsID = %v, want ErrPeerNotFound", err)
	}
	stats := d.PeerStats()
	if got := stats[1]; got.MetricsID != "replacement" || got.CarrierPayload != 0 || got.PMTUSearching {
		t.Fatalf("replacement peer state = %#v", got)
	}
}

func TestEgressWithOverlappingPrefixesPrefersMoreSpecificPeer(t *testing.T) {
	t.Parallel()
	// Peer 0 owns the broad prefix, peer 1 a more specific one inside it. A
	// destination inside the narrow prefix must never fall back to peer 0.
	inNarrow := ipv4Packet(10, 0, 80)
	copy(inNarrow[16:20], []byte{10, 1, 0, 5})
	inBroadOnly := ipv4Packet(10, 0, 80)
	copy(inBroadOnly[16:20], []byte{10, 2, 0, 5})

	native := newFakeTUN("a", 1500, [][]byte{inNarrow, inBroadOnly})
	config := twoPeerConfig(t, native)
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 0},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), PeerID: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range config.Peers {
		config.Peers[i].Sender.AllowedIPs = allowed
		config.Peers[i].Receiver.AllowedIPs = allowed
	}
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	carriers, sizes, n, err := readCarriers(d)
	if err != nil || n != 2 {
		t.Fatalf("readCarriers() = (%d, %v), want both destinations routed", n, err)
	}
	byDest := map[netip.Addr][]byte{}
	for i := 0; i < n; i++ {
		byDest[netip.AddrFrom16([16]byte(carriers[i][24:40]))] = carriers[i][:sizes[i]]
	}
	narrowCarrier := byDest[netip.MustParseAddr("fe80::c")]
	broadCarrier := byDest[netip.MustParseAddr("fe80::b")]
	if narrowCarrier == nil || broadCarrier == nil {
		t.Fatalf("carrier peers = %v, want one per peer", byDest)
	}
	if !bytes.Contains(narrowCarrier, inNarrow[16:20]) {
		t.Fatal("narrow-prefix destination was not sent to the more specific peer")
	}
	if !bytes.Contains(broadCarrier, inBroadOnly[16:20]) {
		t.Fatal("broad-prefix destination was not sent to the covering peer")
	}
}

func TestIngressAttributesCarrierToItsOwnPeer(t *testing.T) {
	t.Parallel()
	// Peer 1 sends a packet whose inner source belongs to peer 0's prefix. The
	// receiver must reject it: the global match resolves to a different peer
	// than the carrier that authenticated it.
	spoofed := ipv4Packet(10, 0, 80)
	copy(spoofed[12:16], []byte{192, 0, 2, 9})
	copy(spoofed[16:20], []byte{10, 0, 0, 1})

	senderNative := newFakeTUN("s", 1500, [][]byte{spoofed})
	senderConfig := twoPeerConfig(t, senderNative)
	// Let the sender emit it by routing that destination to peer 1.
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 1}})
	if err != nil {
		t.Fatal(err)
	}
	senderConfig.Peers[1].Sender.AllowedIPs = allowed
	senderConfig.Peers[0].Sender.AllowedIPs = allowed
	sender, err := New(senderConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	carriers, sizes, n, err := readCarriers(sender)
	if err != nil || n != 1 {
		t.Fatalf("readCarriers() = (%d, %v)", n, err)
	}

	// The receiver's local carrier is the destination the sender used, and its
	// peer 1 is the sender. Peer 0 keeps its own distinct carrier.
	receiverNative := newFakeTUN("r", 1500)
	receiverConfig := twoPeerConfig(t, receiverNative)
	receiverLocal := netip.MustParseAddr("fe80::c")
	senderCarrier := netip.MustParseAddr("fe80::a")
	other := netip.MustParseAddr("fe80::b")
	for i := range receiverConfig.Peers {
		receiverConfig.Peers[i].Sender.CarrierSource = receiverLocal
		receiverConfig.Peers[i].Receiver.CarrierDest = receiverLocal
	}
	receiverConfig.Peers[0].Sender.CarrierDest = other
	receiverConfig.Peers[0].Receiver.CarrierSource = other
	receiverConfig.Peers[1].Sender.CarrierDest = senderCarrier
	receiverConfig.Peers[1].Receiver.CarrierSource = senderCarrier
	receiver, err := New(receiverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })

	if wrote, err := receiver.Write(sized(carriers, sizes, n), 0); err != nil || wrote != n {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", wrote, err, n)
	}
	if written := receiverNative.written(); len(written) != 0 {
		t.Fatalf("spoofed packet reached the TUN: %v", bytes.TrimRight(written[0], "\x00"))
	}
	if stats := receiver.Stats(); stats.RXSourceSpoofDrops != 1 {
		t.Fatalf("Stats() = %+v, want one source-spoof drop", stats)
	}
}

func TestReconfigureRemovesAndAddsPeers(t *testing.T) {
	t.Parallel()
	toFirst := ipv4Packet(10, 0, 80)
	copy(toFirst[16:20], []byte{192, 0, 2, 5})
	toNew := ipv4Packet(10, 0, 80)
	copy(toNew[16:20], []byte{203, 0, 113, 5})

	native := newFakeTUN("a", 1500, [][]byte{toFirst})
	config := twoPeerConfig(t, native)
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, _, n, err := readCarriers(d); err != nil || n != 1 {
		t.Fatalf("initial readCarriers() = (%d, %v)", n, err)
	}

	// Remove peer 1 and give its freed slot to a peer owning a new prefix.
	local := netip.MustParseAddr("fe80::a")
	newCarrier := netip.MustParseAddr("fe80::d")
	routes, err := peerroute.NewSnapshot([]peerroute.AllowedIP{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), PeerID: 0},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), PeerID: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	replacement := config.Peers[1]
	replacement.Sender.CarrierDest = newCarrier
	replacement.Sender.AllowedIPs = routes
	replacement.Receiver.CarrierSource = newCarrier
	replacement.Receiver.AllowedIPs = routes
	if err := d.Reconfigure(map[peerroute.PeerID]PeerConfig{1: replacement}, []peerroute.PeerID{1}, routes); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDataEnabled(1, true); err != nil {
		t.Fatal(err)
	}

	native.appendBatch([][]byte{toFirst, toNew})

	carriers, sizes, n, err := readCarriers(d)
	if err != nil || n != 2 {
		t.Fatalf("readCarriers() = (%d, %v), want survivor and new peer routed", n, err)
	}
	destinations := map[netip.Addr]bool{}
	for i := 0; i < n; i++ {
		destinations[netip.AddrFrom16([16]byte(carriers[i][24:40]))] = true
	}
	if !destinations[netip.MustParseAddr("fe80::b")] || !destinations[newCarrier] {
		t.Fatalf("carrier destinations = %v", destinations)
	}
	_ = sizes
	_ = local

	// The removed peer's carrier source must now be rejected on ingress.
	packet := make([]byte, 128)
	written, err := carrier.MarshalEnvelopeTo(packet,
		netip.MustParseAddr("fe80::c"), netip.MustParseAddr("fe80::a"),
		[]byte{0, 20, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x45, 0, 0, 20, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	before := d.Stats().RXPacketRejects
	if wrote, err := d.Write([][]byte{packet[:written]}, 0); err != nil || wrote != 1 {
		t.Fatalf("Write() = (%d, %v)", wrote, err)
	}
	if got := d.Stats().RXPacketRejects; got != before+1 {
		t.Fatalf("RXPacketRejects = %d, want %d", got, before+1)
	}
}

func TestReconfigureRetainsRemovedPeerReceiverDrops(t *testing.T) {
	t.Parallel()
	d := func() *Device {
		native := newFakeTUN("a", 1500)
		device, err := New(twoPeerConfig(t, native))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = device.Close() })
		return device
	}()
	peer := d.table.Load().peers[1]
	peer.rxMu.Lock()
	peer.dropsBase.SourceSpoof = 3
	peer.dropsBase.NativeFragment = 2
	peer.dropsBase.InnerInvalid = 1
	peer.rxMu.Unlock()
	before := d.Stats()
	if before.RXSourceSpoofDrops != 3 || before.RXNativeFragmentDrops != 2 || before.RXPacketRejects != 6 {
		t.Fatalf("seeded drops = %+v", before)
	}
	if err := d.Reconfigure(nil, []peerroute.PeerID{1}, d.table.Load().routes); err != nil {
		t.Fatal(err)
	}
	after := d.Stats()
	if after.RXSourceSpoofDrops != before.RXSourceSpoofDrops || after.RXNativeFragmentDrops != before.RXNativeFragmentDrops ||
		after.RXPacketRejects != before.RXPacketRejects {
		t.Fatalf("removed peer drops changed: before=%+v after=%+v", before, after)
	}
}

func TestReconfigurePurgesRemovedPeerQueuesBeforeReuse(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := twoPeerConfig(t, native)
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	d.txMu.Lock()
	if err := d.enqueuePayloadLocked(0, []byte{0x01}); err != nil {
		d.txMu.Unlock()
		t.Fatal(err)
	}
	if err := d.enqueuePayloadLocked(1, []byte{0xaa, 0xbb}); err != nil {
		d.txMu.Unlock()
		t.Fatal(err)
	}
	if err := d.enqueuePayloadLocked(0, []byte{0x02}); err != nil {
		d.txMu.Unlock()
		t.Fatal(err)
	}
	d.txMu.Unlock()
	first := transport.TXBatch{{Payload: make([]byte, 1)}}
	if got, err := d.ReadPayloads(first); err != nil || got != 1 || first[0].PeerID != 0 || first[0].Payload[0] != 0x01 {
		t.Fatalf("drain first DATA = (%d, %v), descriptor=%+v", got, err, first[0])
	}

	codec, err := control.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 32)
	n, err := codec.MarshalTo(frame, []byte{0x08, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.EnqueueControl(1, frame[:n]); err != nil {
		t.Fatal(err)
	}
	d.txMu.Lock()
	if err := d.enqueuePayloadLocked(1, []byte{0xcc}); err != nil {
		d.txMu.Unlock()
		t.Fatal(err)
	}
	d.txMu.Unlock()

	if err := d.Reconfigure(map[peerroute.PeerID]PeerConfig{1: config.Peers[1]}, []peerroute.PeerID{1}, config.Peers[0].Sender.AllowedIPs); err != nil {
		t.Fatal(err)
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	if d.queueCount != 1 || d.queuePeers[d.queueHead] != 0 || d.queueLens[d.queueHead] != 1 || d.queueData[d.queueHead*d.dataStride] != 0x02 {
		t.Fatalf("DATA queue after peer replacement = count %d head %d peer %d len %d data %#x, want survivor peer 0", d.queueCount, d.queueHead, d.queuePeers[d.queueHead], d.queueLens[d.queueHead], d.queueData[d.queueHead*d.dataStride])
	}
	if d.controlSched.count != 0 {
		t.Fatalf("CONTROL queue count = %d after peer replacement, want 0", d.controlSched.count)
	}
}

func TestConcurrentReconfigureSerializesPeerSnapshots(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := twoPeerConfig(t, native)
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	routes, err := peerroute.NewSnapshot([]peerroute.AllowedIP{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), PeerID: 0},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), PeerID: 1},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), PeerID: 2},
		{Prefix: netip.MustParsePrefix("100.64.0.0/10"), PeerID: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	peer2 := config.Peers[0]
	peer2.Sender.PeerID, peer2.Receiver.PeerID = 2, 2
	peer2.Sender.CarrierDest = netip.MustParseAddr("fe80::d")
	peer2.Receiver.CarrierSource = peer2.Sender.CarrierDest
	peer2.Sender.AllowedIPs, peer2.Receiver.AllowedIPs = routes, routes
	peer3 := config.Peers[0]
	peer3.Sender.PeerID, peer3.Receiver.PeerID = 3, 3
	peer3.Sender.CarrierDest = netip.MustParseAddr("fe80::e")
	peer3.Receiver.CarrierSource = peer3.Sender.CarrierDest
	peer3.Sender.AllowedIPs, peer3.Receiver.AllowedIPs = routes, routes

	errs := make(chan error, 2)
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		errs <- d.Reconfigure(map[peerroute.PeerID]PeerConfig{2: peer2}, nil, routes)
	}()
	go func() {
		defer group.Done()
		errs <- d.Reconfigure(map[peerroute.PeerID]PeerConfig{3: peer3}, nil, routes)
	}()
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	d.txMu.Lock()
	defer d.txMu.Unlock()
	for _, id := range []peerroute.PeerID{2, 3} {
		if _, ok := d.peerFor(id); !ok {
			t.Fatalf("peer %d missing after concurrent Reconfigure", id)
		}
	}
}

func TestReconfigureRejectsOccupiedSlotAndUnknownRemoval(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := twoPeerConfig(t, native)
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	routes := d.table.Load().routes
	if err := d.Reconfigure(map[peerroute.PeerID]PeerConfig{0: config.Peers[0]}, nil, routes); err == nil {
		t.Fatal("adding into an occupied slot must fail")
	}
	if err := d.Reconfigure(nil, []peerroute.PeerID{7}, routes); err == nil {
		t.Fatal("removing an unknown slot must fail")
	}
}

func TestReconfigureRejectsAddedPeerAboveActiveCarrierSize(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := twoPeerConfig(t, native)
	config.MaxCarrierPayload = 1400
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	peer := config.Peers[1]
	peer.Sender.PeerID = 2
	peer.Receiver.PeerID = 2
	peer.Sender.CarrierDest = netip.MustParseAddr("fe80::d")
	peer.Receiver.CarrierSource = peer.Sender.CarrierDest
	peer.Sender.CarrierPayload = 1400
	if err := d.Reconfigure(map[peerroute.PeerID]PeerConfig{2: peer}, nil, config.Peers[0].Sender.AllowedIPs); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Reconfigure() error = %v, want ErrInvalidConfig", err)
	}
}

func TestReconfigureNilRoutesAfterRemovingPeerZeroDoesNotPanic(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := twoPeerConfig(t, native)
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// With no route snapshot, the surviving peer is the fallback target.
	if err := d.Reconfigure(nil, []peerroute.PeerID{0}, nil); err != nil {
		t.Fatal(err)
	}
	packet := ipv4Packet(10, 0, 80)
	copy(packet[16:20], []byte{198, 51, 100, 5})
	native.appendBatch([][]byte{packet})
	if _, _, n, err := readCarriers(d); err != nil || n != 1 {
		t.Fatalf("readCarriers() = (%d, %v), want one surviving-peer carrier", n, err)
	}
}

func TestQueueCapacityUsesSmallestPeerPayload(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500)
	config := twoPeerConfig(t, native)
	config.CarrierQueueSize = 4096
	config.MaxCarrierPayload = 65495
	config.Peers[1].Sender.CarrierPayload = 65495
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// The DATA stride follows the largest carrier, but peer zero still emits
	// up to three fragments per inner packet. Queue admission must retain
	// that smaller-payload peer's worst case rather than sizing for peer one.
	if d.dataFragments != 3 {
		t.Fatalf("dataFragments = %d, want 3", d.dataFragments)
	}
	want := activeCarrierQueueSlots(config.CarrierQueueSize, 3, d.batch, len(config.Peers))
	if len(d.queueLens) != want {
		t.Fatalf("active queue slots = %d, want %d", len(d.queueLens), want)
	}
}

func marshalStranger(dst []byte) (int, error) {
	return carrier.MarshalEnvelopeTo(dst,
		netip.MustParseAddr("fe80::dead"), netip.MustParseAddr("fe80::a"),
		[]byte{0, 20, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x45, 0, 0, 20, 0, 0, 0, 0})
}

func TestUnknownCarrierSourceIsRejected(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("r", 1500)
	d, err := New(twoPeerConfig(t, native))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// A well-formed carrier from an address no configured peer owns.
	packet := make([]byte, 128)
	written, err := marshalStranger(packet)
	if err != nil {
		t.Fatal(err)
	}
	if wrote, err := d.Write([][]byte{packet[:written]}, 0); err != nil || wrote != 1 {
		t.Fatalf("Write() = (%d, %v), want the carrier counted and skipped", wrote, err)
	}
	if stats := d.Stats(); stats.RXPacketRejects != 1 {
		t.Fatalf("Stats() = %+v, want the unknown source counted", stats)
	}
}
