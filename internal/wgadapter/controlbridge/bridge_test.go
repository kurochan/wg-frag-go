package controlbridge

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/controlplane"
	controlstate "github.com/kurochan/wg-frag-go/internal/core/control/state"
	"github.com/kurochan/wg-frag-go/internal/core/datapath"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

type bridgeClock struct{ now time.Time }

func (c bridgeClock) Now() time.Time { return c.now }

type bridgeEntropy struct{ values []uint64 }

func (e *bridgeEntropy) Uint64() (uint64, error) {
	if len(e.values) == 0 {
		return 0, errors.New("entropy exhausted")
	}
	value := e.values[0]
	e.values = e.values[1:]
	return value, nil
}

type fakeTUN struct {
	mu sync.Mutex

	frames    [][]byte
	enabled   bool
	sender    datapath.SenderConfig
	receiver  datapath.ReceiverConfig
	installs  int
	enableSet int
}

type orderedTUN struct {
	fakeTUN

	order []string
}

func (t *orderedTUN) EnqueueControl(peer peerroute.PeerID, frame []byte) error {
	t.mu.Lock()
	t.frames = append(t.frames, append([]byte(nil), frame...))
	t.order = append(t.order, "enqueue")
	t.mu.Unlock()
	return nil
}

func (t *orderedTUN) SetDataEnabled(_ peerroute.PeerID, enabled bool) error {
	t.mu.Lock()
	t.enabled = enabled
	t.enableSet++
	if enabled {
		t.order = append(t.order, "enable")
	} else {
		t.order = append(t.order, "disable")
	}
	t.mu.Unlock()
	return nil
}

func (t *orderedTUN) calls() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.order...)
}

func (t *fakeTUN) EnqueueControl(_ peerroute.PeerID, frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.frames = append(t.frames, append([]byte(nil), frame...))
	return nil
}

func (t *fakeTUN) InstallDataPlane(_ peerroute.PeerID, sender datapath.SenderConfig, receiver datapath.ReceiverConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sender, t.receiver = sender, receiver
	t.installs++
	return nil
}

func (t *fakeTUN) SetDataEnabled(_ peerroute.PeerID, enabled bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = enabled
	t.enableSet++
	return nil
}

func (t *fakeTUN) takeFrames() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	frames := t.frames
	t.frames = nil
	return frames
}

func (t *fakeTUN) snapshot() (bool, datapath.SenderConfig, datapath.ReceiverConfig, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.enabled, t.sender, t.receiver, t.installs
}

func (t *fakeTUN) installCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.installs
}

func TestBidirectionalControlOpensOnlyNegotiatedDirectionalDataPlane(t *testing.T) {
	t.Parallel()
	aEngine := testEngine(t, 0xa001, 101)
	bEngine := testEngine(t, 0xb001, 202)
	aTUN, bTUN := new(fakeTUN), new(fakeTUN)
	a, err := New(Config{Engine: aEngine, TUN: aTUN, SenderBase: senderBase("fe80::a", "fe80::b"), ReceiverBase: receiverBase(t, "fe80::b", "fe80::a")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Engine: bEngine, TUN: bTUN, SenderBase: senderBase("fe80::b", "fe80::a"), ReceiverBase: receiverBase(t, "fe80::a", "fe80::b")})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}

	for step := 0; step < 100; step++ {
		progressed := false
		for _, frame := range aTUN.takeFrames() {
			progressed = true

			if err := b.DeliverControl(0, frame); err != nil {
				t.Fatal(err)
			}
		}
		for _, frame := range bTUN.takeFrames() {
			progressed = true

			if err := a.DeliverControl(0, frame); err != nil {
				t.Fatal(err)
			}
		}
		if !progressed {
			break
		}
	}

	aEnabled, aSender, aReceiver, aInstalls := aTUN.snapshot()
	bEnabled, bSender, bReceiver, bInstalls := bTUN.snapshot()
	if !aEnabled || !bEnabled || aInstalls == 0 || bInstalls == 0 {
		t.Fatalf("DATA gate did not open: a=%v/%d b=%v/%d", aEnabled, aInstalls, bEnabled, bInstalls)
	}
	if aSender.DataSessionID != bReceiver.DataSessionID || bSender.DataSessionID != aReceiver.DataSessionID {
		t.Fatalf("directional sessions mismatch: a tx/rx=%d/%d b tx/rx=%d/%d", aSender.DataSessionID, aReceiver.DataSessionID, bSender.DataSessionID, bReceiver.DataSessionID)
	}
	if aSender.DataSessionID == aReceiver.DataSessionID {
		t.Fatal("local TX and RX session unexpectedly share one ID")
	}
}

func TestStartDoesNotDisableDataOnRepeatedCall(t *testing.T) {
	t.Parallel()
	engine := testEngine(t, 0xc001, 301)
	tun := new(fakeTUN)
	bridge, err := New(Config{
		Engine:       engine,
		TUN:          tun,
		PeerID:       7,
		SenderBase:   senderBase("fe80::a", "fe80::b"),
		ReceiverBase: receiverBase(t, "fe80::b", "fe80::a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	before := tun.installCount()
	if err := bridge.Start(); err != nil {
		t.Fatalf("second Start() error = %v, want nil", err)
	}
	after := tun.installCount()
	if after != before {
		t.Fatalf("second Start() unexpectedly touched the TUN: installs %d -> %d", before, after)
	}
}

func TestStartIsIdempotentAfterInboundExchangeStartsIt(t *testing.T) {
	t.Parallel()
	engine := testEngine(t, 0xc101, 302)
	tun := new(fakeTUN)
	bridge, err := New(Config{
		Engine:       engine,
		TUN:          tun,
		PeerID:       7,
		SenderBase:   senderBase("fe80::a", "fe80::b"),
		ReceiverBase: receiverBase(t, "fe80::b", "fe80::a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := testEngine(t, 0xd101, 402)
	outbound, err := remote.Start()
	if err != nil || len(outbound) != 1 {
		t.Fatalf("remote Start() = (%d frames, %v)", len(outbound), err)
	}
	if err := bridge.DeliverControl(7, outbound[0].Frame); err != nil {
		t.Fatalf("DeliverControl() error = %v", err)
	}
	if err := bridge.Start(); err != nil {
		t.Fatalf("Start() after inbound exchange error = %v, want nil", err)
	}
}

func TestStartClosesDataBeforeQueueingControl(t *testing.T) {
	t.Parallel()
	tun := new(orderedTUN)
	bridge, err := New(Config{
		Engine:       testEngine(t, 0xc201, 303),
		TUN:          tun,
		PeerID:       7,
		SenderBase:   senderBase("fe80::a", "fe80::b"),
		ReceiverBase: receiverBase(t, "fe80::b", "fe80::a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	calls := tun.calls()
	firstDisable, firstEnqueue := -1, -1
	for i, call := range calls {
		if call == "disable" && firstDisable < 0 {
			firstDisable = i
		}
		if call == "enqueue" && firstEnqueue < 0 {
			firstEnqueue = i
		}
	}
	if firstDisable < 0 || firstEnqueue < 0 || firstDisable > firstEnqueue {
		t.Fatalf("calls = %v, want disable before enqueue", calls)
	}
}

func TestUpdateRoutesChangesFutureDataPlaneInstall(t *testing.T) {
	t.Parallel()
	aEngine := testEngine(t, 0xe001, 501)
	bEngine := testEngine(t, 0xf001, 601)
	aTUN, bTUN := new(fakeTUN), new(fakeTUN)
	a, err := New(Config{Engine: aEngine, TUN: aTUN, PeerID: 0, SenderBase: senderBase("fe80::a", "fe80::b"), ReceiverBase: receiverBase(t, "fe80::b", "fe80::a")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Engine: bEngine, TUN: bTUN, PeerID: 0, SenderBase: senderBase("fe80::b", "fe80::a"), ReceiverBase: receiverBase(t, "fe80::a", "fe80::b")})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), PeerID: 0}})
	if err != nil {
		t.Fatal(err)
	}
	a.UpdateRoutes(routes)
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 100; step++ {
		progressed := false
		for _, frame := range aTUN.takeFrames() {
			progressed = true

			if err := b.DeliverControl(0, frame); err != nil {
				t.Fatal(err)
			}
		}
		for _, frame := range bTUN.takeFrames() {
			progressed = true

			if err := a.DeliverControl(0, frame); err != nil {
				t.Fatal(err)
			}
		}
		if !progressed {
			break
		}
	}
	_, sender, receiver, installs := aTUN.snapshot()
	if installs == 0 {
		t.Fatal("route update did not install a data plane")
	}
	if sender.AllowedIPs != routes || receiver.AllowedIPs != routes {
		t.Fatalf("installed routes = sender %p receiver %p, want %p", sender.AllowedIPs, receiver.AllowedIPs, routes)
	}
}

func TestBridgeRejectsControlForAnotherPeer(t *testing.T) {
	t.Parallel()
	bridge, err := New(Config{
		Engine:       testEngine(t, 0xc101, 302),
		TUN:          new(fakeTUN),
		PeerID:       7,
		SenderBase:   senderBase("fe80::a", "fe80::b"),
		ReceiverBase: receiverBase(t, "fe80::b", "fe80::a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.DeliverControl(8, []byte{0, 0, 1}); !errors.Is(err, ErrPeerMismatch) {
		t.Fatalf("wrong-peer DeliverControl() error = %v, want ErrPeerMismatch", err)
	}
	if err := bridge.ReportUnknownDataSession(8, 1); !errors.Is(err, ErrPeerMismatch) {
		t.Fatalf("wrong-peer ReportUnknownDataSession() error = %v, want ErrPeerMismatch", err)
	}
}

func testEngine(t *testing.T, epoch, session uint64) *controlplane.Engine {
	t.Helper()
	engine, err := controlplane.New(controlplane.Config{State: controlstate.Config{
		MaxCarrierPayload:    613,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                bridgeClock{now: time.Unix(0, 0)},
		Entropy:              &bridgeEntropy{values: []uint64{epoch, session}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func senderBase(source, dest string) datapath.SenderConfig {
	return datapath.SenderConfig{
		DataSessionID:  1,
		CarrierSource:  netip.MustParseAddr(source),
		CarrierDest:    netip.MustParseAddr(dest),
		CarrierPayload: 613,
		MinPack:        128,
		RemotePeerMTU:  1500,
	}
}

func receiverBase(t *testing.T, source, dest string) datapath.ReceiverConfig {
	t.Helper()
	routes, err := peerroute.NewSnapshot([]peerroute.AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 0}})
	if err != nil {
		t.Fatal(err)
	}
	return datapath.ReceiverConfig{
		PeerID:          0,
		DataSessionID:   1,
		CarrierSource:   netip.MustParseAddr(source),
		CarrierDest:     netip.MustParseAddr(dest),
		AllowedIPs:      routes,
		Slots:           8,
		PerPeerSlots:    8,
		MaxPacketSize:   1500,
		Lifetime:        time.Second,
		ReorderEnabled:  true,
		ReorderCapacity: 8,
		ReorderMaxDelay: 10 * time.Millisecond,
	}
}
