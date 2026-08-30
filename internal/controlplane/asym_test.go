package controlplane

import (
	"testing"
	"time"

	controlstate "github.com/kurochan/wg-frag-go/internal/core/control/state"
)

func TestAsymmetricMTUReachesReady(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{}
	newEngineMTU := func(mtu uint32, epoch uint64) *Engine {
		engine, err := New(Config{State: controlstate.Config{
			MaxCarrierPayload:    65432,
			MinCarrierPayload:    613,
			ReassemblyLifetimeMs: 2000,
			LocalPeerMTU:         mtu,
			StateSyncMinInterval: time.Second,
			Clock:                clock,
			Entropy:              &countingEntropy{next: epoch},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return engine
	}
	a, b := newEngineMTU(9612, 0xe001), newEngineMTU(1280, 0xf001)
	pending, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 64 && len(pending) > 0; round++ {
		next := make([]Outbound, 0, len(pending))
		for _, message := range pending {
			out, err := b.HandleInbound(message.Frame)
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			next = append(next, out...)
		}
		a, b = b, a
		pending = next
	}
	if !a.DataSendAllowed() || !b.DataSendAllowed() {
		t.Fatalf("engines did not reach DATA-ready: %07b / %07b", a.MissingFlags(), b.MissingFlags())
	}
}
