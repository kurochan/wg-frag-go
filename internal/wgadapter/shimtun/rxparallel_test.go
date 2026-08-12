package shimtun

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/datapath"
)

// carrierCollector implements datapath.CarrierSink for building test carriers.
type carrierCollector struct{ carriers [][]byte }

func (s *carrierCollector) DeliverCarrier(packet []byte) error {
	s.carriers = append(s.carriers, append([]byte(nil), packet...))
	return nil
}

// peerCarriers builds count single-packet DATA carriers from one remote peer
// of twoPeerConfig, with inner sources inside that peer's allowed prefix.
func peerCarriers(t *testing.T, peer int, count int) [][]byte {
	t.Helper()
	sources := []netip.Addr{netip.MustParseAddr("fe80::b"), netip.MustParseAddr("fe80::c")}
	prefixes := [][]byte{{192, 0, 2, 0}, {198, 51, 100, 0}}
	collector := &carrierCollector{}
	sender, err := datapath.NewSender(datapath.SenderConfig{
		DataSessionID:  1,
		CarrierSource:  sources[peer],
		CarrierDest:    netip.MustParseAddr("fe80::a"),
		CarrierPayload: 613,
		MinPack:        128,
		RemotePeerMTU:  1500,
	}, collector)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		packet := ipv4Packet(0, byte(i), 200)
		copy(packet[12:16], prefixes[peer])
		packet[15] = byte(i%250 + 1)
		if err := sender.Add(packet); err != nil {
			t.Fatal(err)
		}
		if err := sender.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if len(collector.carriers) != count {
		t.Fatalf("carriers = %d, want %d", len(collector.carriers), count)
	}
	return collector.carriers
}

func TestWriteRunsPeersConcurrently(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("r", 1500)
	d, err := New(twoPeerConfig(t, native))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	peer0, ok := d.peerFor(0)
	if !ok {
		t.Fatal("peer 0 missing")
	}
	carriers := peerCarriers(t, 1, 1)

	// A blocked receive batch for one peer must not stall another peer.
	peer0.rxMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := d.Write(carriers, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write() = %v", err)
		}
	case <-time.After(2 * time.Second):
		peer0.rxMu.Unlock()
		t.Fatal("peer 1 Write blocked behind peer 0's RX lock")
	}
	peer0.rxMu.Unlock()
	waitFor(t, func() bool { return d.Stats().RXInnerDelivered == 1 })
}

func TestWriteBatchTracksOnePeerOnce(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("r", 1500)
	d, err := New(twoPeerConfig(t, native))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	carriers := peerCarriers(t, 0, 2)
	if got, err := d.Write(carriers, 0); err != nil || got != len(carriers) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", got, err, len(carriers))
	}
	waitFor(t, func() bool { return d.Stats().RXInnerDelivered == 2 })
}

func TestConcurrentWritesDeliverAllPeers(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("r", 1500)
	d, err := New(twoPeerConfig(t, native))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	const perPeer = 200
	batches := [2][][]byte{peerCarriers(t, 0, perPeer), peerCarriers(t, 1, perPeer)}
	var group sync.WaitGroup
	errs := make(chan error, 2)
	for peer := 0; peer < 2; peer++ {
		group.Add(1)
		go func(carriers [][]byte) {
			defer group.Done()
			for _, packet := range carriers {
				if _, err := d.Write([][]byte{packet}, 0); err != nil {
					errs <- err
					return
				}
				d.Stats()
			}
		}(batches[peer])
	}
	group.Wait()
	close(errs)
	if err := <-errs; err != nil {
		t.Fatalf("concurrent Write() = %v", err)
	}
	waitFor(t, func() bool { return d.Stats().RXInnerDelivered == 2*perPeer })
	if stats := d.Stats(); stats.RXPacketRejects != 0 || stats.RXSourceSpoofDrops != 0 {
		t.Fatalf("Stats() = %+v, want no rejects", stats)
	}
	if got := len(native.written()); got != 2*perPeer {
		t.Fatalf("native packets = %d, want %d", got, 2*perPeer)
	}
}
