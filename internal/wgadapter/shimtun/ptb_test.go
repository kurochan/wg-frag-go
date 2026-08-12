package shimtun

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

func oversizeInner() []byte {
	packet := ipv4Packet(9, 0, 1400)
	copy(packet[16:20], []byte{10, 2, 0, 5})
	return packet
}

func TestOversizeInnerEmitsPacketTooBig(t *testing.T) {
	t.Parallel()
	native := newFakeTUN("a", 1500, [][]byte{oversizeInner()})
	config := pairConfig(t, native, true, 64)
	config.Peers[0].Sender.RemotePeerMTU = 1280
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	waitFor(t, func() bool { return d.Stats().TXPTBSent == 1 })
	if stats := d.Stats(); stats.TXPeerMTUDrops != 1 {
		t.Fatalf("Stats() = %+v, want one peer MTU drop", stats)
	}
	got := native.written()
	if len(got) != 1 {
		t.Fatalf("native writes = %d, want one PTB", len(got))
	}
	ptb := got[0]
	if ptb[9] != 1 || ptb[20] != 3 || ptb[21] != 4 {
		t.Fatalf("not Fragmentation Needed: proto=%d type=%d code=%d", ptb[9], ptb[20], ptb[21])
	}
	if mtu := binary.BigEndian.Uint16(ptb[26:28]); mtu != 1280 {
		t.Fatalf("next-hop MTU = %d, want the peer inner MTU", mtu)
	}
	if [4]byte(ptb[16:20]) != [4]byte{10, 0, 0, 9} {
		t.Fatalf("PTB destination = %v, want the original source", ptb[16:20])
	}
	// Sourcing from the original destination keeps the injected packet
	// deliverable: a local source would be a kernel martian.
	if [4]byte(ptb[12:16]) != [4]byte{10, 2, 0, 5} {
		t.Fatalf("PTB source = %v, want the original destination", ptb[12:16])
	}
}

func TestOversizeInnerToMulticastIsSilentDrop(t *testing.T) {
	t.Parallel()
	packet := ipv4Packet(9, 0, 1400)
	copy(packet[16:20], []byte{224, 0, 0, 5})
	native := newFakeTUN("a", 1500, [][]byte{packet})
	config := pairConfig(t, native, true, 64)
	config.Peers[0].Sender.RemotePeerMTU = 1280
	// Route the multicast destination to the peer so the MTU check is reached.
	allowed, err := peerroute.NewSnapshot([]peerroute.AllowedIP{
		{Prefix: netip.MustParsePrefix("224.0.0.0/8"), PeerID: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	config.Peers[0].Sender.AllowedIPs = allowed
	config.Peers[0].Receiver.AllowedIPs = allowed
	d, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	waitFor(t, func() bool { return d.Stats().TXPeerMTUDrops == 1 })
	if stats := d.Stats(); stats.TXPTBSent != 0 {
		t.Fatalf("Stats() = %+v, want the multicast PTB suppressed", stats)
	}
	if got := native.written(); len(got) != 0 {
		t.Fatalf("native writes = %d, want none", len(got))
	}
}
