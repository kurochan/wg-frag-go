package peerroute

import (
	"errors"
	"net/netip"
	"testing"
)

func TestSnapshotIPv4LongestPrefixMatch(t *testing.T) {
	t.Parallel()
	snapshot := mustSnapshot(t, []AllowedIP{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), PeerID: 1},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 2},
		{Prefix: netip.MustParsePrefix("10.20.0.0/16"), PeerID: 3},
		{Prefix: netip.MustParsePrefix("10.20.30.40/32"), PeerID: 4},
	})

	tests := []struct {
		address string
		peer    PeerID
	}{
		{address: "192.0.2.1", peer: 1},
		{address: "10.1.2.3", peer: 2},
		{address: "10.20.1.2", peer: 3},
		{address: "10.20.30.40", peer: 4},
	}
	for _, test := range tests {
		peer, ok := snapshot.LookupPeer(netip.MustParseAddr(test.address))
		if !ok || peer != test.peer {
			t.Fatalf("LookupPeer(%s) = (%d, %v), want (%d, true)", test.address, peer, ok, test.peer)
		}
	}
}

func TestSnapshotIPv6LongestPrefixMatch(t *testing.T) {
	t.Parallel()
	snapshot := mustSnapshot(t, []AllowedIP{
		{Prefix: netip.MustParsePrefix("::/0"), PeerID: 1},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), PeerID: 2},
		{Prefix: netip.MustParsePrefix("2001:db8:1234::/48"), PeerID: 3},
		{Prefix: netip.MustParsePrefix("2001:db8:1234::7/128"), PeerID: 4},
	})

	tests := []struct {
		address string
		peer    PeerID
	}{
		{address: "2001:4860::1", peer: 1},
		{address: "2001:db8:ffff::1", peer: 2},
		{address: "2001:db8:1234::1", peer: 3},
		{address: "2001:db8:1234::7", peer: 4},
	}
	for _, test := range tests {
		peer, ok := snapshot.LookupPeer(netip.MustParseAddr(test.address))
		if !ok || peer != test.peer {
			t.Fatalf("LookupPeer(%s) = (%d, %v), want (%d, true)", test.address, peer, ok, test.peer)
		}
	}
}

func TestSnapshotOverlapAndGlobalSourceValidation(t *testing.T) {
	t.Parallel()
	snapshot := mustSnapshot(t, []AllowedIP{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 1},
		{Prefix: netip.MustParsePrefix("10.20.0.0/16"), PeerID: 2},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), PeerID: 1},
		{Prefix: netip.MustParsePrefix("2001:db8:20::/48"), PeerID: 2},
	})

	if snapshot.ValidateSource(1, netip.MustParseAddr("10.20.1.1")) {
		t.Fatal("less-specific IPv4 peer spoofed a more-specific peer prefix")
	}
	if !snapshot.ValidateSource(2, netip.MustParseAddr("10.20.1.1")) {
		t.Fatal("winning IPv4 peer was rejected")
	}
	if snapshot.ValidateSource(1, netip.MustParseAddr("2001:db8:20::1")) {
		t.Fatal("less-specific IPv6 peer spoofed a more-specific peer prefix")
	}
	if !snapshot.ValidateSource(2, netip.MustParseAddr("2001:db8:20::1")) {
		t.Fatal("winning IPv6 peer was rejected")
	}
}

func TestNewSnapshotRejectsDuplicateNormalizedPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		secondPeer PeerID
	}{
		{name: "same peer", secondPeer: 1},
		{name: "different peer", secondPeer: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := []AllowedIP{
				{Prefix: netip.MustParsePrefix("10.20.30.1/24"), PeerID: 1},
				{Prefix: netip.MustParsePrefix("10.20.30.0/24"), PeerID: test.secondPeer},
			}
			snapshot, err := NewSnapshot(entries)
			if snapshot != nil {
				t.Fatalf("NewSnapshot() snapshot = %v, want nil", snapshot)
			}
			if !errors.Is(err, ErrDuplicateAllowedIP) {
				t.Fatalf("NewSnapshot() error = %v, want ErrDuplicateAllowedIP", err)
			}

			var duplicate *DuplicateAllowedIPError
			if !errors.As(err, &duplicate) {
				t.Fatalf("NewSnapshot() error = %v, want DuplicateAllowedIPError", err)
			}
			if duplicate.Prefix != netip.MustParsePrefix("10.20.30.0/24") || duplicate.FirstIndex != 0 || duplicate.SecondIndex != 1 {
				t.Fatalf("duplicate detail = %+v", duplicate)
			}
		})
	}
}

func TestNewSnapshotRejectsInvalidPrefixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		prefix netip.Prefix
	}{
		{name: "zero", prefix: netip.Prefix{}},
		{name: "IPv4 bits out of range", prefix: netip.PrefixFrom(netip.MustParseAddr("192.0.2.0"), 33)},
		{name: "IPv6 bits out of range", prefix: netip.PrefixFrom(netip.MustParseAddr("2001:db8::"), 129)},
		{name: "IPv4-mapped IPv6", prefix: netip.MustParsePrefix("::ffff:192.0.2.0/120")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := NewSnapshot([]AllowedIP{{Prefix: test.prefix, PeerID: 1}})
			if snapshot != nil || !errors.Is(err, ErrInvalidAllowedIP) {
				t.Fatalf("NewSnapshot() = (%v, %v), want (nil, ErrInvalidAllowedIP)", snapshot, err)
			}
		})
	}
}

func TestSnapshotUnknownAndInvalidFailClosed(t *testing.T) {
	t.Parallel()
	snapshot := mustSnapshot(t, []AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 7}})
	tests := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::ffff:10.1.2.3"),
		netip.MustParseAddr("fe80::1%eth0"),
		{},
	}
	for _, address := range tests {
		if peer, ok := snapshot.LookupPeer(address); ok {
			t.Fatalf("LookupPeer(%s) = (%d, true), want unknown", address, peer)
		}
		if snapshot.ValidateSource(7, address) {
			t.Fatalf("ValidateSource(7, %s) = true, want false", address)
		}
	}
	if peer, ok := (*Snapshot)(nil).LookupPeer(netip.MustParseAddr("10.1.2.3")); ok {
		t.Fatalf("nil LookupPeer() = (%d, true), want unknown", peer)
	}
}

func TestSnapshotIsImmutableFromInput(t *testing.T) {
	t.Parallel()
	entries := []AllowedIP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 1}}
	snapshot := mustSnapshot(t, entries)
	entries[0] = AllowedIP{Prefix: netip.MustParsePrefix("192.0.2.0/24"), PeerID: 2}

	peer, ok := snapshot.LookupPeer(netip.MustParseAddr("10.1.2.3"))
	if !ok || peer != 1 {
		t.Fatalf("LookupPeer() after input mutation = (%d, %v), want (1, true)", peer, ok)
	}
}

func TestEmptySnapshotFailsClosed(t *testing.T) {
	t.Parallel()
	snapshot := mustSnapshot(t, nil)
	if snapshot.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", snapshot.Len())
	}
	if peer, ok := snapshot.LookupPeer(netip.MustParseAddr("10.0.0.1")); ok {
		t.Fatalf("LookupPeer() = (%d, true), want unknown", peer)
	}
}

func TestLookupPeerAllocations(t *testing.T) {
	snapshot := mustSnapshot(t, []AllowedIP{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), PeerID: 1},
		{Prefix: netip.MustParsePrefix("10.20.0.0/16"), PeerID: 2},
		{Prefix: netip.MustParsePrefix("::/0"), PeerID: 3},
		{Prefix: netip.MustParsePrefix("2001:db8:20::/48"), PeerID: 4},
	})
	v4 := netip.MustParseAddr("10.20.1.2")
	v6 := netip.MustParseAddr("2001:db8:20::1")

	allocs := testing.AllocsPerRun(1000, func() {
		if peer, ok := snapshot.LookupPeer(v4); !ok || peer != 2 {
			panic("unexpected IPv4 lookup")
		}
		if peer, ok := snapshot.LookupPeer(v6); !ok || peer != 4 {
			panic("unexpected IPv6 lookup")
		}
		if !snapshot.ValidateSource(2, v4) || !snapshot.ValidateSource(4, v6) {
			panic("unexpected source validation")
		}
	})
	if allocs != 0 {
		t.Fatalf("LookupPeer/ValidateSource allocations = %f, want 0", allocs)
	}
}

func mustSnapshot(t *testing.T, allowed []AllowedIP) *Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot(allowed)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return snapshot
}
