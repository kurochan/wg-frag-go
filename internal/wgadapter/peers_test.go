package wgadapter

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

func peerID(value int) peerroute.PeerID { return peerroute.PeerID(value) }

func TestPreparePeersHidesUserAllowedIPsFromWireGuard(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Interface: config.Interface{PrivateKey: key(1), ListenPort: 51820},
		Peers: []config.Peer{{
			PublicKey:           key(2),
			Endpoint:            "127.0.0.1:51821",
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("2001:db8:20::/64")},
			PersistentKeepalive: 25,
		}},
	}
	plan, err := PreparePeers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	peer := plan.Peers[0]
	if !plan.LocalCarrier.IsLinkLocalUnicast() || !peer.Carrier.IsLinkLocalUnicast() || plan.LocalCarrier == peer.Carrier {
		t.Fatalf("carrier addresses = %s, %s", plan.LocalCarrier, peer.Carrier)
	}
	if id, ok := plan.Routes.LookupPeer(netip.MustParseAddr("10.20.1.1")); !ok || id != 0 {
		t.Fatalf("user route lookup = (%d, %t)", id, ok)
	}
	if !strings.Contains(plan.UAPI, "allowed_ip="+peer.Carrier.String()+"/128\n") {
		t.Fatalf("UAPI misses hidden carrier /128:\n%s", plan.UAPI)
	}
	for _, forbidden := range []string{"10.20.0.0/16", "2001:db8:20::/64"} {
		if strings.Contains(plan.UAPI, forbidden) {
			t.Fatalf("UAPI exposes user AllowedIPs %q:\n%s", forbidden, plan.UAPI)
		}
	}
	if !strings.Contains(plan.UAPI, "replace_peers=true\n") || !strings.Contains(plan.UAPI, "endpoint=127.0.0.1:51821\n") || !strings.HasSuffix(plan.UAPI, "\n\n") {
		t.Fatalf("unexpected UAPI:\n%s", plan.UAPI)
	}
}

func TestPreparePeersWritesPresharedKeyToWireGuard(t *testing.T) {
	t.Parallel()
	psk := key(9)
	cfg := &config.Config{
		Interface: config.Interface{PrivateKey: key(1)},
		Peers:     []config.Peer{{PublicKey: key(2), PresharedKey: &psk}},
	}
	plan, err := PreparePeers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.UAPI, "preshared_key="+hex.EncodeToString(psk[:])+"\n") {
		t.Fatalf("UAPI misses preshared key:\n%s", plan.UAPI)
	}

	psk[0] ^= 0xff
	updateCfg := &config.Config{
		Interface: cfg.Interface,
		Peers:     []config.Peer{{PublicKey: key(2), PresharedKey: &psk}},
	}
	update, err := PreparePeerUpdate(updateCfg, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(update.UAPI, "preshared_key="+hex.EncodeToString(psk[:])+"\n") {
		t.Fatalf("update UAPI misses changed preshared key:\n%s", update.UAPI)
	}
	addedPSK := key(10)
	addedPublic := key(3)
	addedCfg := &config.Config{
		Interface: cfg.Interface,
		Peers: []config.Peer{
			{PublicKey: key(2), PresharedKey: &psk},
			{PublicKey: addedPublic, PresharedKey: &addedPSK},
		},
	}
	added, err := PreparePeerUpdate(addedCfg, update.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(added.UAPI, "public_key="+hex.EncodeToString(addedPublic[:])+"\n") ||
		!strings.Contains(added.UAPI, "preshared_key="+hex.EncodeToString(addedPSK[:])+"\n") {
		t.Fatalf("added peer UAPI misses preshared key:\n%s", added.UAPI)
	}
}

func TestPreparePeersAssignsDistinctCarriersAndRoutes(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Interface: config.Interface{PrivateKey: key(1), ListenPort: 51820},
		Peers: []config.Peer{
			{PublicKey: key(2), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}},
			{PublicKey: key(3), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16"), netip.MustParsePrefix("10.3.0.0/16")}},
			{PublicKey: key(4), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		},
	}
	plan, err := PreparePeers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Peers) != 3 {
		t.Fatalf("peers = %d, want 3", len(plan.Peers))
	}
	seen := map[netip.Addr]bool{plan.LocalCarrier: true}
	for i, peer := range plan.Peers {
		if peer.ID != peerID(i) {
			t.Fatalf("peer %d has ID %d", i, peer.ID)
		}
		if seen[peer.Carrier] {
			t.Fatalf("carrier %s is not unique", peer.Carrier)
		}
		seen[peer.Carrier] = true
		if !strings.Contains(plan.UAPI, "allowed_ip="+peer.Carrier.String()+"/128\n") {
			t.Fatalf("UAPI misses carrier for peer %d", i)
		}
	}
	// The default route must lose to a more specific prefix owned by another
	// peer, since egress selection is a global longest-prefix match.
	for address, want := range map[string]int{
		"10.1.0.5":  0,
		"10.2.0.5":  1,
		"10.3.0.5":  1,
		"192.0.2.1": 2,
	} {
		id, ok := plan.Routes.LookupPeer(netip.MustParseAddr(address))
		if !ok || int(id) != want {
			t.Fatalf("LookupPeer(%s) = (%d, %t), want %d", address, id, ok, want)
		}
	}
}

func TestPreparePeersRejectsEmptyAndDuplicateKeys(t *testing.T) {
	t.Parallel()
	for _, cfg := range []*config.Config{nil, {}} {
		if _, err := PreparePeers(cfg); !errors.Is(err, ErrNoPeers) {
			t.Fatalf("PreparePeers(%#v) error = %v, want ErrNoPeers", cfg, err)
		}
	}
	duplicate := &config.Config{
		Interface: config.Interface{PrivateKey: key(1)},
		Peers: []config.Peer{
			{PublicKey: key(2), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}},
			{PublicKey: key(2), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}},
		},
	}
	if _, err := PreparePeers(duplicate); !errors.Is(err, ErrDuplicatePeer) {
		t.Fatalf("duplicate key error = %v, want ErrDuplicatePeer", err)
	}
}

func TestPreparePeersRejectsUnsafeDirectConfig(t *testing.T) {
	t.Parallel()
	base := &config.Config{Interface: config.Interface{PrivateKey: key(1)}}
	base.Peers = []config.Peer{{PublicKey: key(2), Endpoint: "127.0.0.1:51820\nremove=true"}}
	if _, err := PreparePeers(base); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("control-byte endpoint error = %v, want ErrInvalidPeer", err)
	}
	base.Peers[0].Endpoint = ""
	base.Peers[0].PublicKey = config.Key{}
	if _, err := PreparePeers(base); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("zero public key error = %v, want ErrInvalidPeer", err)
	}
}

func TestPreparePeersCopiesAllowedIPs(t *testing.T) {
	t.Parallel()
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	cfg := &config.Config{
		Interface: config.Interface{PrivateKey: key(1)},
		Peers:     []config.Peer{{PublicKey: key(2), AllowedIPs: prefixes}},
	}
	plan, err := PreparePeers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	prefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	if got := plan.Peers[0].AllowedIPs[0]; got != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("plan AllowedIPs aliased input: got %s", got)
	}
}

func key(value byte) (result config.Key) {
	for i := range result {
		result[i] = value
	}
	return result
}

func configWithPeers(t *testing.T, count int) *config.Config {
	t.Helper()
	cfg := &config.Config{Interface: config.Interface{PrivateKey: key(1), ListenPort: 51820}}
	for i := 0; i < count; i++ {
		prefix := netip.MustParsePrefix(netip.AddrFrom4([4]byte{10, byte(i + 1), 0, 0}).String() + "/16")
		cfg.Peers = append(cfg.Peers, config.Peer{
			PublicKey:  key(byte(i + 2)),
			AllowedIPs: []netip.Prefix{prefix},
		})
	}
	return cfg
}

func TestPreparePeerUpdateKeepsSurvivorIDsAndReusesFreedSlots(t *testing.T) {
	t.Parallel()
	base := configWithPeers(t, 3)
	previous, err := PreparePeers(base)
	if err != nil {
		t.Fatal(err)
	}

	// Remove the middle peer and add a new one: the newcomer must take the
	// freed slot while both survivors keep their IDs.
	next := configWithPeers(t, 4)
	next.Peers = []config.Peer{base.Peers[0], base.Peers[2], next.Peers[3]}
	update, err := PreparePeerUpdate(next, previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(update.Survivors) != 2 || len(update.Added) != 1 || len(update.Removed) != 1 {
		t.Fatalf("diff = %d survivors, %d added, %d removed", len(update.Survivors), len(update.Added), len(update.Removed))
	}
	ids := map[[32]byte]peerroute.PeerID{}
	for _, peer := range update.Plan.Peers {
		ids[peer.PublicKey] = peer.ID
	}
	if ids[base.Peers[0].PublicKey] != 0 || ids[base.Peers[2].PublicKey] != 2 {
		t.Fatalf("survivor IDs moved: %v", ids)
	}
	if ids[next.Peers[2].PublicKey] != 1 {
		t.Fatalf("new peer ID = %d, want the freed slot 1", ids[next.Peers[2].PublicKey])
	}
	if update.Removed[0].PublicKey != base.Peers[1].PublicKey {
		t.Fatal("wrong peer removed")
	}

	// Routes must resolve with the stable IDs.
	for _, peer := range update.Plan.Peers {
		id, ok := update.Plan.Routes.LookupPeer(peer.AllowedIPs[0].Addr())
		if !ok || id != peer.ID {
			t.Fatalf("route for %s resolved to %d, want %d", peer.AllowedIPs[0], id, peer.ID)
		}
	}

	uapi := update.UAPI
	if !strings.Contains(uapi, "remove=true") {
		t.Fatal("UAPI does not remove the dropped peer")
	}
	if strings.Contains(uapi, "replace_peers") {
		t.Fatal("incremental UAPI must not replace all peers")
	}
}

func TestPreparePeerUpdateRejectsLocalKeyChange(t *testing.T) {
	t.Parallel()
	base := configWithPeers(t, 1)
	previous, err := PreparePeers(base)
	if err != nil {
		t.Fatal(err)
	}
	changed := configWithPeers(t, 1)
	changed.Interface.PrivateKey[5] ^= 0xff
	if _, err := PreparePeerUpdate(changed, previous); err == nil {
		t.Fatal("local key change must be rejected")
	}
}

func TestPreparePeerUpdateRecreatesPeerWhenEndpointIsCleared(t *testing.T) {
	t.Parallel()
	base := configWithPeers(t, 1)
	base.Peers[0].Endpoint = "127.0.0.1:51820"
	previous, err := PreparePeers(base)
	if err != nil {
		t.Fatal(err)
	}
	next := configWithPeers(t, 1)
	update, err := PreparePeerUpdate(next, previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(update.Survivors) != 0 || len(update.Added) != 1 || len(update.Removed) != 1 {
		t.Fatalf("diff = %d survivors, %d added, %d removed", len(update.Survivors), len(update.Added), len(update.Removed))
	}
	if update.Added[0].ID != update.Removed[0].ID {
		t.Fatalf("replacement IDs = %d/%d, want stable slot", update.Added[0].ID, update.Removed[0].ID)
	}
	if !strings.Contains(update.UAPI, "remove=true") {
		t.Fatalf("UAPI does not remove endpoint-bearing peer:\n%s", update.UAPI)
	}
}

func TestPreparePeerUpdateWritesOnlyWireguardChangedSurvivors(t *testing.T) {
	t.Parallel()
	base := configWithPeers(t, 2)
	previous, err := PreparePeers(base)
	if err != nil {
		t.Fatal(err)
	}
	next := configWithPeers(t, 2)
	next.Peers[1].Endpoint = "127.0.0.1:51820"
	update, err := PreparePeerUpdate(next, previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(update.Survivors) != 2 || len(update.Changed) != 1 || update.Changed[0].PublicKey != next.Peers[1].PublicKey {
		t.Fatalf("survivors/changed = %d/%d", len(update.Survivors), len(update.Changed))
	}
	if strings.Contains(update.UAPI, hex.EncodeToString(next.Peers[0].PublicKey[:])) {
		t.Fatal("unchanged survivor was unnecessarily written to UAPI")
	}
	if !strings.Contains(update.UAPI, "endpoint=127.0.0.1:51820\n") {
		t.Fatalf("changed survivor endpoint missing from UAPI:\n%s", update.UAPI)
	}
	if strings.Contains(update.UAPI, "replace_allowed_ips=true\n") || strings.Contains(update.UAPI, "allowed_ip=") {
		t.Fatalf("changed survivor unnecessarily rewrote carrier routes:\n%s", update.UAPI)
	}
}
