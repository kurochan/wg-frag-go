package config

import (
	"net/netip"
	"testing"
)

func TestCloneIsIndependent(t *testing.T) {
	t.Parallel()
	key := Key{1}
	source := Default()
	source.Interface.Addresses = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	source.Interface.MetricsListen.Addresses = []string{"127.0.0.1:9910"}
	source.Interface.MetricsInclude = []string{"wgf_*"}
	source.Interface.MetricsExclude = []string{"wgf_peer_*"}
	source.Peers = []Peer{{
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")},
		PresharedKey: &key,
	}}

	cloned := Clone(&source)
	cloned.Interface.Addresses[0] = netip.MustParsePrefix("192.0.2.1/24")
	cloned.Interface.MetricsListen.Addresses[0] = "[::1]:9910"
	cloned.Interface.MetricsInclude[0] = "wgf_tx_*"
	cloned.Interface.MetricsExclude[0] = "wgf_rx_*"
	cloned.Peers[0].AllowedIPs[0] = netip.MustParsePrefix("10.2.0.0/24")
	cloned.Peers[0].PresharedKey[0] = 2

	if source.Interface.Addresses[0] != netip.MustParsePrefix("10.0.0.1/24") ||
		source.Interface.MetricsListen.Addresses[0] != "127.0.0.1:9910" ||
		source.Interface.MetricsInclude[0] != "wgf_*" ||
		source.Interface.MetricsExclude[0] != "wgf_peer_*" ||
		source.Peers[0].AllowedIPs[0] != netip.MustParsePrefix("10.1.0.0/24") ||
		source.Peers[0].PresharedKey[0] != 1 {
		t.Fatal("Clone shares mutable configuration storage with its source")
	}
}

func TestCloneNil(t *testing.T) {
	t.Parallel()
	if Clone(nil) != nil {
		t.Fatal("Clone(nil) returned a non-nil configuration")
	}
}
