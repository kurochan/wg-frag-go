package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

func encodedKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytesOf(value, 32))
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func TestParseDefaults(t *testing.T) {
	t.Parallel()
	input := "[Interface]\nPrivateKey = " + encodedKey(1) + "\n"
	config, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	iface := config.Interface
	if iface.MTU != limits.DefaultInnerMTU || iface.MTUDiscovery != "auto" ||
		iface.MinCarrierPayload != limits.DefaultCarrierPayload || iface.MaxCarrierPayload != DefaultMaxCarrierPayload ||
		iface.ReassemblySlots != DefaultReassemblySlots || !iface.PeerReassemblySlots.Auto ||
		iface.ReassemblyLifetime != 2*time.Second || !iface.Reorder || iface.ReorderMaxDelay != 10*time.Millisecond ||
		!iface.Workers.Auto || !iface.TUNQueues.Auto || iface.SocketBuffer != DefaultSocketBuffer || iface.Metrics || !iface.MetricsListen.Auto {
		t.Fatalf("defaults = %+v", iface)
	}
	if len(iface.Addresses) != 0 || len(config.Peers) != 0 {
		t.Fatalf("unexpected addresses or peers: %+v", config)
	}
}

func TestParseAllFieldsAndRepeatedLists(t *testing.T) {
	t.Parallel()
	input := `
        # leading comment
        [Interface] ; interface comment
        Address = 10.0.0.1/24, 2001:db8::1/64
        Address = 192.0.2.1/32
        PrivateKey = ` + encodedKey(1) + ` # secret
        ListenPort = 51820
        MTU = 9000
        WGFMTUDiscovery = auto
        WGFMinCarrierPayload = 613
        WGFMaxCarrierPayload = 1400
        WGFReassemblySlots = 512
        WGFPeerReassemblySlots = 64
        WGFReassemblyLifetime = 1500ms
        WGFReorder = false
        WGFReorderMaxDelay = 20ms
        WGFWorkers = 4
		WGFTUNQueues = 2
		WGFSocketBuffer = 2097152
        WGFMetrics = on
        WGFMetricsListen = 127.0.0.1:9910,[::1]:9910
        WGFMetricsInclude = wgf_tx_*,wgf_peer_pmtu_*
        WGFMetricsExclude = wgf_*_drops_total

        [Peer]
        PublicKey = ` + encodedKey(2) + `
        PresharedKey = ` + encodedKey(4) + `
        Endpoint = example.net:51820
        AllowedIPs = 10.1.0.1/24, ::/0
        AllowedIPs = 192.0.2.9/32
        PersistentKeepalive = 25
        WGFPeerID = edge-a

        [Peer]
        PublicKey = ` + encodedKey(3) + `
        Endpoint = [2001:db8::2]:12345
        PersistentKeepalive = off
    `
	config, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	iface := config.Interface
	if len(iface.Addresses) != 3 || iface.ListenPort != 51820 || iface.MTU != 9000 ||
		iface.MinCarrierPayload != 613 || iface.MaxCarrierPayload != 1400 || iface.ReassemblySlots != 512 ||
		iface.PeerReassemblySlots != (AutoCount{Count: 64}) || iface.ReassemblyLifetime != 1500*time.Millisecond ||
		iface.Reorder || iface.ReorderMaxDelay != 20*time.Millisecond || iface.Workers != (AutoCount{Count: 4}) ||
		iface.TUNQueues != (AutoCount{Count: 2}) || iface.SocketBuffer != 2<<20 || !iface.Metrics || iface.MetricsListen.Auto ||
		len(iface.MetricsListen.Addresses) != 2 || len(iface.MetricsInclude) != 2 || len(iface.MetricsExclude) != 1 {
		t.Fatalf("interface = %+v", iface)
	}
	if len(config.Peers) != 2 || len(config.Peers[0].AllowedIPs) != 3 || config.Peers[0].PersistentKeepalive != 25 || config.Peers[1].PersistentKeepalive != 0 || config.Peers[0].PresharedKey == nil || *config.Peers[0].PresharedKey != keyValue(4) || config.Peers[0].MetricsID != "edge-a" {
		t.Fatalf("peers = %+v", config.Peers)
	}
	if got := config.Peers[0].AllowedIPs[0]; got != netip.MustParsePrefix("10.1.0.0/24") {
		t.Fatalf("masked AllowedIP = %s", got)
	}
}

func keyValue(value byte) (key Key) {
	for i := range key {
		key[i] = value
	}
	return key
}

func TestParseRejectsInvalidConfigurations(t *testing.T) {
	t.Parallel()
	privateKey := encodedKey(1)
	publicKey := encodedKey(2)
	tests := []struct {
		name  string
		input string
	}{
		{name: "unknown section", input: "[Other]\nX = y\n"},
		{name: "unknown field", input: "[Interface]\nPrivateKey = " + privateKey + "\nUnknown = 1\n"},
		{name: "duplicate singleton", input: "[Interface]\nPrivateKey = " + privateKey + "\nMTU = 1500\nMTU = 1500\n"},
		{name: "invalid key", input: "[Interface]\nPrivateKey = bad\n"},
		{name: "zero key", input: "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"},
		{name: "MTU too small", input: "[Interface]\nPrivateKey = " + privateKey + "\nMTU = 1279\n"},
		{name: "min carrier too small", input: "[Interface]\nPrivateKey = " + privateKey + "\nMTU = 9612\nWGFMinCarrierPayload = 612\n"},
		{name: "max below min", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFMinCarrierPayload = 700\nWGFMaxCarrierPayload = 699\n"},
		{name: "max above IPv6 ceiling", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFMaxCarrierPayload = 65449\n"},
		{name: "lifetime too short", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFReassemblyLifetime = 99ms\n"},
		{name: "bad bool", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFReorder = 1\n"},
		{name: "bad metrics switch", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFMetrics = true\n"},
		{name: "metrics hostname", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFMetricsListen = localhost:9910\n"},
		{name: "metrics unmatched selection", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFMetricsInclude = unknown\n"},
		{name: "metrics two wildcards", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFMetricsInclude = wgf_*_*\n"},
		{name: "bad auto count", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFWorkers = 0\n"},
		{name: "auto count overflow", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFWorkers = 18446744073709551615\n"},
		{name: "socket buffer too small", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFSocketBuffer = 65535\n"},
		{name: "socket buffer too large", input: "[Interface]\nPrivateKey = " + privateKey + "\nWGFSocketBuffer = 268435457\n"},
		{name: "bad CIDR", input: "[Interface]\nPrivateKey = " + privateKey + "\nAddress = 10.0.0.1\n"},
		{name: "mapped address", input: "[Interface]\nPrivateKey = " + privateKey + "\nAddress = ::ffff:192.0.2.1/128\n"},
		{name: "mapped allowed IP", input: "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + publicKey + "\nAllowedIPs = ::ffff:192.0.2.1/128\n"},
		{name: "mapped endpoint", input: "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + publicKey + "\nEndpoint = [::ffff:192.0.2.1]:51820\n"},
		{name: "invalid endpoint", input: "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + publicKey + "\nEndpoint = example.net\n"},
		{name: "invalid endpoint hostname", input: "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + publicKey + "\nEndpoint = bad_host:51820\n"},
		{name: "duplicate peer key", input: "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + publicKey + "\n[Peer]\nPublicKey = " + publicKey + "\n"},
		{name: "duplicate metrics peer ID", input: "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\nPublicKey = " + publicKey + "\nWGFPeerID = edge\n[Peer]\nPublicKey = " + encodedKey(3) + "\nWGFPeerID = edge\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tt.input)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Parse() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestMetricsPeerID(t *testing.T) {
	t.Parallel()
	peer := Peer{PublicKey: keyValue(2)}
	first := MetricsPeerID(peer)
	if first != MetricsPeerID(peer) || len(first) != 16 {
		t.Fatalf("MetricsPeerID = %q", first)
	}
	for _, char := range first {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			t.Fatalf("MetricsPeerID contains %q", char)
		}
	}
	peer.MetricsID = "edge-a"
	if got := MetricsPeerID(peer); got != "edge-a" {
		t.Fatalf("MetricsPeerID explicit = %q", got)
	}
}

func TestMetricsInterfaceIDUsesSeparateStableDomain(t *testing.T) {
	t.Parallel()
	key := keyValue(2)
	first := MetricsInterfaceID(key)
	if first != MetricsInterfaceID(key) || len(first) != 16 {
		t.Fatalf("MetricsInterfaceID = %q", first)
	}
	for _, char := range first {
		if (char < 'a' || char > 'z') && (char < '2' || char > '7') {
			t.Fatalf("MetricsInterfaceID contains %q", char)
		}
	}
	if first == MetricsPeerID(Peer{PublicKey: key}) {
		t.Fatal("interface and peer IDs share a domain")
	}
}

func TestParseEmptyMetricSelection(t *testing.T) {
	t.Parallel()
	input := "[Interface]\nPrivateKey = " + encodedKey(1) + "\nWGFMetricsInclude =\nWGFMetricsExclude =\n"
	parsed, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Interface.MetricsInclude) != 0 || len(parsed.Interface.MetricsExclude) != 0 {
		t.Fatalf("metric selections = %#v, %#v", parsed.Interface.MetricsInclude, parsed.Interface.MetricsExclude)
	}
}

func TestParseRejectsExplicitMetricsIDCollidingWithDerivedID(t *testing.T) {
	t.Parallel()
	derivedPeer := Peer{PublicKey: keyValue(3)}
	input := "[Interface]\nPrivateKey = " + encodedKey(1) + "\n[Peer]\nPublicKey = " + encodedKey(2) +
		"\nWGFPeerID = " + MetricsPeerID(derivedPeer) + "\n[Peer]\nPublicKey = " + encodedKey(3) + "\n"
	if _, err := Parse(strings.NewReader(input)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Parse() error = %v, want ErrInvalidConfig", err)
	}
}

func TestValidatePeersRejectsRuntimeMetricsIDCollision(t *testing.T) {
	t.Parallel()
	peers := []Peer{{PublicKey: keyValue(2), MetricsID: "edge"}, {PublicKey: keyValue(3), MetricsID: "edge"}}
	if err := ValidatePeers(peers); err == nil {
		t.Fatal("duplicate runtime WGFPeerID succeeded")
	}
	peers[1].MetricsID = "INVALID"
	if err := ValidatePeers(peers); err == nil {
		t.Fatal("invalid runtime WGFPeerID succeeded")
	}
}

func TestParseAllowsIPv6CarrierCeiling(t *testing.T) {
	t.Parallel()
	input := "[Interface]\nPrivateKey = " + encodedKey(1) + "\nWGFMaxCarrierPayload = 65448\n"
	config, err := Parse(strings.NewReader(input))
	if err != nil || config.Interface.MaxCarrierPayload != MaxCarrierPayload {
		t.Fatalf("Parse() = (%+v, %v)", config, err)
	}
}

func TestParseRequiredFields(t *testing.T) {
	t.Parallel()
	tests := []string{
		"",
		"[Interface]\n",
		"[Peer]\nPublicKey = " + encodedKey(2) + "\n",
		"[Interface]\nPrivateKey = " + encodedKey(1) + "\n[Peer]\nAllowedIPs = 10.0.0.0/8\n",
	}
	for _, input := range tests {
		if _, err := Parse(strings.NewReader(input)); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Parse(%q) error = %v, want ErrInvalidConfig", input, err)
		}
	}
}

func TestParseCommentAfterUnicodeWhitespace(t *testing.T) {
	t.Parallel()
	input := "[Interface]\nPrivateKey = " + encodedKey(1) + "\u3000# comment\n"
	if _, err := Parse(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("[Interface]\nPrivateKey = " + encodedKey(1) + "\n"))
	f.Add([]byte("[Interface]\nPrivateKey = " + encodedKey(1) + "\n[Peer]\nPublicKey = " + encodedKey(2) + "\nAllowedIPs = 10.0.0.0/24\n"))
	f.Add(bytes.Repeat([]byte("["), 1024))

	f.Fuzz(func(t *testing.T, input []byte) {
		config, err := Parse(bytes.NewReader(input))
		if err != nil {
			return
		}
		if config == nil {
			t.Fatal("successful Parse returned nil config")
		}
		if config.Interface.MTU < limits.MinInnerMTU || config.Interface.MTU > limits.MaxInnerMTU {
			t.Fatalf("successful Parse returned invalid MTU %d", config.Interface.MTU)
		}
		if config.Interface.MinCarrierPayload > config.Interface.MaxCarrierPayload {
			t.Fatalf("successful Parse returned invalid carrier range %d..%d", config.Interface.MinCarrierPayload, config.Interface.MaxCarrierPayload)
		}
	})
}
