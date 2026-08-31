package controlconfig

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/protobuf/proto"
)

func controlConfigKey(value byte) config.Key {
	var key config.Key
	for i := range key {
		key[i] = value
	}
	return key
}

func encodedControlConfigKey(value byte) string {
	key := controlConfigKey(value)
	return base64.StdEncoding.EncodeToString(key[:])
}

func TestInterfaceSpecConfigRoundTrip(t *testing.T) {
	t.Parallel()

	privateKey := controlConfigKey(1)
	peerKey := controlConfigKey(2)
	psk := controlConfigKey(3)
	peer, err := config.NewPeerWithPresharedKeyBytes(
		base64.StdEncoding.EncodeToString(peerKey[:]),
		"198.51.100.2:51820",
		[]string{"10.0.0.1/24", "2001:db8::1/64"},
		25,
		psk[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	peer.MetricsID = "edge-a"
	want := config.Default()
	want.Interface.PrivateKey = privateKey
	want.Interface.ListenPort = 51820
	want.Interface.MTU = 9000
	want.Interface.MTUDiscovery = "auto"
	want.Interface.MinCarrierPayload = 1000
	want.Interface.MaxCarrierPayload = 2000
	want.Interface.ReassemblySlots = 512
	want.Interface.PeerReassemblySlots = config.AutoCount{Count: 64}
	want.Interface.ReassemblyLifetime = 1500 * time.Millisecond
	want.Interface.Reorder = false
	want.Interface.ReorderMaxDelay = 20 * time.Millisecond
	want.Interface.Workers = config.AutoCount{Count: 4}
	want.Interface.TUNQueues = config.AutoCount{Count: 2}
	want.Interface.SocketBuffer = 2 << 20
	want.Interface.FwMark = 1234
	want.Peers = []config.Peer{peer}

	spec := SpecFromConfig("wgf0", &want, true)
	got, err := Create(spec, &want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", *got, want)
	}
	if gotName := spec.GetInterfaceName(); gotName != "wgf0" {
		t.Fatalf("interface name = %q", gotName)
	}
	if spec.HasPrivateKey() || len(spec.GetPrivateKey()) != 0 {
		t.Fatalf("status spec exposed private key %x", spec.GetPrivateKey())
	}
	if action := spec.GetPeers()[0].GetPresharedKeyAction(); action != controlapiv1.PresharedKeyAction_SET {
		t.Fatalf("PSK action = %s", action)
	}
}

func TestInterfaceSpecConfigDefaultsAndAutoCounts(t *testing.T) {
	t.Parallel()

	spec := controlapiv1.InterfaceSpec_builder{}.Build()
	privateKey := controlConfigKey(1)
	spec.SetPrivateKey(privateKey[:])
	got, err := Create(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Default()
	want.Interface.PrivateKey = privateKey
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("defaults = %#v, want %#v", *got, want)
	}

	spec.SetPeerReassemblySlots(64)
	spec.SetWorkers(4)
	spec.SetTunQueues(2)
	got, err = Create(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Interface.PeerReassemblySlots != (config.AutoCount{Count: 64}) ||
		got.Interface.Workers != (config.AutoCount{Count: 4}) || got.Interface.TUNQueues != (config.AutoCount{Count: 2}) {
		t.Fatalf("explicit counts = %#v", got.Interface)
	}

	encoded := SpecFromConfig("wgf0", got, true)
	if encoded.GetPeerReassemblySlots() != 64 || encoded.GetWorkers() != 4 || encoded.GetTunQueues() != 2 {
		t.Fatalf("encoded counts = %d/%d/%d", encoded.GetPeerReassemblySlots(), encoded.GetWorkers(), encoded.GetTunQueues())
	}
	encoded = SpecFromConfig("wgf0", &want, true)
	if encoded.GetPeerReassemblySlots() != 0 || encoded.GetWorkers() != 0 || encoded.GetTunQueues() != 0 {
		t.Fatalf("encoded auto counts = %d/%d/%d", encoded.GetPeerReassemblySlots(), encoded.GetWorkers(), encoded.GetTunQueues())
	}
}

func TestInterfaceSpecConfigPreserve(t *testing.T) {
	t.Parallel()

	peerKey := controlConfigKey(2)
	psk := controlConfigKey(3)
	currentPeer, err := config.NewPeerWithPresharedKeyBytes(
		base64.StdEncoding.EncodeToString(peerKey[:]), "198.51.100.2:51820", nil, 0, psk[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	current := config.Default()
	current.Interface.PrivateKey = controlConfigKey(1)
	current.Peers = []config.Peer{currentPeer}
	spec := SpecFromConfig("wgf0", &current, false)
	if len(spec.GetPrivateKey()) != 0 || len(spec.GetPeers()[0].GetPresharedKey()) != 0 ||
		spec.GetPeers()[0].GetPresharedKeyAction() != controlapiv1.PresharedKeyAction_PRESERVE {
		t.Fatal("secret-free snapshot contains secret material")
	}

	createSpec := proto.Clone(spec).(*controlapiv1.InterfaceSpec)
	createSpec.SetPrivateKey(current.Interface.PrivateKey[:])
	if _, err := Create(createSpec, nil); !errors.Is(err, errPreserveWithoutCurrent) {
		t.Fatalf("without current error = %v, want %v", err, errPreserveWithoutCurrent)
	}
	got, err := Create(spec, &current)
	if err != nil {
		t.Fatal(err)
	}
	if got.Peers[0].PresharedKey == nil || *got.Peers[0].PresharedKey != psk {
		t.Fatalf("preserved PSK = %#v", got.Peers[0].PresharedKey)
	}
	if got.Peers[0].PresharedKey == current.Peers[0].PresharedKey {
		t.Fatal("PSK pointer was aliased")
	}
	if got.Interface.PrivateKey != current.Interface.PrivateKey {
		t.Fatal("omitted private key was not preserved")
	}
}

func TestCreateReplacesPrivateKey(t *testing.T) {
	t.Parallel()

	current := config.Default()
	current.Interface.PrivateKey = controlConfigKey(1)
	replacement := controlConfigKey(4)
	spec := controlapiv1.InterfaceSpec_builder{}.Build()
	spec.SetPrivateKey(replacement[:])

	got, err := Create(spec, &current)
	if err != nil {
		t.Fatal(err)
	}
	if got.Interface.PrivateKey != replacement {
		t.Fatalf("private key = %x, want %x", got.Interface.PrivateKey, replacement)
	}
	if got.Interface.PrivateKey == current.Interface.PrivateKey {
		t.Fatal("private key was preserved instead of replaced")
	}
}

func TestPeersFromSpecPSKActions(t *testing.T) {
	t.Parallel()

	publicKey := controlConfigKey(2)
	currentPSK := controlConfigKey(3)
	currentPeer, err := config.NewPeerWithPresharedKeyBytes(
		base64.StdEncoding.EncodeToString(publicKey[:]), "198.51.100.2:51820", nil, 0, currentPSK[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	current := config.Default()
	current.Peers = []config.Peer{currentPeer}
	setPSK := controlConfigKey(4)

	tests := []struct {
		name    string
		action  controlapiv1.PresharedKeyAction
		key     []byte
		wantPSK *config.Key
	}{
		{name: "preserve", action: controlapiv1.PresharedKeyAction_PRESERVE, wantPSK: &currentPSK},
		{name: "set", action: controlapiv1.PresharedKeyAction_SET, key: setPSK[:], wantPSK: &setPSK},
		{name: "clear", action: controlapiv1.PresharedKeyAction_CLEAR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			peer := controlapiv1.PeerSpec_builder{}.Build()
			peer.SetPublicKey(base64.StdEncoding.EncodeToString(publicKey[:]))
			peer.SetPresharedKeyAction(tt.action)
			if tt.key != nil {
				peer.SetPresharedKey(tt.key)
			}
			specs := []*controlapiv1.PeerSpec{peer}
			before := proto.Clone(peer)

			got, err := PeersFromSpec(specs, &current)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(peer, before) {
				t.Fatal("PeersFromSpec mutated the input peer spec")
			}
			if tt.wantPSK == nil {
				if got[0].PresharedKey != nil {
					t.Fatalf("PSK = %x, want nil", got[0].PresharedKey)
				}
				return
			}
			if got[0].PresharedKey == nil || *got[0].PresharedKey != *tt.wantPSK {
				t.Fatalf("PSK = %#v, want %x", got[0].PresharedKey, *tt.wantPSK)
			}
			if tt.action == controlapiv1.PresharedKeyAction_PRESERVE && got[0].PresharedKey == current.Peers[0].PresharedKey {
				t.Fatal("preserved PSK pointer was aliased")
			}
		})
	}
}

func TestConversionDoesNotMutateInputSpec(t *testing.T) {
	t.Parallel()

	privateKey := controlConfigKey(1)
	publicKey := controlConfigKey(2)
	psk := controlConfigKey(3)
	peer := controlapiv1.PeerSpec_builder{}.Build()
	peer.SetPublicKey(base64.StdEncoding.EncodeToString(publicKey[:]))
	peer.SetAllowedIps([]string{"10.0.0.1/24", "2001:db8::1/64"})
	peer.SetEndpoint("198.51.100.2:51820")
	peer.SetPersistentKeepaliveSec(25)
	peer.SetPresharedKey(psk[:])
	peer.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_SET)
	spec := controlapiv1.InterfaceSpec_builder{}.Build()
	spec.SetPrivateKey(privateKey[:])
	spec.SetMtu(9000)
	spec.SetPeers([]*controlapiv1.PeerSpec{peer})
	before := proto.Clone(spec)

	if _, err := Create(spec, nil); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(spec, before) {
		t.Fatal("Create mutated the input interface spec")
	}
}

func TestSpecFromConfigDoesNotMutateConfig(t *testing.T) {
	t.Parallel()

	publicKey := controlConfigKey(2)
	psk := controlConfigKey(3)
	peer, err := config.NewPeerWithPresharedKeyBytes(
		base64.StdEncoding.EncodeToString(publicKey[:]), "198.51.100.2:51820", []string{"10.0.0.1/24"}, 25, psk[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Default()
	want.Interface.PrivateKey = controlConfigKey(1)
	want.Interface.Addresses = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
	want.Peers = []config.Peer{peer}
	before := cloneConfigForControlConfigTest(want)

	_ = SpecFromConfig("wgf0", &want, true)
	if !reflect.DeepEqual(want, before) {
		t.Fatalf("SpecFromConfig mutated config:\n got: %#v\nwant: %#v", want, before)
	}
}

func TestCreateAcceptsSupportedBoundaryValues(t *testing.T) {
	t.Parallel()

	privateKey := controlConfigKey(1)
	tests := []struct {
		name   string
		modify func(*controlapiv1.InterfaceSpec)
	}{
		{name: "listen port maximum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetListenPort(65535)
		}},
		{name: "inner mtu minimum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetMtu(1280)
		}},
		{name: "inner mtu maximum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetMtu(9612)
			spec.SetMinCarrierPayload(614)
		}},
		{name: "socket buffer minimum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetSocketBuffer(uint32(config.MinSocketBuffer))
		}},
		{name: "socket buffer maximum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetSocketBuffer(uint32(config.MaxSocketBuffer))
		}},
		{name: "reassembly lifetime bounds", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetReassemblyLifetimeMs(100)
		}},
		{name: "explicit positive counts", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetReassemblySlots(1)
			spec.SetPeerReassemblySlots(1)
			spec.SetWorkers(1)
			spec.SetTunQueues(1)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec := controlapiv1.InterfaceSpec_builder{}.Build()
			spec.SetPrivateKey(privateKey[:])
			tt.modify(spec)
			if _, err := Create(spec, nil); err != nil {
				t.Fatalf("Create() = %v", err)
			}
		})
	}
}

func TestCreateRejectsValuesOutsideSupportedRanges(t *testing.T) {
	t.Parallel()

	privateKey := controlConfigKey(1)
	tests := []struct {
		name   string
		modify func(*controlapiv1.InterfaceSpec)
	}{
		{name: "inner mtu below minimum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetMtu(1279)
		}},
		{name: "inner mtu above maximum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetMtu(9613)
		}},
		{name: "carrier payload below protocol minimum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetMinCarrierPayload(612)
		}},
		{name: "carrier payload above protocol maximum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetMaxCarrierPayload(uint32(config.MaxCarrierPayload + 1))
		}},
		{name: "reassembly lifetime below minimum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetReassemblyLifetimeMs(99)
		}},
		{name: "reassembly lifetime above maximum", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetReassemblyLifetimeMs(60001)
		}},
		{name: "reorder delay must be positive", modify: func(spec *controlapiv1.InterfaceSpec) {
			spec.SetReorderMaxDelayMs(0)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spec := controlapiv1.InterfaceSpec_builder{}.Build()
			spec.SetPrivateKey(privateKey[:])
			tt.modify(spec)
			if _, err := Create(spec, nil); err == nil {
				t.Fatal("Create() succeeded")
			}
		})
	}
}

func cloneConfigForControlConfigTest(source config.Config) config.Config {
	clone := source
	clone.Interface.Addresses = append([]netip.Prefix(nil), source.Interface.Addresses...)
	clone.Peers = make([]config.Peer, len(source.Peers))
	for i, peer := range source.Peers {
		clone.Peers[i] = peer
		clone.Peers[i].AllowedIPs = append([]netip.Prefix(nil), peer.AllowedIPs...)
		if peer.PresharedKey != nil {
			key := *peer.PresharedKey
			clone.Peers[i].PresharedKey = &key
		}
	}
	return clone
}

func TestInterfaceSpecConfigRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validPublic := encodedControlConfigKey(2)
	tests := []struct {
		name   string
		modify func(*controlapiv1.InterfaceSpec)
	}{
		{name: "missing private key", modify: func(*controlapiv1.InterfaceSpec) {}},
		{name: "empty private key", modify: func(spec *controlapiv1.InterfaceSpec) { spec.SetPrivateKey([]byte{}) }},
		{name: "short private key", modify: func(spec *controlapiv1.InterfaceSpec) { spec.SetPrivateKey([]byte{1}) }},
		{name: "unsupported mtu discovery", modify: func(spec *controlapiv1.InterfaceSpec) { spec.SetMtuDiscovery("probe") }},
		{name: "port overflow", modify: func(spec *controlapiv1.InterfaceSpec) { spec.SetListenPort(65536) }},
		{name: "socket buffer too small", modify: func(spec *controlapiv1.InterfaceSpec) { spec.SetSocketBuffer(uint32(config.MinSocketBuffer - 1)) }},
		{name: "preserve without current", modify: func(spec *controlapiv1.InterfaceSpec) {
			peer := controlapiv1.PeerSpec_builder{}.Build()
			peer.SetPublicKey(validPublic)
			spec.SetPeers([]*controlapiv1.PeerSpec{peer})
		}},
		{name: "set key wrong size", modify: func(spec *controlapiv1.InterfaceSpec) {
			peer := controlapiv1.PeerSpec_builder{}.Build()
			peer.SetPublicKey(validPublic)
			peer.SetPresharedKey([]byte{1})
			peer.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_SET)
			spec.SetPeers([]*controlapiv1.PeerSpec{peer})
		}},
		{name: "clear with key", modify: func(spec *controlapiv1.InterfaceSpec) {
			peer := controlapiv1.PeerSpec_builder{}.Build()
			peer.SetPublicKey(validPublic)
			peer.SetPresharedKey([]byte{1})
			peer.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
			spec.SetPeers([]*controlapiv1.PeerSpec{peer})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := controlapiv1.InterfaceSpec_builder{}.Build()
			if tt.name != "missing private key" {
				privateKey := controlConfigKey(1)
				spec.SetPrivateKey(privateKey[:])
			}
			tt.modify(spec)
			if _, err := Create(spec, nil); err == nil {
				t.Fatal("Create succeeded")
			}
		})
	}
}

func TestInterfaceSpecConfigCanonicalizesAllowedIPs(t *testing.T) {
	t.Parallel()

	public := encodedControlConfigKey(2)
	spec := controlapiv1.InterfaceSpec_builder{}.Build()
	privateKey := controlConfigKey(1)
	spec.SetPrivateKey(privateKey[:])
	peer := controlapiv1.PeerSpec_builder{}.Build()
	peer.SetPublicKey(public)
	peer.SetAllowedIps([]string{"10.0.0.1/24"})
	peer.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
	spec.SetPeers([]*controlapiv1.PeerSpec{peer})
	got, err := Create(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Peers[0].AllowedIPs[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Fatalf("allowed IP = %s", got.Peers[0].AllowedIPs[0])
	}
}
