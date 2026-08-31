package daemonruntime

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/controlbridge"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
)

func TestClassifyRuntimeFault(t *testing.T) {
	t.Parallel()
	if got := classifyRuntimeFault(errors.New("carrier queue full")); got != runtimePeerFault {
		t.Fatalf("ordinary bridge error scope = %d, want peer", got)
	}
	for _, err := range []error{shimtun.ErrClosed, shimtun.ErrShortBuffer, shimtun.ErrShortNativeWrite, shimtun.ErrControlSink, shimtun.ErrInvalidConfig} {
		if got := classifyRuntimeFault(err); got != runtimeInterfaceFault {
			t.Fatalf("classifyRuntimeFault(%v) = %d, want interface", err, got)
		}
	}
	if got := classifyRuntimeFault(shimtun.ErrPeerNotFound); got != runtimePeerFault {
		t.Fatalf("classifyRuntimeFault(ErrPeerNotFound) = %d, want peer", got)
	}
	if got := classifyRuntimeFault(controlbridge.ErrStateInvalid); got != runtimeInterfaceFault {
		t.Fatalf("classifyRuntimeFault(ErrStateInvalid) = %d, want interface", got)
	}
}

func TestReassemblySlots(t *testing.T) {
	t.Parallel()
	iface := config.Interface{
		ReassemblySlots:     4096,
		PeerReassemblySlots: config.AutoCount{Count: 64},
	}
	if got := reassemblySlots(iface); got != 64 {
		t.Fatalf("reassemblySlots() = %d, want 64", got)
	}
	iface.PeerReassemblySlots = config.AutoCount{Auto: true}
	if got := reassemblySlots(iface); got != 4096 {
		t.Fatalf("reassemblySlots(auto) = %d, want 4096", got)
	}
}

func TestPeerIDsForEndpointUsesObservedWireGuardEndpoint(t *testing.T) {
	t.Parallel()
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	plan := wgadapter.Plan{Peers: []wgadapter.PeerPlan{
		{ID: 1, PublicKey: [32]byte{1}, Endpoint: "peer.example:51820"},
		{ID: 2, Endpoint: "peer.example:51820"},
		{ID: 3, Endpoint: "192.0.2.11:51820"},
	}}
	uapi := "public_key=" + hex.EncodeToString(plan.Peers[0].PublicKey[:]) + "\nendpoint=" + endpoint.String() + "\n\n"
	if got := peerIDsForEndpoint(plan, uapi, endpoint); len(got) != 1 || got[0] != peerroute.PeerID(1) {
		t.Fatalf("peerIDsForEndpoint() = %v, want [1]", got)
	}
}

func TestPeerIDsForEndpointRejectsAmbiguousObservedEndpoint(t *testing.T) {
	t.Parallel()
	endpoint := netip.MustParseAddrPort("192.0.2.10:51820")
	plan := wgadapter.Plan{Peers: []wgadapter.PeerPlan{
		{ID: 1, PublicKey: [32]byte{1}},
		{ID: 2, PublicKey: [32]byte{2}},
	}}
	uapi := "public_key=" + hex.EncodeToString(plan.Peers[0].PublicKey[:]) + "\nendpoint=" + endpoint.String() +
		"\n\npublic_key=" + hex.EncodeToString(plan.Peers[1].PublicKey[:]) + "\nendpoint=" + endpoint.String() + "\n\n"
	if got := peerIDsForEndpoint(plan, uapi, endpoint); len(got) != 0 {
		t.Fatalf("peerIDsForEndpoint() = %v, want no attribution", got)
	}
}
