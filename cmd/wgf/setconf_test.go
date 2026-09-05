package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

func TestUDPBatchSizeChangeRequiresRestart(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	status := &controlapiv1.InterfaceStatus{}
	status.SetSpec(controlconfig.SpecFromConfig("wgf0", &cfg, false))
	if !restartSettingsEqual("wgf0", status, &cfg) {
		t.Fatal("unchanged UDP batch size requires restart")
	}
	cfg.Interface.UDPBatchSize = config.MinUDPBatchSize
	if restartSettingsEqual("wgf0", status, &cfg) {
		t.Fatal("changed UDP batch size did not require restart")
	}
}

func TestDesiredFromConfigPreservesExplicitEmptyAndZeroFields(t *testing.T) {
	t.Parallel()
	desired := desiredFromConfig([]config.Peer{{}}, true)
	if len(desired) != 1 {
		t.Fatalf("desired peers = %d, want 1", len(desired))
	}
	if !desired[0].HasEndpoint() || desired[0].GetEndpoint() != "" {
		t.Fatalf("empty endpoint presence = %t, value %q", desired[0].HasEndpoint(), desired[0].GetEndpoint())
	}
	if !desired[0].HasPersistentKeepaliveSec() || desired[0].GetPersistentKeepaliveSec() != 0 {
		t.Fatalf("zero keepalive presence = %t, value %d", desired[0].HasPersistentKeepaliveSec(), desired[0].GetPersistentKeepaliveSec())
	}
	if desired[0].GetPresharedKeyAction() != controlapiv1.PresharedKeyAction_CLEAR {
		t.Fatalf("setconf missing PSK action = %s, want CLEAR", desired[0].GetPresharedKeyAction())
	}
	preserved := desiredFromConfig([]config.Peer{{}}, false)
	if preserved[0].GetPresharedKeyAction() != controlapiv1.PresharedKeyAction_PRESERVE {
		t.Fatalf("addconf missing PSK action = %s, want PRESERVE", preserved[0].GetPresharedKeyAction())
	}
}

func TestDesiredPeerMetricsIDRoundTrips(t *testing.T) {
	t.Parallel()
	configured := desiredFromConfig([]config.Peer{{MetricsID: "edge-a"}}, true)
	if got := configured[0].GetMetricsId(); got != "edge-a" {
		t.Fatalf("configured metrics ID = %q", got)
	}
	status := controlapiv1.PeerStatus_builder{}.Build()
	status.SetMetricsId("edge-b")
	running := desiredFromStatus([]*controlapiv1.PeerStatus{status})
	if got := running[0].GetMetricsId(); got != "edge-b" {
		t.Fatalf("running metrics ID = %q", got)
	}
}

func TestMergePeersPreservesExistingMetricsID(t *testing.T) {
	t.Parallel()
	base := controlapiv1.PeerSpec_builder{}.Build()
	base.SetPublicKey("AAA=")
	base.SetMetricsId("edge-a")
	addition := controlapiv1.PeerSpec_builder{}.Build()
	addition.SetPublicKey("AAA=")
	addition.SetEndpoint("192.0.2.1:51820")

	merged := mergePeers([]*controlapiv1.PeerSpec{base}, []*controlapiv1.PeerSpec{addition})
	if got := merged[0].GetMetricsId(); got != "edge-a" {
		t.Fatalf("merged metrics ID = %q, want edge-a", got)
	}
}

func TestMergePeersClearsMissingPSKForNewPeer(t *testing.T) {
	t.Parallel()
	addition := controlapiv1.PeerSpec_builder{}.Build()
	addition.SetPublicKey("BBB=")

	merged := mergePeers(nil, []*controlapiv1.PeerSpec{addition})
	if got := merged[0].GetPresharedKeyAction(); got != controlapiv1.PresharedKeyAction_CLEAR {
		t.Fatalf("new peer PSK action = %s, want CLEAR", got)
	}
}

func TestApplyPeerEdits(t *testing.T) {
	t.Parallel()
	current := []*controlapiv1.PeerSpec{
		testDesiredPeer("AAA=", "192.0.2.1:1", []string{"10.1.0.0/24"}),
		testDesiredPeer("BBB=", "", []string{"10.2.0.0/24"}),
	}
	edited, err := applyPeerEdits(current, []string{
		"peer", "BBB=", "remove",
		"peer", "AAA=", "endpoint", "192.0.2.9:2", "persistent-keepalive", "25",
		"peer", "CCC=", "allowed-ips", "10.3.0.0/24,10.4.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(edited) != 2 {
		t.Fatalf("peers = %d, want BBB removed and CCC added", len(edited))
	}
	if edited[0].GetPublicKey() != "AAA=" || edited[0].GetEndpoint() != "192.0.2.9:2" ||
		edited[0].GetPersistentKeepaliveSec() != 25 {
		t.Fatalf("edited peer = %+v", edited[0])
	}
	if edited[1].GetPublicKey() != "CCC=" || len(edited[1].GetAllowedIps()) != 2 {
		t.Fatalf("added peer = %+v", edited[1])
	}
	if got := edited[1].GetPresharedKeyAction(); got != controlapiv1.PresharedKeyAction_CLEAR {
		t.Fatalf("added peer PSK action = %s, want CLEAR", got)
	}
}

func TestApplyPeerEditsRejectsStrayArguments(t *testing.T) {
	t.Parallel()
	if _, err := applyPeerEdits(nil, []string{"endpoint", "x"}); err == nil {
		t.Fatal("directive without peer must fail")
	}
	if _, err := applyPeerEdits(nil, []string{"peer", "AAA=", "bogus"}); err == nil {
		t.Fatal("unknown directive must fail")
	}
}

func TestParseKeepaliveRequiresStrictUnsignedInteger(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"25x", "-1", "65536", ""} {
		if _, err := parseKeepalive(value); err == nil {
			t.Fatalf("parseKeepalive(%q) unexpectedly succeeded", value)
		}
	}
	if got, err := parseKeepalive("25"); err != nil || got != 25 {
		t.Fatalf("parseKeepalive(25) = (%d, %v)", got, err)
	}
}

func TestSetCommandSubmitsEditedSnapshot(t *testing.T) {
	t.Parallel()
	status := func(context.Context, string, string) (*controlapiv1.InterfaceStatus, error) {
		response := testStatusResponse(7, []*controlapiv1.PeerStatus{
			testPeerStatus("AAA=", "", []string{"10.1.0.0/24"}, false),
		})
		ref := controlapiv1.InterfaceRef_builder{}.Build()
		ref.SetInterfaceName("wgf0")
		ref.SetInterfaceInstanceId([]byte{1, 2, 3, 4})
		response.SetRef(ref)
		return response, nil
	}
	var got *controlapiv1.ApplyPeersRequest
	apply := func(_ context.Context, _ string, request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
		got = request
		return testApplyResponse(8), nil
	}
	var out bytes.Buffer
	err := setCommand([]string{"wgf0", "peer", "BBB=", "allowed-ips", "10.2.0.0/24"}, status, apply, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetTarget().GetInterfaceName() != "wgf0" ||
		!bytes.Equal(got.GetMutation().GetExpectedInstanceId(), []byte{1, 2, 3, 4}) ||
		got.GetMutation().GetExpectedGeneration() != 7 || len(got.GetMutation().GetRequestId()) != 16 {
		t.Fatalf("request = %+v", got)
	}
	if len(got.GetPeers()) != 2 || got.GetPeers()[1].GetPublicKey() != "BBB=" {
		t.Fatalf("peers = %+v", got.GetPeers())
	}
	if !bytes.Contains(out.Bytes(), []byte("generation 8")) {
		t.Fatalf("output = %q", out.String())
	}
}
