package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/config"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

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

func TestApplyPeerEdits(t *testing.T) {
	t.Parallel()
	current := []*controlapiv1.DesiredPeer{
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
	status := func(context.Context, string) (*controlapiv1.GetStatusResponse, error) {
		return testStatusResponse(7, []*controlapiv1.PeerStatus{
			testPeerStatus("AAA=", "", []string{"10.1.0.0/24"}, false),
		}), nil
	}
	var got *controlapiv1.ApplyConfigRequest
	apply := func(_ context.Context, _ string, request *controlapiv1.ApplyConfigRequest) (*controlapiv1.ApplyConfigResponse, error) {
		got = request
		return testApplyResponse(8), nil
	}
	var out bytes.Buffer
	err := setCommand([]string{"wgf0", "peer", "BBB=", "allowed-ips", "10.2.0.0/24"}, status, apply, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetExpectedGeneration() != 7 || len(got.GetRequestId()) != 16 {
		t.Fatalf("request = %+v", got)
	}
	if len(got.GetPeers()) != 2 || got.GetPeers()[1].GetPublicKey() != "BBB=" {
		t.Fatalf("peers = %+v", got.GetPeers())
	}
	if !bytes.Contains(out.Bytes(), []byte("generation 8")) {
		t.Fatalf("output = %q", out.String())
	}
}
