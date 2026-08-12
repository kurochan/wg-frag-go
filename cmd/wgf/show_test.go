package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

func TestShowRendersDaemonStatus(t *testing.T) {
	t.Parallel()
	fake := func(context.Context, string) (*controlapiv1.GetStatusResponse, error) {
		first := testPeerStatus("PEERKEY=", "192.0.2.1:51820", []string{"10.2.0.0/24"}, true)
		first.SetTransferRxBytes(7)
		first.SetTransferTxBytes(9)
		first.SetConfirmedCarrierPayload(1400)
		first.SetControlPathState("SEARCH_COMPLETE")
		second := testPeerStatus("SECONDKEY=", "", nil, false)
		counters := controlapiv1.ShimCounters_builder{}.Build()
		counters.SetTxCarriers(5)
		counters.SetControlExploratoryEvictions(2)
		counters.SetControlCoalesces(3)
		counters.SetControlQueueDrops(4)
		status := testStatusResponse(0, []*controlapiv1.PeerStatus{first, second})
		status.SetInterfaceName("wgf0")
		status.SetPublicKey("LOCALKEY=")
		status.SetListenPort(51820)
		status.SetMtu(9612)
		status.SetCounters(counters)
		return status, nil
	}
	var out bytes.Buffer
	if err := show([]string{"wgf0"}, fake, &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"interface: wgf0", "PEERKEY=", "allowed ips: 10.2.0.0/24",
		"wgf data: ready", "wgf carrier payload: 1400 bytes", "wgf control path: SEARCH_COMPLETE", "carriers: 5 sent",
		"control pressure: queue drops 4, exploratory evictions 2, coalesces 3",
		"SECONDKEY=", "wgf data: handshaking",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("show output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `\n`) {
		t.Fatalf("show output contains a literal newline escape: %q", text)
	}
}

func TestShowAllSkipsUnreachableSockets(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"wgf0.sock", "wgf1.sock", "not-a-socket"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unreachable := func(context.Context, string) (*controlapiv1.GetStatusResponse, error) {
		return nil, errors.New("no daemon")
	}
	var out bytes.Buffer
	if err := showAll(unreachable, dir, &out); err != nil || out.Len() != 0 {
		t.Fatalf("showAll = %v, output %q", err, out.String())
	}
	if err := showInterfaces(unreachable, dir, &out); err != nil || out.Len() != 0 {
		t.Fatalf("showInterfaces = %v, output %q", err, out.String())
	}

	name := "wgf1"
	reachable := func(_ context.Context, socket string) (*controlapiv1.GetStatusResponse, error) {
		if filepath.Base(socket) != "wgf1.sock" {
			return nil, errors.New("no daemon")
		}
		return controlapiv1.GetStatusResponse_builder{InterfaceName: &name}.Build(), nil
	}
	if err := showInterfaces(reachable, dir, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "wgf1\n" {
		t.Fatalf("interfaces = %q, want wgf1", out.String())
	}
}

func TestGenpskEmitsUnclampedKey(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if err := genpsk(nil, &out); err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(out.String())) != 44 {
		t.Fatalf("genpsk output = %q, want 44 base64 chars", out.String())
	}
}
