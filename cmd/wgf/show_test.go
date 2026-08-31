package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurochan/wg-frag-go/controlapi"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

func TestShowRendersDaemonStatus(t *testing.T) {
	t.Parallel()
	fake := func(context.Context, string, string) (*controlapiv1.InterfaceStatus, error) {
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
		ref := controlapiv1.InterfaceRef_builder{}.Build()
		ref.SetInterfaceName("wgf0")
		status.SetRef(ref)
		status.SetPublicKey("LOCALKEY=")
		status.SetListenPort(51820)
		status.SetMtu(9612)
		status.SetCounters(counters)
		return status, nil
	}
	var out bytes.Buffer
	if err := show([]string{"wgf0"}, fake, nil, &out); err != nil {
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
	unreachable := func(context.Context, string, string) (*controlapiv1.InterfaceStatus, error) {
		return nil, errors.New("no daemon")
	}
	var out bytes.Buffer
	if err := showAll(unreachable, nil, dir, &out); err != nil || out.Len() != 0 {
		t.Fatalf("showAll = %v, output %q", err, out.String())
	}
	if err := showInterfaces(unreachable, nil, dir, &out); err != nil || out.Len() != 0 {
		t.Fatalf("showInterfaces = %v, output %q", err, out.String())
	}

	name := "wgf1"
	reachable := func(_ context.Context, socket, _ string) (*controlapiv1.InterfaceStatus, error) {
		if filepath.Base(socket) != "wgf1.sock" {
			return nil, errors.New("no daemon")
		}
		ref := controlapiv1.InterfaceRef_builder{}.Build()
		ref.SetInterfaceName(name)
		return controlapiv1.InterfaceStatus_builder{Ref: ref}.Build(), nil
	}
	if err := showInterfaces(reachable, nil, dir, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "wgf1\n" {
		t.Fatalf("interfaces = %q, want wgf1", out.String())
	}
}

func TestShowDiscoversManagerInterfaces(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	managerSocket := controlapi.ManagerSocketPathIn(dir)
	managerDir := filepath.Dir(managerSocket)
	if err := os.Mkdir(managerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managerSocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ref := controlapiv1.InterfaceRef_builder{}.Build()
	ref.SetInterfaceName("wgf-managed")
	managed := controlapiv1.InterfaceStatus_builder{Ref: ref}.Build()
	lister := func(_ context.Context, socket string) ([]*controlapiv1.InterfaceStatus, error) {
		if socket != managerSocket {
			t.Fatalf("manager socket = %q, want %q", socket, managerSocket)
		}
		return []*controlapiv1.InterfaceStatus{managed}, nil
	}
	var out bytes.Buffer
	if err := showInterfaces(nil, lister, dir, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "wgf-managed\n" {
		t.Fatalf("interfaces = %q", out.String())
	}
}

func TestShowReportsManagerListFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	managerSocket := controlapi.ManagerSocketPathIn(dir)
	if err := os.MkdirAll(filepath.Dir(managerSocket), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managerSocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	want := errors.New("permission denied")
	lister := func(context.Context, string) ([]*controlapiv1.InterfaceStatus, error) {
		return nil, want
	}
	var out bytes.Buffer
	err := showInterfaces(nil, lister, dir, &out)
	if !errors.Is(err, want) || !strings.Contains(err.Error(), managerSocket) {
		t.Fatalf("show interfaces error = %v, want manager list failure", err)
	}
}

func TestShowNamedInterfaceFallsBackToManagerSocket(t *testing.T) {
	t.Parallel()
	fake := func(_ context.Context, socket, name string) (*controlapiv1.InterfaceStatus, error) {
		if socket != controlapi.ManagerSocketPath() {
			return nil, errors.New("per-interface daemon unavailable")
		}
		ref := controlapiv1.InterfaceRef_builder{}.Build()
		ref.SetInterfaceName(name)
		return controlapiv1.InterfaceStatus_builder{Ref: ref}.Build(), nil
	}
	var out bytes.Buffer
	if err := show([]string{"wgf0"}, fake, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "interface: wgf0") {
		t.Fatalf("show output = %q", out.String())
	}
}

func TestShowNamedInterfaceReportsBothSocketFailures(t *testing.T) {
	t.Parallel()
	perInterfaceErr := errors.New("permission denied")
	managerErr := errors.New("manager unavailable")
	fake := func(_ context.Context, socket, _ string) (*controlapiv1.InterfaceStatus, error) {
		if socket == controlapi.ManagerSocketPath() {
			return nil, managerErr
		}
		return nil, perInterfaceErr
	}
	err := show([]string{"wgf0"}, fake, nil, &bytes.Buffer{})
	if !errors.Is(err, perInterfaceErr) || !errors.Is(err, managerErr) {
		t.Fatalf("show error = %v, want both socket failures", err)
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
