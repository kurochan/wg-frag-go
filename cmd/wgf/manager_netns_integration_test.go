//go:build linux && integration

package main

import (
	"context"
	"encoding/base64"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/controlapi"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// TestWGFManagerNetNSLifecycle exercises the public manager API against real
// Linux TUN devices. It verifies that a runtime restart preserves the TUN
// identity and that two independently managed interfaces can carry traffic.
func TestWGFManagerNetNSLifecycle(t *testing.T) {
	if os.Getenv("WGF_RUN_NETNS") != "1" {
		t.Skip("set WGF_RUN_NETNS=1 to run privileged Linux netns integration")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun unavailable: %v", err)
	}

	managerA := startNetNSManagerRunner(t, "mga")
	managerB := startNetNSManagerRunner(t, "mgb")
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	vethA, vethB := "mga"+suffix, "mgb"+suffix
	createVeth(t, vethA, vethB, managerA.ns, managerB.ns)
	managerA.vethName = vethA
	managerB.vethName = vethB
	configureVeth(t, managerA.ns, vethA, "198.18.0.1/30")
	configureVeth(t, managerB.ns, vethB, "198.18.0.2/30")

	managerA.activate(t)
	managerB.activate(t)
	clientA := dialNetNSManager(t, managerA)
	defer clientA.Close()
	clientB := dialNetNSManager(t, managerB)
	defer clientB.Close()

	privateA0, publicA0 := managerTestKeyPair(t)
	privateB0, publicB0 := managerTestKeyPair(t)
	statusA0 := createManagedInterface(t, clientA, managerInterfaceSpec("mga0", privateA0, publicB0, "198.18.0.2:51821", "10.2.0.0/24", 51820), 1)
	statusB0 := createManagedInterface(t, clientB, managerInterfaceSpec("mgb0", privateB0, publicA0, "198.18.0.1:51820", "10.1.0.0/24", 51821), 2)
	waitForLink(t, managerA, "mga0")
	waitForLink(t, managerB, "mgb0")
	configureInner(t, managerA.ns, "mga0", "10.1.0.1/24", "10.2.0.0/24")
	configureInner(t, managerB.ns, "mgb0", "10.2.0.1/24", "10.1.0.0/24")
	waitForManagerDataReady(t, clientA, statusA0.GetStatus().GetRef(), clientB, statusB0.GetStatus().GetRef())
	exchangeUDP(t, managerA.ns, managerB.ns, 1472)

	indexBefore := linkIndex(t, managerA.ns, "mga0")
	restart := restartManagedInterfaceRequest(statusA0.GetStatus(), managerInterfaceSpecWithoutPrivateKey("mga0", publicB0, "198.18.0.2:51821", "10.2.0.0/24", 51820), 3)
	restarted := callRestart(t, clientA, restart)
	if restarted.GetStatus().GetGeneration() <= statusA0.GetStatus().GetGeneration() {
		t.Fatalf("restart generation = %d, before %d", restarted.GetStatus().GetGeneration(), statusA0.GetStatus().GetGeneration())
	}
	waitForManagerLifecycle(t, clientA, restarted.GetStatus().GetRef(), controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING)
	if got := linkIndex(t, managerA.ns, "mga0"); got != indexBefore {
		t.Fatalf("TUN link index after restart = %d, before %d", got, indexBefore)
	}
	if got := linkName(t, managerA.ns, "mga0"); got != "mga0" {
		t.Fatalf("TUN name after restart = %q", got)
	}
	waitForManagerDataReady(t, clientA, restarted.GetStatus().GetRef(), clientB, statusB0.GetStatus().GetRef())
	exchangeUDP(t, managerA.ns, managerB.ns, 1472)

	privateA1, publicA1 := managerTestKeyPair(t)
	privateB1, publicB1 := managerTestKeyPair(t)
	statusA1 := createManagedInterface(t, clientA, managerInterfaceSpec("mga1", privateA1, publicB1, "198.18.0.2:51823", "10.4.0.0/24", 51822), 4)
	statusB1 := createManagedInterface(t, clientB, managerInterfaceSpec("mgb1", privateB1, publicA1, "198.18.0.1:51822", "10.3.0.0/24", 51823), 5)
	waitForLink(t, managerA, "mga1")
	waitForLink(t, managerB, "mgb1")
	configureInner(t, managerA.ns, "mga1", "10.3.0.1/24", "10.4.0.0/24")
	configureInner(t, managerB.ns, "mgb1", "10.4.0.1/24", "10.3.0.0/24")
	waitForManagerDataReady(t, clientA, restarted.GetStatus().GetRef(), clientB, statusB0.GetStatus().GetRef())
	waitForManagerDataReady(t, clientA, statusA1.GetStatus().GetRef(), clientB, statusB1.GetStatus().GetRef())
	exchangeUDPAddresses(t, managerA.ns, managerB.ns, "10.3.0.1:0", "10.4.0.1:49003", 1472)

	listA := listManagedInterfaces(t, clientA)
	listB := listManagedInterfaces(t, clientB)
	if len(listA.GetInterfaces()) != 2 || len(listB.GetInterfaces()) != 2 {
		t.Fatalf("managed interface counts = %d/%d, want 2/2", len(listA.GetInterfaces()), len(listB.GetInterfaces()))
	}
	deleteManagedInterface(t, clientA, statusA1.GetStatus().GetRef(), statusA1.GetStatus().GetGeneration(), 6)
	deleteManagedInterface(t, clientB, statusB1.GetStatus().GetRef(), statusB1.GetStatus().GetGeneration(), 7)
	waitForLinkGone(t, managerA.ns, "mga1")
	waitForLinkGone(t, managerB.ns, "mgb1")
	if got := len(listManagedInterfaces(t, clientA).GetInterfaces()); got != 1 {
		t.Fatalf("interfaces after delete on A = %d, want 1", got)
	}
	if got := len(listManagedInterfaces(t, clientB).GetInterfaces()); got != 1 {
		t.Fatalf("interfaces after delete on B = %d, want 1", got)
	}

	deleteManagedInterface(t, clientA, restarted.GetStatus().GetRef(), restarted.GetStatus().GetGeneration(), 8)
	deleteManagedInterface(t, clientB, statusB0.GetStatus().GetRef(), statusB0.GetStatus().GetGeneration(), 9)
	waitForLinkGone(t, managerA.ns, "mga0")
	waitForLinkGone(t, managerB.ns, "mgb0")
}

func managerTestKeyPair(t *testing.T) ([]byte, string) {
	t.Helper()
	private, public := netNSKeyPair(t)
	decoded, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		t.Fatalf("decode test private key: %v", err)
	}
	return decoded, public
}

func managerInterfaceSpec(name string, private []byte, peer, endpoint, allowed string, port int) *controlapiv1.InterfaceSpec {
	spec := managerInterfaceSpecWithoutPrivateKey(name, peer, endpoint, allowed, port)
	spec.SetPrivateKey(private)
	return spec
}

func managerInterfaceSpecWithoutPrivateKey(name, peer, endpoint, allowed string, port int) *controlapiv1.InterfaceSpec {
	spec := controlapiv1.InterfaceSpec_builder{}.Build()
	spec.SetInterfaceName(name)
	spec.SetListenPort(uint32(port))
	spec.SetMtu(1500)
	spec.SetMaxCarrierPayload(2000)
	spec.SetReassemblySlots(64)
	peerSpec := controlapiv1.PeerSpec_builder{}.Build()
	peerSpec.SetPublicKey(peer)
	peerSpec.SetEndpoint(endpoint)
	peerSpec.SetAllowedIps([]string{allowed})
	peerSpec.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
	spec.SetPeers([]*controlapiv1.PeerSpec{peerSpec})
	return spec
}

func dialNetNSManager(t *testing.T, runner *netNSRunner) *controlapi.Client {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		client, err := controlapi.DialUnix(ctx, runner.socketPath)
		if err == nil {
			_, err = client.ListInterfaces(ctx, controlapiv1.ListInterfacesRequest_builder{}.Build())
		}
		cancel()
		if err == nil {
			return client
		}
		if client != nil {
			_ = client.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("manager socket %q did not become ready; logs:\n%s", runner.socketPath, runner.logs.String())
	return nil
}

func createManagedInterface(t *testing.T, client *controlapi.Client, spec *controlapiv1.InterfaceSpec, id byte) *controlapiv1.CreateInterfaceResponse {
	t.Helper()
	request := controlapiv1.CreateInterfaceRequest_builder{}.Build()
	request.SetRequestId(managerNetNSRequestID(id))
	request.SetSpec(spec)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	response, err := client.CreateInterface(ctx, request)
	if err != nil {
		t.Fatalf("create %s: %v", spec.GetInterfaceName(), err)
	}
	if response.GetStatus().GetLifecycle() != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING {
		t.Fatalf("create %s lifecycle = %s", spec.GetInterfaceName(), response.GetStatus().GetLifecycle())
	}
	if got := response.GetStatus().GetNativeInterfaceName(); got != spec.GetInterfaceName() {
		t.Fatalf("create %s native interface = %q", spec.GetInterfaceName(), got)
	}
	return response
}

func restartManagedInterfaceRequest(current *controlapiv1.InterfaceStatus, spec *controlapiv1.InterfaceSpec, id byte) *controlapiv1.RestartInterfaceRequest {
	request := controlapiv1.RestartInterfaceRequest_builder{}.Build()
	request.SetTarget(current.GetRef())
	mutation := controlapiv1.MutationContext_builder{}.Build()
	mutation.SetExpectedInstanceId(current.GetRef().GetInterfaceInstanceId())
	mutation.SetExpectedGeneration(current.GetGeneration())
	mutation.SetRequestId(managerNetNSRequestID(id))
	request.SetMutation(mutation)
	request.SetSpec(spec)
	return request
}

func callRestart(t *testing.T, client *controlapi.Client, request *controlapiv1.RestartInterfaceRequest) *controlapiv1.RestartInterfaceResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := client.RestartInterface(ctx, request)
	if err != nil {
		t.Fatalf("restart interface: %v", err)
	}
	return response
}

func deleteManagedInterface(t *testing.T, client *controlapi.Client, ref *controlapiv1.InterfaceRef, generation uint64, id byte) {
	t.Helper()
	request := controlapiv1.DeleteInterfaceRequest_builder{}.Build()
	request.SetTarget(ref)
	mutation := controlapiv1.MutationContext_builder{}.Build()
	mutation.SetExpectedInstanceId(ref.GetInterfaceInstanceId())
	mutation.SetExpectedGeneration(generation)
	mutation.SetRequestId(managerNetNSRequestID(id))
	request.SetMutation(mutation)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.DeleteInterface(ctx, request); err != nil {
		t.Fatalf("delete %s: %v", ref.GetInterfaceName(), err)
	}
}

func listManagedInterfaces(t *testing.T, client *controlapi.Client) *controlapiv1.ListInterfacesResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.ListInterfaces(ctx, controlapiv1.ListInterfacesRequest_builder{}.Build())
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	return response
}

func waitForManagerDataReady(t *testing.T, clientA *controlapi.Client, refA *controlapiv1.InterfaceRef, clientB *controlapi.Client, refB *controlapiv1.InterfaceRef) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		readyA := managerInterfaceDataReady(t, clientA, refA)
		readyB := managerInterfaceDataReady(t, clientB, refB)
		if readyA && readyB {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("manager CONTROL gates did not open for %s/%s", refA.GetInterfaceName(), refB.GetInterfaceName())
}

func managerInterfaceDataReady(t *testing.T, client *controlapi.Client, ref *controlapiv1.InterfaceRef) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	request := controlapiv1.GetInterfaceRequest_builder{}.Build()
	request.SetTarget(ref)
	response, err := client.GetInterface(ctx, request)
	if err != nil {
		return false
	}
	status := response.GetStatus()
	if status == nil || status.GetLifecycle() != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING {
		return false
	}
	peers := status.GetPeers()
	if len(peers) == 0 {
		return false
	}
	for _, peer := range peers {
		if !peer.GetDataReady() {
			return false
		}
	}
	return true
}

func waitForManagerLifecycle(t *testing.T, client *controlapi.Client, ref *controlapiv1.InterfaceRef, want controlapiv1.InterfaceLifecycle) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		request := controlapiv1.GetInterfaceRequest_builder{}.Build()
		request.SetTarget(ref)
		response, err := client.GetInterface(ctx, request)
		cancel()
		if err == nil && response.GetStatus().GetLifecycle() == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("interface %s did not reach lifecycle %s", ref.GetInterfaceName(), want)
}

func managerNetNSRequestID(value byte) []byte {
	requestID := make([]byte, 16)
	for index := range requestID {
		requestID[index] = value
	}
	return requestID
}

func linkIndex(t *testing.T, ns netns.NsHandle, name string) int {
	t.Helper()
	var index int
	inNetNS(t, ns, func() error {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		index = link.Attrs().Index
		return nil
	})
	return index
}

func linkName(t *testing.T, ns netns.NsHandle, name string) string {
	t.Helper()
	var actual string
	inNetNS(t, ns, func() error {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		actual = link.Attrs().Name
		return nil
	})
	return actual
}

func waitForLinkGone(t *testing.T, ns netns.NsHandle, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var exists bool
		if err := withNetNS(ns, func() error {
			_, err := netlink.LinkByName(name)
			exists = err == nil
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !exists {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("TUN %q still exists after delete", name)
}
