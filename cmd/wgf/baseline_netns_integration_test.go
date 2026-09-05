//go:build linux && integration

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/platform/linux/wgbind"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// This compares plain wireguard-go over the same TUN, Bind and netns topology.

const (
	netNSBaselineEnv = "WGF_NETNS_BASELINE"
	netNSBaselineMTU = "WGF_NETNS_BASELINE_MTU"
)

// runBaselineWireGuardGo wires the native TUN directly to wireguard-go.
func runBaselineWireGuardGo(ifname, path string) error {
	cfg, err := config.ParseFile(path)
	if err != nil {
		return err
	}
	if len(cfg.Peers) != 1 {
		return fmt.Errorf("baseline requires exactly one peer")
	}
	mtu := cfg.Interface.MTU
	if raw := os.Getenv(netNSBaselineMTU); raw != "" {
		mtu, err = strconv.Atoi(raw)
		if err != nil {
			return err
		}
	}
	native, err := tun.CreateTUN(ifname, mtu)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer closeNetNSResource(native)
	actualName, err := native.Name()
	if err != nil {
		return err
	}

	bind := wgbind.New()
	wg := device.NewDevice(native, bind, device.NewLogger(device.LogLevelSilent, ""))
	defer wg.Close()

	peer := cfg.Peers[0]
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", hex.EncodeToString(cfg.Interface.PrivateKey[:]))
	fmt.Fprintf(&uapi, "listen_port=%d\n", cfg.Interface.ListenPort)
	uapi.WriteString("replace_peers=true\n")
	fmt.Fprintf(&uapi, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
	uapi.WriteString("replace_allowed_ips=true\n")
	for _, prefix := range peer.AllowedIPs {
		fmt.Fprintf(&uapi, "allowed_ip=%s\n", prefix)
	}
	if peer.Endpoint != "" {
		fmt.Fprintf(&uapi, "endpoint=%s\n", peer.Endpoint)
	}
	fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n\n", peer.PersistentKeepalive)
	if err := wg.IpcSet(uapi.String()); err != nil {
		return err
	}
	if err := wg.Up(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "wgbase %s is running (plain wireguard-go, mtu=%d)\n", actualName, mtu)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
	defer signal.Stop(signals)
	for {
		if received := <-signals; received != syscall.SIGUSR1 {
			return nil
		}
		if uapiState, err := wg.IpcGet(); err == nil {
			for line := range strings.Lines(uapiState) {
				if strings.HasPrefix(line, "last_handshake_time_sec=") {
					fmt.Fprintf(os.Stdout, "wgbase %s %s", actualName, line)
				}
			}
		}
	}
}

// TestWireGuardGoBaselineNetNS measures plain wireguard-go on the shim topology.
//
//	WGF_RUN_NETNS=1 WGF_NETNS_BASELINE_MTU=1420 WGF_NETNS_BENCH_BYTES=67108864 \
//	  go test -tags=integration -run '^TestWireGuardGoBaselineNetNS$' ./cmd/wgf
func TestWireGuardGoBaselineNetNS(t *testing.T) {
	if os.Getenv("WGF_RUN_NETNS") != "1" {
		t.Skip("set WGF_RUN_NETNS=1 to run privileged Linux netns integration")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun unavailable: %v", err)
	}
	t.Setenv(netNSBaselineEnv, "1")
	if os.Getenv(netNSBaselineMTU) == "" {
		// 1500 minus IPv4, UDP and WireGuard data headers.
		t.Setenv(netNSBaselineMTU, "1420")
	}

	tmp := t.TempDir()
	privateA, publicA := netNSKeyPair(t)
	privateB, publicB := netNSKeyPair(t)
	configA := writeNetNSConfig(t, tmp+"/a.conf", privateA, publicB, 51820, "198.18.0.2:51821", "10.2.0.0/24")
	configB := writeNetNSConfig(t, tmp+"/b.conf", privateB, publicA, 51821, "198.18.0.1:51820", "10.1.0.0/24")

	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	vethA, vethB := "bsa"+suffix, "bsb"+suffix
	runnerA := startNetNSRunner(t, "wgba", configA, "")
	runnerB := startNetNSRunner(t, "wgbb", configB, "")

	createVeth(t, vethA, vethB, runnerA.ns, runnerB.ns)
	runnerA.vethName = vethA
	runnerB.vethName = vethB
	configureVeth(t, runnerA.ns, vethA, "198.18.0.1/30")
	configureVeth(t, runnerB.ns, vethB, "198.18.0.2/30")
	runnerA.activate(t)
	runnerB.activate(t)
	waitForLink(t, runnerA, "wgba")
	waitForLink(t, runnerB, "wgbb")
	configureInner(t, runnerA.ns, "wgba", "10.1.0.1/24", "10.2.0.0/24")
	configureInner(t, runnerB.ns, "wgbb", "10.2.0.1/24", "10.1.0.0/24")

	// Plain WireGuard has no shim gate; wait for a successful handshake.
	waitForBaselineReachability(t, runnerA.ns, runnerB.ns)

	mtu, _ := strconv.Atoi(os.Getenv(netNSBaselineMTU))
	payload := mtu - 28 // IPv4 + UDP headers
	exchangeUDP(t, runnerA.ns, runnerB.ns, payload)
	t.Logf("baseline UDP %d-byte inner payload: pass (inner MTU %d)", payload, mtu)

	if raw := os.Getenv("WGF_NETNS_BENCH_BYTES"); raw != "" {
		bytes, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || bytes <= 0 {
			t.Fatalf("invalid WGF_NETNS_BENCH_BYTES %q", raw)
		}
		measureTCP(t, runnerA.ns, runnerB.ns, bytes, netNSBenchStreams(t))
	}
}

func waitForBaselineReachability(t *testing.T, from, to netns.NsHandle) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if baselineProbe(t, from, to) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("plain wireguard-go peers did not become reachable")
}

func baselineProbe(t *testing.T, from, to netns.NsHandle) bool {
	t.Helper()
	listener := listenUDPInNS(t, to, "10.2.0.1:49001")
	defer closeNetNSResource(listener)
	sender := dialUDPInNS(t, from, "10.1.0.1:0", "10.2.0.1:49001")
	defer closeNetNSResource(sender)
	if _, err := sender.Write([]byte("probe")); err != nil {
		return false
	}
	if err := listener.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		return false
	}
	buffer := make([]byte, 64)
	_, _, err := listener.ReadFromUDP(buffer)
	return err == nil
}
