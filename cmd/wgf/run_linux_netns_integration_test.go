//go:build linux && integration

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	netNSHelperEnv  = "WGF_NETNS_HELPER"
	netNSSocketEnv  = "WGF_NETNS_CONTROL_SOCKET"
	netNSCPUProfile = "WGF_NETNS_CPU_PROFILE"
	// These opt-in scenarios deliberately exercise recovery paths without
	// changing the daemon or invoking iproute2 from the test process.
	netNSControlRecoveryEnv = "WGF_NETNS_CONTROL_RECOVERY"
	netNSBaseRecoveryEnv    = "WGF_NETNS_BASE_FAILURE_RECOVERY"
	netNSRawEnv             = "WGF_NETNS_RAW"
	netNSNoFragmentEnv      = "WGF_NETNS_NO_UNDERLAY_FRAGMENTATION"
	netNSUnderlayMTU        = 1500
	netNSBaseFailureMTU     = 700
	helperHold              = "hold"
	helperRun               = "run"
)

var netNSPMTUStats = regexp.MustCompile(`confirmed_carrier_payload=(\d+) pmtu_searching=(true|false)`)

var netNSMissingFlags = regexp.MustCompile(`missing_flags=([01]+)`)

var netNSControlPathState = regexp.MustCompile(`control_path_state=([A-Z_]+)`)

func TestWGFNetNSHoldHelper(t *testing.T) {
	if os.Getenv(netNSHelperEnv) != helperHold {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGTERM)
	defer signal.Stop(signals)
	if <-signals == syscall.SIGTERM {
		os.Exit(0)
	}
	env := replaceEnv(os.Environ(), netNSHelperEnv, helperRun)
	args := []string{os.Args[0], "-test.run", "^TestWGFNetNSRunHelper$"}
	if path := os.Getenv(netNSCPUProfile); path != "" {
		args = append(args, "-test.cpuprofile="+path)
	}
	if err := syscall.Exec(os.Args[0], args, env); err != nil {
		fmt.Fprintln(os.Stderr, "exec netns runner:", err)
		os.Exit(1)
	}
}

func TestWGFNetNSRunHelper(t *testing.T) {
	if os.Getenv(netNSHelperEnv) != helperRun {
		return
	}
	ifname, path := os.Getenv("WGF_NETNS_IFNAME"), os.Getenv("WGF_NETNS_CONFIG")
	if os.Getenv(netNSRawEnv) == "1" {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
		defer signal.Stop(signals)
		<-signals
		return
	}
	args := []string{ifname, "--config", path}
	if socket := os.Getenv(netNSSocketEnv); socket != "" {
		args = append(args, "--control-socket", socket)
	}
	run := func() error { return runCommand(args, os.Stdout, os.Stderr) }
	if os.Getenv(netNSBaselineEnv) == "1" {
		run = func() error { return runBaselineWireGuardGo(ifname, path) }
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "netns runner:", err)
		os.Exit(1)
	}
}

// TestWGFNetNSWireGuardUDP is an opt-in Linux integration test.  It performs
// namespace, veth, address, route and application-socket setup through netlink
// from Go; it neither shells out to iproute2 nor relies on a test script.
func TestWGFNetNSWireGuardUDP(t *testing.T) {
	if os.Getenv("WGF_RUN_NETNS") != "1" {
		t.Skip("set WGF_RUN_NETNS=1 to run privileged Linux netns integration")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun unavailable: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("netns integration failed; runner logs are emitted by their cleanup handlers")
		}
	})

	tmp := t.TempDir()
	profileDir := os.Getenv("WGF_NETNS_PROFILE_DIR")
	if profileDir != "" {
		if err := os.MkdirAll(profileDir, 0o700); err != nil {
			t.Fatalf("create WGF_NETNS_PROFILE_DIR: %v", err)
		}
	}
	privateA, publicA := netNSKeyPair(t)
	privateB, publicB := netNSKeyPair(t)
	configA := writeNetNSConfig(t, tmp+"/a.conf", privateA, publicB, 51820, "198.18.0.2:51821", "10.2.0.0/24")
	configB := writeNetNSConfig(t, tmp+"/b.conf", privateB, publicA, 51821, "198.18.0.1:51820", "10.1.0.0/24")

	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	vethA, vethB := "wga"+suffix, "wgb"+suffix
	runnerA := startNetNSRunner(t, "wgfa", configA, profileDir)
	runnerB := startNetNSRunner(t, "wgfb", configB, profileDir)

	createVeth(t, vethA, vethB, runnerA.ns, runnerB.ns)
	configureVeth(t, runnerA.ns, vethA, "198.18.0.1/30")
	configureVeth(t, runnerB.ns, vethB, "198.18.0.2/30")
	runnerA.vethName = vethA
	runnerB.vethName = vethB

	if baseRecoveryScenario() {
		// A 700-byte underlay can carry the handshake but not the BASE probe.
		// Restore the normal MTU only after observing the explicit ERROR state.
		setVethMTU(t, runnerA.ns, vethA, netNSBaseFailureMTU)
		setVethMTU(t, runnerB.ns, vethB, netNSBaseFailureMTU)
	}

	var capture *underlayCapture
	if noFragmentScenario() {
		capture = startUnderlayCapture(t, runnerA.ns, vethA)
		defer func() {
			capture.close()
			packets, fragments := capture.snapshot()
			t.Logf("underlay IPv4 capture: packets=%d fragments=%d", packets, fragments)
			if packets == 0 {
				t.Errorf("underlay capture saw no IPv4 packets")
			}
			if fragments != 0 {
				t.Errorf("underlay emitted %d fragmented IPv4 packets", fragments)
			}
		}()
	}

	if controlRecoveryScenario() {
		// Start one side first, while its CONTROL datagrams have no receiver.
		// The normal CONTROL retry path must recover when the second side starts.
		runnerA.activate(t)
		waitForDataNotReady(t, runnerA)
		runnerB.activate(t)
	} else {
		runnerA.activate(t)
		runnerB.activate(t)
	}
	waitForLink(t, runnerA, "wgfa")
	waitForLink(t, runnerB, "wgfb")
	configureInner(t, runnerA.ns, "wgfa", "10.1.0.1/24", "10.2.0.0/24")
	configureInner(t, runnerB.ns, "wgfb", "10.2.0.1/24", "10.1.0.0/24")
	if baseRecoveryScenario() {
		waitForBaseError(t, runnerA, runnerB)
		setVethMTU(t, runnerA.ns, vethA, netNSUnderlayMTU)
		setVethMTU(t, runnerB.ns, vethB, netNSUnderlayMTU)
	}

	// DATA remains fail-closed until both CONTROL exchanges complete.
	waitForDataReady(t, runnerA, runnerB)
	if baseRecoveryScenario() {
		waitForControlPathRecovery(t, runnerA, runnerB)
	}
	if raw := os.Getenv("WGF_NETNS_MTU"); raw != "" {
		// v1 drops native fragments, so stay within the configured MTU.
		mtu, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid WGF_NETNS_MTU %q", raw)
		}
		exchangeUDP(t, runnerA.ns, runnerB.ns, mtu-28)
	} else {
		exchangeUDP(t, runnerA.ns, runnerB.ns, 1472)
		exchangeUDP(t, runnerA.ns, runnerB.ns, 9584)
	}
	if os.Getenv("WGF_NETNS_REQUIRE_PMTU") == "1" || noFragmentScenario() {
		waitForPMTU(t, runnerA, runnerB)
	}
	if raw := os.Getenv("WGF_NETNS_BENCH_BYTES"); raw != "" {
		bytes, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || bytes <= 0 {
			t.Fatalf("invalid WGF_NETNS_BENCH_BYTES %q", raw)
		}
		streams := netNSBenchStreams(t)
		measureTCP(t, runnerA.ns, runnerB.ns, bytes, streams)
		logRunnerStats(t, runnerA, runnerB)
	}
}

func netNSBenchStreams(t *testing.T) int {
	t.Helper()
	raw := os.Getenv("WGF_NETNS_BENCH_STREAMS")
	if raw == "" {
		return 1
	}
	streams, err := strconv.Atoi(raw)
	if err != nil || streams < 1 || streams > 16 {
		t.Fatalf("invalid WGF_NETNS_BENCH_STREAMS %q; want 1..16", raw)
	}
	return streams
}

// logRunnerStats records each runner's final counters.
func logRunnerStats(t *testing.T, runners ...*netNSRunner) {
	t.Helper()
	for _, runner := range runners {
		if err := runner.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
			return
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, runner := range runners {
		lines := strings.Split(runner.logs.String(), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], " stats: ") {
				t.Log(strings.TrimSpace(lines[i]))
				break
			}
		}
	}
}

type netNSRunner struct {
	cmd      *exec.Cmd
	ns       netns.NsHandle
	logs     *lockedBuffer
	vethName string
	stopOnce sync.Once
}

// runnerSocketDir is a short private directory; a t.TempDir path would exceed
// the 108-byte sun_path limit.
func runnerSocketDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "wgfns")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func startNetNSRunner(t *testing.T, ifname, config, profileDir string) *netNSRunner {
	t.Helper()
	logs := new(lockedBuffer)
	cmd := exec.Command(os.Args[0], "-test.run", "^TestWGFNetNSHoldHelper$")
	// A private socket per runner: /run is shared across the namespaces, so
	// reusing the default path lets a lingering daemon from an earlier run
	// keep the next one from starting.
	socket := filepath.Join(runnerSocketDir(t), ifname+".sock")
	cmd.Env = append(replaceEnv(os.Environ(), netNSHelperEnv, helperHold),
		"WGF_NETNS_IFNAME="+ifname, "WGF_NETNS_CONFIG="+config, netNSSocketEnv+"="+socket)
	if profileDir != "" {
		cmd.Env = append(cmd.Env, netNSCPUProfile+"="+filepath.Join(profileDir, ifname+".cpu.pprof"))
	}
	cmd.Stdout, cmd.Stderr = logs, logs
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNET,
		Setpgid:    true,
		// Pdeathsig fires when the creating OS thread exits, which the Go
		// runtime may do at any time, so it would kill a healthy runner
		// mid-test. t.Cleanup stops runners on the normal and failing paths.
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start netns runner: %v", err)
	}
	ns, err := netns.GetFromPid(cmd.Process.Pid)
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Fatalf("open child netns: %v", err)
	}
	runner := &netNSRunner{cmd: cmd, ns: ns, logs: logs}
	t.Cleanup(func() { runner.stop(t) })
	return runner
}

func (r *netNSRunner) activate(t *testing.T) {
	t.Helper()
	if err := r.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatalf("activate netns runner: %v; logs:\n%s", err, r.logs.String())
	}
}

func (r *netNSRunner) stop(t *testing.T) {
	t.Helper()
	r.stopOnce.Do(func() {
		_ = r.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- r.cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("netns runner stopped: %v; logs:\n%s", err, r.logs.String())
			}
		case <-time.After(5 * time.Second):
			// Kill the whole process group. The helper execs the daemon, but
			// retaining the group cleanup makes this safe if it gains children.
			_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
			<-done
			t.Logf("netns runner killed after timeout; logs:\n%s", r.logs.String())
		}
		if r.vethName != "" {
			deleteLinkBestEffort(r.ns, r.vethName)
		}
		_ = r.ns.Close()
		if t.Failed() {
			// Preserve stats and goroutine dumps when the test fails. This is
			// best effort; the process has already been asked to terminate.
			t.Logf("runner logs:\n%s", r.logs.String())
		}
	})
}

func createVeth(t *testing.T, a, b string, nsA, nsB netns.NsHandle) {
	t.Helper()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: a, MTU: 1500}, PeerName: b, PeerMTU: 1500}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	// If either move fails, remove whichever endpoint is still visible in the
	// initial namespace. Once both endpoints are moved, netNSRunner.stop
	// removes them from their child namespaces.
	movedA, movedB := false, false
	defer func() {
		if movedA && movedB {
			return
		}
		for _, name := range []string{a, b} {
			if link, err := netlink.LinkByName(name); err == nil {
				_ = netlink.LinkDel(link)
			}
		}
	}()
	linkA, err := netlink.LinkByName(a)
	if err != nil {
		t.Fatalf("lookup veth A: %v", err)
	}
	if err := netlink.LinkSetNsFd(linkA, int(nsA)); err != nil {
		t.Fatalf("move veth A: %v", err)
	}
	movedA = true
	linkB, err := netlink.LinkByName(b)
	if err != nil {
		t.Fatalf("lookup veth B: %v", err)
	}
	if err := netlink.LinkSetNsFd(linkB, int(nsB)); err != nil {
		t.Fatalf("move veth B: %v", err)
	}
	movedB = true
}

func setVethMTU(t *testing.T, ns netns.NsHandle, name string, mtu int) {
	t.Helper()
	inNetNS(t, ns, func() error {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		return netlink.LinkSetMTU(link, mtu)
	})
}

func deleteLinkBestEffort(ns netns.NsHandle, name string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := netns.Get()
	if err != nil {
		return
	}
	defer current.Close()
	if err := netns.Set(ns); err != nil {
		return
	}
	if link, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(link)
	}
	_ = netns.Set(current)
}

func configureVeth(t *testing.T, ns netns.NsHandle, name, cidr string) {
	t.Helper()
	inNetNS(t, ns, func() error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(lo); err != nil {
			return err
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	})
}

func configureInner(t *testing.T, ns netns.NsHandle, ifname, address, destination string) {
	t.Helper()
	inNetNS(t, ns, func() error {
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr(address)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		_, dst, err := net.ParseCIDR(destination)
		if err != nil {
			return err
		}
		return netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst})
	})
}

func waitForLink(t *testing.T, runner *netNSRunner, ifname string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		inNetNS(t, runner.ns, func() error {
			_, err := netlink.LinkByName(ifname)
			found = err == nil
			return nil
		})
		if found {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	var present []string
	inNetNS(t, runner.ns, func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			present = append(present, link.Attrs().Name)
		}
		return nil
	})
	t.Fatalf("timed out waiting for TUN %q; links present: %v; runner logs:\n%s", ifname, present, runner.logs.String())
}

func inNetNS(t *testing.T, target netns.NsHandle, fn func() error) {
	t.Helper()
	if err := withNetNS(target, fn); err != nil {
		t.Fatal(err)
	}
}

func withNetNS(target netns.NsHandle, fn func() error) (returnErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer current.Close()
	if err := netns.Set(target); err != nil {
		return fmt.Errorf("enter target netns: %w", err)
	}
	defer func() {
		if err := netns.Set(current); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("restore netns: %w", err))
		}
	}()
	if err := fn(); err != nil {
		return fmt.Errorf("netns operation: %w", err)
	}
	return nil
}

func exchangeUDP(t *testing.T, from, to netns.NsHandle, size int) {
	t.Helper()
	server := listenUDPInNS(t, to, "10.2.0.1:49001")
	defer server.Close()
	go func() {
		_ = server.SetDeadline(time.Now().Add(15 * time.Second))
		buf := make([]byte, size+1)
		for {
			n, peer, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n != size {
				return
			}
			// The forward direction may be ready a control round before the
			// reverse direction. Keep echoing retries until the client sees one.
			_, _ = server.WriteToUDP(buf[:n], peer)
		}
	}()
	client := dialUDPInNS(t, from, "10.1.0.1:0", "10.2.0.1:49001")
	defer client.Close()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	deadline := time.Now().Add(12 * time.Second)
	buf := make([]byte, size+1)
	for time.Now().Before(deadline) {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("UDP write %d bytes: %v", size, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := client.Read(buf)
		if err == nil {
			if !bytes.Equal(buf[:n], payload) {
				t.Fatalf("UDP payload mismatch for %d bytes", size)
			}
			t.Logf("UDP %d-byte inner payload: pass", size)
			return
		}
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("UDP read %d bytes: %v", size, err)
		}
	}
	t.Fatalf("UDP %d-byte round trip timed out", size)
}

func measureTCP(t *testing.T, from, to netns.NsHandle, size int64, streams int) {
	measureTCPAddresses(t, from, to, "10.1.0.1:0", "10.2.0.1:49002", size, streams)
}

func measureTCPAddresses(t *testing.T, from, to netns.NsHandle, local, remote string, size int64, streams int) {
	t.Helper()
	if streams == 1 {
		measureTCPSingleAddresses(t, from, to, local, remote, size)
		return
	}
	if size%int64(streams) != 0 {
		t.Fatalf("TCP inner_bytes=%d is not divisible by streams=%d", size, streams)
	}
	measureTCPParallelAddresses(t, from, to, local, remote, size/int64(streams), streams)
}

func measureTCPSingle(t *testing.T, from, to netns.NsHandle, size int64) {
	measureTCPSingleAddresses(t, from, to, "10.1.0.1:0", "10.2.0.1:49002", size)
}

func measureTCPSingleAddresses(t *testing.T, from, to netns.NsHandle, local, remote string, size int64) {
	t.Helper()
	listener := listenTCPInNS(t, to, remote)
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
			_, err = io.CopyN(io.Discard, conn, size)
			if err == nil {
				_, err = conn.Write([]byte{1})
			}
			_ = conn.Close()
		}
		serverDone <- err
	}()
	conn, err := dialTCPRetry(from, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("set TCP deadline: %v", err)
	}
	started := time.Now()
	chunk := make([]byte, 128<<10)
	for sent := int64(0); sent < size; {
		remaining := size - sent
		write := len(chunk)
		if int64(write) > remaining {
			write = int(remaining)
		}
		n, err := conn.Write(chunk[:write])
		if err != nil {
			t.Fatalf("TCP write: %v", err)
		}
		sent += int64(n)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatalf("TCP acknowledgement: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("TCP server: %v", err)
	}
	elapsed := time.Since(started)
	t.Logf("TCP inner_bytes=%d streams=1 elapsed=%s inner_gbps=%.3f", size, elapsed.Round(time.Millisecond), float64(size*8)/elapsed.Seconds()/1e9)
}

func measureTCPParallel(t *testing.T, from, to netns.NsHandle, perStream int64, streams int) {
	measureTCPParallelAddresses(t, from, to, "10.1.0.1:0", "10.2.0.1:49002", perStream, streams)
}

func measureTCPParallelAddresses(t *testing.T, from, to netns.NsHandle, local, remote string, perStream int64, streams int) {
	t.Helper()
	listener := listenTCPInNS(t, to, remote)
	defer listener.Close()
	serverDone := make(chan error, streams)
	for range streams {
		go func() {
			conn, err := listener.AcceptTCP()
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
				_, err = io.CopyN(io.Discard, conn, perStream)
				if err == nil {
					_, err = conn.Write([]byte{1})
				}
				_ = conn.Close()
			}
			serverDone <- err
		}()
	}
	clientDone := make(chan error, streams)
	started := time.Now()
	for range streams {
		go func() {
			conn, err := dialTCPRetry(from, local, remote)
			if err != nil {
				clientDone <- err
				return
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
				clientDone <- err
				return
			}
			chunk := make([]byte, 128<<10)
			for sent := int64(0); sent < perStream; {
				write := len(chunk)
				if remaining := perStream - sent; int64(write) > remaining {
					write = int(remaining)
				}
				n, err := conn.Write(chunk[:write])
				if err != nil {
					clientDone <- err
					return
				}
				sent += int64(n)
			}
			_, err = io.ReadFull(conn, make([]byte, 1))
			clientDone <- err
		}()
	}
	var transferErr error
	for range streams {
		if err := <-clientDone; err != nil {
			transferErr = errors.Join(transferErr, fmt.Errorf("TCP client: %w", err))
		}
	}
	if transferErr != nil {
		_ = listener.Close()
	}
	for range streams {
		if err := <-serverDone; err != nil {
			transferErr = errors.Join(transferErr, fmt.Errorf("TCP server: %w", err))
		}
	}
	if transferErr != nil {
		t.Fatal(transferErr)
	}
	elapsed := time.Since(started)
	t.Logf("TCP inner_bytes=%d streams=%d elapsed=%s inner_gbps=%.3f", perStream*int64(streams), streams, elapsed.Round(time.Millisecond), float64(perStream*int64(streams)*8)/elapsed.Seconds()/1e9)
}

func listenUDPInNS(t *testing.T, ns netns.NsHandle, address string) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	inNetNS(t, ns, func() error {
		addr, err := net.ResolveUDPAddr("udp4", address)
		if err != nil {
			return err
		}
		conn, err = net.ListenUDP("udp4", addr)
		return err
	})
	return conn
}

func dialUDPInNS(t *testing.T, ns netns.NsHandle, local, remote string) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	inNetNS(t, ns, func() error {
		localAddr, err := net.ResolveUDPAddr("udp4", local)
		if err != nil {
			return err
		}
		remoteAddr, err := net.ResolveUDPAddr("udp4", remote)
		if err != nil {
			return err
		}
		conn, err = net.DialUDP("udp4", localAddr, remoteAddr)
		return err
	})
	return conn
}

func listenTCPInNS(t *testing.T, ns netns.NsHandle, address string) *net.TCPListener {
	t.Helper()
	var listener *net.TCPListener
	inNetNS(t, ns, func() error {
		addr, err := net.ResolveTCPAddr("tcp4", address)
		if err != nil {
			return err
		}
		listener, err = net.ListenTCP("tcp4", addr)
		return err
	})
	return listener
}

func dialTCPRetry(ns netns.NsHandle, local, remote string) (*net.TCPConn, error) {
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		var conn *net.TCPConn
		var dialErr error
		if err := withNetNS(ns, func() error {
			localAddr, err := net.ResolveTCPAddr("tcp4", local)
			if err != nil {
				return err
			}
			remoteAddr, err := net.ResolveTCPAddr("tcp4", remote)
			if err != nil {
				return err
			}
			conn, dialErr = net.DialTCP("tcp4", localAddr, remoteAddr)
			return nil
		}); err != nil {
			return nil, err
		}
		if dialErr == nil {
			return conn, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("TCP connect to %s timed out", remote)
}

// waitForDataReady waits until every CONTROL gate is open.
func waitForDataReady(t *testing.T, runners ...*netNSRunner) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		for _, runner := range runners {
			if err := runner.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
				t.Fatalf("read CONTROL stats: %v", err)
			}
		}
		time.Sleep(150 * time.Millisecond)
		ready := true
		for _, runner := range runners {
			matches := netNSMissingFlags.FindAllStringSubmatch(runner.logs.String(), -1)
			if len(matches) == 0 || strings.Trim(matches[len(matches)-1][1], "0") != "" {
				ready = false
				break
			}
		}
		if ready {
			return
		}
	}
	for _, runner := range runners {
		t.Logf("runner logs:\n%s", runner.logs.String())
	}
	t.Fatal("CONTROL gates did not open on both peers")
}

// waitForDataNotReady proves that a deliberately broken path is fail-closed
// before the recovery action is applied. It intentionally has a short bound:
// this is a fault-injection observation, not the normal CONTROL convergence
// wait used by waitForDataReady.
func waitForDataNotReady(t *testing.T, runners ...*netNSRunner) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, runner := range runners {
			if err := runner.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
				t.Fatalf("read CONTROL stats: %v", err)
			}
		}
		time.Sleep(150 * time.Millisecond)
		for _, runner := range runners {
			matches := netNSMissingFlags.FindAllStringSubmatch(runner.logs.String(), -1)
			if len(matches) == 0 || strings.Trim(matches[len(matches)-1][1], "0") != "" {
				ready = false
				break
			}
		}
		if !ready {
			return
		}
	}
	t.Fatal("fault-injected path unexpectedly opened all CONTROL gates")
}

// waitForBaseError proves that the low-MTU injection reached the recoverable
// BASE ERROR state, rather than merely observing that DATA is still gated.
// The state is emitted by the daemon's SIGUSR1 stats line and is sampled for
// every peer before the underlay MTU is restored.
func waitForBaseError(t *testing.T, runners ...*netNSRunner) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, runner := range runners {
			if err := runner.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
				t.Fatalf("read CONTROL path state: %v", err)
			}
		}
		time.Sleep(150 * time.Millisecond)
		errorState := true
		for _, runner := range runners {
			matches := netNSControlPathState.FindAllStringSubmatch(runner.logs.String(), -1)
			if len(matches) == 0 || matches[len(matches)-1][1] != "ERROR" {
				errorState = false
				break
			}
		}
		if errorState {
			return
		}
	}
	for _, runner := range runners {
		t.Logf("runner logs:\n%s", runner.logs.String())
	}
	t.Fatal("BASE failure did not reach CONTROL ERROR state")
}

func waitForControlPathRecovery(t *testing.T, runners ...*netNSRunner) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, runner := range runners {
			if err := runner.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
				t.Fatalf("read recovered CONTROL path state: %v", err)
			}
		}
		time.Sleep(150 * time.Millisecond)
		recovered := true
		for _, runner := range runners {
			matches := netNSControlPathState.FindAllStringSubmatch(runner.logs.String(), -1)
			if len(matches) == 0 || matches[len(matches)-1][1] == "ERROR" {
				recovered = false
				break
			}
		}
		if recovered {
			return
		}
	}
	for _, runner := range runners {
		t.Logf("runner logs:\n%s", runner.logs.String())
	}
	t.Fatal("CONTROL path remained in ERROR after BASE recovery")
}

func waitForPMTU(t *testing.T, runners ...*netNSRunner) {
	t.Helper()
	// Where an oversized probe is dropped remotely each failed candidate is
	// retried three times. With the default 64KiB ceiling, two binary-search
	// passes can therefore take more than a minute on a 1500-byte path.
	started := time.Now()
	deadline := started.Add(180 * time.Second)
	for time.Now().Before(deadline) {
		for _, runner := range runners {
			if err := runner.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
				t.Fatalf("read PMTU stats: %v", err)
			}
		}
		time.Sleep(150 * time.Millisecond)
		confirmed := true
		values := make([]string, 0, len(runners))
		for _, runner := range runners {
			matches := netNSPMTUStats.FindAllStringSubmatch(runner.logs.String(), -1)
			if len(matches) == 0 {
				confirmed = false
				break
			}
			last := matches[len(matches)-1]
			payload, _ := strconv.Atoi(last[1])
			if payload <= 613 || last[2] != "false" {
				confirmed = false
				break
			}
			values = append(values, last[1])
		}
		if confirmed {
			t.Logf("DPLPMTUD confirmed carrier payloads: %s in %s", strings.Join(values, ", "), time.Since(started).Round(time.Millisecond))
			return
		}
	}
	for _, runner := range runners {
		t.Logf("runner logs:\n%s", runner.logs.String())
	}
	t.Fatal("DPLPMTUD did not confirm a carrier payload above BASE")
}

func netNSKeyPair(t *testing.T) (string, string) {
	t.Helper()
	private, err := generatePrivateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	public, err := derivePublicKey(private)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public[:])
}

func controlRecoveryScenario() bool {
	return os.Getenv(netNSControlRecoveryEnv) == "1"
}

func baseRecoveryScenario() bool {
	return os.Getenv(netNSBaseRecoveryEnv) == "1" ||
		os.Getenv("WGF_NETNS_BASE_RECOVERY") == "1" ||
		os.Getenv("WGF_NETNS_BASE_FAILURE") == "1"
}

func noFragmentScenario() bool {
	return os.Getenv(netNSNoFragmentEnv) == "1" || os.Getenv("WGF_NETNS_NO_FRAGMENTATION") == "1"
}

// underlayCapture observes the actual IPv4 packets crossing the veth. The
// kernel's AF_PACKET socket is bound in the target namespace once and remains
// tied to that namespace after the test goroutine returns to its original one.
// This avoids iproute2/tcpdump dependencies while detecting MF/fragment-offset
// bits on the wire.
type underlayCapture struct {
	fd        int
	done      chan struct{}
	closeOne  sync.Once
	mu        sync.Mutex
	packets   int
	fragments int
}

func startUnderlayCapture(t *testing.T, ns netns.NsHandle, ifname string) *underlayCapture {
	t.Helper()
	capture := &underlayCapture{fd: -1, done: make(chan struct{})}
	var setupErr error
	inNetNS(t, ns, func() error {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IP)))
		if err != nil {
			setupErr = err
			return nil
		}
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			_ = unix.Close(fd)
			setupErr = err
			return nil
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: link.Attrs().Index}); err != nil {
			_ = unix.Close(fd)
			setupErr = err
			return nil
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fd)
			setupErr = err
			return nil
		}
		capture.fd = fd
		return nil
	})
	if setupErr != nil {
		t.Fatalf("capture underlay veth: %v", setupErr)
	}
	go capture.readLoop()
	t.Cleanup(capture.close)
	return capture
}

func (c *underlayCapture) readLoop() {
	defer close(c.done)
	buffer := make([]byte, 64<<10)
	for {
		n, _, err := unix.Recvfrom(c.fd, buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		c.mu.Lock()
		c.packets++
		if ipv4Fragment(buffer[:n]) {
			c.fragments++
		}
		c.mu.Unlock()
	}
}

func (c *underlayCapture) snapshot() (packets, fragments int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.packets, c.fragments
}

func (c *underlayCapture) close() {
	c.closeOne.Do(func() {
		if c.fd >= 0 {
			_ = unix.Close(c.fd)
		}
		<-c.done
	})
}

func ipv4Fragment(packet []byte) bool {
	if len(packet) < 14 {
		return false
	}
	offset := 14
	etherType := binary.BigEndian.Uint16(packet[12:14])
	// Account for one or more VLAN tags so a tagged veth still gets checked.
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(packet) < offset+4 {
			return false
		}
		etherType = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4
	}
	if etherType != 0x0800 || len(packet) < offset+20 {
		return false
	}
	ihl := int(packet[offset]&0x0f) * 4
	if ihl < 20 || len(packet) < offset+ihl {
		return false
	}
	return binary.BigEndian.Uint16(packet[offset+6:offset+8])&0x3fff != 0
}

func TestIPv4Fragment(t *testing.T) {
	packet := make([]byte, 14+20)
	packet[12], packet[13] = 0x08, 0x00
	packet[14] = 0x45
	if ipv4Fragment(packet) {
		t.Fatal("unfragmented IPv4 packet reported as fragmented")
	}
	packet[14+6] = 0x20 // MF flag.
	if !ipv4Fragment(packet) {
		t.Fatal("MF IPv4 packet not detected")
	}
	packet[14+6], packet[14+7] = 0, 1 // non-zero fragment offset.
	if !ipv4Fragment(packet) {
		t.Fatal("offset IPv4 packet not detected")
	}
}

func htons(value uint16) uint16 {
	return value<<8 | value>>8
}

func writeNetNSConfig(t *testing.T, path, private, peer string, port int, endpoint, allowed string) string {
	t.Helper()
	mtu := 9612
	if raw := os.Getenv("WGF_NETNS_MTU"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid WGF_NETNS_MTU %q", raw)
		}
		mtu = parsed
	}
	extra := ""
	if slots := os.Getenv("WGF_NETNS_SLOTS"); slots != "" {
		extra = "WGFReassemblySlots = " + slots + "\n"
	}
	contents := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %d\nMTU = %d\n"+extra+"\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", private, port, mtu, peer, endpoint, allowed)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func replaceEnv(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
