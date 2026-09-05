//go:build linux && integration

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func logNetNSTCPInfo(t *testing.T, connection *net.TCPConn) {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Logf("TCP_INFO unavailable: %v", err)
		return
	}
	var info *unix.TCPInfo
	var infoErr error
	if err := raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		t.Logf("TCP_INFO unavailable: %v", err)
		return
	}
	if infoErr != nil {
		t.Logf("TCP_INFO unavailable: %v", infoErr)
		return
	}
	t.Logf("TCP sender: total_retrans=%d rtt_us=%d rttvar_us=%d snd_cwnd=%d", info.Total_retrans, info.Rtt, info.Rttvar, info.Snd_cwnd)
}

// measureNetNSLatency samples a small inner UDP flow before and after load.
// These are RTT samples, not one-way delay or a loaded latency percentile.
func measureNetNSLatency(t *testing.T, from, to netns.NsHandle, phase string) {
	t.Helper()
	server := listenUDPInNS(t, to, "10.2.0.1:49011")
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := server.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	defer func() {
		_ = server.Close()
		<-done
	}()
	client := dialUDPInNS(t, from, "10.1.0.1:0", "10.2.0.1:49011")
	defer func() { _ = client.Close() }()
	var payload, reply [32]byte
	samples := make([]time.Duration, 0, 24)
	for sequence := range 24 {
		binary.BigEndian.PutUint32(payload[:4], uint32(sequence))
		started := time.Now()
		if err := client.SetDeadline(started.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(payload[:]); err != nil {
			t.Fatal(err)
		}
		for {
			n, err := client.Read(reply[:])
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					break
				}
				t.Fatal(err)
			}
			if n == len(reply) && reply == payload {
				samples = append(samples, time.Since(started))
				break
			}
		}
	}
	if len(samples) == 0 {
		t.Fatal("all UDP latency probes timed out")
	}
	slices.Sort(samples)
	t.Logf("UDP RTT %s: received=%d/24 min=%s p50=%s p95=%s max=%s", phase, len(samples), samples[0], samples[len(samples)/2], samples[(len(samples)-1)*95/100], samples[len(samples)-1])
}

// applyNetNSImpairment changes only the test's disposable underlay veth. Both
// directions use the same settings; removing the namespace removes the qdisc.
func applyNetNSImpairment(t *testing.T, ns netns.NsHandle, name string) {
	t.Helper()
	latency := netNSDurationMicros(t, "WGF_NETNS_DELAY")
	jitter := netNSDurationMicros(t, "WGF_NETNS_JITTER")
	if jitter > latency {
		t.Fatal("WGF_NETNS_JITTER must not exceed WGF_NETNS_DELAY")
	}
	var loss float64
	if raw := os.Getenv("WGF_NETNS_LOSS_PERCENT"); raw != "" {
		var err error
		loss, err = strconv.ParseFloat(raw, 32)
		if err != nil || math.IsNaN(loss) || loss < 0 || loss > 100 {
			t.Fatalf("invalid WGF_NETNS_LOSS_PERCENT %q; want 0..100", raw)
		}
	}
	var rate uint64
	if raw := os.Getenv("WGF_NETNS_RATE_MBIT"); raw != "" {
		mbit, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || mbit == 0 || mbit > 100000 {
			t.Fatalf("invalid WGF_NETNS_RATE_MBIT %q; want 1..100000", raw)
		}
		rate = mbit * 125000 // Netem's rate is in bytes per second.
	}
	if latency == 0 && loss == 0 && rate == 0 {
		return
	}
	inNetNS(t, ns, func() error {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		qdisc := netlink.NewNetem(netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		}, netlink.NetemQdiscAttrs{
			Latency: latency, Jitter: jitter, Loss: float32(loss),
			Limit: 10000, Rate64: rate,
		})
		if err := netlink.QdiscReplace(qdisc); err != nil {
			return fmt.Errorf("configure test netem: %w", err)
		}
		return nil
	})
	t.Logf("underlay %s netem: delay_us=%d jitter_us=%d loss_percent=%g rate_bytes_per_second=%d limit=10000", name, latency, jitter, loss, rate)
}

func netNSDurationMicros(t *testing.T, key string) uint32 {
	t.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return 0
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration < 0 || duration.Microseconds() > math.MaxUint32 || (duration > 0 && duration < time.Microsecond) {
		t.Fatalf("invalid %s %q; want a nonnegative duration representable in microseconds", key, raw)
	}
	return uint32(duration.Microseconds())
}
