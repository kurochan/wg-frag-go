//go:build linux && integration

package main

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// TestRawVethNetNS measures the direct veth path using the same namespace and
// TCP helpers as the WireGuard and WGF integration tests.
func TestRawVethNetNS(t *testing.T) {
	if os.Getenv("WGF_RUN_NETNS") != "1" {
		t.Skip("set WGF_RUN_NETNS=1 to run privileged Linux netns integration")
	}
	t.Setenv(netNSRawEnv, "1")

	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	vethA, vethB := "rawa"+suffix, "rawb"+suffix
	runnerA := startNetNSRunner(t, "rawa", "", "")
	runnerB := startNetNSRunner(t, "rawb", "", "")

	createVeth(t, vethA, vethB, runnerA.ns, runnerB.ns)
	runnerA.vethName = vethA
	runnerB.vethName = vethB
	configureVeth(t, runnerA.ns, vethA, "198.18.0.1/30")
	configureVeth(t, runnerB.ns, vethB, "198.18.0.2/30")
	runnerA.activate(t)
	runnerB.activate(t)

	bytes := int64(64 << 20)
	if raw := os.Getenv("WGF_NETNS_BENCH_BYTES"); raw != "" {
		var err error
		bytes, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || bytes <= 0 {
			t.Fatalf("invalid WGF_NETNS_BENCH_BYTES %q", raw)
		}
	}
	measureTCPAddresses(t, runnerA.ns, runnerB.ns, "198.18.0.1:0", "198.18.0.2:49002", bytes, netNSBenchStreams(t))
}
