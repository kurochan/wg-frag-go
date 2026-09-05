# Local Lima benchmark and validation

This document preserves the local, Lima-based Linux integration procedure.
It is useful for development and regression checks, but its measurements are
not the primary end-to-end reference values; see [`benchmark.md`](benchmark.md)
for the AWS reference results.

The 2026-09-05 Lima evidence is preserved in [`docs/benchmarks/`](benchmarks/);
these are development observations rather than replacements for the AWS
reference.

| Scope | Structured results | Raw logs |
| --- | --- | --- |
| Initial development comparison, including rejected experiments and startup failures | [results](benchmarks/lima-2026-09-05.json) | [logs and commands](benchmarks/lima-2026-09-05-raw.tar.gz) |
| UDP batch 128/256, before the later CONTROL startup investigation | [results](benchmarks/lima-2026-09-05-udp-batch.json) | [logs](benchmarks/lima-2026-09-05-udp-batch-raw.tar.gz) |
| CONTROL retry fix | [startup results](benchmarks/lima-2026-09-05-control-startup.json) | [diagnostic logs](benchmarks/lima-2026-09-05-control-startup-raw.tar.gz) |
| Send-buffer headroom comparison | [throughput results](benchmarks/lima-2026-09-05-headroom.json) | [logs](benchmarks/lima-2026-09-05-headroom-raw.tar.gz) |

The adopted Linux runtime default is `WGFUDPBatchSize=256`; `128` remains an
explicit tuning option. The capability startup fast-retry window is 130
seconds. These settings are independent of the configured inner MTU.

## 1. Prepare the Lima VM

On macOS / Apple Silicon, use a dedicated Lima VM without a host filesystem
mount. Cross-build the Linux test binary on the host and transfer it to `/tmp`
in the VM with `limactl copy`.

```bash
limactl start -y \
  --name=wgf-bench \
  --cpus=8 \
  --memory=12 \
  --disk=50 \
  --mount-none \
  --containerd=none \
  --vm-type=vz \
  template:ubuntu
```

Requirements:

- Linux arm64
- `/dev/net/tun`
- `CAP_NET_ADMIN` (normally through `sudo`)
- `WGF_RUN_NETNS=1`

Confirm that no host share is present:

```bash
limactl shell wgf-bench -- sh -lc \
  'uname -a; go version; findmnt -t virtiofs,9p,fuse || true'
```

## 2. Build and transfer the integration binary

Build the Linux arm64 test binary on the host.

```bash
repo_dir="$(git rev-parse --show-toplevel)"
tmp_dir="${TMPDIR:-/tmp}"
cd "$repo_dir"
GOCACHE="$tmp_dir/wgf-go-build-cache" \
  GOOS=linux GOARCH=arm64 \
  go test -c -tags=integration \
  -o "$tmp_dir/wgf-netns-integration.test" \
  ./cmd/wgf

limactl copy "$tmp_dir/wgf-netns-integration.test" \
  wgf-bench:/tmp/wgf-netns-integration.test
```

## 3. Run integration and fault-injection tests

Run the standard WGF integration test:

```bash
limactl shell wgf-bench -- sudo sh -lc '
  chmod 0755 /tmp/wgf-netns-integration.test
  WGF_RUN_NETNS=1 \
    /tmp/wgf-netns-integration.test \
    -test.v -test.run "^TestWGFNetNSWireGuardUDP$"
'
```

The test creates temporary network namespaces, veth pairs, native TUN devices,
and wireguard-go peers. It verifies bidirectional forwarding of inner UDP
payloads of 1472 and 9584 bytes. On normal completion and test failure it
cleans up child process groups, namespaces, veth devices, TUN devices, and
sockets.

Run the direct veth and plain wireguard-go baseline comparisons in the VM:

```bash
limactl shell wgf-bench -- sudo sh -lc '
  WGF_RUN_NETNS=1 WGF_NETNS_BENCH_BYTES=67108864 \
    /tmp/wgf-netns-integration.test \
    -test.v -test.run "^TestRawVethNetNS$"

  WGF_RUN_NETNS=1 WGF_NETNS_BASELINE_MTU=1420 \
    WGF_NETNS_BENCH_BYTES=67108864 \
    /tmp/wgf-netns-integration.test \
    -test.v -test.run "^TestWireGuardGoBaselineNetNS$"
'
```

Fault-injection variants:

```bash
limactl shell wgf-bench -- sudo sh -lc '
  chmod 0755 /tmp/wgf-netns-integration.test

  WGF_RUN_NETNS=1 WGF_NETNS_CONTROL_RECOVERY=1 \
    /tmp/wgf-netns-integration.test \
    -test.v -test.run "^TestWGFNetNSWireGuardUDP$"

  WGF_RUN_NETNS=1 WGF_NETNS_BASE_FAILURE_RECOVERY=1 \
    /tmp/wgf-netns-integration.test \
    -test.v -test.run "^TestWGFNetNSWireGuardUDP$"

  WGF_RUN_NETNS=1 WGF_NETNS_NO_UNDERLAY_FRAGMENTATION=1 \
    /tmp/wgf-netns-integration.test \
    -test.v -test.run "^TestWGFNetNSWireGuardUDP$"
'
```

With `WGF_NETNS_REQUIRE_PMTU=1`, the TCP measurement starts only after both
sides confirm a carrier payload larger than the 613-byte BASE payload. For a
WGF MTU comparison, set `WGF_NETNS_MTU` to the desired value (for example
1500, 3000, 6000, or 9600).

## 4. Measure TCP inner goodput

```bash
limactl shell wgf-bench -- sudo sh -lc '
  WGF_RUN_NETNS=1 \
  WGF_NETNS_REQUIRE_PMTU=1 \
  WGF_NETNS_BENCH_BYTES=67108864 \
    /tmp/wgf-netns-integration.test \
    -test.v -test.run "^TestWGFNetNSWireGuardUDP$"
'
```

For repeated comparisons on a known path, optionally set
`WGF_NETNS_MAX_CARRIER_PAYLOAD=1400` on both builds to cap the PMTU search.
This sets the normal `WGFMaxCarrierPayload` configuration; CONTROL exchange
and PMTU confirmation still run. Keep `WGF_NETNS_REQUIRE_PMTU=1` and verify
that both runs report the same confirmed payload. Omit the ceiling when
validating discovery from the production default. This does not change the
inner MTU.

`WGF_NETNS_UDP_BATCH_SIZE` optionally sets `WGFUDPBatchSize` on both endpoints
for UDP batch tuning. Omit it to exercise the production default. Keep the
inner MTU, socket buffer, GOMAXPROCS, and PMTU ceiling identical when comparing
batch sizes. This setting changes the packet batch capacity, not the kernel
socket buffer in bytes (`WGFSocketBuffer`).

To approximate an inter-site path, the integration test can install netem on
both disposable underlay veth devices. For example:

```bash
limactl shell wgf-bench -- sudo env \
  WGF_RUN_NETNS=1 WGF_NETNS_MTU=1500 WGF_NETNS_REQUIRE_PMTU=1 \
  WGF_NETNS_MAX_CARRIER_PAYLOAD=1400 WGF_NETNS_DELAY=20ms \
  WGF_NETNS_JITTER=5ms WGF_NETNS_RATE_MBIT=200 \
  WGF_NETNS_BENCH_BYTES=8388608 \
  /tmp/wgf-netns-integration.test -test.v \
  -test.run '^TestWGFNetNSWireGuardUDP$'
```

The delay and jitter apply **per direction** (approximately 40ms base RTT in
this example). `WGF_NETNS_LOSS_PERCENT=0.1` optionally adds 0.1% netem loss
in each direction. Repeat with `WGF_NETNS_MTU=9600` for larger inner packets;
both inner MTUs require WGF fragmentation at a carrier payload of 1400 bytes.
The queue limit is 10000; the rate is optional. Settings apply during CONTROL
and DATA traffic, and namespace cleanup removes the qdiscs. With delay set,
the test reports 24 small UDP RTT samples before and after TCP, including
timeouts; these are not loaded-latency percentiles. GSO/GRO remain enabled
when supported, so netem loss on a veth skb is not necessarily independent
loss of individual wire datagrams. Record that distinction when interpreting
the results. Use smaller byte counts than the local benchmark so a slow WAN
case stays within the TCP test's 60-second deadline. The 8 MiB example measures
a short transfer including slow start, not steady-state WAN capacity. Increase
the byte count for sustained-load measurements after a successful smoke test.

For startup diagnosis, `WGF_NETNS_STARTUP_ONLY=1` stops after CONTROL readiness,
the UDP echo check, and any requested PMTU confirmation; it skips RTT sampling
and TCP measurement. The capability fast-retry window is 130 seconds; this is
separate from the CONTROL readiness wait and the TCP measurement's 60-second
deadline. `WGF_NETNS_LOG_RUNNERS=1` preserves endpoint logs even on success.
Combine it with `WGF_LOG_LEVEL=debug` to include WireGuard handshake events.
Do not use this logging mode for throughput comparisons.

Measurement rules:

- Exclude the first run as warm-up.
- Run each condition at least five times.
- Run A/B conditions alternately in the same time window without rebooting the
  VM.
- Record the start time, commit or diff hash, VM specification, `uname -a`,
  `go version`, MTUs, socket buffer, confirmed carrier payload, GSO/GRO state,
  drops, expirations, queue overflows, and whether child processes remain.
- Report median, minimum, and maximum throughput. Do not treat a single run as
  a general performance limit.

`inner_gbps` counts reconstructed inner TCP bytes. Preserve raw output instead
of manually transcribing it.

## 5. Historical local results

The following values were measured on 2026-08-05 using three Lima VMs (6 CPUs /
4 GiB on each traffic endpoint and one router), underlay MTU 1500, approximately
0.65 ms RTT, and a single 10-second iperf3 TCP flow. The VMs shared host CPUs,
so these are observations for that environment rather than hardware limits.

| Configuration | Inner goodput |
| --- | ---: |
| Raw underlay TCP | 3.12–3.56 Gbps |
| WGF, inner MTU 1420 | 3.64–3.66 Gbps |
| WGF, inner MTU 9612 | 4.03–4.11 Gbps |
| wireguard-go userspace, MTU 1420 | 3.79–3.90 Gbps |
| Kernel WireGuard, MTU 1420 | 3.91–3.93 Gbps |

These historical local values are retained for development comparison and are
not directly comparable with the AWS measurements.

## 6. Quick lifecycle validation

On 2026-08-12, `wgf quick up` and `wgf quick down` were run as root in the
dedicated Lima VM using a real `/dev/net/tun` interface and a loopback UDP
endpoint. Two concurrent `quick down` operations were started while a
two-second `PreDown` hook held the lock. The first teardown returned 0; the
second returned the expected "another quick operation is already in progress"
error. A loopback `tcpdump` captured a 230-byte WireGuard UDP packet before
teardown. The daemon process group, TUN interface, manifest, PID file, and
socket were all absent after teardown.
