# Local Lima benchmark and validation

This document preserves the local, host-based Linux integration procedure.
It is useful for development and regression checks, but its measurements are
not the primary end-to-end reference values; see [`benchmark.md`](benchmark.md)
for the AWS reference results.

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
WGF_RUN_NETNS=1 WGF_NETNS_CONTROL_RECOVERY=1 \
  go test -tags=integration -count=1 \
  -run '^TestWGFNetNSWireGuardUDP$' ./cmd/wgf

WGF_RUN_NETNS=1 WGF_NETNS_BASE_FAILURE_RECOVERY=1 \
  go test -tags=integration -count=1 \
  -run '^TestWGFNetNSWireGuardUDP$' ./cmd/wgf

WGF_RUN_NETNS=1 WGF_NETNS_NO_UNDERLAY_FRAGMENTATION=1 \
  go test -tags=integration -count=1 \
  -run '^TestWGFNetNSWireGuardUDP$' ./cmd/wgf
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
