# Linux benchmark and validation

This document keeps the primary benchmark results and the detailed AWS
reference data. The local Lima procedure is in
[`benchmark-local.md`](benchmark-local.md). The measurements are reference
observations, not hardware limits or a guarantee of Internet throughput.

## At a glance

### Primary environment

The primary measurement ran on 2026-08-12 in two temporary Linux network
namespaces on one dedicated four-vCPU Ubuntu 26.04 AWS instance. The namespaces
were connected by a veth pair with MTU 1500 in both directions. There was no
external network hop and no `tc` impairment.

Each result below is one 256 MiB TCP single-flow transfer after setup.
`inner_gbps` counts reconstructed inner bytes.

### Primary results

| Path | Inner MTU | Confirmed carrier payload | TCP single-flow |
| --- | ---: | ---: | ---: |
| Direct veth | — | — | 57.232 Gbps |
| wireguard-go baseline | 1420 | — | 3.959 Gbps |
| WGF | 1500 | 1400 bytes | 3.621 Gbps |
| WGF | 3000 | 1400 bytes | 4.858 Gbps |
| WGF | 6000 | 1400 bytes | 5.274 Gbps |
| WGF | 9600 | 1400 bytes | 5.378 Gbps |

The WGF cases passed bidirectional UDP forwarding checks at each configured
inner MTU. The measured setup run converged to a 1400-byte carrier payload in
approximately 62–63 seconds. The baseline is standard wireguard-go userspace;
the namespace test did not use a kernel WireGuard module.

## Reproduce the primary measurement

The Linux integration tests create and clean up the temporary namespaces, veth
pair, TUN devices, sockets, and child process groups.

```bash
WGF_RUN_NETNS=1 WGF_NETNS_BENCH_BYTES=268435456 \
  go test -tags=integration -count=1 -run '^TestRawVethNetNS$' ./cmd/wgf

WGF_RUN_NETNS=1 WGF_NETNS_BASELINE_MTU=1420 \
  WGF_NETNS_BENCH_BYTES=268435456 \
  go test -tags=integration -count=1 \
  -run '^TestWireGuardGoBaselineNetNS$' ./cmd/wgf

WGF_RUN_NETNS=1 WGF_NETNS_MTU=9600 WGF_NETNS_REQUIRE_PMTU=1 \
  WGF_NETNS_BENCH_BYTES=268435456 \
  go test -tags=integration -count=1 \
  -run '^TestWGFNetNSWireGuardUDP$' ./cmd/wgf
```

Change `WGF_NETNS_MTU` to 1500, 3000, or 6000 to reproduce the other WGF
rows. The test requires Linux, `/dev/net/tun`, and `CAP_NET_ADMIN`.

## Detailed AWS reference measurements

### Cross-region setup

On 2026-08-12, two dedicated four-vCPU `c8i.xlarge` instances ran Ubuntu
26.04, Linux `7.0.0-1006-aws`, and x86_64. They communicated over the public
IPv4 path between `ap-northeast-2` and `ap-northeast-1`. The underlay PMTU was
1500 bytes and RTT was approximately 33–35 ms. `iperf3` ran for eight seconds
with one TCP stream (`-P 1`) or four parallel streams (`-P 4`). Unless noted,
each value is a single run.

The WGF binary was built from the working tree and transferred to both
instances. Kernel WireGuard used its standard 1420-byte interface MTU. WGF
used the indicated inner MTU and did not depend on underlay IP fragmentation.

### No impairment

| Path | Inner MTU | RTT average | TCP single | Retransmits | TCP four parallel | Retransmits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Public path | — | 35.14 ms | 0.84 Gbps | 0 | 3.03 Gbps | 895 |
| Kernel WireGuard | 1420 | 33.11 ms | 0.87 Gbps | 340 | 3.12 Gbps | 39 |
| WGF | 1300 | 33.25 ms | 0.71 Gbps | 0 | 2.79 Gbps | 0 |
| WGF | 1500 | 34.07 ms | 0.71 Gbps | 0 | 2.83 Gbps | 271 |
| WGF | 3000 | 33.85 ms | 0.71 Gbps | 0 | 2.52 Gbps | 289 |
| WGF | 6000 | 34.05 ms | 0.70 Gbps | 0 | 2.74 Gbps | 23 |
| WGF | 9600 | 34.08 ms | 0.70 Gbps | 0 | 2.74 Gbps | 5 |

WGF MTU 3000 was repeated five times for a noise check: 0.734, 0.733,
0.736, 0.738, and 0.739 Gbps (median 0.736 Gbps).

### One-sided 0.1% underlay loss

`tc netem loss 0.1%` was applied temporarily to the underlay NIC on the
`ap-northeast-1` endpoint. The impairment was one-sided and did not target
WGF's inner TUN traffic.

| Path | Inner MTU | RTT average | TCP single | Retransmits | TCP four parallel | Retransmits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Public path | — | 32.57 ms | 0.85 Gbps | 0 | 3.08 Gbps | 1,400 |
| WGF | 1300 | 33.83 ms | 0.70 Gbps | 0 | 2.73 Gbps | 0 |
| WGF | 3000 | 33.97 ms | 0.737 Gbps (median of 5) | 0 | 2.72 Gbps | 2,453 |
| WGF | 6000 | 34.11 ms | 0.75 Gbps | 0 | 2.90 Gbps | 0 |
| WGF | 9600 | 33.96 ms | 0.75 Gbps | 0 | 2.86 Gbps | 510 |

The MTU 3000 median used 0.731, 0.741, 0.737, 0.739, and 0.735 Gbps. Its
four-stream value was a separate run. WGF MTU 1500 was not measured in this
matrix.

### One-sided 1% underlay loss

`tc netem loss 1%` was applied temporarily to the same underlay NIC. This is a
one-sided physical-NIC impairment, not a measured end-to-end loss percentage.
The qdisc was restored to `mq` with `fq_codel` children during cleanup.

| Path | Inner MTU | RTT average | TCP single | Retransmits | TCP four parallel | Retransmits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Public path | — | 34.36 ms | 0.90 Gbps | 0 | 3.01 Gbps | 2,733 |
| WGF | 1300 | 34.04 ms | 0.68 Gbps | 0 | 2.25 Gbps | 435 |
| WGF | 1500 | 33.95 ms | 0.69 Gbps | 0 | 2.25 Gbps | 1,374 |
| WGF | 3000 | 33.97 ms | 0.70 Gbps | 0 | 2.44 Gbps | 306 |
| WGF | 6000 | 33.93 ms | 0.70 Gbps | 0 | 2.62 Gbps | 292 |
| WGF | 9600 | 33.97 ms | 0.71 Gbps | 0 | 2.63 Gbps | 357 |

Ping loss was 0% in the ten-packet samples. Retransmit columns are the
`iperf3` TCP sender counters, not packet-loss percentages. This loss matrix
was not repeated enough to establish a stable MTU ordering.

## Core and lifecycle measurements

### Receiver core

On 2026-08-12, a dedicated Linux arm64 Lima VM ran
`go test -run='^$' -bench='BenchmarkReceiver(MultiLane|MultiPeer|Construction)$'
-benchmem -benchtime=2s` in `internal/core/datapath`. The hot path performed
zero allocations:

| Benchmark | Result |
| --- | ---: |
| MultiLane, 1 lane | 115.5 ns/op |
| MultiLane, 8 lanes | 117.5 ns/op |
| MultiLane, 64 lanes | 135.3 ns/op |
| MultiLane, 256 lanes | 139.3 ns/op |
| MultiPeer, 1 peer | 109.9 ns/op |
| MultiPeer, 2 peers | 110.2 ns/op |
| MultiPeer, 8 peers | 111.3 ns/op |
| Receiver construction, 16 slots | 124,868 B/op |
| Receiver construction, 64 slots | 437,286 B/op |
| Receiver construction, 256 slots | 1,718,700 B/op |

The complete process reached 86,348 KiB maximum RSS. Construction memory is
bounded by the configured slot count; these are core measurements, not tunnel
throughput.

### Quick lifecycle

On 2026-08-12, `wgf quick up` and `wgf quick down` were run as root in the
dedicated Lima VM with a real `/dev/net/tun` interface and loopback UDP
endpoint. Concurrent teardown was also tested while a two-second `PreDown`
hook held the lock. The first teardown succeeded; the second returned the
expected in-progress error. After teardown, the daemon process group, TUN
interface, manifest, PID file, and socket were absent.

## Scope and notes

- Same-host namespace results isolate the data path; they do not predict WAN
  throughput, NIC RSS, or kernel scheduling on another machine.
- Cross-region rows use a public path and should not be compared directly with
  same-host namespace rows.
- UDP results from the exploratory cross-region runs are omitted because the
  high-rate runs did not complete consistently.
- When adding delay with netem, use a queue limit large enough for the target
  bandwidth-delay product.
- On Ubuntu 26.04, AppArmor may deny wireguard-tools access to the userspace
  UAPI socket. This is separate from WGF's control socket.
