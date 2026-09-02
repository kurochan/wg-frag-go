# Monitoring

WGF can expose a process-wide endpoint in OpenMetrics text format. A process
running one interface and a manager process running several interfaces use the
same metric names and label schema. The endpoint is disabled unless explicitly
enabled.

## Enable the endpoint

For `wgf run` and `wgf quick`, enable metrics in the interface configuration:

```ini
WGFMetrics = on
WGFMetricsListen = auto
```

`auto` opens TCP listeners on both `127.0.0.1` and `::1`, using the effective
WireGuard `ListenPort`. If one loopback family is unavailable, WGF keeps the
other listener. To use another address, provide one or more comma-separated
IP-literal `host:port` values. Explicit non-loopback listeners expose the
endpoint without authentication or TLS and must be protected by the host's
network policy.

The manager uses equivalent process-level flags:

```sh
wgf manager --metrics \
  --metrics-listen 127.0.0.1:9910 \
  --metrics-listen '[::1]:9910'
```

Manager listeners must be explicit IP-literal addresses with non-zero ports.
The per-interface `auto` setting is not available before a manager has an
interface and a WireGuard listen port.

The endpoint serves `GET /metrics` and `HEAD /metrics` with the OpenMetrics
content type. It has no authentication or TLS. Keep listeners on loopback
unless a protected local collector requires another address.

## Scrape behavior

WGF takes a metrics snapshot when `/metrics` is requested. The completed
response is reused for up to one second, so repeated scrapes do not run a
collector for every request. There is no background metrics collector in the
packet path. A scrape failure returns HTTP 500 and does not stop the tunnel.

## Metric selection

`WGFMetricsInclude` and `WGFMetricsExclude` (or the manager's
`--metrics-include` and `--metrics-exclude` flags) select canonical emitted
sample names. An include list limits the result; an exclude list always takes
precedence. Each pattern may contain at most one `*`, matching any sequence of
characters. `?`, character classes, escapes, and regular expressions are not
supported. Unknown or unmatched patterns reject the configuration or manager
startup.

For example:

```ini
WGFMetrics = on
WGFMetricsInclude = wgf_tx_*,wgf_rx_*,wgf_peer_pmtu_*
WGFMetricsExclude = wgf_*_drops_total
```

## Labels and identity

Metrics are grouped by scope:

| Scope | Metrics | Labels |
| --- | --- | --- |
| Process | `wgf_build_info` | `version`, `commit`, `go_version` |
| Process | `wgf_manager_interfaces` | none |
| Interface | `wgf_tx_*`, `wgf_rx_*`, `wgf_carrier_*`, `wgf_control_*`, `wgf_preconfirm_drops_total`, `wgf_reassembly_expirations_total`, `wgf_udp_socket_drops_total` | `interface`, `interface_id` |
| Peer | `wgf_peer_pmtu_*`, `wgf_peer_data_forwarding_enabled` | `interface`, `interface_id`, `peer_id` |

Process metrics never receive an artificial interface label. Interface and
peer series use the same labels whether the process owns one interface or
many. `interface_id` is stable for a WireGuard public-key identity. A peer's
configured `WGFPeerID` is used when present; otherwise WGF derives a stable
opaque 16-character ID from the peer public key.

Counters continue across runtime generations and normal delete/recreate
cycles within one process. A process restart starts a new counter lifetime.

## Metric inventory

The following names are the canonical selector inputs and emitted sample
names.

### Process

| Name | Type | Meaning |
| --- | --- | --- |
| `wgf_build_info` | gauge | Build and Go runtime information. |
| `wgf_manager_interfaces` | gauge | Interfaces currently managed by the process. |

### Interface

| Name | Type | Meaning |
| --- | --- | --- |
| `wgf_tx_carriers_total` | counter | DATA carriers transmitted. |
| `wgf_tx_packet_drops_total` | counter | Inner packets dropped before transmission. |
| `wgf_tx_native_fragment_drops_total` | counter | Native IP fragments dropped on transmit. |
| `wgf_tx_route_drops_total` | counter | Packets dropped because no peer route matched. |
| `wgf_tx_peer_mtu_drops_total` | counter | Packets dropped because they exceed the peer MTU. |
| `wgf_tx_ptb_sent_total` | counter | Packet Too Big messages sent to the native TUN. |
| `wgf_rx_data_carriers_total` | counter | DATA carriers received. |
| `wgf_rx_inner_packets_total` | counter | Reassembled packets delivered to the native TUN. |
| `wgf_rx_packet_rejects_total` | counter | Received packets rejected by the shim. |
| `wgf_rx_native_fragment_drops_total` | counter | Native IP fragments dropped on receive. |
| `wgf_rx_source_spoof_drops_total` | counter | Packets dropped by source validation. |
| `wgf_rx_native_write_drops_total` | counter | Packets dropped because the native TUN could not accept them. |
| `wgf_carrier_queue_overflows_total` | counter | DATA carrier queue overflows. |
| `wgf_control_queue_drops_total` | counter | CONTROL descriptors dropped because the scheduler was full. |
| `wgf_control_exploratory_evictions_total` | counter | Exploratory CONTROL descriptors evicted for critical messages. |
| `wgf_control_coalesces_total` | counter | CONTROL descriptors coalesced by the scheduler. |
| `wgf_control_rate_suppression_episodes_total` | counter | CONTROL rate-limit suppression episodes. |
| `wgf_control_materialization_drops_total` | counter | CONTROL descriptors dropped during materialization. |
| `wgf_control_ingress_rate_limited_total` | counter | Inbound CONTROL messages rate limited. |
| `wgf_preconfirm_drops_total` | counter | Packets dropped before the CONTROL gate opened. |
| `wgf_reassembly_expirations_total` | counter | Incomplete reassemblies that expired. |
| `wgf_udp_socket_drops_total` | counter | Kernel-reported UDP receive drops. |

### Peer

| Name | Type | Meaning |
| --- | --- | --- |
| `wgf_peer_pmtu_carrier_payload_bytes` | gauge | Confirmed carrier payload limit. |
| `wgf_peer_pmtu_searching` | gauge | `1` while PMTU search is in progress, otherwise `0`. |
| `wgf_peer_data_forwarding_enabled` | gauge | `1` when DATA forwarding is enabled, otherwise `0`. |
