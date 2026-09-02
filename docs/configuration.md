# Configuration reference

WGF reads WireGuard-style INI files. On Linux, `wgf quick up <interface>` reads
`/etc/wgf/<interface>.conf`; `wgf run` accepts an explicit path. Validate a
file before starting it. `check` accepts both runtime settings and quick-only
settings, but does not run hooks or inspect the host routing state:

```sh
wgf check --config /etc/wgf/wgf0.conf
```

Start from [`../examples/wgf0.conf.example`](../examples/wgf0.conf.example).
Keep private-key files mode 0600.

## Standard interface settings

| Key | Default | Notes |
| --- | --- | --- |
| `Address` | unset | One or more IPv4 or IPv6 CIDR prefixes. `wgf quick` assigns them to the TUN. |
| `PrivateKey` | required | Base64 WireGuard private key. |
| `ListenPort` | `0` | UDP port; zero lets the operating system select one. |
| `MTU` | `1500` | Inner TUN MTU. Allowed range: 1280 through 9612 bytes. |
| `FwMark` | `0` | Linux outer UDP socket mark. `wgf quick` uses it for full-tunnel loop avoidance. Ignored by macOS `wgf run`. |

On Linux, `wgf quick` additionally handles `Table`, `PreUp`, `PostUp`, `PreDown`,
`PostDown`, and `SaveConfig` using wg-quick-compatible behavior. `DNS` is
ignored with a warning.

## WGF settings

All WGF-specific settings belong in `[Interface]`.

| Key | Default | Accepted values | Effect |
| --- | ---: | --- | --- |
| `WGFMTUDiscovery` | `auto` | `auto` | Enables the v1 DPLPMTUD state machine. Other values are not supported. |
| `WGFMinCarrierPayload` | `613` | At least `max(613, ceil(MTU / 16) + 12)` | BASE carrier payload. Raise it only when the path is known to carry the larger size. |
| `WGFMaxCarrierPayload` | `65432` | `WGFMinCarrierPayload` through `65448` | Local search ceiling. The effective ceiling is also limited by the peer and outer address family. |
| `WGFReassemblySlots` | `4096` | Positive integer | Maximum slot budget used per peer when `WGFPeerReassemblySlots = auto`. Storage is allocated at startup. |
| `WGFPeerReassemblySlots` | `auto` | `auto` or positive integer no larger than `WGFReassemblySlots` | Per-peer reassembly slot limit. |
| `WGFReassemblyLifetime` | `2s` | `100ms` through `60s` | Lifetime measured from the first fragment. Later fragments do not extend it. |
| `WGFReorder` | `true` | `true` or `false` | Enables short completed-packet reordering per wire lane. |
| `WGFReorderMaxDelay` | `10ms` | Positive Go duration | Maximum time to hold a reorder gap before skipping it. |
| `WGFSocketBuffer` | `3145728` | `65536` through `268435456` bytes | Requested size for each outer UDP send and receive buffer. The kernel may cap the effective size. |
| `WGFWorkers` | `auto` | `auto` or positive integer | Accepted for forward compatibility. v1 uses one shim worker and logs a warning for an explicit value. |
| `WGFTUNQueues` | `auto` | `auto` or positive integer | Accepted for forward compatibility. v1 uses one TUN queue and logs a warning for an explicit value. |
| `WGFMetrics` | `off` | `off` or `on` | Enables the unauthenticated OpenMetrics endpoint. |
| `WGFMetricsListen` | `auto` | `auto` or comma-separated IP-literal `host:port` values | `auto` attempts both `127.0.0.1` and `::1` using the effective UDP `ListenPort` number over TCP; either loopback family is sufficient when the other is unavailable. Explicit non-loopback listeners are allowed, but expose metrics without authentication. |
| `WGFMetricsInclude` | unset | Comma-separated metric-name patterns | Limits exposed metrics. A pattern has at most one `*`; empty means every metric. |
| `WGFMetricsExclude` | unset | Comma-separated metric-name patterns | Removes metrics after inclusion. Exclude takes precedence. |

See [Monitoring](monitoring.md) for endpoint behavior, metric selection,
labels, and the metric inventory.

The reassembly allocation for one peer is approximately
`WGFPeerReassemblySlots * MTU`, plus metadata and completed-packet/reorder
storage. `auto` uses `WGFReassemblySlots` for every peer, so reduce the global
slot setting or set an explicit per-peer value when configuring many peers.

`WGFMaxCarrierPayload` is not an assertion that an underlay can carry that
size. DATA starts only after the base probe succeeds, and the PMTU engine uses
the negotiated limit as a search ceiling. The default works for IPv4 and is
one 16-byte WireGuard padding bucket below the IPv6 protocol maximum.

## Peer settings

| Key | Default | Notes |
| --- | --- | --- |
| `PublicKey` | required | Base64 WireGuard public key. Each peer key must be unique. |
| `PresharedKey` | unset | Optional base64 32-byte WireGuard preshared key. |
| `Endpoint` | unset | Hostname or IP address with UDP port. IPv6 endpoints use brackets. |
| `AllowedIPs` | unset | One or more comma-separated CIDR prefixes. Used for outbound peer selection and inbound source validation. |
| `PersistentKeepalive` | `off` | `off` or an integer number of seconds. |
| `WGFPeerID` | derived | Lowercase letters, digits, `_`, or `-`, up to 32 characters | Optional stable `peer_id` label for peer metrics. It must be unique within the interface. When omitted, WGF derives a 16-character opaque ID from the first 10 bytes of BLAKE2s(`"wgf:" || raw_public_key`), encoded as lowercase unpadded base32. |

Do not add WGF's hidden carrier addresses to `AllowedIPs`; WGF derives and
installs them internally.

## Runtime peer updates

`wgf set`, `setconf`, `addconf`, and `syncconf` update only peer settings over
the local control socket. The running interface private key, listen port, and
MTU must still match the supplied configuration; change those by restarting the
interface with `wgf quick` or `wgf run`.

The public gRPC service and its multi-interface manager are documented in the
[Control API reference](control-api.md). The API uses the same interface and
peer settings, but address assignment and route policy remain outside the API.
