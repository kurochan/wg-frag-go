# wg-frag-go

`wg-frag-go` is a userspace Layer 3 fragmentation and packing shim built
around `wireguard-go`. It preserves a large inner IP MTU over a smaller
underlay without changing WireGuard's handshake, Noise protocol, encryption,
key rotation, endpoint roaming, or replay protection.

The shim runs between a native L3 TUN and WireGuard's plaintext device:

```text
inner IPv4/IPv6 packet
        |
        v
WGF DATA records packed into a carrier
        |
        v
wireguard-go
        |
        v
encrypted UDP/IP underlay
```

Both endpoints must run WGF for DATA traffic. A stock WireGuard endpoint can
still establish the underlying WireGuard session, but it does not understand
WGF carriers.

## Features

- Inner MTU from 1280 through 9612 bytes (default: 1500).
- Up to 16 fragments per inner packet.
- Multiple records from different inner packets can share one carrier.
- Fixed-size reassembly and reorder queues with bounded memory and no hot-path
  allocation.
- A hidden, deterministic IPv6 carrier address per WireGuard peer. The carrier
  is not exposed as an interface address, route, or user-configured AllowedIP.
- CONTROL carriers encoded with protobuf (edition 2024) for capability exchange,
  sequence reset, peer MTU exchange, reachability checks, and PMTU discovery.
- Runtime DPLPMTUD based on RFC 8899. DATA starts at the 613-byte base carrier
  payload and grows after successful probes; a failed confirmation returns to
  the base and retries with backoff.
- Linux outer-UDP sockets that reject IP fragmentation and report local
  `EMSGSIZE` failures to the PMTU engine. `recvmmsg`/`sendmmsg` and UDP GSO/GRO
  are used when available, with automatic fallback.
- WireGuard-style multi-peer configuration and `AllowedIPs` longest-prefix
  selection plus ingress source validation.
- `wgf` and `wgf-quick` command-line workflows, a per-interface Unix control
  socket, gRPC control API, structured `slog` logging, and systemd units.

The wire format and state-machine rules are documented in
[`docs/protocol.md`](docs/protocol.md).

## Requirements

The runtime targets Linux on amd64 and arm64. Building the binary
requires Go 1.26.4 or newer. Running an interface normally requires root or
the capabilities needed to create a TUN device, configure routes and rules,
set the UDP socket mark, and request socket buffers.

## Build and install

```sh
make build
sudo install -m 0755 bin/wgf /usr/bin/wgf
sudo ln -sf wgf /usr/bin/wgf-quick
sudo install -d -m 0700 /etc/wg-frag
sudo install -m 0644 dist/systemd/wgf@.service dist/systemd/wgf.target \
  /usr/lib/systemd/system/
sudo systemctl daemon-reload
```

The complete installation and operations guide is
[`docs/install.md`](docs/install.md).

Protobuf generation uses the pinned tools in `tools/go.mod`:

```sh
make proto
make proto-check
go tool -modfile=tools/go.mod buf lint
```

## Configuration

Configuration follows the familiar WireGuard INI shape. A minimal interface
contains an address, a private key, and one or more peers:

```ini
[Interface]
Address = 10.0.0.1/24
PrivateKey = <base64-private-key>
ListenPort = 51820
MTU = 1500

[Peer]
PublicKey = <base64-peer-public-key>
Endpoint = example.net:51820
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
PresharedKey = <base64-preshared-key>
```

`MTU` is the inner TUN MTU. The configured value must be between 1280 and
9612 bytes; WGF fragments packets that exceed the current carrier payload.
WGF-specific settings control the base and maximum carrier payload, PMTU
discovery, reassembly capacity and lifetime, reorder behavior, and UDP socket
buffers. See the parser and [`docs/protocol.md`](docs/protocol.md) for the
accepted ranges and protocol limits.

`PresharedKey` is optional and uses the standard 32-byte WireGuard preshared
key format. Generate one with `wgf genpsk`.

User `AllowedIPs` are used for outbound peer selection and for validating the
source address of reassembled inbound packets. WGF's hidden carrier addresses
are managed internally and must not be added to the user configuration.

## Commands

```sh
wgf genkey | tee private.key | wgf pubkey
wgf genpsk
wgf check --config /etc/wg-frag/wgf0.conf

# Foreground daemon
sudo wgf run wgf0 --config /etc/wg-frag/wgf0.conf

# wg-quick-style lifecycle (wgf-quick is an executable-name alias)
sudo wgf quick up wgf0
sudo wgf quick down wgf0
sudo wgf quick save wgf0
sudo wgf quick strip wgf0

# systemd lifecycle
sudo systemctl enable --now wgf@wgf0
sudo systemctl stop wgf@wgf0

# Status and configuration
wgf show
wgf show wgf0
wgf show wgf0 path-mtu
wgf show wgf0 stats
wgf showconf wgf0
```

`wgf-quick` is an alias for `wgf quick`; `wgf run` remains a foreground
per-interface daemon. `wgf quick` creates the interface, starts the daemon,
and applies addresses and routes. `Table = auto` provides the WireGuard-style
full-tunnel policy-routing rules and endpoint-route exemption. `Table = off`
leaves route management to the caller.

## Logging and management

The daemon writes structured logs with Go's `log/slog` package. Normal INFO
events are limited to startup, shutdown, configuration changes, forwarding
state changes, and PMTU changes. Packet-level failures are counted and
rate-limited rather than logged individually.

Diagnostic behavior can be adjusted with environment variables:

- `WGF_LOG_LEVEL`: `debug`, `info` (default), `warn`, `error`, or `silent`.
- `WGF_LOG_FORMAT`: `text` (default) or `json`.
- `WGF_CPU_PROFILE`: write a Go CPU profile to the specified path while the
  daemon runs. This is an operator diagnostic and should normally be unset;
  protect the output because it can reveal runtime and workload details.

These are diagnostic environment variables, not configuration-file settings.

Each interface exposes a private Unix socket under
`/run/wg-frag/<interface>.sock` with mode 0600. `wgf show`, `set`,
`setconf`, `addconf`, and `syncconf` use the gRPC `controlapi/v1` service over
that socket. The socket is local-only and is not a network listener.

## Protocol and behavior

WGF DATA and CONTROL carriers are never mixed. DATA records have a 12-byte
header containing the fragment index/count, wire lane, 16-bit data session,
32-bit lane sequence, and original packet offset. The carrier payload contains
as many complete records as fit; a record count is not transmitted.

The sender drains each TUN batch to `EAGAIN` and flushes all partial carriers
immediately; there is no packing-delay timer. Reassembly waits for all
fragments of a packet, while reorder is applied independently to completed
packets within each lane. A reorder gap is held for at most the configured
short delay (10 ms by default) and then skipped.

Native IPv4 fragments and IPv6 Fragment Header packets are rejected and counted.
WGF does not retransmit inner packets. WireGuard provides authentication,
confidentiality, and outer replay protection; WGF validates carrier structure,
peer identity, session state, sequence state, and user `AllowedIPs` after
decryption.

## Testing

The normal test suite, lint, and race checks do not require a privileged Linux
environment:

```sh
go test ./...
make lint
make test-race
```

Fuzz targets cover configuration parsing, inner IP parsing, carrier and
CONTROL decoding, and receiver input handling:

```sh
make fuzz
FUZZTIME=5m make fuzz
```

Privileged Linux integration tests are opt-in. They create temporary network
namespaces, veth links, TUN devices, and WireGuard peers entirely from Go;
they do not mount host directories or invoke `ip`, `tc`, or `tcpdump`:

```sh
make test-netns
make test-netns-control-recovery
make test-netns-base-recovery
make test-netns-no-fragment
make bench-netns
```

The reproducible measurement procedure and retained Linux observations are in
[`docs/benchmark.md`](docs/benchmark.md).

The tests require Linux networking capabilities (normally `CAP_NET_ADMIN` and
`CAP_NET_RAW`) and `/dev/net/tun`. Fault-injection variants are selected by the
`WGF_NETNS_*` environment variables described in the Makefile and test names.

## Security model

WireGuard remains the cryptographic and peer-authentication boundary. WGF
treats authenticated peers as potentially malformed: all carrier lengths,
record ranges, protobuf limits, session transitions, reassembly bounds, and
source prefixes are checked before a packet reaches the TUN. See
[`docs/threat-model.md`](docs/threat-model.md) for the detailed trust boundary
and operational assumptions.

## License

This project is distributed under the MIT License; see [`LICENSE`](LICENSE).

Security reports are handled on a best-effort basis without warranty. Use the
private reporting instructions in [`SECURITY.md`](SECURITY.md) rather than
publishing sensitive details in an issue.

## Project relationship

wg-frag-go uses the WireGuard protocol and the `wireguard-go` implementation,
but it is an independent project and is not affiliated with, endorsed by, or
part of the WireGuard project.
