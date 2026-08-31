# wg-frag-go

[日本語](README.ja.md)

`wg-frag-go` (WGF) is a userspace Layer 3 fragmentation and packing shim built
around `wireguard-go`. It preserves a large inner IP MTU over a smaller
underlay without changing WireGuard's handshake, Noise protocol, encryption,
key rotation, endpoint roaming, or replay protection.

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

Both endpoints need WGF for DATA traffic. A stock WireGuard peer can establish
the underlying WireGuard session but cannot exchange WGF carriers.

## Features

- Inner MTU from 1280 through 9612 bytes, with up to 16 fragments per packet.
- Carrier packing, bounded reassembly and reorder queues, and no normal
  hot-path allocation.
- Runtime DPLPMTUD based on RFC 8899, starting from a safe 613-byte carrier
  payload and adapting to the path.
- WireGuard-style multi-peer configuration, `AllowedIPs` selection and ingress
  source validation, plus a transport-independent Go manager API, local gRPC
  adapter, multi-interface ownership, and systemd support.

Read the [wire protocol](docs/protocol.md) for the compatibility boundary and
state-machine rules.

## Performance

WGF is designed for a low-GC steady-state forwarding path while retaining the
configured inner MTU. In a four-vCPU cross-region reference environment, one
TCP flow reached about 0.7 Gbps and four parallel flows reached 2.5–2.8 Gbps
at inner MTUs from 1500 through 9600 bytes. These are reference measurements,
not throughput guarantees. See [benchmarks](docs/benchmark.md) for the method,
full results, and local validation.

## Quick start

WGF runs on Linux amd64/arm64 and macOS amd64/arm64. Linux supports both
`wgf run`, `wgf manager`, and `wgf quick`; macOS supports `wgf run` and
`wgf manager`. Interface creation and route management require root or
equivalent network privileges.

Install on a supported Ubuntu release from the Launchpad PPA:

```sh
sudo add-apt-repository ppa:kurochan/wg-frag-go
sudo apt update
sudo apt install wg-frag-go
```

Create `/etc/wg-frag/wgf0.conf` from
[`examples/wgf0.conf.example`](examples/wgf0.conf.example), protect it with
mode `0600`, then validate and start it:

```sh
sudo wgf check --config /etc/wg-frag/wgf0.conf
sudo systemctl enable --now wgf@wgf0
sudo wgf show wgf0
```

Packages do not automatically enable or start tunnel units. GitHub Release
archives, installation alternatives, configuration details, operational
diagnostics, and upgrade behavior are in [Installation and operations](docs/install.md).

## Documentation

- [Installation and operations](docs/install.md): release packages, PPA,
  starting, diagnostics, AppArmor, and upgrades.
- [Configuration reference](docs/configuration.md): all interface, peer, and
  WGF-specific settings.
- [Control API](docs/control-api.md): the in-process Go API, public gRPC API,
  multi-interface manager, lifecycle, and mutation rules.
- [Wire protocol](docs/protocol.md): carrier formats, capabilities, PMTU, and
  reassembly behavior.
- [Security model](docs/threat-model.md): trust boundary, validation, and
  residual risks.
- [Benchmarks](docs/benchmark.md): reproducible Internet and Linux results.

## Development

Building requires Go 1.26.0 or newer. The normal validation suite does not
require privileged networking:

```sh
make build
go test ./...
make lint
make test-race
```

Privileged Linux network-namespace tests and benchmark commands are documented
in [benchmarks](docs/benchmark.md).

## Security

WireGuard remains the cryptographic and peer-authentication boundary. WGF
validates carrier structure, peer and session state, resource bounds, and
inner source prefixes before delivering a packet to the TUN. See the
[security model](docs/threat-model.md) for details.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md), not a
public issue.

## License

This project is distributed under the MIT License; see [LICENSE](LICENSE).

## Project relationship

wg-frag-go uses the WireGuard protocol and `wireguard-go`, but is an
independent project and is not affiliated with, endorsed by, or part of the
WireGuard project.
