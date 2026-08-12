# Installation and operations

Supported runtime targets are Linux amd64 and arm64. The correctness baseline
is Linux 5.10 or newer; Linux 6.2 or newer is recommended for performance.

## Installed files

```text
/usr/bin/wgf
/usr/bin/wgf-quick -> wgf          # executable-name alias
/usr/lib/systemd/system/wgf@.service
/usr/lib/systemd/system/wgf.target
/etc/wg-frag/            # configuration directory (0700)
/usr/share/doc/wg-frag-go/
```

## Build and install

```sh
make build          # ./bin/wgf
sudo install -m 0755 bin/wgf /usr/bin/wgf
sudo ln -sf wgf /usr/bin/wgf-quick
sudo install -m 0644 dist/systemd/wgf@.service dist/systemd/wgf.target /usr/lib/systemd/system/
sudo install -d -m 0700 /etc/wg-frag
sudo systemctl daemon-reload
```

## Configuration

Place configuration in `/etc/wg-frag/<interface>.conf`. `wgf quick up`
warns when the file is not mode 0600. The format is compatible with wg-quick:
`Address` and `MTU` are runtime settings, while `Table`, `FwMark`, `PreUp`,
`PostUp`, `PreDown`, `PostDown`, and `SaveConfig` are handled by `quick`.
`DNS` is not supported and is ignored with a warning. WGF-specific keys such as
`WGFSocketBuffer` are passed to the runtime.

```ini
[Interface]
Address = 10.0.0.1/24
PrivateKey = ...
ListenPort = 51820
MTU = 9612

[Peer]
PublicKey = ...
Endpoint = example.net:51820
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
PresharedKey = ...
```

`MTU` is the inner TUN MTU and must be within 1280..9612. It may exceed the
underlay MTU; WGF fragments the excess data.

## Starting and stopping

```sh
sudo systemctl enable --now wgf@wgf0     # /etc/wg-frag/wgf0.conf
# or manually:
sudo wgf quick up wgf0
sudo wgf quick down wgf0
```

`wgf quick up` writes a 0600 runtime snapshot and input snapshot under
`/run/wg-frag/`; these files are not the authority for persistent
configuration. It starts the `wgf run` daemon and configures addresses, routes,
and policy routing. On failure it rolls changes back in reverse order.

### Full tunnel (`AllowedIPs = 0.0.0.0/0`)

With the default `Table = auto`, `quick` installs the default route in a
dedicated table. If `FwMark` is not specified, it selects an unused mark/table
starting at 51820. It then installs a `not fwmark` rule and a
`suppress_prefixlength 0` rule to avoid routing the endpoint back through the
tunnel. The daemon applies the same mark to its outer UDP socket with `SO_MARK`.

`Table = off` disables all route changes. `Table = <n>` installs routes in the
specified table without adding policy rules, matching wg-quick behavior.

## Inspecting status

```sh
wgf show                 # all interfaces
wgf show wgf0            # detailed status
wgf show wgf0 path-mtu   # DPLPMTUD state, including ERROR reason
wgf show wgf0 stats      # machine-readable key=value output
wgf showconf wgf0        # running configuration in setconf syntax
```

## Permissions

Run as root or with at least `CAP_NET_ADMIN` for TUN creation, route/rule
changes, `SO_MARK`, and `SO_RCVBUFFORCE`. If `SO_RCVBUFFORCE` is unavailable,
WGF logs a warning and continues. Never pass private keys as command-line
arguments; keep them in the configuration file.

## Diagnostics

Normal logs use Go's `log/slog` package and are intentionally limited to
low-frequency lifecycle and path-state events. Set these environment variables
for diagnostics:

- `WGF_LOG_LEVEL`: `debug`, `info` (default), `warn`, `error`, or `silent`.
- `WGF_LOG_FORMAT`: `text` (default) or `json`.
- `WGF_CPU_PROFILE`: write a Go CPU profile to the specified path while the
  daemon runs. Leave it unset during normal operation and protect the output
  file because it can reveal runtime and workload details.

These are process environment variables, not configuration-file settings.

## Ubuntu and AppArmor

Ubuntu 26.04 AppArmor policies can restrict Unix sockets and file access more
strictly. In the observed environment, `wg` was denied access to a userspace
UAPI socket. WGF's own control socket is
`/run/wg-frag/<interface>.sock` with mode 0600 and parent directory
0700. When packaging WGF with an AppArmor profile, allow read/write access to
`/run/wg-frag/**` and `/dev/net/tun`.

## Upgrades

The daemon has no persistent runtime state; the configuration file is the sole
authority.

```sh
sudo install -m 0755 bin/wgf /usr/bin/wgf
sudo systemctl restart wgf@wgf0
```

The tunnel is interrupted for a few seconds during restart. To roll back,
restore the previous binary and repeat the same procedure. Capabilities are
negotiated with `CapabilitiesHello`, so v1 peers continue to work with another
v1 binary.
