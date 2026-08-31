# Control API

WGF exposes a local gRPC control service for inspecting and changing running
interfaces. The protobuf definitions are in
[`proto/controlapi/v1`](../proto/controlapi/v1), and the Go convenience client
is the public [`controlapi`](../controlapi) package.

The service listens on a Unix-domain socket. The socket is created with mode
0600, and its parent directory is private to the daemon. The socket provides
local access control; the gRPC service does not add a second authentication or
TLS layer. Run clients with the same privileges as the daemon or grant access
to the socket through the host's normal privilege mechanism.

## Process modes

`wgf run` keeps the traditional one-process, one-interface model. It starts
one interface in the foreground and uses the per-interface socket returned by
`controlapi.SocketPath`:

```text
Linux:  /run/wg-frag/<interface>.sock
macOS:  /var/db/wg-frag/<interface>.sock
```

The socket can be overridden with `--control-socket`.

`wgf manager` starts a process without an initial interface. Interfaces can
then be created and removed through the API. Its default socket is returned by
`controlapi.ManagerSocketPath`:

```text
Linux:  /run/wg-frag/manager/control.sock
macOS:  /var/db/wg-frag/manager/control.sock
```

`wgf show`, `wgf show all`, and `wgf show interfaces` discover interfaces
served by this manager socket as well as traditional per-interface sockets.

Use `--max-interfaces` to set the manager's interface limit; the default is
16. Manager mode accepts process-level metrics options on the command line.
It does not read an interface configuration file when it starts.

For example, this exposes one process-wide endpoint on both loopback address
families:

```sh
sudo wgf manager --metrics \
  --metrics-listen 127.0.0.1:9910 \
  --metrics-listen '[::1]:9910'
```

Manager listeners must be explicit IP-literal addresses with non-zero ports;
the per-interface `auto` setting is not meaningful before any interface
exists. Process-level metrics settings are fixed when the daemon starts and
are not part of `RestartInterface`.

Each interface owns its TUN, WireGuard device, UDP bind, shim queues, and
peer state. The manager does not change `GOMAXPROCS`. `wgf run` uses the same
manager implementation with a maximum of one interface.

## In-process Go API

Applications embedding WGF can use `manager.Manager` directly without opening
a Unix socket. The in-process API and gRPC API accept the same protobuf request
and response types and execute the same implementation:

```go
ctx := context.Background()
mgr, err := manager.New(manager.Options{MaxInterfaces: 4})
if err != nil {
	return err
}
defer mgr.Close(context.Background())

privateKey := make([]byte, 32)
requestID := make([]byte, 16)
if _, err := rand.Read(privateKey); err != nil {
	return err
}
if _, err := rand.Read(requestID); err != nil {
	return err
}

spec := controlapiv1.InterfaceSpec_builder{}.Build()
spec.SetInterfaceName("wgf0")
spec.SetPrivateKey(privateKey)
spec.SetMtu(1500)

request := controlapiv1.CreateInterfaceRequest_builder{}.Build()
request.SetRequestId(requestID)
request.SetSpec(spec)
if _, err := mgr.CreateInterface(ctx, request); err != nil {
	return err
}
```

Import `manager` from `github.com/kurochan/wg-frag-go/manager` and generated
messages from `github.com/kurochan/wg-frag-go/proto/controlapi/v1`.
`manager.Manager` owns every interface it creates. Its `Close` method is
idempotent and stops all owned runtimes; a context deadline can stop waiting
without canceling the cleanup already in progress.

The gRPC server owns only its listener and Unix socket. When embedding both,
close the gRPC server first to stop admitting new calls, then close the
manager. The server allows admitted calls five seconds to finish before
canceling them. The `wgf` command follows this shutdown order.

## Go gRPC client

The public client uses the generated protobuf service and does not expose an
HTTP or TCP control endpoint:

```go
ctx := context.Background()
client, err := controlapi.DialUnix(ctx, controlapi.ManagerSocketPath())
if err != nil {
	return err
}
defer client.Close()

response, err := client.ListInterfaces(ctx,
	controlapiv1.ListInterfacesRequest_builder{}.Build())
if err != nil {
	return err
}
for _, status := range response.GetInterfaces() {
	// Inspect status.GetRef(), status.GetNativeInterfaceName(),
	// status.GetLifecycle(), and status.GetSpec().
	_ = status
}
```

Import `controlapi` from the repository root and the generated messages from
`github.com/kurochan/wg-frag-go/proto/controlapi/v1`. `Client.Raw` is available
when an application needs generated gRPC call options or interceptors.

## RPCs

The service provides the following operations:

| RPC | Behavior |
| --- | --- |
| `ListInterfaces` | Returns the status of every interface currently held by the process. |
| `GetInterface` | Returns one interface's status. Set `include_secrets` to include peer preshared keys; the interface private key is never returned. |
| `CreateInterface` | Validates, creates, and starts an interface from an `InterfaceSpec`. The interface name and a 32-byte private key are required. |
| `DeleteInterface` | Stops the interface, closes its TUN anchor, and removes it from the manager. |
| `ApplyPeers` | Replaces the complete peer desired set without restarting the interface. |
| `RestartInterface` | Replaces the runtime generation. It is used for interface-level settings that cannot be changed in place. |

`InterfaceSpec` deliberately does not contain `Address` or route policy.
Address assignment and host route policy remain outside this API. The
interface `MTU` is the inner TUN MTU; WGF-specific carrier and reassembly
settings are part of the same spec. See the
[configuration reference](configuration.md) for the accepted values.

`InterfaceStatus.native_interface_name` is the OS TUN name to configure. It
normally matches the requested interface name on Linux; on macOS it reports
the allocated `utunN` name.

`PeerSpec.preshared_key_action` controls secret handling:

- `SET` supplies a new raw 32-byte preshared key.
- `CLEAR` removes the preshared key.
- `PRESERVE` keeps the current key and must not include key bytes. It is used
  by status snapshots that omit secrets.

When creating a peer without a preshared key, use `CLEAR`. `PRESERVE` requires
that the same peer already exists in the current configuration.

`RestartInterface` accepts a complete replacement spec. If its private key is
omitted, the current private key is preserved; other omitted fields take their
normal configuration defaults. The interface name cannot change during a
restart. A private-key change creates a new WireGuard identity and is rejected
if another active interface already uses that public key.

## Mutation safety

Mutating calls use a `MutationContext`:

```text
request_id            exactly 16 non-zero bytes
expected_instance_id  the 16-byte instance ID from InterfaceStatus.ref
expected_generation   the generation from InterfaceStatus
```

`CreateInterface` carries `request_id` at the top level. `DeleteInterface`,
`ApplyPeers`, and `RestartInterface` carry the same fields inside
`MutationContext`. The instance ID prevents a request for an old interface
from applying after an interface with the same name has been recreated. The
generation prevents an update based on an outdated status snapshot. A stale
instance or generation is rejected with an aborted gRPC status.

Mutation requests are idempotent within one process. Retrying the same
`request_id` with the same request returns the retained success or error;
reusing it for a different request is rejected. Use a new request ID only when
starting a new mutation from a freshly read status and generation. The retained
request cache is bounded and process-local, so a process restart does not
replay old requests. Pending entries are not evicted because doing so could
execute one request twice. If an operating-system call never returns, restart
the manager rather than reissuing that mutation under another request ID.

After a mutation has been admitted, a caller deadline can stop waiting but
does not cancel the mutation. A caller that receives an ambiguous transport
error must retry the identical request with the same `request_id` to learn the
definitive result before issuing a dependent mutation.

`ApplyPeers` is a complete desired-state replacement, not a single-peer patch.
The response reports an optional error for each added or surviving peer. A
peer whose control path cannot be started stays disabled while the interface
remains available for other peers.

## Runtime lifecycle

`InterfaceStatus.lifecycle` reports `CREATING`, `RUNNING`, `RESTARTING`,
`DELETING`, `ROLLING_BACK`, or `ERROR`.

An interface supervisor owns a persistent TUN anchor while individual runtime
generations own leases for that anchor. A restart stops and joins the old
generation, creates a new WireGuard/UDP/shim generation, and keeps the TUN
anchor. WireGuard session state, UDP socket state, reassembly state, and
reorder state are recreated, so a restart can temporarily interrupt traffic.
Deleting the interface closes the anchor as well.

If a runtime stops unexpectedly or a restart cannot be recovered, the
supervisor enters `ERROR` and keeps the control socket available. Clients can
inspect the error, retry a restart, or delete the interface. Runtime
generation counters are accumulated while an interface remains in the same
process. Counters for the same WireGuard public-key identity continue across
normal delete/recreate cycles. The manager retains every active identity and
the 256 most recently updated inactive identities; older inactive histories
are evicted. A process restart resets all retained counters.

## OpenMetrics

Metrics are process-scoped: a process has one process-wide OpenMetrics endpoint,
backed by one or more listeners, whether it manages one interface or many. The
metric schema is the same in both modes.

- Process metrics, including `wgf_build_info` and
  `wgf_manager_interfaces`, have no interface label.
- Interface metrics have `interface` and `interface_id` labels.
- Peer metrics additionally have a `peer_id` label.

`interface_id` is stable for a WireGuard public-key identity. A peer's
`WGFPeerID` is used when configured; otherwise WGF derives an opaque stable ID
from BLAKE2s(`"wgf:" || raw_public_key`). Counter series continue across
runtime generations within the same process. The endpoint creates a snapshot
when scraped and does not run a background metrics collector in the packet
path. Selection can be restricted with the include/exclude settings described
in the [configuration reference](configuration.md).

## Configuration and CLI relationship

The existing `wgf set`, `setconf`, `addconf`, and `syncconf` commands use the
same local service to update peers on a running interface. They do not change
interface-level runtime settings. Use `RestartInterface` through the API, or
restart the interface through `wgf run`/`wgf quick`, for those settings.

On Linux, `systemctl reload wgf@<interface>` rereads the canonical quick
configuration and uses `ApplyPeers` for peer-only changes or
`RestartInterface` for runtime settings. Quick-managed addresses, routes,
hooks, and process metrics are not changed by reload; modifying them returns
an error and requires an explicit service restart. A reload stops retrying an
ambiguous mutation after two minutes so the systemd reload job and quick lock
cannot remain blocked forever. If a published change must be rolled back, the
rollback receives a separate two-minute budget.

The API does not persist desired interface specifications. Keep the
configuration in the operator's configuration management system and recreate
interfaces after a manager process restart.
