# WGF threat model

## Scope and trust boundary

This document defines the security boundary of the WGF version 1 carrier
protocol. See [`protocol.md`](protocol.md) for the wire format.

WGF does not change the WireGuard handshake, AEAD, key rotation, transport
replay protection, or endpoint roaming. The additional attack surface is the
carrier parser, AllowedIPs mirror, queues, reassembly, reorder, CONTROL, and
DPLPMTUD after WireGuard has authenticated and decrypted the packet.

The protected invariants are:

- A packet routed to peer A cannot spoof an inner source owned by peer B.
- Fragments and state from different peers are never mixed.
- Malformed input cannot cause a panic, out-of-bounds access, or unbounded
  allocation.
- Remote values cannot increase queues, timers, logs, or probe traffic without
  bounds.
- Stale sessions, epochs, and responses cannot become current again.
- WGF never silently falls back to outer fragmentation.
- DATA is not allowed before capability, session, PeerMTU, reachability, and
  BASE confirmation complete.
- A carrier size that was not acknowledged is never made current.

## Adversaries

### Authenticated malicious peer

An authenticated WireGuard peer is not trusted with respect to WGF plaintext.
Assume it can send malformed lengths, contradictory fragments, overlaps,
duplicate or stale IDs, spoofed inner sources, large protobuf fields, padded
probes, CONTROL floods, and invalid path responses.

WireGuard authenticates which configured key sent a carrier. It does not prove
that the peer follows WGF, owns an inner source address, or maintains honest
application state.

### On-path attacker

An underlay attacker can observe, drop, delay, duplicate, and reorder encrypted
datagrams, and can inject unauthenticated UDP. Under the WireGuard cryptographic
assumptions it cannot forge authenticated WGF plaintext. It can still reduce
throughput or force loss, path fallback, and continued dormant state.

### Local boundary

An unprivileged local user can generate traffic routed to the TUN and attempt to
connect to the local management endpoint. Root, the kernel, the WGF process,
private keys, and configuration management performed with root privileges are
trusted boundaries.

## Carrier and peer isolation

The receiver validates the derived carrier source associated with the
authenticated peer, the local destination, the fixed IPv6 header, Next Header
253, the absence of extensions, the exact length, and the absence of trailing
bytes. Derived-address collisions are rejected fail-closed before applying a
configuration.

The hidden carrier `/128` and user inner AllowedIPs are separate:

- Carrier `/128`: peer selection and carrier-source validation by
  `wireguard-go`.
- User AllowedIPs mirror: outbound inner routing and reconstructed-source
  validation.

For each inbound inner source, WGF performs the global WireGuard-compatible
longest-prefix match. It accepts the packet only when the resulting peer is the
peer that authenticated the carrier. Merely matching any prefix belonging to a
peer is insufficient. Configuration updates fail closed. Removing a peer purges
its reassembly, reorder, CONTROL, path, and cache state.

Peer identity is always part of the reassembly key. The current receiver owns
one peer per reassembler, so its per-peer quota cannot evict another peer's
assembling slot.

## Malformed input and bounded memory

Untrusted lengths are checked with overflow-safe arithmetic before any slice,
index, or copy operation. The DATA parser validates carrier and record limits,
the 12-byte header, non-empty data, a maximum of 16 fragments, valid indexes,
nonzero sessions, consistent counts, ranges, overlaps, contiguous completion,
and the reconstructed IP length.

An exact duplicate uses first-write-wins. A conflicting duplicate, overlap, or
count/range violation destroys that reassembly; a partial packet is never sent
to the TUN.

The DATA hot path uses slabs, fixed rings, fixed slots, and a fixed reorder queue
allocated at startup. Peer advertisements are clamped by local configuration
and protocol limits; remote values are not used directly as allocation sizes.
There are no per-packet timer objects.

Before protobuf decoding, CONTROL validates frame length, the normal CONTROL
limit, the separate probe limit, recursion and field limits, and exactly one
body. Large `MtuProbe.padding` is skipped rather than copied. Carrier, DATA,
protobuf, fragment combinations, and state transitions are fuzz-tested, and
malformed input must not panic.

## Replay, restart, and reorder

In addition to WireGuard replay protection, WGF identifies daemon restarts and
delayed packets:

- DATA sessions are nonzero and scoped to a peer and sending direction.
- The reassembly key contains the session, lane, and u32 lane sequence.
- Collisions with current or recently retired sessions are rejected for the
  reassembly lifetime.
- Non-current DATA is dropped and produces a rate-limited
  `StateSyncRequired`.
- A control epoch is a random nonzero value per process and sending direction.
- Message IDs are nonzero and monotonically allocated within an epoch.
- Responses are matched to an outstanding request and `reply_to`, and echo the
  request epoch.
- Only `CapabilitiesHello` can introduce an unknown epoch; a retired epoch is
  rejected for four minutes.

When a new remote DATA session is accepted, only that peer's receive direction
is purged. A `StateSyncRequired` for the current local session resets only local
outbound readiness and preserves the independent remote inbound session.

Reorder is not a reliability protocol. Its window is bounded and below 2^31. A
gap is held for at most 10 ms and then flushed; overflow flushes immediately,
and packets older than the advanced expected sequence are dropped. There is no
retransmission or global ordering across lanes.

## Native fragments

Native inner IPv4 fragments and IPv6 Fragment Headers are rejected in both
directions. This excludes ambiguous lengths, overlaps, resource exhaustion, and
filter evasion from the v1 scope. Drops are counted, but WGF does not generate
PTB for a packet that was already fragmented.

An unfragmented packet larger than the peer receive MTU is not converted to DATA.
Only when safety and rate-limit conditions allow it does WGF return IPv4
Fragmentation Needed or ICMPv6 Packet Too Big to the local TUN. Without a local
source address of the same address family it drops the packet and increments a
counter.

## PMTU black holes and path manipulation

DPLPMTUD treats an ACK as evidence only when peer, control/path epoch, the
outstanding request, and reported size all match. An ACK proves one direction
only.

WGF does not mistake a single loss for an MTU reduction:

- Each candidate is sent at most three times with pacing.
- A larger-search failure narrows only the search limit and does not lower the
  current confirmed size.
- Independent passes and a final confirmation are required.
- Only three consecutive timeouts for the current-size confirmation enter a
  black-hole state.
- After fallback, DATA remains stopped until minimum Ping/Pong and BASE ACK
  succeed.
- An endpoint or outer address-family change discards the ceiling.
- ICMP PTB alone cannot confirm the ceiling.

An authenticated malicious peer can ACK a probe and then discard DATA. Forcing
the peer to forward traffic is out of scope. The impact is confined to
availability toward that peer and does not expand memory or source
authorization.

The Linux bind disables outer fragmentation and reports local `EMSGSIZE` to
PMTU. Integration tests inspect actual packet length, kernel fragment counters,
ICMP, and UDP GSO segment size. An ACK alone does not prove that the underlay
was unfragmented.

## CONTROL abuse and amplification

Even authenticated CONTROL is subject to peer and global ingress rate limits
before expensive decoding or response generation. Ping responses, logs, retries,
retired epochs, and outstanding requests are bounded. ACKs do not echo probe
padding; padded bytes are generated only at dequeue time. WGF does not respond
to anything other than a valid current-epoch request or a valid Hello that
introduces a new epoch.

Initial outbound scheduler budget:

- 16 entries in the interface-wide CONTROL ring.
- At most 8 exploratory entries, reserving at least 8 for critical entries.
- At most 8 outstanding MTU probes per peer.
- 32 messages/s per peer, burst 8.
- 128 messages/s interface-wide, burst 16.
- After at most 4 CONTROL services, service at least 1 pending DATA carrier.

A critical enqueue may evict the oldest exploratory entry. If every entry is
critical, WGF coalesces only an identical peer, kind, epoch, message ID, and
reply target; correlated responses therefore remain distinct. Otherwise it
drops the descriptor and recovers through bounded retry. CONTROL and DATA must
not starve each other permanently.

## Local management

The parent directory of each per-interface Unix socket is owned by root or the
effective user and has mode `0700`; the socket is mode `0600`. Interface names
are validated against an allowlist and symlink paths are rejected. A stale
socket is reclaimed only after checking file type, liveness, inode identity,
and the single-instance lock; the stale socket entry itself is not trusted by
owner metadata. Private and preshared keys are hidden from normal CLI output
and never written to logs.

These controls protect the management API from an unprivileged local user. They
do not protect against root-equivalent access, access to private keys, or binary
replacement.

## Explicit non-goals and residual risks

- DATA compatibility with stock WireGuard.
- Confidentiality from a configured peer or an administrator who holds its key.
- Resistance to traffic analysis based on encrypted packet size and timing.
- Congestion control, retransmission, or reliable delivery inside the shim.
- Protection against a compromised kernel, root, WGF/wireguard-go process, or
  cryptographic primitive.
- Forwarding native inner fragments.
- Global ordering across lanes.
- Complete availability under sustained authenticated CPU or bandwidth
  exhaustion.

Rate limits and bounded pools limit memory use and response amplification, but
they do not make processing an in-limit attack free. A malicious peer can cause
evictions or service degradation for its own peer state. Metrics and logs must
not create unbounded labels or strings controlled by peers, while still making
the event observable.
