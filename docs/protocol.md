# WGF wire protocol v1

## Purpose and compatibility boundary

This document defines the version 1 plaintext carrier protocol that
`wg-frag-go` (WGF) passes to `wireguard-go`. It does not change the
WireGuard handshake, Noise protocol, transport envelope, AEAD, key rotation,
replay protection, endpoint roaming, or UDP transport.

The decrypted payload has a different meaning from stock WireGuard, so both
endpoints must run WGF for DATA traffic. An inner payload is a complete IPv4 or
IPv6 datagram that has not already been natively fragmented. The supported
inner MTU is 1280..9612 bytes and does not depend on outer IP fragmentation or
MSS clamping.

```text
inner IPv4/IPv6 packet
  -> WGF DATA record sequence
  -> hidden synthetic IPv6 carrier
  -> WireGuard encryption/transport
  -> UDP/IP underlay
```

## Hidden IPv6 carrier

The carrier address is a private IPv6 link-local `/128`, deterministically
derived from the static public key.

```text
carrier prefix  = fe80::/64
carrier IID     = first64(BLAKE2s-256(
                    "wg-frag/carrier-address/v1:" ||
                    wireguard_static_public_key_raw_32_bytes))
carrier address = fe80::/64 || carrier IID
```

`first64` uses the first eight digest bytes in wire order. Collisions between
the local key and all peer-derived addresses are detected before applying the
configuration and rejected fail-closed. The salt is a protocol constant shared
by every implementation; the implementation or repository name is not part
of it. The two sides must not use different salts.

The synthetic IPv6 header is always 40 bytes. Its transmitted fields are:

| Field | Value |
| --- | --- |
| Version | 6 |
| Traffic Class / Flow Label | 0 / 0 |
| Payload Length | exact carrier payload length |
| Next Header | 253 |
| Hop Limit | 64 |
| Source | address derived from the local static public key |
| Destination | address derived from the peer static public key |

Next Header 253 is an experimental/test value from
[IANA IPv6 Parameters](https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml).
It is not used to distinguish DATA from CONTROL.

On receive, WGF validates the 40-byte fixed header, absence of extension
headers and jumbograms, Next Header 253, agreement between Payload Length and
the buffer length, absence of trailing bytes, and the expected peer-derived
source and local destination. Traffic Class, Flow Label, and Hop Limit are not
acceptance conditions.

The daemon configures only each peer's derived carrier `/128` in
`wireguard-go`'s internal AllowedIPs. The address is not exposed as an OS
interface address, route, NDP entry, user configuration, or `wgf show` field.
An interface has one local carrier address.

## DATA format

All multi-byte integers use network byte order. A carrier payload is a sequence
of records and does not contain a record count. The parser adds each record
length and must end exactly at the end of the payload.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | total record length, including the 12-byte header |
| 2 | 1 | high 4 bits: fragment index; low 4 bits: fragment count - 1 |
| 3 | 1 | wire lane ID |
| 4 | 2 | data session ID |
| 6 | 4 | lane sequence |
| 10 | 2 | byte offset in the original inner packet |
| 12 | variable | fragment data |

The record length at payload offset 0 determines the carrier type.

```text
0       CONTROL; the entire carrier is CONTROL
1..11   invalid/reserved
>= 12   DATA
```

A zero length in the middle of a DATA sequence is invalid. CONTROL and DATA
are never mixed.

### Validation conditions

- The complete record fits within the carrier payload.
- Fragment data is at least one byte (record length 12 is invalid).
- Fragment count is 1..16 and the index is less than the count.
- The data session ID is 1..65535. Zero drops the entire packet.
- Fragment counts agree for the same reassembly key.
- Offset plus data length is within the local maximum inner packet size.
- Ranges do not overlap and completed coverage is contiguous.
- The reconstructed IPv4 Total Length or IPv6 Payload Length agrees with the
  buffer length.

The reassembly key is unique by:

```text
peer identity + data session ID + wire lane ID + lane sequence
```

### Session, lane, and sequence

The sender selects a nonzero u16 data session ID for a new exchange. When the
receiver accepts a new session through `ResetSequence`, it atomically purges
only that peer's receive-direction reassembly and reorder state. DATA for a
non-current session is dropped and a rate-limited `StateSyncRequired` is
returned. A collision with the current or recently retired ID returns
`RESULT_CODE_SESSION_COLLISION`.

There are 256 fixed u8 wire lanes, independent of the number of local workers.
Lane sequence is a monotonically increasing u32 value per peer and lane;
comparisons use modulo 2^32 and the window remains below 2^31. A
session/lane/sequence key is not reused within the receiver-advertised
reassembly lifetime. If safe wraparound cannot be guaranteed, new admission
on that lane stops.

The default lane hash uses the outermost inner IP 5-tuple. For UDP destination
port 4789, if the VXLAN Ethernet payload contains IPv4 or IPv6, the inner
5-tuple is added as well. The default recursion depth is 1 and the hard maximum
is 4. Malformed or unknown encapsulation falls back to the outermost key. The
hash uses a process-random keyed hash.

Ordering is guaranteed only within a lane. No global ordering is provided
across lanes.

### Packing

Records from different inner packets or lanes may share a carrier when they
belong to the same peer and the same TX owner. Different peers are never mixed.

Before starting a new packet in the tail of a partial carrier, the sender
calculates whether using that tail for the first fragment would keep the total
fragment count at or below 16. If not, it flushes the carrier and repeats the
decision with an empty carrier. The local `min-pack=128` rule then suppresses
starting a packet in an extremely small tail.

There is no packing-delay timer. After draining a TUN batch to `EAGAIN`, the
sender immediately flushes every partial carrier belonging to the TX owner.

## CONTROL format

CONTROL occupies the entire carrier payload.

```text
marker            u16 = 0x0000
protocol_version  u8  = 1
protobuf payload      = through the end of the carrier payload
```

The fixed header is 3 bytes and adds no overhead to DATA. The schema is defined
in [`proto/wire/v1/control.proto`](../proto/wire/v1/control.proto).

The `Control` envelope contains a nonzero `message_id`, a `reply_to` for
responses, a nonzero `control_epoch`, `padding` used only by `MtuProbe`, and
exactly one body. `message_id` starts at 1 within an epoch; zero and reuse after
wraparound are forbidden.

A response echoes the request's control epoch and does not use an independent
responder-sending epoch. `reply_to` must equal the corresponding request ID.
Unknown, stale, and duplicate responses are dropped.

A control epoch is a random nonzero value for each process and sending
direction. Only a valid `CapabilitiesHello` may introduce an unknown epoch.
The receiver retains retired epochs for four minutes and never returns to a
previous current epoch. Other CONTROL messages with an unknown epoch receive
no response and are dropped.

Before protobuf decoding, WGF validates carrier and CONTROL lengths, the normal
CONTROL limit and probe limit, recursion and field sizes, and the body count. It
also applies peer and global ingress rate limits. Probe padding is not copied
into a queue or echoed in an ACK.

## Capabilities and the DATA gate

Interface bring-up does not wait for a peer. A peer starts dormant and begins
an exchange when the first inner packet arrives or a WGF timer derived from
user `PersistentKeepalive` fires. A side that receives a valid peer Hello also
starts its reverse exchange if its own exchange has not started.

The v1 capability requirements are:

- DATA protocol version: exactly 1
- maximum fragments: exactly 16
- maximum carrier payload: at least 613, at least the local BASE, and no more
  than the protocol/outer-AF limit
- reassembly lifetime: 100..60000 ms (default 2 seconds)
- peer MTU: 1280..9612 bytes
- each side's required feature bits are a subset of the other side's supported
  feature bits

There is no silent version or feature downgrade. DATA in each sending direction
remains fail-closed until all of the following are true:

1. A matching `CapabilitiesAck` for the local Hello was accepted.
2. The peer's independent epoch Hello was received and validated.
3. Required feature bits are satisfied in both directions.
4. A matching Ack for the local `ResetSequence` was accepted.
5. A matching Ack for the local `PeerMTU` was accepted.
6. The remote receive `PeerMTU` was received and stored.
7. A minimum-size Ping/Pong succeeded.
8. The local BASE-size `MtuProbe` succeeded.

Packets for an unconfirmed peer enter a fixed eight-slot per-peer pre-confirmation
queue; overflow drops the oldest packet. Control retries start at 200 ms and
use exponential backoff with full jitter, capped at 60 seconds. A valid CONTROL
message clears the backoff.

An accepted `ResetSequenceAck` may include the most recent carrier payload that
the responder received successfully. This value is an advisory hint for the
requester's next send-direction PMTU search. It is accepted only within the
negotiated carrier ceiling and is ignored at or below BASE. The hint is used as
the first raise candidate after BASE succeeds; it does not confirm PMTU and it
never opens the DATA gate. If the hinted probe fails, the normal bounded search
continues from the observed result.

An unfragmented inner packet larger than the peer receive MTU is not converted
to DATA. When possible, WGF returns IPv4 Fragmentation Needed or ICMPv6 Packet
Too Big to the local TUN. In a route-only configuration without a suitable
same-AF local source, it drops the packet and increments a counter.

## Ping and DPLPMTUD

WGF uses [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html) to search for a
carrier payload ceiling per peer, sending direction, and current endpoint/path.
Ping/Pong confirms reachability and RTT only; it does not count as an MTU
success.

After the minimum Ping/Pong succeeds, WGF sends a BASE `MtuProbe`. The default
BASE carrier payload is 613 bytes and the synthetic IPv6 carrier is 653 bytes.
After subtracting the 12-byte DATA header, 601 bytes remain for fragment data,
so 16 fragments can carry 9616 bytes. A BASE outer datagram is 716 bytes over
outer IPv4 and 736 bytes over outer IPv6. If BASE cannot be established, DATA
does not start and the peer enters a recoverable ERROR/backoff state.

`MtuProbe` uses a standalone CONTROL carrier and `Control.padding` to reach the
candidate payload length. The ACK does not return padding; it returns only the
measured payload size. The sender accepts an ACK only when peer, control/path
epoch, outstanding `reply_to`, and candidate size all match.

Search procedure:

1. Increase candidates exponentially from BASE to bracket a failure.
2. Binary-search the buckets where outer size changes after WireGuard's
   16-byte padding.
3. Send each candidate at most three times with pacing; classify it as a
   failure only when all attempts time out.
4. Accept two independent passes that converge. If they disagree, run a third
   pass and use the median.
5. Promote a size to the current confirmed value only after a final confirmation
   of that same size succeeds.

The initial search and periodic refresh use the same final-confirmation rule.
The optional ResetSequence hint only changes the first raise candidate; it does
not change the confirmation or fallback rules.

The initial timeout is 2 seconds until Ping/Pong supplies an RTT sample. The
measured SRTT is carried into the PMTU search, after which the timeout is
`max(100ms, 4 * SRTT)`. Probe retries remain capped at three attempts per
candidate. This keeps short paths responsive while retaining a floor for
scheduling and queueing jitter.
The active path confirms the current size every 60 seconds and performs a
non-blocking raise search every 600 seconds. A current-size confirmation must
time out three times consecutively to enter BLACK_HOLE and immediately return
to BASE. DATA remains stopped until minimum Ping/Pong and the BASE probe succeed
again. An endpoint or outer address-family change also discards the confirmed
ceiling and restarts from BASE. ICMP PTB is advisory; it cannot confirm a ceiling
without a probe ACK.

The protocol carrier payload limit is 65432 bytes over outer IPv4 and 65448 bytes
over outer IPv6. The effective search limit is the minimum of the local value,
the remote value, and the current outer address-family limit.

The Linux custom `conn.Bind` disables outer fragmentation and reports local
`EMSGSIZE` to the PMTU engine. Because a successful probe alone does not prove
that the underlay is unfragmented, integration tests also inspect actual packet
length, `Ip_FragCreates`, `Ip6FragCreates`, ICMP, and UDP GSO segment size.

## Reassembly and reorder

Reassembly uses fixed slots and storage allocated at startup for each peer; the
data hot path does not allocate. With `WGFPeerReassemblySlots=auto`, storage is
`WGFReassemblySlots * configured MTU` per peer; an explicit value sets the slot
count. The deadline is `first_fragment_at + lifetime` and is not extended by
later fragments. The current receiver creates one reassembler per peer, so its
peer quota cannot evict another peer's assembling entry. When the quota is full,
it evicts that peer's oldest `Assembling` entry.
`CompletedQueued` and `Writing` entries are not evicted and their slots are not
reused until the TUN write completes.

An exact duplicate fragment uses first-write-wins and increments a counter.
Conflicting duplicates, overlaps, count mismatches, and invalid ranges drop the
whole packet.

Reorder operates on completed packets independently of reassembly. Each lane
delivers in-order packets immediately and holds future sequence numbers in a
fixed queue. A gap is held for at most 10 ms, then flushed in sequence order
with the gap skipped. Older or late packets are dropped. On queue overflow, the
gap is flushed immediately rather than discarding the oldest completed packet.
There is no retransmission.

## Source validation and native fragments

WireGuard itself validates only the hidden carrier source against its AllowedIPs.
WGF reruns the full WireGuard-compatible longest-prefix match against the user
AllowedIPs for every reconstructed inner source. It delivers the packet to the
TUN only when the result is the peer that authenticated the carrier. Merely
matching any prefix belonging to that peer is insufficient. Outbound peer
selection uses the same global longest-prefix match and requires all records in
a carrier to resolve to the same peer.

In v1, native IPv4 fragments (MF set or a nonzero offset) and packets containing
an IPv6 Fragment Header are dropped and counted in both directions. WGF does not
generate PTB for an inner packet that was already fragmented.

See [`threat-model.md`](threat-model.md) for security assumptions and residual
risks.
