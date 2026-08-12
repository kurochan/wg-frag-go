// Package controlplane drives one peer's v1 CONTROL startup exchange. PMTU
// candidate canonicalization and transport datagram sizing are injected by
// the adapter; nil strategies keep this package transport-neutral.
//
// Engine is single-owner and is not safe for concurrent use; all methods that
// read or mutate it must be serialized by the caller. Start and HandleInbound
// return newly allocated frames. Ownership of every returned Frame transfers
// to the caller, which may synchronously copy it into the shim's fixed CONTROL
// ring.
package controlplane
