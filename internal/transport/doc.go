// Package transport defines the small, transport-neutral carrier boundary.
//
// The boundary exchanges carrier payloads, not synthetic IP packets. A
// payload is a DATA record sequence or one CONTROL frame. The transport
// adapter authenticates a datagram and supplies the logical peer ID; the shim
// owns routing, sequencing, reassembly, and CONTROL policy.
//
// Descriptors borrow caller-owned buffers. A descriptor returned by a read is
// valid until the caller reuses its buffer; a descriptor supplied to a write
// is read synchronously and is not retained after the call returns. Batch
// slices and their buffers must remain stable for the duration of the call.
package transport
