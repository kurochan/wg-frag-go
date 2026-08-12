// Package state implements the OS-independent CONTROL capability and session
// gate.
//
// State has a single owner and is not safe for concurrent use. Callers pass
// decoded wirev1.Control messages to it and serialize the returned decisions
// themselves. Protobuf framing, retries, timers, and transport I/O live in
// higher layers.
package state
