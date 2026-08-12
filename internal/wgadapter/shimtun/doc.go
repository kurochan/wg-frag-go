// Package shimtun adapts a native inner-IP TUN to the synthetic IPv6 carrier
// TUN consumed by wireguard-go.
//
// The adapter keeps one owner for native reads and each peer's sender, while
// peer receive/reassembly state is independently serialized. DATA and CONTROL
// queues use fixed, bounded storage; carrier and packet slices are consumed
// synchronously and must not be retained by sinks.
package shimtun
