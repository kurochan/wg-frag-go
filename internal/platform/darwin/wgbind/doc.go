// Package wgbind provides the macOS UDP transport used by wgf.
//
// Bind uses one IPv4 and one IPv6 UDP socket, disables outer IP fragmentation
// on both, and reports synchronous EMSGSIZE failures to the platform-neutral
// control plane. macOS has no Linux UDP GSO/GRO or error queue equivalent, so
// this implementation deliberately uses one datagram per syscall.
package wgbind
