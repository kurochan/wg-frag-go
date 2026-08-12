// Package peerroute implements platform-independent peer routing primitives.
//
// Carrier addresses are hidden IPv6 addresses used only between the WGF shim
// and wireguard-go. They are not assigned to an operating-system interface.
// User AllowedIPs are compiled into immutable IPv4 and IPv6 longest-prefix
// snapshots used for both outbound peer selection and inbound source
// validation.
package peerroute
