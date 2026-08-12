// Package control implements the OS-independent CONTROL carrier frame.
//
// A v1 frame is exactly one carrier payload:
//
//	uint16 marker = 0x0000 (network byte order)
//	uint8  protocol version = 1
//	bytes  protobuf payload
//
// A CONTROL frame cannot be mixed with DATA records. Codec therefore treats
// its input as the complete carrier payload and returns the complete bytes
// after the fixed header without copying them.
//
// This package deliberately does not interpret or generate protobuf messages,
// correlate requests, or implement the CONTROL state machine. Those layers
// consume and produce the protobuf payload passed to Codec.
package control
