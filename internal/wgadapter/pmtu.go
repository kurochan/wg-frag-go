package wgadapter

// CanonicalCarrierPayload rounds a WGF carrier payload down to the largest
// value represented by the WireGuard 16-byte plaintext padding bucket.
func CanonicalCarrierPayload(payload uint32) uint32 {
	const (
		syntheticIPv6Header = 40
		paddingBoundary     = 16
	)
	if payload < syntheticIPv6Header {
		return payload
	}
	return (payload+syntheticIPv6Header)/paddingBoundary*paddingBoundary - syntheticIPv6Header
}

// WireGuardDatagramSize returns the UDP payload size emitted by WireGuard for
// one WGF carrier payload. It includes the WireGuard data header and tag.
func WireGuardDatagramSize(payload uint32) int {
	const (
		wireGuardOverhead   = 32
		syntheticIPv6Header = 40
		paddingBoundary     = 16
	)
	return wireGuardOverhead + int((payload+syntheticIPv6Header+paddingBoundary-1)/paddingBoundary*paddingBoundary)
}
