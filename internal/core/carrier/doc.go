// Package carrier encodes and decodes wg-frag-go DATA carrier records.
//
// Records use network byte order and are decoded without copying fragment data.
// Callers provide destination storage when encoding so the hot path does not
// require allocations.
package carrier
