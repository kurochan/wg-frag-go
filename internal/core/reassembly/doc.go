// Package reassembly provides fixed-capacity, OS-independent DATA fragment
// reassembly.
//
// All packet storage and peer counters are allocated by New. Accept performs
// direct copies into fixed slots and does not allocate on the hot path.
package reassembly
