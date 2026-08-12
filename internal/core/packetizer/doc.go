// Package packetizer packs DATA records from different inner packets into a
// bounded carrier payload. It owns no buffers: callers provide one reusable
// buffer and synchronously consume flushed carriers through Emitter.
package packetizer
