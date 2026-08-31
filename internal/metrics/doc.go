// Package metrics defines WGF's bounded-cardinality OpenMetrics surface.
//
// It contains the canonical metric names, configuration-time selection rules,
// and the text encoder. Runtime code supplies a point-in-time Snapshot when a
// client requests /metrics; process samples have no interface labels, while
// interface and peer samples are emitted with a fixed label schema. The
// package never observes the packet hot path.
package metrics
