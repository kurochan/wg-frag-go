// Package metrics defines WGF's bounded-cardinality OpenMetrics surface.
//
// It contains the canonical metric names, configuration-time selection rules,
// and the text encoder. Runtime code supplies a point-in-time Snapshot when a
// client requests /metrics; this package never observes the packet hot path.
package metrics
