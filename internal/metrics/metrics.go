package metrics

import (
	"errors"
	"fmt"
	"strings"
)

// Descriptor defines one supported OpenMetrics metric and its family metadata.
type Descriptor struct {
	// Name is the canonical emitted sample name and selector input.
	Name   string
	Family string
	Help   string
	Type   string
	Scope  Scope
}

// Scope identifies the owner of a metric series and its required labels.
type Scope uint8

const (
	// ScopeProcess identifies metrics that describe the running process.
	ScopeProcess Scope = iota
	// ScopeInterface identifies metrics that describe one WGF interface.
	ScopeInterface
	// ScopePeer identifies metrics that describe one peer on one interface.
	ScopePeer
)

// Descriptors is the canonical, stable set of metrics. Configuration
// selection is validated against this list so a typo never silently removes
// observability.
var Descriptors = []Descriptor{
	processGauge("wgf_build_info", "Build information for the running WGF binary."),
	processGauge("wgf_manager_interfaces", "Interfaces currently managed by this WGF process."),
	interfaceCounter("wgf_tx_carriers_total", "DATA carriers transmitted by the shim."),
	interfaceCounter("wgf_tx_packet_drops_total", "Inner packets dropped before transmission."),
	interfaceCounter("wgf_tx_native_fragment_drops_total", "Native IP fragments dropped on transmit."),
	interfaceCounter("wgf_tx_route_drops_total", "Inner packets dropped because no peer route matched."),
	interfaceCounter("wgf_tx_peer_mtu_drops_total", "Inner packets dropped because they exceed the peer MTU."),
	interfaceCounter("wgf_tx_ptb_sent_total", "Packet Too Big messages sent to the native TUN."),
	interfaceCounter("wgf_rx_data_carriers_total", "DATA carriers received by the shim."),
	interfaceCounter("wgf_rx_inner_packets_total", "Reassembled inner packets delivered to the native TUN."),
	interfaceCounter("wgf_rx_packet_rejects_total", "Received packets rejected by the shim."),
	interfaceCounter("wgf_rx_native_fragment_drops_total", "Native IP fragments dropped on receive."),
	interfaceCounter("wgf_rx_source_spoof_drops_total", "Received packets dropped by source validation."),
	interfaceCounter("wgf_rx_native_write_drops_total", "Packets dropped because the native TUN could not accept them."),
	interfaceCounter("wgf_carrier_queue_overflows_total", "DATA carrier queue overflows."),
	interfaceCounter("wgf_control_queue_drops_total", "CONTROL descriptors dropped because the scheduler was full."),
	interfaceCounter("wgf_control_exploratory_evictions_total", "Exploratory CONTROL descriptors evicted for critical messages."),
	interfaceCounter("wgf_control_coalesces_total", "CONTROL descriptors coalesced by the scheduler."),
	interfaceCounter("wgf_control_rate_suppression_episodes_total", "CONTROL rate-limit suppression episodes."),
	interfaceCounter("wgf_control_materialization_drops_total", "CONTROL descriptors dropped during materialization."),
	interfaceCounter("wgf_control_ingress_rate_limited_total", "Inbound CONTROL messages rate limited."),
	interfaceCounter("wgf_preconfirm_drops_total", "Inner packets dropped before the CONTROL gate opened."),
	interfaceCounter("wgf_reassembly_expirations_total", "Incomplete reassemblies expired."),
	interfaceCounter("wgf_udp_socket_drops_total", "Kernel-reported UDP socket receive drops."),
	peerGauge("wgf_peer_pmtu_carrier_payload_bytes", "Confirmed carrier payload limit for a peer."),
	peerGauge("wgf_peer_pmtu_searching", "Whether a peer is searching for a carrier payload limit."),
	peerGauge("wgf_peer_data_forwarding_enabled", "Whether DATA forwarding is enabled for a peer."),
}

func processGauge(name, help string) Descriptor {
	return Descriptor{Name: name, Family: name, Help: help, Type: "gauge", Scope: ScopeProcess}
}

func interfaceCounter(name, help string) Descriptor {
	return Descriptor{Name: name, Family: strings.TrimSuffix(name, "_total"), Help: help, Type: "counter", Scope: ScopeInterface}
}

func peerGauge(name, help string) Descriptor {
	return Descriptor{Name: name, Family: name, Help: help, Type: "gauge", Scope: ScopePeer}
}

var known = func() map[string]struct{} {
	result := make(map[string]struct{}, len(Descriptors))
	for _, descriptor := range Descriptors {
		result[descriptor.Name] = struct{}{}
	}
	return result
}()

// Selector filters metrics by their canonical emitted names.
type Selector struct {
	include []string
	exclude []string
}

// NewSelector validates include and exclude patterns. Empty include selects all
// metrics; exclude always takes precedence.
func NewSelector(include, exclude []string) (Selector, error) {
	if err := validatePatterns(include); err != nil {
		return Selector{}, fmt.Errorf("metrics include: %w", err)
	}
	if err := validatePatterns(exclude); err != nil {
		return Selector{}, fmt.Errorf("metrics exclude: %w", err)
	}
	return Selector{include: append([]string(nil), include...), exclude: append([]string(nil), exclude...)}, nil
}

// Enabled reports whether name is selected by this selector.
func (s Selector) Enabled(name string) bool {
	if _, ok := known[name]; !ok {
		return false
	}
	if len(s.include) != 0 && !matchesAny(s.include, name) {
		return false
	}
	return !matchesAny(s.exclude, name)
}

func validatePatterns(patterns []string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			return errors.New("empty pattern")
		}
		if strings.Count(pattern, "*") > 1 {
			return fmt.Errorf("pattern %q contains more than one *", pattern)
		}
		if strings.ContainsAny(pattern, "?[]\\") {
			return fmt.Errorf("pattern %q contains unsupported wildcard syntax", pattern)
		}
		matched := false
		for name := range known {
			if match(pattern, name) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("pattern %q matches no metric", pattern)
		}
	}
	return nil
}

func matchesAny(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if match(pattern, name) {
			return true
		}
	}
	return false
}

func match(pattern, name string) bool {
	before, after, wildcard := strings.Cut(pattern, "*")
	if !wildcard {
		return pattern == name
	}
	return strings.HasPrefix(name, before) && strings.HasSuffix(name, after) && len(name) >= len(before)+len(after)
}
