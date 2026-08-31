//go:build linux || darwin

package manager

import (
	"bytes"
	"runtime"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/metrics"
	"github.com/kurochan/wg-frag-go/internal/version"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

// GatherOpenMetrics renders a process-wide snapshot for all interfaces owned
// by the manager. Metrics are collected only when this method is called.
func (manager *Manager) GatherOpenMetrics(include, exclude []string) ([]byte, error) {
	selector, err := metrics.NewSelector(include, exclude)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := metrics.WriteOpenMetrics(&output, selector, manager.metricsSnapshot()); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (manager *Manager) metricsSnapshot() metrics.Snapshot {
	items := manager.supervisors()
	snapshot := metrics.Snapshot{
		BuildLabels: map[string]string{
			"version":    version.Version,
			"commit":     version.Commit,
			"go_version": runtime.Version(),
		},
		Samples: []metrics.Sample{{Name: "wgf_manager_interfaces", Value: uint64(len(items))}},
	}
	for _, supervisor := range items {
		if current, ok := supervisor.metricsSnapshot(); ok {
			snapshot.InterfaceSnapshots = append(snapshot.InterfaceSnapshots, current)
		}
	}
	return snapshot
}

func (supervisor *interfaceSupervisor) metricsSnapshot() (metrics.InterfaceSnapshot, bool) {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	supervisor.mu.RLock()
	running := supervisor.running
	publicKey := supervisor.publicKey
	name := supervisor.name
	supervisor.mu.RUnlock()

	base := supervisor.manager.counterBase(publicKey)
	if running == nil {
		return metrics.InterfaceSnapshot{
			Name:    name,
			ID:      config.MetricsInterfaceID(config.Key(publicKey)),
			Samples: counterMetricSamples(base),
		}, true
	}
	live := running.metricsSnapshot()
	if len(live.InterfaceSnapshots) != 1 {
		return metrics.InterfaceSnapshot{}, false
	}
	current := live.InterfaceSnapshots[0]
	baseValues := counterMetricValues(base)
	for index := range current.Samples {
		current.Samples[index].Value += baseValues[current.Samples[index].Name]
	}
	return current, true
}

func counterMetricSamples(counters *controlapiv1.ShimCounters) []metrics.Sample {
	values := counterMetricValues(counters)
	samples := make([]metrics.Sample, 0, len(values))
	for name, value := range values {
		samples = append(samples, metrics.Sample{Name: name, Value: value})
	}
	return samples
}

func counterMetricValues(counters *controlapiv1.ShimCounters) map[string]uint64 {
	if counters == nil {
		counters = controlapiv1.ShimCounters_builder{}.Build()
	}
	return map[string]uint64{
		"wgf_tx_carriers_total":                       counters.GetTxCarriers(),
		"wgf_tx_packet_drops_total":                   counters.GetTxPacketDrops(),
		"wgf_tx_native_fragment_drops_total":          counters.GetTxNativeFragmentDrops(),
		"wgf_tx_route_drops_total":                    counters.GetTxRouteDrops(),
		"wgf_tx_peer_mtu_drops_total":                 counters.GetTxPeerMtuDrops(),
		"wgf_tx_ptb_sent_total":                       counters.GetTxPtbSent(),
		"wgf_rx_data_carriers_total":                  counters.GetRxDataCarriers(),
		"wgf_rx_inner_packets_total":                  counters.GetRxInnerDelivered(),
		"wgf_rx_packet_rejects_total":                 counters.GetRxPacketRejects(),
		"wgf_rx_native_fragment_drops_total":          counters.GetRxNativeFragmentDrops(),
		"wgf_rx_source_spoof_drops_total":             counters.GetRxSourceSpoofDrops(),
		"wgf_rx_native_write_drops_total":             counters.GetRxNativeWriteDrops(),
		"wgf_carrier_queue_overflows_total":           counters.GetCarrierQueueOverflows(),
		"wgf_control_queue_drops_total":               counters.GetControlQueueDrops(),
		"wgf_control_exploratory_evictions_total":     counters.GetControlExploratoryEvictions(),
		"wgf_control_coalesces_total":                 counters.GetControlCoalesces(),
		"wgf_control_rate_suppression_episodes_total": counters.GetControlRateSuppressionEpisodes(),
		"wgf_control_materialization_drops_total":     counters.GetControlMaterializationDrops(),
		"wgf_control_ingress_rate_limited_total":      counters.GetControlIngressRateLimited(),
		"wgf_preconfirm_drops_total":                  counters.GetPreconfirmDrops(),
		"wgf_reassembly_expirations_total":            counters.GetReassemblyExpirations(),
		"wgf_udp_socket_drops_total":                  counters.GetUdpSocketDrops(),
	}
}
