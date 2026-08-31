package daemonruntime

import (
	"errors"
	"runtime"
	"strconv"
	"strings"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/metrics"
	"github.com/kurochan/wg-frag-go/internal/version"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
)

func effectiveListenPort(uapi string) (uint16, error) {
	for line := range strings.Lines(uapi) {
		value, ok := strings.CutPrefix(line, "listen_port=")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
		if err != nil || port == 0 {
			return 0, errors.New("WireGuard reported an invalid listen port")
		}
		return uint16(port), nil
	}
	return 0, errors.New("WireGuard did not report a listen port")
}

// MetricsSnapshot returns the data-plane metrics for this generation. The
// manager is responsible for adding retained counters from prior generations.
func (rt *daemonRuntime) metricsSnapshot() metrics.Snapshot {
	stats := rt.shim.Stats()
	dropsV4, dropsV6 := rt.bind.SocketDrops()
	interfaceID := config.MetricsInterfaceID(config.Key(rt.plan.LocalPublicKey))
	snapshot := metrics.Snapshot{
		BuildLabels: map[string]string{
			"version":    version.Version,
			"commit":     version.Commit,
			"go_version": runtime.Version(),
		},
		InterfaceSnapshots: []metrics.InterfaceSnapshot{{
			Name:    rt.ifname,
			ID:      interfaceID,
			Samples: interfaceMetricSamples(stats, dropsV4+dropsV6),
		}},
	}
	for _, peer := range rt.shim.PeerStats() {
		if peer.MetricsID == "" {
			continue
		}
		labels := map[string]string{"peer_id": peer.MetricsID}
		snapshot.InterfaceSnapshots[0].Samples = append(snapshot.InterfaceSnapshots[0].Samples,
			metrics.Sample{Name: "wgf_peer_pmtu_carrier_payload_bytes", Labels: labels, Value: uint64(peer.CarrierPayload)},
			metrics.Sample{Name: "wgf_peer_pmtu_searching", Labels: labels, Value: boolMetricValue(peer.PMTUSearching)},
			metrics.Sample{Name: "wgf_peer_data_forwarding_enabled", Labels: labels, Value: boolMetricValue(peer.DataForwardingEnabled)},
		)
	}
	return snapshot
}

func interfaceMetricSamples(stats shimtun.Stats, socketDrops uint64) []metrics.Sample {
	return []metrics.Sample{
		{Name: "wgf_tx_carriers_total", Value: stats.TXCarriers},
		{Name: "wgf_tx_packet_drops_total", Value: stats.TXPacketDrops},
		{Name: "wgf_tx_native_fragment_drops_total", Value: stats.TXNativeFragmentDrops},
		{Name: "wgf_tx_route_drops_total", Value: stats.TXRouteDrops},
		{Name: "wgf_tx_peer_mtu_drops_total", Value: stats.TXPeerMTUDrops},
		{Name: "wgf_tx_ptb_sent_total", Value: stats.TXPTBSent},
		{Name: "wgf_rx_data_carriers_total", Value: stats.RXDataCarriers},
		{Name: "wgf_rx_inner_packets_total", Value: stats.RXInnerDelivered},
		{Name: "wgf_rx_packet_rejects_total", Value: stats.RXPacketRejects},
		{Name: "wgf_rx_native_fragment_drops_total", Value: stats.RXNativeFragmentDrops},
		{Name: "wgf_rx_source_spoof_drops_total", Value: stats.RXSourceSpoofDrops},
		{Name: "wgf_rx_native_write_drops_total", Value: stats.RXNativeWriteDrops},
		{Name: "wgf_carrier_queue_overflows_total", Value: stats.CarrierQueueOverflows},
		{Name: "wgf_control_queue_drops_total", Value: stats.ControlQueueDrops},
		{Name: "wgf_control_exploratory_evictions_total", Value: stats.ControlExploratoryEvictions},
		{Name: "wgf_control_coalesces_total", Value: stats.ControlCoalesces},
		{Name: "wgf_control_rate_suppression_episodes_total", Value: stats.ControlRateSuppressionEpisodes},
		{Name: "wgf_control_materialization_drops_total", Value: stats.ControlMaterializationDrops},
		{Name: "wgf_control_ingress_rate_limited_total", Value: stats.ControlIngressRateLimited},
		{Name: "wgf_preconfirm_drops_total", Value: stats.PreconfirmDrops},
		{Name: "wgf_reassembly_expirations_total", Value: stats.ReassemblyExpirations},
		{Name: "wgf_udp_socket_drops_total", Value: socketDrops},
	}
}

func boolMetricValue(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
