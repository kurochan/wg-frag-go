package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

// runInterfaces lists every daemon reachable through the runtime socket
// directory, so `wgf show all` and `wgf show interfaces` need no registry.
func runInterfaces(socketDir string) []string {
	entries, err := os.ReadDir(socketDir)
	if err != nil {
		return nil
	}
	names := []string{}

	for _, entry := range entries {
		if name, ok := strings.CutSuffix(entry.Name(), ".sock"); ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func showInterfaces(getStatus statusGetter, socketDir string, stdout io.Writer) error {
	for _, name := range runInterfaces(socketDir) {
		if _, err := getStatus(context.Background(), filepath.Join(socketDir, name+".sock")); err == nil {
			fmt.Fprintln(stdout, name)
		}
	}
	return nil
}

func showAll(getStatus statusGetter, socketDir string, stdout io.Writer) error {
	first := true

	for _, name := range runInterfaces(socketDir) {
		status, err := getStatus(context.Background(), filepath.Join(socketDir, name+".sock"))
		if err != nil {
			continue
		}
		if !first {
			fmt.Fprintln(stdout)
		}
		first = false

		renderStatus(stdout, status)
	}
	return nil
}

// renderPathMTU is the `wgf show <if> path-mtu` view: one line per peer with
// the DPLPMTUD state that matters when diagnosing a black-holed path.
func renderPathMTU(w io.Writer, status *controlapiv1.GetStatusResponse) {
	fmt.Fprintf(w, "interface: %s\n", status.GetInterfaceName())

	for _, peer := range status.GetPeers() {
		fmt.Fprintf(w, "peer: %s\n", peer.GetPublicKey())
		fmt.Fprintf(w, "  carrier payload: %d bytes\n", peer.GetConfirmedCarrierPayload())
		fmt.Fprintf(w, "  searching: %t\n", peer.GetPmtuSearching())
		if peer.GetControlPathState() != "" {
			fmt.Fprintf(w, "  control path: %s\n", peer.GetControlPathState())
		}
		if peer.GetControlPathError() != "" {
			fmt.Fprintf(w, "  control path error: %s\n", peer.GetControlPathError())
		}
	}
}

// renderFragment is the `wgf show <if> fragment` view: the fragmentation and
// reassembly counters without the peer session details.
func renderFragment(w io.Writer, status *controlapiv1.GetStatusResponse) {
	counters := status.GetCounters()
	fmt.Fprintf(w, "interface: %s\n", status.GetInterfaceName())
	fmt.Fprintf(w, "  carriers sent: %d\n", counters.GetTxCarriers())
	fmt.Fprintf(w, "  carriers received: %d\n", counters.GetRxDataCarriers())
	fmt.Fprintf(w, "  inner packets delivered: %d\n", counters.GetRxInnerDelivered())
	fmt.Fprintf(w, "  reassembly expirations: %d\n", counters.GetReassemblyExpirations())
	fmt.Fprintf(w, "  peer mtu drops: %d\n", counters.GetTxPeerMtuDrops())
	fmt.Fprintf(w, "  ptb sent: %d\n", counters.GetTxPtbSent())
}

// renderStats is the `wgf show <if> stats` view: every counter, one per line,
// in a stable machine-friendly key=value format.
func renderStats(w io.Writer, status *controlapiv1.GetStatusResponse) {
	counters := status.GetCounters()
	fmt.Fprintf(w, "interface=%s\n", status.GetInterfaceName())
	fmt.Fprintf(w, "generation=%d\n", status.GetGeneration())
	fmt.Fprintf(w, "tx_carriers=%d\n", counters.GetTxCarriers())
	fmt.Fprintf(w, "tx_packet_drops=%d\n", counters.GetTxPacketDrops())
	fmt.Fprintf(w, "tx_route_drops=%d\n", counters.GetTxRouteDrops())
	fmt.Fprintf(w, "tx_peer_mtu_drops=%d\n", counters.GetTxPeerMtuDrops())
	fmt.Fprintf(w, "tx_ptb_sent=%d\n", counters.GetTxPtbSent())
	fmt.Fprintf(w, "rx_data_carriers=%d\n", counters.GetRxDataCarriers())
	fmt.Fprintf(w, "rx_inner_delivered=%d\n", counters.GetRxInnerDelivered())
	fmt.Fprintf(w, "rx_packet_rejects=%d\n", counters.GetRxPacketRejects())
	fmt.Fprintf(w, "rx_source_spoof_drops=%d\n", counters.GetRxSourceSpoofDrops())
	fmt.Fprintf(w, "rx_native_write_drops=%d\n", counters.GetRxNativeWriteDrops())
	fmt.Fprintf(w, "carrier_queue_overflows=%d\n", counters.GetCarrierQueueOverflows())
	fmt.Fprintf(w, "preconfirm_drops=%d\n", counters.GetPreconfirmDrops())
	fmt.Fprintf(w, "reassembly_expirations=%d\n", counters.GetReassemblyExpirations())
	fmt.Fprintf(w, "udp_socket_drops=%d\n", counters.GetUdpSocketDrops())
	fmt.Fprintf(w, "control_exploratory_evictions=%d\n", counters.GetControlExploratoryEvictions())
	fmt.Fprintf(w, "control_coalesces=%d\n", counters.GetControlCoalesces())
	fmt.Fprintf(w, "control_queue_drops=%d\n", counters.GetControlQueueDrops())
	fmt.Fprintf(w, "control_rate_suppression_episodes=%d\n", counters.GetControlRateSuppressionEpisodes())
	fmt.Fprintf(w, "control_materialization_drops=%d\n", counters.GetControlMaterializationDrops())
	fmt.Fprintf(w, "control_ingress_rate_limited=%d\n", counters.GetControlIngressRateLimited())
	for _, peer := range status.GetPeers() {
		prefix := "peer." + peer.GetPublicKey()
		fmt.Fprintf(w, "%s.carrier_payload=%d\n", prefix, peer.GetConfirmedCarrierPayload())
		fmt.Fprintf(w, "%s.searching=%t\n", prefix, peer.GetPmtuSearching())
		fmt.Fprintf(w, "%s.data_ready=%t\n", prefix, peer.GetDataReady())
		fmt.Fprintf(w, "%s.control_path=%s\n", prefix, peer.GetControlPathState())
		fmt.Fprintf(w, "%s.rx_bytes=%d\n", prefix, peer.GetTransferRxBytes())
		fmt.Fprintf(w, "%s.tx_bytes=%d\n", prefix, peer.GetTransferTxBytes())
	}
}
