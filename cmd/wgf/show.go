package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/kurochan/wg-frag-go/controlapi"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

// statusGetter is injected by tests; the default queries the daemon socket.
type statusGetter func(ctx context.Context, socketPath, interfaceName string) (*controlapiv1.InterfaceStatus, error)
type statusLister func(ctx context.Context, socketPath string) ([]*controlapiv1.InterfaceStatus, error)

func show(args []string, getStatus statusGetter, listStatuses statusLister, stdout io.Writer) error {
	if len(args) == 0 || args[0] == "" || args[0] == "all" {
		return showAll(getStatus, listStatuses, filepath.Dir(controlapi.SocketPath("x")), stdout)
	}
	if args[0] == "interfaces" {
		return showInterfaces(getStatus, listStatuses, filepath.Dir(controlapi.SocketPath("x")), stdout)
	}
	ifname := args[0]
	socket := controlapi.SocketPath(ifname)
	view := ""

	rest := args[1:]
	explicitSocket := false
	for len(rest) != 0 {
		switch rest[0] {
		case "--control-socket":
			if len(rest) < 2 {
				return errors.New("--control-socket requires a path")
			}
			socket = rest[1]
			explicitSocket = true
			rest = rest[2:]
		case "fragment", "path-mtu", "stats":
			if view != "" {
				return fmt.Errorf("unexpected argument %q", rest[0])
			}
			view = rest[0]
			rest = rest[1:]
		default:
			return fmt.Errorf("unexpected argument %q", rest[0])
		}
	}
	status, err := getStatus(context.Background(), socket, ifname)
	if err != nil && !explicitSocket {
		perInterfaceErr := err
		status, err = getStatus(context.Background(), controlapi.ManagerSocketPath(), ifname)
		if err != nil {
			err = errors.Join(
				fmt.Errorf("per-interface control socket: %w", perInterfaceErr),
				fmt.Errorf("manager control socket: %w", err),
			)
		}
	}
	if err != nil {
		return fmt.Errorf("is `wgf run %s` running? %w", ifname, err)
	}

	switch view {
	case "fragment":
		renderFragment(stdout, status)
	case "path-mtu":
		renderPathMTU(stdout, status)
	case "stats":
		renderStats(stdout, status)
	default:
		renderStatus(stdout, status)
	}
	return nil
}

func renderStatus(w io.Writer, status *controlapiv1.InterfaceStatus) {
	fmt.Fprintf(w, "interface: %s\n", status.GetRef().GetInterfaceName())
	fmt.Fprintf(w, "  public key: %s\n", status.GetPublicKey())
	fmt.Fprintf(w, "  listening port: %d\n", status.GetListenPort())
	fmt.Fprintf(w, "  mtu: %d\n", status.GetMtu())

	for _, peer := range status.GetPeers() {
		fmt.Fprintf(w, "\npeer: %s\n", peer.GetPublicKey())
		if peer.GetEndpoint() != "" {
			fmt.Fprintf(w, "  endpoint: %s\n", peer.GetEndpoint())
		}
		fmt.Fprintf(w, "  allowed ips: %s\n", joinOrNone(peer.GetAllowedIps()))
		if peer.GetLastHandshakeUnix() != 0 {
			fmt.Fprintf(w, "  latest handshake: %s ago\n",
				time.Since(time.Unix(peer.GetLastHandshakeUnix(), 0)).Round(time.Second))
		}
		fmt.Fprintf(w, "  transfer: %d B received, %d B sent\n", peer.GetTransferRxBytes(), peer.GetTransferTxBytes())
		if peer.GetPersistentKeepaliveSec() != 0 {
			fmt.Fprintf(w, "  persistent keepalive: every %d seconds\n", peer.GetPersistentKeepaliveSec())
		}
		state := "handshaking"
		if peer.GetDataReady() {
			state = "ready"
		}
		fmt.Fprintf(w, "  wgf data: %s\n", state)
		fmt.Fprintf(w, "  wgf carrier payload: %d bytes (searching: %t)\n",
			peer.GetConfirmedCarrierPayload(), peer.GetPmtuSearching())
		if peer.GetControlPathState() != "" {
			fmt.Fprintf(w, "  wgf control path: %s\n", peer.GetControlPathState())
		}
		if peer.GetControlPathError() != "" {
			fmt.Fprintf(w, "  wgf control path error: %s\n", peer.GetControlPathError())
		}
	}

	counters := status.GetCounters()
	if counters == nil {
		return
	}
	fmt.Fprintf(w, "\ncounters:\n")
	fmt.Fprintf(w, "  carriers: %d sent, %d received, %d inner delivered\n",
		counters.GetTxCarriers(), counters.GetRxDataCarriers(), counters.GetRxInnerDelivered())
	fmt.Fprintf(w, "  drops: tx %d (route %d, peer mtu %d), rx rejects %d (spoof %d), tun write %d\n",
		counters.GetTxPacketDrops(), counters.GetTxRouteDrops(), counters.GetTxPeerMtuDrops(),
		counters.GetRxPacketRejects(), counters.GetRxSourceSpoofDrops(), counters.GetRxNativeWriteDrops())
	fmt.Fprintf(w, "  ptb sent: %d\n", counters.GetTxPtbSent())
	fmt.Fprintf(
		w,
		"  pressure: carrier queue overflows %d, preconfirm drops %d, "+
			"reassembly expirations %d, udp socket drops %d\n",
		counters.GetCarrierQueueOverflows(), counters.GetPreconfirmDrops(),
		counters.GetReassemblyExpirations(), counters.GetUdpSocketDrops())
	fmt.Fprintf(w, "  control pressure: queue drops %d, exploratory evictions %d, coalesces %d, suppression episodes %d, materialization drops %d\n",
		counters.GetControlQueueDrops(), counters.GetControlExploratoryEvictions(), counters.GetControlCoalesces(),
		counters.GetControlRateSuppressionEpisodes(), counters.GetControlMaterializationDrops())
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, ", ")
}
