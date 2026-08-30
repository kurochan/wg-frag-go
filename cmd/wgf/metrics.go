//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/metrics"
	"github.com/kurochan/wg-frag-go/internal/version"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
)

const openMetricsContentType = "application/openmetrics-text; version=1.0.0; charset=utf-8"

type metricsServer struct {
	listeners []net.Listener
	servers   []*http.Server
	done      sync.WaitGroup
}

func startMetricsServer(iface config.Interface, port uint16, logger *slog.Logger, snapshot func() metrics.Snapshot) (*metricsServer, error) {
	return startMetricsServerWithListen(iface, port, logger, snapshot, net.Listen)
}

type metricsListenFunc func(network, address string) (net.Listener, error)

func startMetricsServerWithListen(
	iface config.Interface,
	port uint16,
	logger *slog.Logger,
	snapshot func() metrics.Snapshot,
	listen metricsListenFunc,
) (*metricsServer, error) {
	selector, err := metrics.NewSelector(iface.MetricsInclude, iface.MetricsExclude)
	if err != nil {
		return nil, err
	}
	addresses, err := metricsAddresses(iface.MetricsListen, port)
	if err != nil {
		return nil, err
	}
	server := &metricsServer{}
	cache := newMetricsResponseCache(selector, snapshot)
	boundAddresses := make([]string, 0, len(addresses))
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/metrics" {
			http.NotFound(w, request)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", openMetricsContentType)
		if request.Method == http.MethodHead {
			return
		}
		body, bodyErr := cache.get()
		if bodyErr != nil {
			http.Error(w, "metrics unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})
	for _, address := range addresses {
		listener, listenErr := listen("tcp", address)
		if listenErr != nil {
			if iface.MetricsListen.Auto {
				if logger != nil {
					logger.Warn("metrics loopback listener unavailable", "address", address, "error", listenErr)
				}
				continue
			}
			_ = server.Close()
			return nil, fmt.Errorf("listen %s: %w", address, listenErr)
		}
		server.listeners = append(server.listeners, listener)
		boundAddress := listener.Addr().String()
		boundAddresses = append(boundAddresses, boundAddress)
		if !isLoopbackMetricsAddress(boundAddress) && logger != nil {
			logger.Warn("metrics listener is not loopback-only", "address", boundAddress)
		}
	}
	if len(server.listeners) == 0 {
		return nil, errors.New("no metrics listener could be started")
	}
	for _, listener := range server.listeners {
		httpServer := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: metricsReadHeaderTimeout,
			WriteTimeout:      metricsWriteTimeout,
			IdleTimeout:       metricsIdleTimeout,
			MaxHeaderBytes:    metricsMaxHeaderBytes,
		}
		server.servers = append(server.servers, httpServer)
		server.done.Add(1)
		go func(listener net.Listener, httpServer *http.Server) {
			defer server.done.Done()
			if serveErr := httpServer.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && logger != nil {
				logger.Warn("metrics listener stopped unexpectedly", "address", listener.Addr().String(), "error", serveErr)
			}
		}(listener, httpServer)
	}
	if logger != nil {
		logger.Info("metrics listener started", "addresses", strings.Join(boundAddresses, ","))
	}
	return server, nil
}

const metricsReadHeaderTimeout = 5 * time.Second

const (
	metricsWriteTimeout   = 10 * time.Second
	metricsIdleTimeout    = 30 * time.Second
	metricsShutdownWait   = 10 * time.Second
	metricsCacheTTL       = time.Second
	metricsMaxHeaderBytes = 4 << 10
)

func (server *metricsServer) Close() error {
	if server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownWait)
	defer cancel()
	var result error
	for _, httpServer := range server.servers {
		if err := httpServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.DeadlineExceeded) {
			result = errors.Join(result, err)
		}
	}
	if ctx.Err() != nil {
		for _, httpServer := range server.servers {
			if err := httpServer.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				result = errors.Join(result, err)
			}
		}
	}
	for _, listener := range server.listeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	server.done.Wait()
	return result
}

type metricsResponseCache struct {
	mu       sync.Mutex
	selector metrics.Selector
	snapshot func() metrics.Snapshot
	body     []byte
	at       time.Time
}

func newMetricsResponseCache(selector metrics.Selector, snapshot func() metrics.Snapshot) *metricsResponseCache {
	return &metricsResponseCache{selector: selector, snapshot: snapshot}
}

func (cache *metricsResponseCache) get() ([]byte, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if time.Since(cache.at) < metricsCacheTTL {
		return cache.body, nil
	}
	var body bytes.Buffer
	if err := metrics.WriteOpenMetrics(&body, cache.selector, cache.snapshot()); err != nil {
		return nil, err
	}
	cache.body = body.Bytes()
	cache.at = time.Now()
	return cache.body, nil
}

func metricsAddresses(listen config.MetricsListen, port uint16) ([]string, error) {
	if listen.Auto {
		if port == 0 {
			return nil, errors.New("effective WireGuard listen port is zero")
		}
		portText := strconv.FormatUint(uint64(port), 10)
		return []string{net.JoinHostPort("127.0.0.1", portText), net.JoinHostPort("::1", portText)}, nil
	}
	if len(listen.Addresses) == 0 {
		return nil, errors.New("no metrics listener addresses")
	}
	return append([]string(nil), listen.Addresses...), nil
}

func isLoopbackMetricsAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

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

func (rt *daemonRuntime) metricsSnapshot() metrics.Snapshot {
	stats := rt.shim.Stats()
	dropsV4, dropsV6 := rt.bind.SocketDrops()
	interfaceLabels := map[string]string{"interface": rt.ifname}
	snapshot := metrics.Snapshot{
		BuildLabels: map[string]string{
			"version":    version.Version,
			"commit":     version.Commit,
			"go_version": runtime.Version(),
		},
		Samples: interfaceMetricSamples(interfaceLabels, stats, dropsV4+dropsV6),
	}
	for _, peer := range rt.shim.PeerStats() {
		if peer.MetricsID == "" {
			continue
		}
		labels := map[string]string{"interface": rt.ifname, "peer_id": peer.MetricsID}
		snapshot.Samples = append(snapshot.Samples,
			metrics.Sample{Name: "wgf_peer_pmtu_carrier_payload_bytes", Labels: labels, Value: uint64(peer.CarrierPayload)},
			metrics.Sample{Name: "wgf_peer_pmtu_searching", Labels: labels, Value: boolMetricValue(peer.PMTUSearching)},
			metrics.Sample{Name: "wgf_peer_data_forwarding_enabled", Labels: labels, Value: boolMetricValue(peer.DataForwardingEnabled)},
		)
	}
	return snapshot
}

func interfaceMetricSamples(labels map[string]string, stats shimtun.Stats, socketDrops uint64) []metrics.Sample {
	return []metrics.Sample{
		{Name: "wgf_tx_carriers_total", Labels: labels, Value: stats.TXCarriers},
		{Name: "wgf_tx_packet_drops_total", Labels: labels, Value: stats.TXPacketDrops},
		{Name: "wgf_tx_native_fragment_drops_total", Labels: labels, Value: stats.TXNativeFragmentDrops},
		{Name: "wgf_tx_route_drops_total", Labels: labels, Value: stats.TXRouteDrops},
		{Name: "wgf_tx_peer_mtu_drops_total", Labels: labels, Value: stats.TXPeerMTUDrops},
		{Name: "wgf_tx_ptb_sent_total", Labels: labels, Value: stats.TXPTBSent},
		{Name: "wgf_rx_data_carriers_total", Labels: labels, Value: stats.RXDataCarriers},
		{Name: "wgf_rx_inner_packets_total", Labels: labels, Value: stats.RXInnerDelivered},
		{Name: "wgf_rx_packet_rejects_total", Labels: labels, Value: stats.RXPacketRejects},
		{Name: "wgf_rx_native_fragment_drops_total", Labels: labels, Value: stats.RXNativeFragmentDrops},
		{Name: "wgf_rx_source_spoof_drops_total", Labels: labels, Value: stats.RXSourceSpoofDrops},
		{Name: "wgf_rx_native_write_drops_total", Labels: labels, Value: stats.RXNativeWriteDrops},
		{Name: "wgf_carrier_queue_overflows_total", Labels: labels, Value: stats.CarrierQueueOverflows},
		{Name: "wgf_control_queue_drops_total", Labels: labels, Value: stats.ControlQueueDrops},
		{Name: "wgf_control_exploratory_evictions_total", Labels: labels, Value: stats.ControlExploratoryEvictions},
		{Name: "wgf_control_coalesces_total", Labels: labels, Value: stats.ControlCoalesces},
		{Name: "wgf_control_rate_suppression_episodes_total", Labels: labels, Value: stats.ControlRateSuppressionEpisodes},
		{Name: "wgf_control_materialization_drops_total", Labels: labels, Value: stats.ControlMaterializationDrops},
		{Name: "wgf_control_ingress_rate_limited_total", Labels: labels, Value: stats.ControlIngressRateLimited},
		{Name: "wgf_preconfirm_drops_total", Labels: labels, Value: stats.PreconfirmDrops},
		{Name: "wgf_reassembly_expirations_total", Labels: labels, Value: stats.ReassemblyExpirations},
		{Name: "wgf_udp_socket_drops_total", Labels: labels, Value: socketDrops},
	}
}

func boolMetricValue(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
