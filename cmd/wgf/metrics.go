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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/metrics"
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

func startMetricsServerRenderer(iface config.Interface, port uint16, logger *slog.Logger, render func() ([]byte, error)) (*metricsServer, error) {
	if _, err := metrics.NewSelector(iface.MetricsInclude, iface.MetricsExclude); err != nil {
		return nil, err
	}
	return startMetricsServerRendererWithListen(iface, port, logger, render, net.Listen)
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
	render := func() ([]byte, error) {
		var body bytes.Buffer
		if err := metrics.WriteOpenMetrics(&body, selector, snapshot()); err != nil {
			return nil, err
		}
		return body.Bytes(), nil
	}
	return startMetricsServerRendererWithListen(iface, port, logger, render, listen)
}

func startMetricsServerRendererWithListen(
	iface config.Interface,
	port uint16,
	logger *slog.Logger,
	render func() ([]byte, error),
	listen metricsListenFunc,
) (*metricsServer, error) {
	addresses, err := metricsAddresses(iface.MetricsListen, port)
	if err != nil {
		return nil, err
	}
	server := &metricsServer{}
	cache := newMetricsResponseCache(render)
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
					logger.Warn("metrics loopback address is unavailable", "address", address, "error", listenErr)
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
		return nil, errors.New("no metrics listener could be opened")
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
	mu     sync.Mutex
	render func() ([]byte, error)
	body   []byte
	at     time.Time
}

func newMetricsResponseCache(render func() ([]byte, error)) *metricsResponseCache {
	return &metricsResponseCache{render: render}
}

func (cache *metricsResponseCache) get() ([]byte, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if time.Since(cache.at) < metricsCacheTTL {
		return cache.body, nil
	}
	body, err := cache.render()
	if err != nil {
		return nil, err
	}
	cache.body = body
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
