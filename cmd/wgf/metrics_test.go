//go:build linux || darwin

package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/metrics"
)

func TestMetricsAddresses(t *testing.T) {
	t.Parallel()
	got, err := metricsAddresses(config.MetricsListen{Auto: true}, 51820)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:51820", "[::1]:51820"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("metricsAddresses = %#v, want %#v", got, want)
	}
	if _, err := metricsAddresses(config.MetricsListen{Auto: true}, 0); err == nil {
		t.Fatal("zero port succeeded")
	}
}

func TestMetricsHTTPHandler(t *testing.T) {
	t.Parallel()
	server, err := startMetricsServer(config.Interface{MetricsListen: config.MetricsListen{Addresses: []string{"127.0.0.1:0"}}}, 0, slog.New(slog.DiscardHandler), func() metrics.Snapshot {
		return metrics.Snapshot{BuildLabels: map[string]string{"version": "test"}}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	url := "http://" + server.listeners[0].Addr().String() + "/metrics"
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "# EOF\n") {
		t.Fatalf("GET /metrics = %d %q", response.StatusCode, body)
	}
	head, err := http.Head(url)
	if err != nil {
		t.Fatal(err)
	}
	_ = head.Body.Close()
	if head.StatusCode != http.StatusOK || head.Header.Get("Content-Type") != openMetricsContentType {
		t.Fatalf("HEAD /metrics = %d %q", head.StatusCode, head.Header.Get("Content-Type"))
	}
	request := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	recorder := httptest.NewRecorder()
	server.servers[0].Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics = %d", recorder.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/other", nil)
	recorder = httptest.NewRecorder()
	server.servers[0].Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET /other = %d", recorder.Code)
	}
}

func TestEffectiveListenPort(t *testing.T) {
	t.Parallel()
	if got, err := effectiveListenPort("private_key=abc\nlisten_port=51820\n"); err != nil || got != 51820 {
		t.Fatalf("effectiveListenPort = (%d, %v)", got, err)
	}
	if _, err := effectiveListenPort("listen_port=0\n"); err == nil {
		t.Fatal("zero port succeeded")
	}
}

func TestMetricsStartClosesPartialListeners(t *testing.T) {
	t.Parallel()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	firstAddress := first.Addr().String()
	_ = first.Close()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	_, portText, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = startMetricsServer(config.Interface{MetricsListen: config.MetricsListen{Addresses: []string{firstAddress, "127.0.0.1:" + portText}}}, 0, nil, func() metrics.Snapshot { return metrics.Snapshot{} })
	if err == nil {
		t.Fatal("startMetricsServer succeeded with an occupied listener")
	}
	probe, err := net.Listen("tcp", firstAddress)
	if err != nil {
		t.Fatalf("first listener was not closed: %v", err)
	}
	_ = probe.Close()
}

func TestMetricsAutoKeepsAvailableLoopbackFamily(t *testing.T) {
	t.Parallel()
	server, err := startMetricsServerWithListen(
		config.Interface{MetricsListen: config.MetricsListen{Auto: true}},
		51820,
		slog.New(slog.DiscardHandler),
		func() metrics.Snapshot { return metrics.Snapshot{} },
		func(_, address string) (net.Listener, error) {
			if strings.HasPrefix(address, "[::1]") {
				return nil, errors.New("IPv6 disabled")
			}
			return net.Listen("tcp", "127.0.0.1:0")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if len(server.listeners) != 1 {
		t.Fatalf("listeners = %d, want 1", len(server.listeners))
	}
}

func TestMetricsCloseWaitsForActiveScrape(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	server, err := startMetricsServer(
		config.Interface{MetricsListen: config.MetricsListen{Addresses: []string{"127.0.0.1:0"}}},
		0,
		slog.New(slog.DiscardHandler),
		func() metrics.Snapshot {
			close(started)
			<-release
			return metrics.Snapshot{}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + server.listeners[0].Addr().String() + "/metrics"
	requestDone := make(chan struct{})
	go func() {
		response, requestErr := http.Get(url)
		if requestErr == nil {
			_ = response.Body.Close()
		}
		close(requestDone)
	}()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before active scrape completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	<-requestDone
}

func TestMetricsCachesScrapesBriefly(t *testing.T) {
	t.Parallel()
	var snapshots atomic.Uint32
	server, err := startMetricsServer(
		config.Interface{MetricsListen: config.MetricsListen{Addresses: []string{"127.0.0.1:0"}}},
		0,
		slog.New(slog.DiscardHandler),
		func() metrics.Snapshot {
			snapshots.Add(1)
			return metrics.Snapshot{}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	url := "http://" + server.listeners[0].Addr().String() + "/metrics"
	for range 2 {
		response, requestErr := http.Get(url)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_ = response.Body.Close()
	}
	if got := snapshots.Load(); got != 1 {
		t.Fatalf("snapshots = %d, want 1", got)
	}
}
