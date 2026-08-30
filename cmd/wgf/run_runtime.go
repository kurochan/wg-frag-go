//go:build linux || darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlapi"
	"github.com/kurochan/wg-frag-go/internal/core/lane"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/transport"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/controlbridge"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

type runtimeBind interface {
	conn.Bind
	socketDropReporter
	SetSocketBuffer(bytes int)
	SocketBufferStatus() (requested, ipv4, ipv6 int)
	SetPathEventHandler(handler func(transport.PathEvent))
}

type runPlatform struct {
	createTUN        func(string, int) (tun.Device, error)
	tunName          func(string) string
	nativeReadOffset int
	newBind          func() runtimeBind
	configureBind    func(runtimeBind, *config.Config) error
	warnSocketBuffer func(runtimeBind, *slog.Logger)
}

// runConfiguredInterface owns the portable daemon lifecycle after each
// platform has supplied its TUN and no-fragment UDP Bind implementation.
func runConfiguredInterface(args []string, stdout, stderr io.Writer, platform runPlatform) error {
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return errors.New("run requires exactly one interface name")
	}
	ifname := args[0]
	cfg, controlSocket, err := parseRunConfig(args[1:], stderr)
	if err != nil {
		return err
	}
	logger := newAppLogger(stderr)
	warnUnwiredConcurrencyOptions(cfg, logger)
	plan, err := wgadapter.PreparePeers(cfg)
	if err != nil {
		return err
	}
	native, err := platform.createTUN(platform.tunName(ifname), cfg.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	bind := platform.newBind()
	bind.SetSocketBuffer(cfg.Interface.SocketBuffer)
	if err := platform.configureBind(bind, cfg); err != nil {
		_ = native.Close()
		return err
	}
	return runDaemon(ifname, native, cfg, plan, bind, platform.nativeReadOffset, controlSocket, logger, platform.warnSocketBuffer)
}

func parseRunConfig(args []string, stderr io.Writer) (*config.Config, string, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to a wgf configuration file")
	controlSocket := flags.String("control-socket", "", "management socket path")
	if err := flags.Parse(args); err != nil {
		return nil, "", err
	}
	if *path == "" {
		return nil, "", errors.New("run requires --config")
	}
	if flags.NArg() != 0 {
		return nil, "", fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	cfg, err := config.ParseFile(*path)
	if err != nil {
		return nil, "", err
	}
	return cfg, *controlSocket, nil
}

func warnUnwiredConcurrencyOptions(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || (cfg.Interface.Workers.Auto && cfg.Interface.TUNQueues.Auto) {
		return
	}
	logger.Warn("WGFWorkers and WGFTUNQueues are not active; using one shim worker and one TUN queue")
}

func runDaemon(
	ifname string,
	native tun.Device,
	cfg *config.Config,
	plan wgadapter.Plan,
	bind runtimeBind,
	nativeReadOffset int,
	controlSocket string,
	logger *slog.Logger,
	warnBuffer func(runtimeBind, *slog.Logger),
) error {
	closeNative := true
	defer func() {
		if closeNative {
			_ = native.Close()
		}
	}()
	actualName, err := native.Name()
	if err != nil {
		return fmt.Errorf("read TUN name: %w", err)
	}
	if actualName == ifname {
		logger = logger.With("interface", ifname)
	} else {
		logger = logger.With("interface", ifname, "native_interface", actualName)
	}
	started := false
	defer func() {
		if started {
			logger.Info("interface stopped")
		}
	}()

	classifier, err := lane.NewClassifier(lane.DefaultDepth)
	if err != nil {
		return err
	}
	peerConfigs, err := dataPlaneBases(cfg, plan, classifier)
	if err != nil {
		return err
	}
	sink := newControlSink()
	shim, err := shimtun.New(shimtun.Config{
		Native:               native,
		Peers:                peerConfigs,
		ControlSink:          sink,
		CarrierQueueSize:     native.BatchSize() * carrierQueueSlotLimitMultiplier,
		ControlQueueSize:     controlQueueSize,
		MaxCarrierPayload:    cfg.Interface.MaxCarrierPayload,
		DataInitiallyEnabled: false,
		NativeReadOffset:     nativeReadOffset,
		NativeWriteOffset:    10,
		ExpirationInterval:   minDuration(100*time.Millisecond, cfg.Interface.ReassemblyLifetime/2),
	})
	if err != nil {
		return err
	}
	logMemoryReservation(logger, cfg, len(plan.Peers), native.BatchSize())
	closeNative = false
	defer func() { _ = shim.Close() }()

	wgTUN, err := wgadapter.NewWireGuardTUN(shim, plan)
	if err != nil {
		return err
	}
	bridges := make(map[peerroute.PeerID]*controlbridge.Bridge, len(plan.Peers))
	for i, peer := range plan.Peers {
		engine, err := newEngine(cfg)
		if err != nil {
			return err
		}
		bridge, err := controlbridge.New(controlbridge.Config{
			Engine: engine, TUN: shim, PeerID: peer.ID, OwnerKey: peer.PublicKey, SenderBase: peerConfigs[i].Sender,
			ReceiverBase: peerConfigs[i].Receiver, Logger: peerLogger(logger, peer),
		})
		if err != nil {
			return err
		}
		bridges[peer.ID] = bridge
		sink.set(peer.ID, bridge)
	}

	pathEvents := make(chan transport.PathEvent, 4)
	bind.SetPathEventHandler(func(event transport.PathEvent) {
		select {
		case pathEvents <- event:
		default:
		}
	})
	wg, err := wgadapter.New(wgadapter.DeviceConfig{TUN: wgTUN, Bind: bind, Logger: newWireGuardLogger(logger)})
	if err != nil {
		return err
	}
	defer wg.Close()
	if err := wgadapter.Apply(wg, plan); err != nil {
		return err
	}
	if err := wg.Up(); err != nil {
		return err
	}
	for _, bridge := range bridges {
		if err := bridge.Start(); err != nil {
			return err
		}
	}
	warnBuffer(bind, logger)

	if controlSocket == "" {
		controlSocket = controlapi.SocketPath(ifname)
	}
	rt := &daemonRuntime{
		ifname: ifname, classifier: classifier, cfg: cfg, plan: plan, shim: shim, wgTUN: wgTUN, wg: wg,
		bind: bind, sink: sink, bridges: bridges, requests: make(map[[16]byte]appliedRequest),
		peerFaults: make(map[peerroute.PeerID]peerFaultState), logger: logger, batchSize: native.BatchSize(),
	}
	var metricsListener *metricsServer
	if cfg.Interface.Metrics {
		uapi, metricsErr := wg.IpcGet()
		if metricsErr == nil {
			var port uint16
			port, metricsErr = effectiveListenPort(uapi)
			if metricsErr == nil {
				metricsListener, metricsErr = startMetricsServer(cfg.Interface, port, logger, rt.metricsSnapshot)
			}
		}
		if metricsErr != nil {
			logger.Warn("metrics disabled", "error", metricsErr)
		} else {
			defer func() {
				if closeErr := metricsListener.Close(); closeErr != nil {
					logger.Warn("metrics listener shutdown failed", "error", closeErr)
				}
				logger.Info("metrics listener stopped")
			}()
		}
	}
	api, err := controlapi.New(controlapi.Config{SocketPath: controlSocket, Status: rt.status, Apply: rt.apply})
	if err != nil {
		return err
	}
	defer api.Close()
	stopProfile, err := startCPUProfile()
	if err != nil {
		return err
	}
	defer stopProfile()
	logger.Info("interface started", "mtu", cfg.Interface.MTU, "peers", len(plan.Peers), "control_socket", controlSocket)
	started = true

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
	defer signal.Stop(signals)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case received := <-signals:
			if received == syscall.SIGUSR1 {
				dropsV4, dropsV6 := bind.SocketDrops()
				stats := shim.Stats()
				logger.Info("runtime stats", "shim", stats, "udp_drops_v4", dropsV4, "udp_drops_v6", dropsV6)
				peerStats := make(map[peerroute.PeerID]shimtun.PeerStats, len(plan.Peers))
				for _, peer := range shim.PeerStats() {
					peerStats[peer.ID] = peer
				}
				for id, snapshot := range rt.bridgeSnapshots() {
					peer := peerStats[id]
					logger.Info("peer stats",
						"peer_id", id,
						"confirmed_carrier_payload", snapshot.CarrierPayload,
						"pmtu_searching", snapshot.PMTUSearching,
						"missing_flags", fmt.Sprintf("%07b", snapshot.MissingFlags),
						"control_path_state", snapshot.Status,
						"control_path_error", snapshot.StatusReason,
						"data_forwarding_enabled", peer.DataForwardingEnabled,
					)
				}
				continue
			}
			logger.Info("shutdown requested", "signal", received.String())
			return nil
		case now := <-ticker.C:
			if err := rt.tick(now); err != nil {
				return fmt.Errorf("control tick: %w", err)
			}
		case event := <-pathEvents:
			if err := rt.reportTransportEvent(time.Now(), event); err != nil {
				return fmt.Errorf("transport error recovery: %w", err)
			}
		}
	}
}

func startCPUProfile() (func(), error) {
	path := os.Getenv("WGF_CPU_PROFILE")
	if path == "" {
		return func() {}, nil
	}
	// #nosec G703 -- The profile path is an explicit operator diagnostic setting.
	profile, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(profile); err != nil {
		_ = profile.Close()
		return nil, err
	}
	return func() {
		pprof.StopCPUProfile()
		_ = profile.Close()
	}, nil
}
