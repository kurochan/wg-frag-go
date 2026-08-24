//go:build linux

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
	"github.com/kurochan/wg-frag-go/internal/controlplane"
	"github.com/kurochan/wg-frag-go/internal/core/lane"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/platform/linux/wgbind"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/controlbridge"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
	"golang.zx2c4.com/wireguard/tun"
)

//nolint:funlen // The command owns one resource lifecycle from setup through teardown.
func runCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return errors.New("run requires exactly one interface name")
	}
	ifname := args[0]
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to a wgf configuration file")

	controlSocket := flags.String(
		"control-socket",
		"",
		"management socket path (default /run/wg-frag/IFNAME.sock)",
	)
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("run requires --config")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	cfg, err := config.ParseFile(*path)
	if err != nil {
		return err
	}
	logger := newAppLogger(stderr)
	warnUnwiredConcurrencyOptions(cfg, logger)

	plan, err := wgadapter.PreparePeers(cfg)
	if err != nil {
		return err
	}

	native, err := tun.CreateTUN(ifname, cfg.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
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
	logger = logger.With("interface", actualName)

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

	engines := make(map[peerroute.PeerID]*controlplane.Engine, len(plan.Peers))

	bridges := make(map[peerroute.PeerID]*controlbridge.Bridge, len(plan.Peers))
	for i, peer := range plan.Peers {
		engine, err := newEngine(cfg)
		if err != nil {
			return err
		}
		bridge, err := controlbridge.New(controlbridge.Config{
			Engine:       engine,
			TUN:          shim,
			PeerID:       peer.ID,
			SenderBase:   peerConfigs[i].Sender,
			ReceiverBase: peerConfigs[i].Receiver,
			Logger:       peerLogger(logger, peer),
		})
		if err != nil {
			return err
		}
		engines[peer.ID], bridges[peer.ID] = engine, bridge
		sink.set(peer.ID, bridge)
	}

	bind := wgbind.New()
	bind.SetSocketBuffer(cfg.Interface.SocketBuffer)
	bind.SetFwMark(cfg.Interface.FwMark)
	pathEvents := make(chan wgbind.PathEvent, 4)

	bind.SetPathEventHandler(func(event wgbind.PathEvent) {
		select {
		case pathEvents <- event:
		default:
		}
	})

	wg, err := wgadapter.New(wgadapter.DeviceConfig{
		TUN:    wgTUN,
		Bind:   bind,
		Logger: newWireGuardLogger(logger),
	})
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

	warnSocketBuffer(bind, logger)

	socketPath := *controlSocket
	if socketPath == "" {
		socketPath = controlapi.SocketPath(actualName)
	}
	rt := &daemonRuntime{
		ifname:     actualName,
		classifier: classifier,
		cfg:        cfg,
		plan:       plan,
		shim:       shim,
		wgTUN:      wgTUN,
		wg:         wg,
		bind:       bind,
		sink:       sink,
		engines:    engines,
		bridges:    bridges,
		requests:   make(map[[16]byte]appliedRequest),
		peerFaults: make(map[peerroute.PeerID]peerFaultState),
		logger:     logger,
		batchSize:  native.BatchSize(),
	}

	api, err := controlapi.New(controlapi.Config{
		SocketPath: socketPath,
		Status:     rt.status,
		Apply:      rt.apply,
	})
	if err != nil {
		return err
	}
	defer api.Close()

	if path := os.Getenv("WGF_CPU_PROFILE"); path != "" {
		// #nosec G703 -- The profile path is an explicit operator diagnostic setting.
		profile, err := os.Create(path)
		if err != nil {
			return err
		}
		if err := pprof.StartCPUProfile(profile); err != nil {
			return err
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = profile.Close()
		}()
	}
	logger.Info("interface started", "mtu", cfg.Interface.MTU, "peers", len(plan.Peers), "control_socket", socketPath)
	started = true

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
	defer signal.Stop(signals)
	controlTicker := time.NewTicker(100 * time.Millisecond)
	defer controlTicker.Stop()

	for {
		select {
		case received := <-signals:
			if received == syscall.SIGUSR1 {
				dropsV4, dropsV6 := bind.SocketDrops()
				logger.Info("runtime stats", "shim", shim.Stats(), "udp_drops_v4", dropsV4, "udp_drops_v6", dropsV6)
				rt.mu.Lock()
				for id, engine := range rt.engines {
					logger.Info(
						"peer stats",
						"peer_id",
						id,
						"confirmed_carrier_payload",
						engine.ConfirmedCarrierPayload(),
						"pmtu_searching",
						engine.PMTUSearching(),
						"missing_flags",
						fmt.Sprintf("%07b", engine.MissingFlags()),
						"control_path_state",
						engine.Status(),
						"control_path_error",
						engine.StatusReason(),
					)
				}
				rt.mu.Unlock()

				continue
			}
			logger.Info("shutdown requested", "signal", received.String())
			return nil
		case now := <-controlTicker.C:
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

// warnUnwiredConcurrencyOptions keeps accepted concurrency settings visible
// without enabling unsupported data-path concurrency.
func warnUnwiredConcurrencyOptions(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || (cfg.Interface.Workers.Auto && cfg.Interface.TUNQueues.Auto) {
		return
	}

	logger.Warn("WGFWorkers and WGFTUNQueues are not active; using one shim worker and one TUN queue")
}

// warnSocketBuffer reports a UDP receive buffer clamped below the request.
func warnSocketBuffer(bind *wgbind.Bind, logger *slog.Logger) {
	requested, v4, v6 := bind.SocketBufferStatus()
	if requested <= 0 {
		return
	}

	for _, socket := range []struct {
		family   string
		achieved int
	}{{"IPv4", v4}, {"IPv6", v6}} {
		if socket.achieved == 0 || socket.achieved >= requested {
			continue
		}
		logger.Warn("UDP socket buffer below requested size",
			"family", socket.family,
			"achieved_bytes", socket.achieved,
			"requested_bytes", requested,
			"remediation", "raise net.core.rmem_max/wmem_max or grant CAP_NET_ADMIN")
	}
}
