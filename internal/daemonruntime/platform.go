//go:build linux || darwin

// Package daemonruntime owns one WGF data-plane generation. It is independent
// of command-line parsing, process signals, and HTTP metrics listeners.
package daemonruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/core/lane"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/metrics"
	"github.com/kurochan/wg-frag-go/internal/transport"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/controlbridge"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

// Bind combines wireguard-go's transport with WGF's path observations.
type Bind interface {
	conn.Bind
	SocketDrops() (ipv4, ipv6 uint64)
	SetSocketBuffer(bytes int)
	SocketBufferStatus() (requested, ipv4, ipv6 int)
	SetPathEventHandler(handler func(transport.PathEvent))
}

// TUNAnchor keeps a native TUN alive while generations use independent
// leases. The anchor must outlive every Runtime started from it.
type TUNAnchor interface {
	Name() string
	Lease(mtu int) (tun.Device, error)
	Close() error
}

// Platform supplies the OS-specific construction hooks used by Factory.
// Production values are returned by DefaultPlatform.
type Platform struct {
	OpenAnchor       func(name string, mtu int) (TUNAnchor, error)
	TUNName          func(interfaceName string) string
	NativeReadOffset int
	NewBind          func() Bind
	ConfigureBind    func(Bind, *config.Config) error
	WarnSocketBuffer func(Bind, *slog.Logger)
}

func (p Platform) openAnchor(name string, mtu int) (TUNAnchor, error) {
	if p.OpenAnchor == nil {
		return nil, errors.New("daemonruntime: platform has no TUN anchor opener")
	}
	return p.OpenAnchor(name, mtu)
}

func (p Platform) tunName(name string) string {
	if p.TUNName == nil {
		return name
	}
	return p.TUNName(name)
}

func (p Platform) newBind() (Bind, error) {
	if p.NewBind == nil {
		return nil, errors.New("daemonruntime: platform has no WireGuard bind factory")
	}
	bind := p.NewBind()
	if bind == nil {
		return nil, errors.New("daemonruntime: platform returned a nil WireGuard bind")
	}
	return bind, nil
}

// Factory starts independent data-plane generations from TUN anchors.
type Factory struct {
	platform Platform
	logger   *slog.Logger
}

// NewFactory creates a generation factory. A nil logger uses slog.Default.
func NewFactory(platform Platform, logger *slog.Logger) *Factory {
	if logger == nil {
		logger = slog.Default()
	}
	return &Factory{platform: platform, logger: logger}
}

// DefaultFactory creates a factory using the native platform implementation.
func DefaultFactory(logger *slog.Logger) *Factory {
	return NewFactory(DefaultPlatform(), logger)
}

// OpenAnchor creates the persistent TUN descriptor for an interface.
func (f *Factory) OpenAnchor(name string, mtu int) (TUNAnchor, error) {
	if f == nil {
		return nil, errors.New("daemonruntime: nil factory")
	}
	if name == "" {
		return nil, errors.New("daemonruntime: empty interface name")
	}
	return f.platform.openAnchor(f.platform.tunName(name), mtu)
}

// Start creates one runtime generation from an existing TUN anchor and config.
// The returned Runtime owns the lease, bind, wireguard-go device, and shim.
func (f *Factory) Start(name string, anchor TUNAnchor, cfg *config.Config) (*Runtime, error) {
	if f == nil {
		return nil, errors.New("daemonruntime: nil factory")
	}
	if anchor == nil {
		return nil, errors.New("daemonruntime: nil TUN anchor")
	}
	if cfg == nil {
		return nil, errors.New("daemonruntime: nil config")
	}
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	plan, err := wgadapter.PreparePeers(cfg)
	if err != nil {
		return nil, err
	}
	bind, err := f.platform.newBind()
	if err != nil {
		return nil, err
	}
	bind.SetSocketBuffer(cfg.Interface.SocketBuffer)
	if f.platform.ConfigureBind != nil {
		if err := f.platform.ConfigureBind(bind, cfg); err != nil {
			_ = bind.Close()
			return nil, err
		}
	}
	lease, err := anchor.Lease(cfg.Interface.MTU)
	if err != nil {
		_ = bind.Close()
		return nil, fmt.Errorf("create TUN lease: %w", err)
	}
	runtime, err := startRuntime(name, lease, cfg, plan, bind, f.platform.NativeReadOffset, f.logger, f.platform.WarnSocketBuffer)
	if err != nil {
		return nil, err
	}
	return runtime, nil
}

// Runtime owns one generation of an interface data plane. Its TUN is a lease;
// closing the generation does not close the supervisor's anchor descriptor.
type Runtime struct {
	runtime *daemonRuntime
	bind    Bind
	shim    *shimtun.Device
	wg      interface{ Close() }

	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
}

func (r *Runtime) setError(err error) {
	r.errMu.Lock()
	r.err = err
	r.errMu.Unlock()
}

// Wait waits for the runtime generation to stop and returns its terminal
// error, if any.
func (r *Runtime) Wait() error {
	<-r.done
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.err
}

// Close stops the generation and waits for all data-plane goroutines.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(r.cancel)
	<-r.done
	return nil
}

// Status returns the current generation status.
func (r *Runtime) Status(includeSecrets bool) (*controlapiv1.InterfaceStatus, error) {
	return r.runtime.status(includeSecrets)
}

// CounterSnapshot returns current data-plane counters.
func (r *Runtime) CounterSnapshot() *controlapiv1.ShimCounters {
	return r.runtime.counterSnapshot()
}

// ApplyPeers applies a complete peer table to the running generation.
func (r *Runtime) ApplyPeers(request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	return r.runtime.applyPeers(request)
}

// ConfigSnapshot returns a deep copy of the current configuration.
func (r *Runtime) ConfigSnapshot() *config.Config {
	r.runtime.mu.Lock()
	defer r.runtime.mu.Unlock()
	return config.Clone(r.runtime.cfg)
}

// MetricsSnapshot returns a snapshot for the process metrics adapter.
func (r *Runtime) MetricsSnapshot() metrics.Snapshot {
	return r.runtime.metricsSnapshot()
}

// EffectiveListenPort reads the port selected by WireGuard.
func (r *Runtime) EffectiveListenPort() (uint16, error) {
	uapi, err := r.runtime.wg.IpcGet()
	if err != nil {
		return 0, err
	}
	return effectiveListenPort(uapi)
}

// DumpStats writes a low-frequency runtime diagnostic through the configured
// logger.
func (r *Runtime) DumpStats() {
	r.dumpStats()
}

func startRuntime(
	ifname string,
	native tun.Device,
	cfg *config.Config,
	plan wgadapter.Plan,
	bind Bind,
	nativeReadOffset int,
	logger *slog.Logger,
	warnBuffer func(Bind, *slog.Logger),
) (_ *Runtime, err error) {
	var shim *shimtun.Device
	var wgTUN *wgadapter.WireGuardTUN
	var wg interface{ Close() }
	defer func() {
		if err == nil {
			return
		}
		if wg != nil {
			wg.Close()
			return
		}
		_ = bind.Close()
		if shim != nil {
			_ = shim.Close()
		} else {
			_ = native.Close()
		}
	}()

	actualName, err := native.Name()
	if err != nil {
		return nil, fmt.Errorf("read TUN name: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	if actualName == ifname {
		logger = logger.With("interface", ifname)
	} else {
		logger = logger.With("interface", ifname, "native_interface", actualName)
	}
	classifier, err := lane.NewClassifier(lane.DefaultDepth)
	if err != nil {
		return nil, err
	}
	peerConfigs, err := dataPlaneBases(cfg, plan, classifier)
	if err != nil {
		return nil, err
	}
	sink := newControlSink()
	shim, err = shimtun.New(shimtun.Config{
		Native:               native,
		Peers:                peerConfigs,
		ControlSink:          sink,
		CarrierQueueSize:     native.BatchSize() * carrierQueueSlotLimitMultiplier,
		ControlQueueSize:     controlQueueSize,
		MaxCarrierPayload:    cfg.Interface.MaxCarrierPayload,
		DataInitiallyEnabled: false,
		NativeReadOffset:     nativeReadOffset,
		NativeWriteOffset:    10,
		ExpirationInterval:   min(100*time.Millisecond, cfg.Interface.ReassemblyLifetime/2),
	})
	if err != nil {
		return nil, err
	}
	logMemoryReservation(logger, cfg, len(plan.Peers), native.BatchSize())

	wgTUN, err = wgadapter.NewWireGuardTUN(shim, plan)
	if err != nil {
		return nil, err
	}
	bridges := make(map[peerroute.PeerID]*controlbridge.Bridge, len(plan.Peers))
	for i, peer := range plan.Peers {
		engine, err := newEngine(cfg)
		if err != nil {
			return nil, err
		}
		bridge, err := controlbridge.New(controlbridge.Config{
			Engine: engine, TUN: shim, PeerID: peer.ID, OwnerKey: peer.PublicKey, SenderBase: peerConfigs[i].Sender,
			ReceiverBase: peerConfigs[i].Receiver, Logger: peerLogger(logger, peer),
		})
		if err != nil {
			return nil, err
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
	wgDevice, err := wgadapter.New(wgadapter.DeviceConfig{TUN: wgTUN, Bind: bind, Logger: newWireGuardLogger(logger)})
	if err != nil {
		return nil, err
	}
	wg = wgDevice
	if err := wgadapter.Apply(wgDevice, plan); err != nil {
		return nil, err
	}
	if err := wgDevice.Up(); err != nil {
		return nil, err
	}
	for _, bridge := range bridges {
		if err := bridge.Start(); err != nil {
			return nil, err
		}
	}
	if warnBuffer != nil {
		warnBuffer(bind, logger)
	}

	rt := &daemonRuntime{
		ifname: ifname, classifier: classifier, cfg: config.Clone(cfg), plan: plan, shim: shim, wgTUN: wgTUN, wg: wgDevice,
		bind: bind, sink: sink, bridges: bridges,
		peerFaults: make(map[peerroute.PeerID]peerFaultState), logger: logger, batchSize: native.BatchSize(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &Runtime{
		runtime: rt,
		bind:    bind,
		shim:    shim,
		wg:      wg,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go running.run(ctx, pathEvents)
	return running, nil
}

func (r *Runtime) run(ctx context.Context, pathEvents <-chan transport.PathEvent) {
	defer close(r.done)
	defer r.runtime.logger.Info("interface stopped")
	defer r.closeDataPlane()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := r.runtime.tick(now); err != nil {
				r.setError(fmt.Errorf("control tick: %w", err))
				return
			}
		case event := <-pathEvents:
			if err := r.runtime.reportTransportEvent(time.Now(), event); err != nil {
				r.setError(fmt.Errorf("transport error recovery: %w", err))
				return
			}
		}
	}
}

func (r *Runtime) closeDataPlane() {
	// WireGuard workers use the shim TUN, so stop them before closing it.
	r.wg.Close()
	_ = r.shim.Close()
}

func (r *Runtime) dumpStats() {
	dropsV4, dropsV6 := r.bind.SocketDrops()
	stats := r.shim.Stats()
	r.runtime.logger.Info(
		"runtime stats",
		"shim", stats,
		"udp_drops_v4", dropsV4,
		"udp_drops_v6", dropsV6,
	)
	r.runtime.mu.Lock()
	peerCount := len(r.runtime.plan.Peers)
	r.runtime.mu.Unlock()
	peerStats := make(map[peerroute.PeerID]shimtun.PeerStats, peerCount)
	for _, peer := range r.shim.PeerStats() {
		peerStats[peer.ID] = peer
	}
	for id, snapshot := range r.runtime.bridgeSnapshots() {
		peer := peerStats[id]
		r.runtime.logger.Info("peer stats",
			"peer_id", id,
			"confirmed_carrier_payload", snapshot.CarrierPayload,
			"pmtu_searching", snapshot.PMTUSearching,
			"missing_flags", fmt.Sprintf("%07b", snapshot.MissingFlags),
			"control_path_state", snapshot.Status,
			"control_path_error", snapshot.StatusReason,
			"data_forwarding_enabled", peer.DataForwardingEnabled,
		)
	}
}
