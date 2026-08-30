package controlbridge

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/kurochan/wg-frag-go/internal/controlplane"
	controlstate "github.com/kurochan/wg-frag-go/internal/core/control/state"
	"github.com/kurochan/wg-frag-go/internal/core/datapath"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
)

var (
	ErrInvalidConfig = errors.New("controlbridge: invalid config")
	ErrStateInvalid  = errors.New("controlbridge: state invalid")
	// ErrPeerMismatch rejects callbacks delivered for a different peer slot.
	ErrPeerMismatch = errors.New("controlbridge: peer ID mismatch")
)

// TUN is the narrow adapter contract needed by Bridge. shimtun.Device
// implements it; keeping this interface local makes the state machine easy to
// test without a kernel TUN or wireguard-go device.
type TUN interface {
	EnqueueControl(peer peerroute.PeerID, frame []byte) error
	InstallDataPlane(peer peerroute.PeerID, sender datapath.SenderConfig, receiver datapath.ReceiverConfig) error
	SetDataEnabled(peer peerroute.PeerID, enabled bool) error
	SetPeerPMTUState(peer peerroute.PeerID, ownerKey [32]byte, carrierPayload uint32, searching bool) error
}

// Snapshot is a consistent, read-only view of one peer's CONTROL state.
// Bridge owns the Engine lock required to produce it.
type Snapshot struct {
	CarrierPayload uint32
	PMTUSearching  bool
	DataReady      bool
	MissingFlags   controlstate.Flags
	Status         controlplane.Status
	StatusReason   string
}

// Config binds one CONTROL engine to one peer's preallocated TUN shim. The
// base configs contain immutable carrier addresses, capacity, and user route
// snapshot. Bridge supplies their direction-specific session IDs and peer MTU.
type Config struct {
	Engine       *controlplane.Engine
	TUN          TUN
	PeerID       peerroute.PeerID
	OwnerKey     [32]byte
	SenderBase   datapath.SenderConfig
	ReceiverBase datapath.ReceiverConfig
	// Logger receives low-frequency control and data-plane state transitions.
	Logger *slog.Logger
}

// Bridge serializes CONTROL messages for one peer and applies a complete
// negotiated data plane only after every CONTROL gate succeeds.
type Bridge struct {
	mu sync.Mutex

	engine           *controlplane.Engine
	tun              TUN
	peerID           peerroute.PeerID
	ownerKey         [32]byte
	senderBase       datapath.SenderConfig
	receiverBase     datapath.ReceiverConfig
	started          bool
	installed        bool
	activeTX         uint16
	activeRX         uint16
	activeMTU        int
	activePayload    int
	activeLifetime   time.Duration
	logger           *slog.Logger
	announced        bool
	announcedPayload int
	errorAnnounced   bool
}

// New returns a bridge with DATA fail-closed. Call Start after wireguard-go is
// up enough to transmit the returned CONTROL carrier through its TUN Read.
func New(config Config) (*Bridge, error) {
	if config.Engine == nil ||
		isNilTUN(config.TUN) ||
		config.SenderBase.DataSessionID == 0 ||
		config.ReceiverBase.DataSessionID == 0 {
		return nil, ErrInvalidConfig
	}
	return &Bridge{
		engine:       config.Engine,
		tun:          config.TUN,
		peerID:       config.PeerID,
		ownerKey:     config.OwnerKey,
		senderBase:   config.SenderBase,
		receiverBase: config.ReceiverBase,
		logger:       config.Logger,
	}, nil
}

// isNilTUN catches typed nil TUN implementations stored in the interface.
func isNilTUN(tun TUN) bool {
	if tun == nil {
		return true
	}
	value := reflect.ValueOf(tun)

	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Start sends the local CapabilitiesHello and keeps DATA closed until the
// whole bidirectional exchange has reached BASE probe confirmation.
func (b *Bridge) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started {
		return nil
	}
	if err := b.tun.SetDataEnabled(b.peerID, false); err != nil {
		return err
	}
	outbound, err := b.engine.Start()
	if err != nil {
		return err
	}
	b.started = true
	return b.applyLocked(outbound)
}

// UpdateRoutes replaces the route snapshot used by future data-plane
// installations. The currently installed sender and receiver are updated by
// the shim's peer-table transaction; keeping the bases in sync prevents a
// later session reset from restoring an older snapshot.
func (b *Bridge) UpdateRoutes(routes *peerroute.Snapshot) {
	b.mu.Lock()
	b.senderBase.AllowedIPs = routes
	b.receiverBase.AllowedIPs = routes
	b.mu.Unlock()
}

// Snapshot returns a state view safe for diagnostics and management APIs.
func (b *Bridge) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked()
}

// DeliverControl implements shimtun.ControlSink. It is safe for wireguard-go
// receive goroutines to call concurrently; it never asks the shim to reenter
// Write and therefore cannot deadlock its DATA reassembly lock.
func (b *Bridge) DeliverControl(peer peerroute.PeerID, frame []byte) error {
	if peer != b.peerID {
		return ErrPeerMismatch
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	outbound, err := b.engine.HandleInbound(frame)
	if err != nil {
		return err
	}
	b.markStartedLocked()
	return b.applyLocked(outbound)
}

// Tick advances timeout-driven CONTROL work. The caller supplies a monotonic
// timestamp from its platform loop. DATA stays enabled while a PMTU refresh is
// in progress and only the confirmed payload replaces its sender.
func (b *Bridge) Tick(now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	outbound, err := b.engine.Tick(now)
	if err != nil {
		return err
	}
	return b.applyLocked(outbound)
}

// ReportTransportError applies a DF/PMTU send failure reported by the Linux
// UDP bind. udpPayloadSize attributes the error to a datagram; zero marks a
// stashed error whose datagram is unknown.
func (b *Bridge) ReportTransportError(now time.Time, transportErr error, udpPayloadSize int) error {
	if !errors.Is(transportErr, syscall.EMSGSIZE) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	outbound, err := b.engine.ReportSendFailure(now, udpPayloadSize)
	if err != nil {
		return err
	}
	return b.applyLocked(outbound)
}

// ReportUnknownDataSession implements shimtun.SessionSink.
func (b *Bridge) ReportUnknownDataSession(peer peerroute.PeerID, sessionID uint16) error {
	if peer != b.peerID {
		return ErrPeerMismatch
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	outbound, err := b.engine.ReportUnknownDataSession(sessionID)
	if err != nil {
		return err
	}
	b.markStartedLocked()
	return b.applyLocked(outbound)
}

func (b *Bridge) markStartedLocked() {
	if !b.started && b.engine.LocalExchangeID().ControlEpoch != 0 {
		b.started = true
	}
}

func (b *Bridge) applyLocked(outbound []controlplane.Outbound) error {
	defer func() {
		// Observability must never make a peer unavailable. The owner key stops
		// a stale callback from updating a peer that reused this slot.
		_ = b.tun.SetPeerPMTUState(b.peerID, b.ownerKey, b.engine.ConfirmedCarrierPayload(), b.engine.PMTUSearching())
	}()
	dataAllowed := b.engine.DataSendAllowed()
	if !dataAllowed {
		if b.engine.Status() == controlplane.StatusError && !b.errorAnnounced {
			b.log(slog.LevelWarn, "control path unavailable", "reason", b.engine.StatusReason())
			b.errorAnnounced = true
		}
		if b.announced {
			b.log(
				slog.LevelWarn,
				"data forwarding suspended",
				"control_path_state",
				b.engine.Status(),
				"reason",
				b.engine.StatusReason(),
			)
			b.announced = false
		}
		// Close DATA before queueing the recovery/control frames. TUN reads run
		// independently of this bridge lock, so queueing first leaves a window
		// where stale DATA can escape after a session reset.
		if err := b.tun.SetDataEnabled(b.peerID, false); err != nil {
			return err
		}
	}
	for _, message := range outbound {
		if err := b.tun.EnqueueControl(b.peerID, message.Frame); err != nil {
			return err
		}
	}
	if !dataAllowed {
		return nil
	}
	b.errorAnnounced = false

	local := b.engine.LocalExchangeID()
	remoteSession := b.engine.RemoteDataSessionID()
	remoteMTU := b.engine.RemotePeerMTU()
	if local.DataSessionID == 0 || remoteSession == 0 || remoteMTU == 0 {
		return errors.Join(ErrStateInvalid, ErrInvalidConfig)
	}
	payload := int(b.engine.ConfirmedCarrierPayload())
	if payload == 0 {
		return errors.Join(ErrStateInvalid, ErrInvalidConfig)
	}
	sender := b.senderBase
	sender.DataSessionID = local.DataSessionID
	sender.RemotePeerMTU = int(remoteMTU)
	sender.CarrierPayload = payload
	// The lane-wrap pause must outlive fragments alive on the peer, so it uses
	// the peer's advertised reassembly lifetime, not the local one.
	lifetime := sender.SequenceReuseLifetime
	if advertised := b.engine.RemoteReassemblyLifetimeMs(); advertised != 0 {
		lifetime = time.Duration(advertised) * time.Millisecond
	}
	sender.SequenceReuseLifetime = lifetime
	receiver := b.receiverBase
	receiver.DataSessionID = remoteSession
	if !b.installed || b.activeTX != sender.DataSessionID || b.activeRX != receiver.DataSessionID ||
		b.activeMTU != sender.RemotePeerMTU || b.activePayload != sender.CarrierPayload ||
		b.activeLifetime != lifetime {
		// Replacing a live data plane is a stop-the-world operation from the
		// caller's perspective. Close the gate before installation so a failed
		// replacement cannot leave DATA flowing with stale limits.
		if err := b.tun.SetDataEnabled(b.peerID, false); err != nil {
			return err
		}
		if err := b.tun.InstallDataPlane(b.peerID, sender, receiver); err != nil {
			return errors.Join(ErrStateInvalid, err)
		}
		b.installed = true
		b.activeTX = sender.DataSessionID
		b.activeRX = receiver.DataSessionID
		b.activeMTU = sender.RemotePeerMTU
		b.activePayload = sender.CarrierPayload
		b.activeLifetime = lifetime
	}
	if err := b.tun.SetDataEnabled(b.peerID, true); err != nil {
		return err
	}
	if !b.announced {
		b.log(slog.LevelInfo, "data forwarding enabled", "carrier_payload", payload, "peer_mtu", remoteMTU)
	} else if b.announcedPayload != payload {
		b.log(
			slog.LevelInfo,
			"carrier payload changed",
			"previous_carrier_payload",
			b.announcedPayload,
			"carrier_payload",
			payload,
		)
	}
	b.announced = true
	b.announcedPayload = payload
	return nil
}

func (b *Bridge) snapshotLocked() Snapshot {
	return Snapshot{
		CarrierPayload: b.engine.ConfirmedCarrierPayload(),
		PMTUSearching:  b.engine.PMTUSearching(),
		DataReady:      b.engine.MissingFlags() == 0,
		MissingFlags:   b.engine.MissingFlags(),
		Status:         b.engine.Status(),
		StatusReason:   b.engine.StatusReason(),
	}
}

func (b *Bridge) log(level slog.Level, message string, args ...any) {
	if b.logger != nil {
		b.logger.Log(context.Background(), level, message, args...)
	}
}

var _ interface {
	DeliverControl(peerID peerroute.PeerID, payload []byte) error
} = (*Bridge)(nil)
var _ interface {
	ReportUnknownDataSession(peerID peerroute.PeerID, sessionID uint16) error
} = (*Bridge)(nil)
