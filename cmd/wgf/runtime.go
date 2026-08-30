package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlplane"
	controlstate "github.com/kurochan/wg-frag-go/internal/core/control/state"
	"github.com/kurochan/wg-frag-go/internal/core/datapath"
	"github.com/kurochan/wg-frag-go/internal/core/lane"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/memoryplan"
	"github.com/kurochan/wg-frag-go/internal/transport"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/controlbridge"
	"github.com/kurochan/wg-frag-go/internal/wgadapter/shimtun"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"golang.zx2c4.com/wireguard/device"
	"google.golang.org/protobuf/proto"
)

const (
	requestCacheEntries             = 256
	requestCacheLifetime            = 10 * time.Minute
	controlQueueSize                = 16
	defaultReorderCapacity          = 64
	carrierQueueSlotLimitMultiplier = limits.MaxFragments * 2
)

// controlSink fans CONTROL out to the bridge owning each peer. The table is
// mutable because ApplyConfig adds and removes bridges at runtime while
// wireguard-go receive goroutines keep delivering frames.
type controlSink struct {
	mu      sync.RWMutex
	bridges map[peerroute.PeerID]*controlbridge.Bridge
}

func newControlSink() *controlSink {
	return &controlSink{bridges: make(map[peerroute.PeerID]*controlbridge.Bridge)}
}

func (s *controlSink) set(peer peerroute.PeerID, bridge *controlbridge.Bridge) {
	s.mu.Lock()
	s.bridges[peer] = bridge
	s.mu.Unlock()
}

func (s *controlSink) remove(peer peerroute.PeerID) {
	s.mu.Lock()
	delete(s.bridges, peer)
	s.mu.Unlock()
}

func (s *controlSink) bridgeFor(peer peerroute.PeerID) *controlbridge.Bridge {
	s.mu.RLock()
	bridge := s.bridges[peer]
	s.mu.RUnlock()
	return bridge
}

func (s *controlSink) DeliverControl(peer peerroute.PeerID, frame []byte) error {
	bridge := s.bridgeFor(peer)
	if bridge == nil {
		// A carrier can already be in flight when ApplyConfig removes its peer.
		// It is authenticated but stale, so dropping it must not fail the TUN.
		return nil
	}
	return bridge.DeliverControl(peer, frame)
}

func (s *controlSink) ReportUnknownDataSession(peer peerroute.PeerID, sessionID uint16) error {
	bridge := s.bridgeFor(peer)
	if bridge == nil {
		return nil
	}
	return bridge.ReportUnknownDataSession(peer, sessionID)
}

type appliedRequest struct {
	hash   [32]byte
	result *controlapiv1.ApplyConfigResponse
	at     time.Time
}

type runtimeFaultScope uint8

const (
	runtimePeerFault runtimeFaultScope = iota + 1
	runtimeInterfaceFault
)

type peerFaultState struct {
	nextRetry time.Time
	delay     time.Duration
	lastLog   time.Time
}

// socketDropReporter exposes best-effort per-family UDP receive-drop counters.
// Platforms without kernel counters can return zeroes.
type socketDropReporter interface {
	SocketDrops() (ipv4, ipv6 uint64)
}

// daemonRuntime owns every per-peer control plane and serializes ticks,
// transport error reports, status reads, and configuration changes.
type daemonRuntime struct {
	mu         sync.Mutex
	ifname     string
	classifier *lane.Classifier
	cfg        *config.Config
	plan       wgadapter.Plan
	shim       *shimtun.Device
	wgTUN      *wgadapter.WireGuardTUN
	wg         *device.Device
	bind       socketDropReporter
	sink       *controlSink
	bridges    map[peerroute.PeerID]*controlbridge.Bridge

	generation uint64
	requests   map[[16]byte]appliedRequest
	peerFaults map[peerroute.PeerID]peerFaultState
	logger     *slog.Logger
	batchSize  int
	fatal      error
}

func (rt *daemonRuntime) bridgeSnapshots() map[peerroute.PeerID]controlbridge.Snapshot {
	rt.mu.Lock()
	bridges := make(map[peerroute.PeerID]*controlbridge.Bridge, len(rt.bridges))
	for id, bridge := range rt.bridges {
		bridges[id] = bridge
	}
	rt.mu.Unlock()

	snapshots := make(map[peerroute.PeerID]controlbridge.Snapshot, len(bridges))
	for id, bridge := range bridges {
		snapshots[id] = bridge.Snapshot()
	}
	return snapshots
}

func (rt *daemonRuntime) tick(now time.Time) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.fatal != nil {
		return rt.fatal
	}

	for id, bridge := range rt.bridges {
		if fault := rt.peerFaults[id]; !fault.nextRetry.IsZero() && now.Before(fault.nextRetry) {
			continue
		}
		if err := bridge.Tick(now); err != nil {
			if handled := rt.handleBridgeErrorLocked(now, id, err); handled != nil {
				return handled
			}
			continue
		}
		rt.clearPeerFaultLocked(id)
	}
	return nil
}

func (rt *daemonRuntime) reportTransportEvent(now time.Time, event transport.PathEvent) error {
	if !event.EndpointKnown || !event.DatagramSizeKnown {
		// An asynchronous error without an endpoint cannot be safely attributed
		// in a multi-peer interface. Confirmation probes recover the affected
		// peer without shrinking unrelated paths.
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.fatal != nil {
		return rt.fatal
	}

	current, err := rt.wg.IpcGet()
	if err != nil {
		return nil
	}
	for _, id := range peerIDsForEndpoint(rt.plan, current, event.Endpoint) {
		bridge := rt.bridges[id]
		if bridge == nil {
			continue
		}
		if err := bridge.ReportTransportError(now, event.Err, event.DatagramSize); err != nil {
			if handled := rt.handleBridgeErrorLocked(now, id, err); handled != nil {
				return handled
			}
			continue
		}
		rt.clearPeerFaultLocked(id)
	}
	return nil
}

func classifyRuntimeFault(err error) runtimeFaultScope {
	switch {
	case errors.Is(err, shimtun.ErrPeerNotFound):
		return runtimePeerFault
	case errors.Is(err, controlbridge.ErrStateInvalid):
		return runtimeInterfaceFault
	case errors.Is(err, shimtun.ErrClosed),
		errors.Is(err, shimtun.ErrShortBuffer),
		errors.Is(err, shimtun.ErrShortNativeWrite),
		errors.Is(err, shimtun.ErrControlSink),
		errors.Is(err, shimtun.ErrInvalidConfig):
		return runtimeInterfaceFault
	default:
		return runtimePeerFault
	}
}

func (rt *daemonRuntime) handleBridgeErrorLocked(now time.Time, id peerroute.PeerID, err error) error {
	if classifyRuntimeFault(err) == runtimeInterfaceFault {
		return rt.failClosed(fmt.Errorf("peer %d exposed an interface-fatal error: %w", id, err))
	}

	if disableErr := rt.shim.SetDataEnabled(id, false); disableErr != nil {
		if errors.Is(disableErr, shimtun.ErrPeerNotFound) {
			// ApplyConfig may have removed this peer while its CONTROL callback
			// was in flight. The peer is already dark and no interface-wide
			// recovery is required.
			delete(rt.peerFaults, id)
			return nil
		}
		return rt.failClosed(fmt.Errorf("disable peer %d after control error: %w", id, disableErr))
	}
	fault := rt.peerFaults[id]
	if fault.delay <= 0 {
		fault.delay = 100 * time.Millisecond
	} else {
		fault.delay *= 2
		if fault.delay > time.Second {
			fault.delay = time.Second
		}
	}
	fault.nextRetry = now.Add(fault.delay)
	if fault.lastLog.IsZero() || now.Sub(fault.lastLog) >= time.Second {
		rt.log(slog.LevelWarn, "peer control operation failed; retrying", "peer_id", id, "retry_in", fault.delay, "error", err)
		fault.lastLog = now
	}
	rt.peerFaults[id] = fault
	return nil
}

func (rt *daemonRuntime) clearPeerFaultLocked(id peerroute.PeerID) {
	if fault, ok := rt.peerFaults[id]; ok {
		if !fault.lastLog.IsZero() {
			rt.log(slog.LevelInfo, "peer control operation recovered", "peer_id", id)
		}
		delete(rt.peerFaults, id)
	}
}

// failClosed disables forwarding when a multi-layer rollback cannot restore a
// coherent peer table. The run loop observes fatal on its next control tick
// and exits, allowing the supervisor to restart from a known configuration.
// rt.mu must be held.
func (rt *daemonRuntime) failClosed(err error) error {
	if rt.fatal != nil {
		return rt.fatal
	}
	rt.fatal = err
	if rt.logger != nil {
		rt.logger.Error("runtime entered fail-closed state", "error", err)
	}

	for id := range rt.bridges {
		_ = rt.shim.SetDataEnabled(id, false)
	}
	return err
}

func peerIDsForEndpoint(plan wgadapter.Plan, uapi string, endpoint netip.AddrPort) []peerroute.PeerID {
	idsByKey := make(map[string]peerroute.PeerID, len(plan.Peers))
	for _, peer := range plan.Peers {
		idsByKey[hex.EncodeToString(peer.PublicKey[:])] = peer.ID
	}
	var current peerroute.PeerID
	currentSet := false
	matched := make([]peerroute.PeerID, 0, 1)
	for line := range strings.Lines(uapi) {
		if value, ok := strings.CutPrefix(line, "public_key="); ok {
			id, known := idsByKey[strings.TrimSpace(value)]
			current, currentSet = id, known
			continue
		}
		if !currentSet {
			continue
		}
		value, ok := strings.CutPrefix(line, "endpoint=")
		if !ok {
			continue
		}
		observed, err := netip.ParseAddrPort(strings.TrimSpace(value))
		if err == nil && observed == endpoint {
			matched = append(matched, current)
		}
	}
	if len(matched) != 1 {
		// An endpoint shared by multiple peers is not enough to attribute an
		// asynchronous path error safely.
		return nil
	}
	return matched
}

// status is the GetStatus handler.
func (rt *daemonRuntime) status(_ context.Context, includeSecrets bool) (*controlapiv1.GetStatusResponse, error) {
	rt.mu.Lock()
	if rt.fatal != nil {
		err := rt.fatal
		rt.mu.Unlock()
		return nil, err
	}
	ifname := rt.ifname
	cfg := *rt.cfg
	plan := rt.plan
	generation := rt.generation
	bridges := make(map[peerroute.PeerID]*controlbridge.Bridge, len(rt.bridges))
	for id, bridge := range rt.bridges {
		bridges[id] = bridge
	}
	rt.mu.Unlock()

	stats := rt.shim.Stats()
	dropsV4, dropsV6 := rt.bind.SocketDrops()
	indexByHexKey := make(map[string]int, len(plan.Peers))
	metricsIDs := make(map[config.Key]string, len(cfg.Peers))
	for _, configured := range cfg.Peers {
		metricsIDs[configured.PublicKey] = configured.MetricsID
	}

	peers := make([]*controlapiv1.PeerStatus, len(plan.Peers))
	for i, peer := range plan.Peers {
		indexByHexKey[hex.EncodeToString(peer.PublicKey[:])] = i

		allowed := make([]string, len(peer.AllowedIPs))
		for j, prefix := range peer.AllowedIPs {
			allowed[j] = prefix.String()
		}
		status := controlapiv1.PeerStatus_builder{}.Build()
		status.SetPublicKey(base64.StdEncoding.EncodeToString(peer.PublicKey[:]))
		if includeSecrets && peer.PresharedKey != nil {
			status.SetPresharedKey(peer.PresharedKey[:])
		}
		status.SetEndpoint(peer.Endpoint)
		status.SetAllowedIps(allowed)
		status.SetPersistentKeepaliveSec(uint32(peer.PersistentKeepalive))
		status.SetMetricsId(metricsIDs[config.Key(peer.PublicKey)])
		if bridge := bridges[peer.ID]; bridge != nil {
			snapshot := bridge.Snapshot()
			status.SetConfirmedCarrierPayload(snapshot.CarrierPayload)
			status.SetPmtuSearching(snapshot.PMTUSearching)
			status.SetDataReady(snapshot.DataReady)
			status.SetControlPathState(string(snapshot.Status))
			status.SetControlPathError(snapshot.StatusReason)
		}
		peers[i] = status
	}
	counters := controlapiv1.ShimCounters_builder{}.Build()
	counters.SetTxCarriers(stats.TXCarriers)
	counters.SetTxPacketDrops(stats.TXPacketDrops)
	counters.SetTxRouteDrops(stats.TXRouteDrops)
	counters.SetTxPeerMtuDrops(stats.TXPeerMTUDrops)
	counters.SetTxPtbSent(stats.TXPTBSent)
	counters.SetRxDataCarriers(stats.RXDataCarriers)
	counters.SetRxInnerDelivered(stats.RXInnerDelivered)
	counters.SetRxPacketRejects(stats.RXPacketRejects)
	counters.SetRxSourceSpoofDrops(stats.RXSourceSpoofDrops)
	counters.SetRxNativeWriteDrops(stats.RXNativeWriteDrops)
	counters.SetCarrierQueueOverflows(stats.CarrierQueueOverflows)
	counters.SetControlExploratoryEvictions(stats.ControlExploratoryEvictions)
	counters.SetControlCoalesces(stats.ControlCoalesces)
	counters.SetControlQueueDrops(stats.ControlQueueDrops)
	counters.SetControlRateSuppressionEpisodes(stats.ControlRateSuppressionEpisodes)
	counters.SetControlMaterializationDrops(stats.ControlMaterializationDrops)
	counters.SetControlIngressRateLimited(stats.ControlIngressRateLimited)
	counters.SetPreconfirmDrops(stats.PreconfirmDrops)
	counters.SetReassemblyExpirations(stats.ReassemblyExpirations)
	counters.SetUdpSocketDrops(dropsV4 + dropsV6)
	response := controlapiv1.GetStatusResponse_builder{}.Build()
	response.SetInterfaceName(ifname)
	response.SetPublicKey(base64.StdEncoding.EncodeToString(plan.LocalPublicKey[:]))
	response.SetListenPort(uint32(cfg.Interface.ListenPort))
	response.SetMtu(uint32(cfg.Interface.MTU))
	response.SetPeers(peers)
	response.SetGeneration(generation)
	response.SetCounters(counters)
	rt.fillWireGuardCounters(indexByHexKey, peers)
	return response, nil
}

func (rt *daemonRuntime) fillWireGuardCounters(indexByHexKey map[string]int, peers []*controlapiv1.PeerStatus) {
	uapi, err := rt.wg.IpcGet()
	if err != nil {
		return
	}
	current := -1

	for line := range strings.Lines(uapi) {
		if value, ok := strings.CutPrefix(line, "public_key="); ok {
			index, known := indexByHexKey[strings.TrimSpace(value)]
			if !known {
				index = -1
			}
			current = index
			continue
		}
		if current < 0 {
			continue
		}
		if value, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				peers[current].SetLastHandshakeUnix(seconds)
			}
		}
		if value, ok := strings.CutPrefix(line, "rx_bytes="); ok {
			if bytes, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64); err == nil {
				peers[current].SetTransferRxBytes(bytes)
			}
		}
		if value, ok := strings.CutPrefix(line, "tx_bytes="); ok {
			if bytes, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64); err == nil {
				peers[current].SetTransferTxBytes(bytes)
			}
		}
	}
}

// apply is the ApplyConfig handler. It publishes the new peer table
// fail-closed: a peer whose control plane cannot start is reported in its
// result and stays dark instead of reverting the whole change.
//
//nolint:cyclop,funlen // ApplyConfig coordinates validation and ordered rollback across layers.
func (rt *daemonRuntime) apply(
	_ context.Context,
	request *controlapiv1.ApplyConfigRequest,
) (*controlapiv1.ApplyConfigResponse, error) {
	requestID, err := parseRequestID(request.GetRequestId())
	if err != nil {
		return nil, err
	}
	hash, err := snapshotHash(request.GetPeers())
	if err != nil {
		return nil, err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.fatal != nil {
		return nil, rt.fatal
	}
	now := time.Now()
	rt.pruneRequestCacheLocked(now)
	if cached, seen := rt.requests[requestID]; seen {
		if cached.hash != hash {
			return nil, errors.New("request_id was already used with a different snapshot")
		}
		return cached.result, nil
	}
	if request.GetExpectedGeneration() != rt.generation {
		return nil, fmt.Errorf("generation conflict: expected %d, current %d", request.GetExpectedGeneration(), rt.generation)
	}
	desired := make([]config.Peer, len(request.GetPeers()))
	for i, peer := range request.GetPeers() {
		var psk []byte
		switch peer.GetPresharedKeyAction() {
		case controlapiv1.PresharedKeyAction_SET:
			psk = peer.GetPresharedKey()
		case controlapiv1.PresharedKeyAction_PRESERVE:
			for _, oldPeer := range rt.cfg.Peers {
				encoded := base64.StdEncoding.EncodeToString(oldPeer.PublicKey[:])
				if encoded == peer.GetPublicKey() && oldPeer.PresharedKey != nil {
					psk = oldPeer.PresharedKey[:]
					break
				}
			}
		case controlapiv1.PresharedKeyAction_CLEAR:
		default:
			return nil, fmt.Errorf("peer %d: invalid preshared-key action", i+1)
		}
		desired[i], err = config.NewPeerWithPresharedKeyBytes(
			peer.GetPublicKey(), peer.GetEndpoint(), peer.GetAllowedIps(),
			peer.GetPersistentKeepaliveSec(), psk,
		)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %w", i+1, err)
		}
		desired[i].MetricsID = peer.GetMetricsId()
	}
	if err := config.ValidatePeers(desired); err != nil {
		return nil, err
	}

	newCfg := *rt.cfg
	newCfg.Peers = desired

	update, err := wgadapter.PreparePeerUpdate(&newCfg, rt.plan)
	if err != nil {
		return nil, err
	}
	added := make(map[peerroute.PeerID]shimtun.PeerConfig, len(update.Added))
	for _, peer := range update.Added {
		base, err := peerDataPlane(&newCfg, update.Plan, peer, rt.classifier)
		if err != nil {
			return nil, err
		}
		added[peer.ID] = base
	}
	// Keep the old control maps intact until all three tables agree. Install the
	// WireGuard peer first: until the facade is updated, a new peer can only be
	// dropped and cannot be attributed to an existing shim peer.
	removedIDs := make([]peerroute.PeerID, len(update.Removed))
	for i, peer := range update.Removed {
		removedIDs[i] = peer.ID
	}
	// Remove retired IDs before publishing the new shim table. This prevents a
	// reused ID from routing a new peer's CONTROL frame to the old bridge.
	for _, peer := range update.Removed {
		rt.sink.remove(peer.ID)
	}
	if err := rt.wg.IpcSet(update.UAPI); err != nil {
		for _, peer := range update.Removed {
			if bridge := rt.bridges[peer.ID]; bridge != nil {
				rt.sink.set(peer.ID, bridge)
			}
		}
		wgRollbackErr := wgadapter.Apply(rt.wg, rt.plan)
		if wgRollbackErr != nil {
			return nil, rt.failClosed(errors.Join(
				fmt.Errorf("wireguard update: %w", err),
				fmt.Errorf("wireguard rollback: %w", wgRollbackErr),
			))
		}
		return nil, fmt.Errorf("wireguard update: %w", err)
	}
	if err := rt.wgTUN.ReconfigureWithShim(update.Plan, func() error {
		return rt.shim.Reconfigure(added, removedIDs, update.Plan.Routes)
	}); err != nil {
		for _, peer := range update.Removed {
			if bridge := rt.bridges[peer.ID]; bridge != nil {
				rt.sink.set(peer.ID, bridge)
			}
		}
		wgRollbackErr := wgadapter.Apply(rt.wg, rt.plan)
		if wgRollbackErr != nil {
			return nil, rt.failClosed(errors.Join(
				fmt.Errorf("reconfigure shim/facade: %w", err),
				fmt.Errorf("wireguard rollback: %w", wgRollbackErr),
			))
		}
		return nil, fmt.Errorf("reconfigure shim/facade: %w", err)
	}
	// The shim transaction has already published the new routing snapshot.
	// Update surviving bridge bases only after UAPI succeeds, so a rollback
	// never leaves a bridge carrying a snapshot different from the shim.

	for _, peer := range update.Survivors {
		if bridge := rt.bridges[peer.ID]; bridge != nil {
			bridge.UpdateRoutes(update.Plan.Routes)
		}
	}

	for _, peer := range update.Removed {
		rt.sink.remove(peer.ID)
		delete(rt.bridges, peer.ID)
		delete(rt.peerFaults, peer.ID)
	}

	startPeer := func(peer wgadapter.PeerPlan, base shimtun.PeerConfig) error {
		engine, err := newEngine(&newCfg)
		if err != nil {
			return err
		}
		bridge, err := controlbridge.New(controlbridge.Config{
			Engine:       engine,
			TUN:          rt.shim,
			PeerID:       peer.ID,
			OwnerKey:     peer.PublicKey,
			SenderBase:   base.Sender,
			ReceiverBase: base.Receiver,
			Logger:       peerLogger(rt.logger, peer),
		})
		if err != nil {
			return err
		}
		if err := bridge.Start(); err != nil {
			return err
		}
		rt.bridges[peer.ID] = bridge
		rt.sink.set(peer.ID, bridge)
		return nil
	}

	response := controlapiv1.ApplyConfigResponse_builder{}.Build()

	results := make([]*controlapiv1.PeerResult, 0, len(update.Added)+len(update.Survivors))
	for _, peer := range update.Added {
		result := controlapiv1.PeerResult_builder{}.Build()
		result.SetPublicKey(base64.StdEncoding.EncodeToString(peer.PublicKey[:]))

		results = append(results, result)
		if err := startPeer(peer, added[peer.ID]); err != nil {
			result.SetError(err.Error())
			rt.log(slog.LevelWarn, "peer control-plane start failed", "peer_id", peer.ID, "error", err)
		}
	}

	for _, peer := range update.Survivors {
		if err := rt.shim.SetPeerMetricsID(peer.ID, peer.PublicKey, peer.MetricsID); err != nil {
			return nil, rt.failClosed(fmt.Errorf("update peer metrics ID: %w", err))
		}
		result := controlapiv1.PeerResult_builder{}.Build()
		result.SetPublicKey(base64.StdEncoding.EncodeToString(peer.PublicKey[:]))
		// A previous ApplyConfig may have installed the peer in the shim and
		// UAPI but failed while starting its control bridge. Retry that cold
		// path on the next snapshot instead of leaving the peer dark forever.
		if rt.bridges[peer.ID] == nil {
			rt.sink.remove(peer.ID)
			delete(rt.bridges, peer.ID)
			base, err := peerDataPlane(&newCfg, update.Plan, peer, rt.classifier)
			if err == nil {
				err = startPeer(peer, base)
			}
			if err != nil {
				result.SetError(err.Error())
				rt.log(slog.LevelWarn, "peer control-plane restart failed", "peer_id", peer.ID, "error", err)
			}
		}
		results = append(results, result)
	}

	rt.cfg = &newCfg
	rt.plan = update.Plan
	rt.generation++
	logMemoryReservation(rt.logger, rt.cfg, len(update.Plan.Peers), rt.batchSize)

	response.SetResults(results)
	response.SetGeneration(rt.generation)
	rt.cacheRequest(requestID, hash, response)
	rt.log(
		slog.LevelInfo,
		"configuration applied",
		"generation",
		rt.generation,
		"added_peers",
		len(update.Added),
		"removed_peers",
		len(update.Removed),
		"surviving_peers",
		len(update.Survivors),
	)
	return response, nil
}

func (rt *daemonRuntime) log(level slog.Level, message string, args ...any) {
	if rt.logger != nil {
		rt.logger.Log(context.Background(), level, message, args...)
	}
}

func (rt *daemonRuntime) cacheRequest(id [16]byte, hash [32]byte, result *controlapiv1.ApplyConfigResponse) {
	now := time.Now()
	rt.pruneRequestCacheLocked(now)
	if len(rt.requests) >= requestCacheEntries {
		oldest, oldestAt := [16]byte{}, now
		for key, entry := range rt.requests {
			if entry.at.Before(oldestAt) {
				oldest, oldestAt = key, entry.at
			}
		}
		delete(rt.requests, oldest)
	}
	rt.requests[id] = appliedRequest{hash: hash, result: result, at: now}
}

func (rt *daemonRuntime) pruneRequestCacheLocked(now time.Time) {
	for key, entry := range rt.requests {
		if now.Sub(entry.at) > requestCacheLifetime {
			delete(rt.requests, key)
		}
	}
}

func parseRequestID(raw []byte) ([16]byte, error) {
	var id [16]byte
	if len(raw) != len(id) {
		return id, errors.New("request_id must be exactly 16 bytes")
	}
	copy(id[:], raw)
	if id == ([16]byte{}) {
		return id, errors.New("request_id must be nonzero")
	}
	return id, nil
}

// snapshotHash canonicalizes the desired peer list so retries of the same
// request are recognized byte-for-byte.
func snapshotHash(peers []*controlapiv1.DesiredPeer) ([32]byte, error) {
	marshal := proto.MarshalOptions{Deterministic: true}
	digest := sha256.New()

	for _, peer := range peers {
		encoded, err := marshal.Marshal(peer)
		if err != nil {
			return [32]byte{}, err
		}

		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(encoded)
	}

	var hash [32]byte
	copy(hash[:], digest.Sum(nil))
	return hash, nil
}

func peerLogger(logger *slog.Logger, peer wgadapter.PeerPlan) *slog.Logger {
	if logger == nil {
		return nil
	}
	return logger.With("peer_id", peer.ID, "peer_public_key", base64.StdEncoding.EncodeToString(peer.PublicKey[:]))
}

func dataPlaneBases(
	cfg *config.Config,
	plan wgadapter.Plan,
	classifier *lane.Classifier,
) ([]shimtun.PeerConfig, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	peers := make([]shimtun.PeerConfig, len(plan.Peers))
	for i, peer := range plan.Peers {
		base, err := peerDataPlane(cfg, plan, peer, classifier)
		if err != nil {
			return nil, err
		}
		peers[i] = base
	}
	return peers, nil
}

func peerDataPlane(
	cfg *config.Config,
	plan wgadapter.Plan,
	peer wgadapter.PeerPlan,
	classifier *lane.Classifier,
) (shimtun.PeerConfig, error) {
	perPeerSlots := reassemblySlots(cfg.Interface)
	if perPeerSlots > cfg.Interface.ReassemblySlots {
		return shimtun.PeerConfig{}, errors.New("peer reassembly slots exceed interface slots")
	}
	return shimtun.PeerConfig{
		MetricsID: peer.MetricsID,
		OwnerKey:  peer.PublicKey,
		Sender: datapath.SenderConfig{
			DataSessionID:  1, // Replaced by Bridge after ResetSequence.
			CarrierPayload: cfg.Interface.MinCarrierPayload,
			MinPack:        limits.DefaultMinPackData,
			RemotePeerMTU:  cfg.Interface.MTU, // Replaced after peer confirmation.
			PeerID:         peer.ID,
			AllowedIPs:     plan.Routes,
			Classifier:     classifier,
		},
		Receiver: datapath.ReceiverConfig{
			PeerID:          peer.ID,
			DataSessionID:   1, // Replaced by Bridge after peer ResetSequence.
			AllowedIPs:      plan.Routes,
			Slots:           perPeerSlots,
			PerPeerSlots:    perPeerSlots,
			MaxPacketSize:   cfg.Interface.MTU,
			Lifetime:        cfg.Interface.ReassemblyLifetime,
			ReorderEnabled:  cfg.Interface.Reorder,
			ReorderCapacity: min(cfg.Interface.ReassemblySlots, defaultReorderCapacity),
			ReorderBudget:   reorderBudget(perPeerSlots, cfg.Interface.Reorder),
			ReorderMaxDelay: cfg.Interface.ReorderMaxDelay,
		},
	}, nil
}

func reorderBudget(slots int, enabled bool) int {
	if !enabled {
		return 0
	}
	return slots - 1
}

func reassemblySlots(iface config.Interface) int {
	if iface.PeerReassemblySlots.Auto {
		return iface.ReassemblySlots
	}
	return iface.PeerReassemblySlots.Count
}

func logMemoryReservation(logger *slog.Logger, cfg *config.Config, peers, batch int) {
	if logger == nil || cfg == nil {
		return
	}
	reorderLanes := 1
	if cfg.Interface.Workers.Count > reorderLanes {
		reorderLanes = cfg.Interface.Workers.Count
	}
	estimate, err := memoryplan.Calculate(memoryplan.Config{
		MTU:               cfg.Interface.MTU,
		Peers:             peers,
		ReassemblySlots:   reassemblySlots(cfg.Interface),
		MaxCarrierPayload: cfg.Interface.MaxCarrierPayload,
		CarrierQueueSlots: batch * carrierQueueSlotLimitMultiplier,
		ControlQueueSlots: controlQueueSize,
		ReorderCapacity:   min(cfg.Interface.ReassemblySlots, defaultReorderCapacity),
		ReorderLanes:      reorderLanes,
		TUNBatchSize:      batch,
	})
	if err != nil {
		logger.Warn("fixed buffer reservation could not be estimated", "error", err)
		return
	}
	logger.Info("fixed buffer reservation", "bytes", estimate.TotalBytes, "reassembly_bytes", estimate.ReassemblyBytes, "carrier_bytes", estimate.CarrierBytes, "control_bytes", estimate.ControlBytes)
}

func newEngine(cfg *config.Config) (*controlplane.Engine, error) {
	return controlplane.New(controlplane.Config{
		CanonicalizeCarrierPayload: wgadapter.CanonicalCarrierPayload,
		TransportDatagramSize:      wgadapter.WireGuardDatagramSize,
		State: controlstate.Config{
			MaxCarrierPayload:    uint32(cfg.Interface.MaxCarrierPayload),
			MinCarrierPayload:    uint32(cfg.Interface.MinCarrierPayload),
			ReassemblyLifetimeMs: uint32(cfg.Interface.ReassemblyLifetime.Milliseconds()),
			LocalPeerMTU:         uint32(cfg.Interface.MTU),
			StateSyncMinInterval: time.Second,
			Clock:                controlstate.ClockFunc(time.Now),
			Entropy: controlstate.EntropyFunc(func() (uint64, error) {
				var bytes [8]byte
				if _, err := rand.Read(bytes[:]); err != nil {
					return 0, err
				}
				return binary.BigEndian.Uint64(bytes[:]), nil
			}),
		},
	})
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
