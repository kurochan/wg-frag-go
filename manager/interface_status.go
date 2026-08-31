//go:build linux || darwin

package manager

import (
	"encoding/base64"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/protobuf/proto"
)

func (supervisor *interfaceSupervisor) diagnosticErrorStatus(
	statusErr error,
	includeSecrets bool,
) *controlapiv1.InterfaceStatus {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	supervisor.mu.RLock()
	current := supervisor.transitionStatusLocked(includeSecrets)
	publicKey := supervisor.publicKey
	running := supervisor.running
	supervisor.mu.RUnlock()
	current.SetLifecycle(controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR)
	current.SetLifecycleError(statusErr.Error())
	var live *controlapiv1.ShimCounters
	if running != nil {
		live = running.counterSnapshot()
	}
	current.SetCounters(addShimCounters(supervisor.manager.counterBase(publicKey), live))
	return current
}

func (supervisor *interfaceSupervisor) status(includeSecrets bool) (*controlapiv1.InterfaceStatus, error) {
	supervisor.mu.RLock()
	if supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING {
		current := supervisor.transitionStatusLocked(includeSecrets)
		publicKey := supervisor.publicKey
		supervisor.mu.RUnlock()
		current.SetCounters(addShimCounters(supervisor.manager.counterBase(publicKey), current.GetCounters()))
		return current, nil
	}
	supervisor.mu.RUnlock()

	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	return supervisor.statusLocked(includeSecrets)
}

// statusLocked reads a stable runtime generation while opMu is held.
func (supervisor *interfaceSupervisor) statusLocked(includeSecrets bool) (*controlapiv1.InterfaceStatus, error) {
	supervisor.mu.RLock()
	running := supervisor.running
	lifecycle := supervisor.lifecycle
	lifecycleErr := supervisor.lifecycleErr
	generation := supervisor.generation
	lastStatus := supervisor.lastStatus
	publicKey := supervisor.publicKey
	cfg := supervisor.config
	anchor := supervisor.anchor
	supervisor.mu.RUnlock()

	var current *controlapiv1.InterfaceStatus
	var err error
	if running != nil {
		current, err = running.status(includeSecrets)
	} else if lastStatus != nil {
		current = proto.Clone(lastStatus).(*controlapiv1.InterfaceStatus)
	} else {
		current = controlapiv1.InterfaceStatus_builder{}.Build()
	}
	if err != nil {
		return nil, err
	}
	current.SetRef(supervisor.ref())
	current.SetLifecycle(lifecycle)
	current.SetLifecycleError(lifecycleErr)
	current.SetGeneration(generation)
	current.SetSpec(controlconfig.SpecFromConfig(supervisor.name, cfg, includeSecrets))
	if anchor != nil {
		current.SetNativeInterfaceName(anchor.Name())
	}
	current.SetCounters(addShimCounters(supervisor.manager.counterBase(publicKey), current.GetCounters()))
	return current, nil
}

func (supervisor *interfaceSupervisor) transitionStatusLocked(includeSecrets bool) *controlapiv1.InterfaceStatus {
	var current *controlapiv1.InterfaceStatus
	if supervisor.lastStatus != nil {
		current = proto.Clone(supervisor.lastStatus).(*controlapiv1.InterfaceStatus)
	} else {
		current = controlapiv1.InterfaceStatus_builder{}.Build()
	}
	current.SetRef(supervisor.ref())
	current.SetLifecycle(supervisor.lifecycle)
	current.SetLifecycleError(supervisor.lifecycleErr)
	current.SetGeneration(supervisor.generation)
	current.SetPublicKey(base64.StdEncoding.EncodeToString(supervisor.publicKey[:]))
	if supervisor.anchor != nil {
		current.SetNativeInterfaceName(supervisor.anchor.Name())
	}
	if supervisor.config != nil {
		current.SetListenPort(uint32(supervisor.config.Interface.ListenPort))
		current.SetMtu(uint32(supervisor.config.Interface.MTU))
		current.SetSpec(controlconfig.SpecFromConfig(supervisor.name, supervisor.config, includeSecrets))
		current.SetPeers(transitionPeerStatuses(current.GetPeers(), supervisor.config, includeSecrets))
	}
	return current
}

func transitionPeerStatuses(
	previous []*controlapiv1.PeerStatus,
	cfg *config.Config,
	includeSecrets bool,
) []*controlapiv1.PeerStatus {
	byPublicKey := make(map[string]*controlapiv1.PeerStatus, len(previous))
	for _, peer := range previous {
		if peer != nil {
			byPublicKey[peer.GetPublicKey()] = peer
		}
	}
	peers := make([]*controlapiv1.PeerStatus, 0, len(cfg.Peers))
	for i := range cfg.Peers {
		configured := cfg.Peers[i]
		publicKey := base64.StdEncoding.EncodeToString(configured.PublicKey[:])
		current := controlapiv1.PeerStatus_builder{}.Build()
		if previousPeer := byPublicKey[publicKey]; previousPeer != nil {
			current = proto.Clone(previousPeer).(*controlapiv1.PeerStatus)
		}
		current.SetPublicKey(publicKey)
		current.SetEndpoint(configured.Endpoint)
		allowedIPs := make([]string, len(configured.AllowedIPs))
		for j, prefix := range configured.AllowedIPs {
			allowedIPs[j] = prefix.String()
		}
		current.SetAllowedIps(allowedIPs)
		current.SetPersistentKeepaliveSec(uint32(configured.PersistentKeepalive))
		current.SetMetricsId(configured.MetricsID)
		current.ClearPresharedKey()
		if includeSecrets && configured.PresharedKey != nil {
			current.SetPresharedKey(configured.PresharedKey[:])
		}
		peers = append(peers, current)
	}
	return peers
}

func (supervisor *interfaceSupervisor) ref() *controlapiv1.InterfaceRef {
	ref := controlapiv1.InterfaceRef_builder{}.Build()
	ref.SetInterfaceName(supervisor.name)
	ref.SetInterfaceInstanceId(append([]byte(nil), supervisor.instanceID[:]...))
	return ref
}

func (supervisor *interfaceSupervisor) captureCounters(running managedRuntime) {
	supervisor.mu.RLock()
	publicKey := supervisor.publicKey
	supervisor.mu.RUnlock()
	supervisor.captureCountersFor(running, publicKey)
}

func (supervisor *interfaceSupervisor) captureCountersFor(running managedRuntime, publicKey [32]byte) {
	if running == nil {
		return
	}
	current, err := running.status(false)
	if err != nil {
		current = controlapiv1.InterfaceStatus_builder{}.Build()
	}
	current.SetCounters(running.counterSnapshot())
	supervisor.manager.retainCounters(publicKey, current.GetCounters())
	current.SetCounters(controlapiv1.ShimCounters_builder{}.Build())
	supervisor.storeLastStatus(current)
}

func (supervisor *interfaceSupervisor) storeLastStatus(status *controlapiv1.InterfaceStatus) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	supervisor.lastStatus = status
}
