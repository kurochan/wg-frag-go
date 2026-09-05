package controlconfig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

var (
	errNilInterfaceSpec       = errors.New("interface spec is nil")
	errMissingPrivateKey      = errors.New("private key is required when creating an interface")
	errInvalidPrivateKeyBytes = errors.New("private key must contain exactly 32 bytes")
	errPreserveWithoutCurrent = errors.New("PRESERVE requires the current configuration")
)

// Create converts an interface specification into runtime configuration.
// An omitted private key is preserved during restart, while all non-secret
// interface fields are based on config.Default.
func Create(spec *controlapiv1.InterfaceSpec, current *config.Config) (*config.Config, error) {
	if spec == nil {
		return nil, errNilInterfaceSpec
	}

	cfg := config.Default()
	if spec.HasPrivateKey() {
		privateKey := spec.GetPrivateKey()
		if len(privateKey) != len(cfg.Interface.PrivateKey) {
			return nil, errInvalidPrivateKeyBytes
		}
		copy(cfg.Interface.PrivateKey[:], privateKey)
	} else if current != nil {
		cfg.Interface.PrivateKey = current.Interface.PrivateKey
	} else {
		return nil, errMissingPrivateKey
	}

	iface := &cfg.Interface
	if spec.HasListenPort() {
		if spec.GetListenPort() > math.MaxUint16 {
			return nil, fmt.Errorf("listen port %d is outside 0..65535", spec.GetListenPort())
		}
		iface.ListenPort = uint16(spec.GetListenPort())
	}
	if spec.HasMtu() {
		value, err := uint32ToInt(spec.GetMtu(), "MTU")
		if err != nil {
			return nil, err
		}
		iface.MTU = value
	}
	if spec.HasMtuDiscovery() {
		if spec.GetMtuDiscovery() != "auto" {
			return nil, fmt.Errorf("MTU discovery %q is not supported", spec.GetMtuDiscovery())
		}
		iface.MTUDiscovery = spec.GetMtuDiscovery()
	}
	if spec.HasMinCarrierPayload() {
		value, err := uint32ToInt(spec.GetMinCarrierPayload(), "minimum carrier payload")
		if err != nil {
			return nil, err
		}
		iface.MinCarrierPayload = value
	}
	if spec.HasMaxCarrierPayload() {
		value, err := uint32ToInt(spec.GetMaxCarrierPayload(), "maximum carrier payload")
		if err != nil {
			return nil, err
		}
		iface.MaxCarrierPayload = value
	}
	if spec.HasReassemblySlots() {
		value, err := uint32ToInt(spec.GetReassemblySlots(), "reassembly slots")
		if err != nil {
			return nil, err
		}
		iface.ReassemblySlots = value
	}
	iface.PeerReassemblySlots = autoCountFromUint32(spec.GetPeerReassemblySlots())
	if spec.HasReassemblyLifetimeMs() {
		iface.ReassemblyLifetime = time.Duration(spec.GetReassemblyLifetimeMs()) * time.Millisecond
	}
	if spec.HasReorder() {
		iface.Reorder = spec.GetReorder()
	}
	if spec.HasReorderMaxDelayMs() {
		iface.ReorderMaxDelay = time.Duration(spec.GetReorderMaxDelayMs()) * time.Millisecond
	}
	iface.Workers = autoCountFromUint32(spec.GetWorkers())
	iface.TUNQueues = autoCountFromUint32(spec.GetTunQueues())
	if spec.HasSocketBuffer() {
		value, err := uint32ToInt(spec.GetSocketBuffer(), "socket buffer")
		if err != nil {
			return nil, err
		}
		if value < config.MinSocketBuffer || value > config.MaxSocketBuffer {
			return nil, fmt.Errorf("socket buffer %d is outside %d..%d bytes", value, config.MinSocketBuffer, config.MaxSocketBuffer)
		}
		iface.SocketBuffer = value
	}
	if spec.HasUdpBatchSize() {
		value, err := uint32ToInt(spec.GetUdpBatchSize(), "UDP batch size")
		if err != nil {
			return nil, err
		}
		if err := config.ValidateUDPBatchSize(value); err != nil {
			return nil, err
		}
		iface.UDPBatchSize = value
	}
	if spec.HasFwMark() {
		iface.FwMark = spec.GetFwMark()
	}

	peers, err := PeersFromSpec(spec.GetPeers(), current)
	if err != nil {
		return nil, err
	}
	cfg.Peers = peers
	if err := config.Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid interface spec: %w", err)
	}
	return &cfg, nil
}

// PeersFromSpec converts control API peer specifications to runtime peers.
// PRESERVE actions require current and copy the current preshared key without
// aliasing its backing storage.
func PeersFromSpec(specs []*controlapiv1.PeerSpec, current *config.Config) ([]config.Peer, error) {
	var peers []config.Peer
	if specs != nil {
		peers = make([]config.Peer, 0, len(specs))
	}
	currentKeys := make(map[config.Key]*config.Key)
	if current != nil {
		currentKeys = make(map[config.Key]*config.Key, len(current.Peers))
		for i := range current.Peers {
			peer := current.Peers[i]
			if peer.PresharedKey != nil {
				key := *peer.PresharedKey
				currentKeys[peer.PublicKey] = &key
			} else {
				currentKeys[peer.PublicKey] = nil
			}
		}
	}
	for i, spec := range specs {
		if spec == nil {
			return nil, fmt.Errorf("peer %d: nil peer spec", i+1)
		}

		action := spec.GetPresharedKeyAction()
		var presharedKey []byte
		switch action {
		case controlapiv1.PresharedKeyAction_PRESERVE:
			if len(spec.GetPresharedKey()) != 0 {
				return nil, fmt.Errorf("peer %d: PRESERVE must not contain a preshared key", i+1)
			}
			if current == nil {
				return nil, fmt.Errorf("peer %d: %w", i+1, errPreserveWithoutCurrent)
			}
			key, ok := currentKeys[peerKeyFromString(spec.GetPublicKey())]
			if !ok {
				return nil, fmt.Errorf("peer %d: PRESERVE peer is not present in the current configuration", i+1)
			}
			if key != nil {
				presharedKey = append([]byte(nil), key[:]...)
			}
		case controlapiv1.PresharedKeyAction_SET:
			if len(spec.GetPresharedKey()) != len(config.Key{}) {
				return nil, fmt.Errorf("peer %d: SET preshared key must contain exactly 32 bytes", i+1)
			}
			presharedKey = append([]byte(nil), spec.GetPresharedKey()...)
		case controlapiv1.PresharedKeyAction_CLEAR:
			if len(spec.GetPresharedKey()) != 0 {
				return nil, fmt.Errorf("peer %d: CLEAR must not contain a preshared key", i+1)
			}
		default:
			return nil, fmt.Errorf("peer %d: unknown preshared key action %d", i+1, action)
		}

		peer, err := config.NewPeerWithPresharedKeyBytes(
			spec.GetPublicKey(),
			spec.GetEndpoint(),
			spec.GetAllowedIps(),
			spec.GetPersistentKeepaliveSec(),
			presharedKey,
		)
		if err != nil {
			return nil, fmt.Errorf("peer %d: %w", i+1, err)
		}
		peer.MetricsID = spec.GetMetricsId()
		peers = append(peers, peer)
	}
	return peers, nil
}

// SpecFromConfig returns a complete interface specification. Interface
// private keys are never returned. When includeSecrets is false, preshared
// keys are omitted and peers use PRESERVE.
func SpecFromConfig(ifname string, cfg *config.Config, includeSecrets bool) *controlapiv1.InterfaceSpec {
	spec := controlapiv1.InterfaceSpec_builder{}.Build()
	spec.SetInterfaceName(ifname)
	if cfg == nil {
		return spec
	}

	iface := cfg.Interface
	spec.SetListenPort(uint32(iface.ListenPort))
	spec.SetMtu(uint32(iface.MTU))
	spec.SetMtuDiscovery(iface.MTUDiscovery)
	spec.SetMinCarrierPayload(uint32(iface.MinCarrierPayload))
	spec.SetMaxCarrierPayload(uint32(iface.MaxCarrierPayload))
	spec.SetReassemblySlots(uint32(iface.ReassemblySlots))
	spec.SetPeerReassemblySlots(autoCountToUint32(iface.PeerReassemblySlots))
	spec.SetReassemblyLifetimeMs(uint32(iface.ReassemblyLifetime / time.Millisecond))
	spec.SetReorder(iface.Reorder)
	spec.SetReorderMaxDelayMs(uint32(iface.ReorderMaxDelay / time.Millisecond))
	spec.SetWorkers(autoCountToUint32(iface.Workers))
	spec.SetTunQueues(autoCountToUint32(iface.TUNQueues))
	spec.SetSocketBuffer(uint32(iface.SocketBuffer))
	spec.SetUdpBatchSize(uint32(iface.UDPBatchSize))
	spec.SetFwMark(iface.FwMark)

	peerSpecs := make([]*controlapiv1.PeerSpec, 0, len(cfg.Peers))
	for i := range cfg.Peers {
		peer := cfg.Peers[i]
		peerSpec := controlapiv1.PeerSpec_builder{}.Build()
		peerSpec.SetPublicKey(base64.StdEncoding.EncodeToString(peer.PublicKey[:]))
		peerSpec.SetEndpoint(peer.Endpoint)
		allowedIPs := make([]string, len(peer.AllowedIPs))
		for j, prefix := range peer.AllowedIPs {
			allowedIPs[j] = prefix.String()
		}
		peerSpec.SetAllowedIps(allowedIPs)
		peerSpec.SetPersistentKeepaliveSec(uint32(peer.PersistentKeepalive))
		if peer.MetricsID != "" {
			peerSpec.SetMetricsId(peer.MetricsID)
		}
		if includeSecrets {
			if peer.PresharedKey == nil {
				peerSpec.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
			} else {
				peerSpec.SetPresharedKey(append([]byte(nil), peer.PresharedKey[:]...))
				peerSpec.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_SET)
			}
		} else {
			peerSpec.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_PRESERVE)
		}
		peerSpecs = append(peerSpecs, peerSpec)
	}
	spec.SetPeers(peerSpecs)
	return spec
}

func autoCountToUint32(value config.AutoCount) uint32 {
	if value.Auto {
		return 0
	}
	return uint32(value.Count)
}

func autoCountFromUint32(value uint32) config.AutoCount {
	if value == 0 {
		return config.AutoCount{Auto: true}
	}
	return config.AutoCount{Count: int(value)}
}

func uint32ToInt(value uint32, name string) (int, error) {
	if uint64(value) > uint64(maxInt()) {
		return 0, fmt.Errorf("%s %d exceeds the platform integer range", name, value)
	}
	return int(value), nil
}

func maxInt() int { return int(^uint(0) >> 1) }

func peerKeyFromString(value string) config.Key {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(config.Key{}) {
		return config.Key{}
	}
	var key config.Key
	copy(key[:], decoded)
	return key
}
