package wgadapter

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

var (
	ErrNoPeers       = errors.New("wgadapter: configuration has no peers")
	ErrDuplicatePeer = errors.New("wgadapter: duplicate peer public key")
	ErrPublicKey     = errors.New("wgadapter: cannot derive local public key")
	// ErrInvalidPeer rejects direct configs that bypass parser validation.
	ErrInvalidPeer = errors.New("wgadapter: invalid peer configuration")
)

// PeerPlan is one peer's resolved identity. Carrier is the hidden link-local
// address wireguard-go selects the peer by; the user AllowedIPs stay in the
// wrapper's routing snapshot and never reach wireguard-go.
type PeerPlan struct {
	ID                  peerroute.PeerID
	PublicKey           [32]byte
	PresharedKey        *[32]byte
	PresharedKeyChanged bool
	Carrier             netip.Addr
	AllowedIPs          []netip.Prefix
	Endpoint            string
	PersistentKeepalive uint16
}

// Plan is the validated transformation from a user-facing WGF config to
// wireguard-go's hidden synthetic carrier configuration.
type Plan struct {
	LocalCarrier   netip.Addr
	LocalPublicKey [32]byte
	Peers          []PeerPlan
	Routes         *peerroute.Snapshot
	UAPI           string
}

// PreparePeers resolves every configured peer. Carrier addresses are derived
// from static public keys and checked for collisions across the local key and
// all peers together, because a collision would let one peer's carriers be
// accepted as another's.
func PreparePeers(cfg *config.Config) (Plan, error) {
	if cfg == nil || len(cfg.Peers) == 0 {
		return Plan{}, ErrNoPeers
	}
	localPublic, err := publicKey(cfg.Interface.PrivateKey)
	if err != nil {
		return Plan{}, err
	}

	keys := make([][]byte, 0, len(cfg.Peers)+1)
	keys = append(keys, localPublic[:])

	seen := make(map[[32]byte]struct{}, len(cfg.Peers))
	for index := range cfg.Peers {
		peer := cfg.Peers[index]
		if peer.PublicKey == (config.Key{}) {
			return Plan{}, fmt.Errorf("%w: peer %d has an all-zero public key", ErrInvalidPeer, index)
		}
		if err := validateEndpoint(peer.Endpoint); err != nil {
			return Plan{}, fmt.Errorf("%w: peer %d endpoint: %w", ErrInvalidPeer, index, err)
		}
		if _, duplicate := seen[peer.PublicKey]; duplicate {
			return Plan{}, fmt.Errorf("%w: %x", ErrDuplicatePeer, peer.PublicKey[:4])
		}
		seen[peer.PublicKey] = struct{}{}

		keys = append(keys, cfg.Peers[index].PublicKey[:])
	}
	addresses, err := peerroute.DeriveUniqueCarrierAddresses(keys)
	if err != nil {
		return Plan{}, err
	}

	plan := Plan{
		LocalCarrier:   addresses[0],
		LocalPublicKey: localPublic,
		Peers:          make([]PeerPlan, len(cfg.Peers)),
	}

	allowed := make([]peerroute.AllowedIP, 0, len(cfg.Peers))
	for i, peer := range cfg.Peers {
		id := peerroute.PeerID(i)

		plan.Peers[i] = PeerPlan{
			ID:                  id,
			PublicKey:           peer.PublicKey,
			PresharedKey:        cloneKey(peer.PresharedKey),
			Carrier:             addresses[i+1],
			AllowedIPs:          append([]netip.Prefix(nil), peer.AllowedIPs...),
			Endpoint:            peer.Endpoint,
			PersistentKeepalive: peer.PersistentKeepalive,
		}
		for _, prefix := range peer.AllowedIPs {
			allowed = append(allowed, peerroute.AllowedIP{Prefix: prefix, PeerID: id})
		}
	}
	if plan.Routes, err = peerroute.NewSnapshot(allowed); err != nil {
		return Plan{}, err
	}
	plan.UAPI = renderUAPI(cfg.Interface, plan.Peers)
	return plan, nil
}

// Apply installs a plan on a running wireguard-go Device.
func Apply(device *device.Device, plan Plan) error {
	if device == nil {
		return errors.New("wgadapter: nil wireguard-go device")
	}
	return device.IpcSet(plan.UAPI)
}

// PeerUpdate is the difference between a running plan and a new desired peer
// set. Surviving peers keep their IDs so live sessions and routing snapshots
// stay valid; UAPI touches only peers that actually changed.
type PeerUpdate struct {
	Plan    Plan
	Added   []PeerPlan
	Removed []PeerPlan
	// Survivors are peers present in both configurations, including unchanged
	// ones; the shim swaps their routing snapshot regardless.
	Survivors []PeerPlan
	// Changed contains surviving peers whose wireguard-go endpoint or
	// keepalive changed. User AllowedIPs remain in the shim snapshot and do not
	// require a UAPI write.
	Changed []PeerPlan
	UAPI    string
}

// PreparePeerUpdate resolves a new configuration against the running plan.
// The interface identity (private key, port, MTU) is not diffed here; runtime
// interface changes are rejected by the daemon before this point.
func PreparePeerUpdate(cfg *config.Config, previous Plan) (PeerUpdate, error) {
	plan, err := PreparePeers(cfg)
	if err != nil {
		return PeerUpdate{}, err
	}
	if plan.LocalCarrier != previous.LocalCarrier || plan.LocalPublicKey != previous.LocalPublicKey {
		return PeerUpdate{}, errors.New("wgadapter: local key changed; restart the daemon")
	}

	previousByKey := make(map[[32]byte]PeerPlan, len(previous.Peers))
	usedIDs := make(map[peerroute.PeerID]bool, len(previous.Peers))
	replaceKeys := make(map[[32]byte]bool)
	for _, peer := range previous.Peers {
		previousByKey[peer.PublicKey] = peer
	}

	update := PeerUpdate{Plan: plan}
	// First pass pins survivors to their existing IDs so freed slots are known
	// before new peers claim them.
	for i := range plan.Peers {
		old, survived := previousByKey[plan.Peers[i].PublicKey]
		// wireguard-go has no endpoint-clear UAPI field. Remove and recreate
		// this peer when an endpoint is explicitly cleared.
		if survived && old.Endpoint != "" && plan.Peers[i].Endpoint == "" {
			replaceKeys[plan.Peers[i].PublicKey] = true
			survived = false
		}
		if survived {
			plan.Peers[i].ID = old.ID
			usedIDs[old.ID] = true
		}
	}
	nextFree := peerroute.PeerID(0)
	for i := range plan.Peers {
		old, survived := previousByKey[plan.Peers[i].PublicKey]
		if replaceKeys[plan.Peers[i].PublicKey] {
			survived = false
		}
		if survived {
			plan.Peers[i].PresharedKeyChanged = !sameKey(old.PresharedKey, plan.Peers[i].PresharedKey)
			update.Survivors = append(update.Survivors, plan.Peers[i])
			if old.Endpoint != plan.Peers[i].Endpoint || old.PersistentKeepalive != plan.Peers[i].PersistentKeepalive || plan.Peers[i].PresharedKeyChanged {
				update.Changed = append(update.Changed, plan.Peers[i])
			}

			continue
		}

		for usedIDs[nextFree] {
			nextFree++
		}
		plan.Peers[i].ID = nextFree
		usedIDs[nextFree] = true

		update.Added = append(update.Added, plan.Peers[i])
	}
	newKeys := make(map[[32]byte]bool, len(plan.Peers))
	for _, peer := range plan.Peers {
		newKeys[peer.PublicKey] = true
	}
	for _, peer := range previous.Peers {
		if !newKeys[peer.PublicKey] || replaceKeys[peer.PublicKey] {
			update.Removed = append(update.Removed, peer)
		}
	}

	allowed := make([]peerroute.AllowedIP, 0, len(plan.Peers))

	for _, peer := range plan.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowed = append(allowed, peerroute.AllowedIP{Prefix: prefix, PeerID: peer.ID})
		}
	}
	if plan.Routes, err = peerroute.NewSnapshot(allowed); err != nil {
		return PeerUpdate{}, err
	}
	update.Plan = plan
	update.UAPI = renderUpdateUAPI(update)
	return update, nil
}

// renderUpdateUAPI emits an incremental IpcSet without replace_peers, so
// wireguard-go keeps handshakes and keys for untouched peers.
func renderUpdateUAPI(update PeerUpdate) string {
	var builder strings.Builder
	for _, peer := range update.Removed {
		fmt.Fprintf(&builder, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		builder.WriteString("remove=true\n")
	}
	for _, peer := range update.Added {
		fmt.Fprintf(&builder, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		builder.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&builder, "allowed_ip=%s/128\n", peer.Carrier)
		if peer.Endpoint != "" {
			fmt.Fprintf(&builder, "endpoint=%s\n", peer.Endpoint)
		}
		if peer.PresharedKey != nil {
			writePresharedKey(&builder, peer.PresharedKey)
		}
		fmt.Fprintf(&builder, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}
	for _, peer := range update.Changed {
		// The hidden carrier /128 is unchanged for a surviving key. Touch only
		// endpoint and keepalive so a config-only route update stays cheap.
		fmt.Fprintf(&builder, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		if peer.Endpoint != "" {
			fmt.Fprintf(&builder, "endpoint=%s\n", peer.Endpoint)
		}
		fmt.Fprintf(&builder, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		if peer.PresharedKeyChanged {
			writePresharedKey(&builder, peer.PresharedKey)
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

func publicKey(private config.Key) ([32]byte, error) {
	if private == (config.Key{}) {
		return [32]byte{}, fmt.Errorf("%w: private key is all zero", ErrPublicKey)
	}

	var base [32]byte
	base[0] = 9
	value, err := curve25519.X25519(private[:], base[:])
	if err != nil || len(value) != 32 {
		return [32]byte{}, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}

	var public [32]byte
	copy(public[:], value)
	return public, nil
}

// validateEndpoint prevents UAPI line injection when callers bypass the
// configuration parser.
func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	if strings.IndexFunc(endpoint, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return errors.New("contains whitespace or a control character")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return errors.New("must be host:port or [IPv6]:port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("port must be in 1..65535")
	}
	return nil
}

func renderUAPI(iface config.Interface, peers []PeerPlan) string {
	var builder strings.Builder

	fmt.Fprintf(&builder, "private_key=%s\n", hex.EncodeToString(iface.PrivateKey[:]))
	fmt.Fprintf(&builder, "listen_port=%d\n", iface.ListenPort)
	builder.WriteString("replace_peers=true\n")

	for _, peer := range peers {
		fmt.Fprintf(&builder, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		builder.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&builder, "allowed_ip=%s/128\n", peer.Carrier)
		if peer.Endpoint != "" {
			fmt.Fprintf(&builder, "endpoint=%s\n", peer.Endpoint)
		}
		if peer.PresharedKey != nil {
			writePresharedKey(&builder, peer.PresharedKey)
		}
		fmt.Fprintf(&builder, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}
	builder.WriteString("\n")
	return builder.String()
}

func cloneKey(key *config.Key) *[32]byte {
	if key == nil {
		return nil
	}
	value := [32]byte(*key)
	return &value
}

func sameKey(left, right *[32]byte) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func writePresharedKey(builder *strings.Builder, key *[32]byte) {
	var value [32]byte
	if key != nil {
		value = *key
	}
	fmt.Fprintf(builder, "preshared_key=%s\n", hex.EncodeToString(value[:]))
}
