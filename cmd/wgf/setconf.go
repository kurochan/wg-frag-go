package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/kurochan/wg-frag-go/controlapi"
	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/protobuf/proto"
)

// applier is injected by tests; the default submits to the daemon socket.
type applier func(
	ctx context.Context,
	socketPath string,
	request *controlapiv1.ApplyPeersRequest,
) (*controlapiv1.ApplyPeersResponse, error)

// confMode distinguishes the three wg(8)-style file commands, which differ
// only in how the file's peers merge with the running set.
type confMode int

const (
	confSet confMode = iota
	confAdd
	confSync
)

func setconf(mode confMode, args []string, getStatus statusGetter, apply applier, stdout io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: <interface> <file> [--control-socket path]")
	}
	ifname, path := args[0], args[1]
	socket := controlapi.SocketPath(ifname)
	if len(args) > 2 {
		if args[2] != "--control-socket" || len(args) != 4 {
			return fmt.Errorf("unexpected argument %q", args[2])
		}
		socket = args[3]
	}
	cfg, err := config.ParseFile(path)
	if err != nil {
		return err
	}
	ctx := context.Background()
	status, err := getStatus(ctx, socket, ifname)
	if err != nil {
		return fmt.Errorf("is `wgf run %s` running? %w", ifname, err)
	}
	// The daemon cannot change its key at runtime; catch a mismatched file
	// here, where the private key is available for comparison.
	public, err := derivePublicKey([32]byte(cfg.Interface.PrivateKey))
	if err != nil {
		return err
	}
	if encoded := base64.StdEncoding.EncodeToString(public[:]); encoded != status.GetPublicKey() {
		return errors.New("the file's PrivateKey does not match the running interface; restart wgf run instead")
	}
	if !restartSettingsEqual(ifname, status, cfg) {
		return errors.New("the file's interface settings require RestartInterface or a wgf run restart")
	}

	desired := desiredFromConfig(cfg.Peers, mode != confAdd)
	if mode == confAdd {
		desired = mergePeers(desiredFromStatus(status.GetPeers()), desired)
	}
	return submit(ctx, ifname, socket, status.GetRef().GetInterfaceInstanceId(), status.GetGeneration(), desired, apply, stdout)
}

func restartSettingsEqual(ifname string, status *controlapiv1.InterfaceStatus, cfg *config.Config) bool {
	if status == nil || cfg == nil || status.GetSpec() == nil {
		return status != nil && cfg != nil &&
			uint16(status.GetListenPort()) == cfg.Interface.ListenPort && int(status.GetMtu()) == cfg.Interface.MTU
	}
	running := proto.Clone(status.GetSpec()).(*controlapiv1.InterfaceSpec)
	desired := controlconfig.SpecFromConfig(ifname, cfg, false)
	running.SetPeers(nil)
	desired.SetPeers(nil)
	running.ClearPrivateKey()
	desired.ClearPrivateKey()
	return proto.Equal(running, desired)
}

func setCommand(args []string, getStatus statusGetter, apply applier, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(
			"usage: set <interface> [--control-socket path] peer <base64 key> " +
				"[remove] [endpoint addr:port] [allowed-ips cidr[,cidr]] " +
				"[persistent-keepalive seconds] [preshared-key key|none] ...",
		)
	}
	ifname := args[0]
	socket := controlapi.SocketPath(ifname)

	rest := args[1:]
	if len(rest) >= 2 && rest[0] == "--control-socket" {
		socket = rest[1]
		rest = rest[2:]
	}
	ctx := context.Background()
	status, err := getStatus(ctx, socket, ifname)
	if err != nil {
		return fmt.Errorf("is `wgf run %s` running? %w", ifname, err)
	}
	desired := desiredFromStatus(status.GetPeers())
	if desired, err = applyPeerEdits(desired, rest); err != nil {
		return err
	}
	return submit(ctx, ifname, socket, status.GetRef().GetInterfaceInstanceId(), status.GetGeneration(), desired, apply, stdout)
}

// applyPeerEdits mutates the desired peer list with wg(8)-style directives.
func applyPeerEdits(desired []*controlapiv1.PeerSpec, args []string) ([]*controlapiv1.PeerSpec, error) {
	index := func(key string) int {
		for i, peer := range desired {
			if peer.GetPublicKey() == key {
				return i
			}
		}
		return -1
	}

	for len(args) != 0 {
		if args[0] != "peer" || len(args) < 2 {
			return nil, fmt.Errorf("unexpected argument %q", args[0])
		}
		key := args[1]
		args = args[2:]
		at := index(key)
		if at < 0 {
			peer := controlapiv1.PeerSpec_builder{}.Build()
			peer.SetPublicKey(key)
			peer.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
			desired = append(desired, peer)
			at = len(desired) - 1
		}

		for len(args) != 0 && args[0] != "peer" {
			directive := args[0]
			switch directive {
			case "remove":
				desired = append(desired[:at], desired[at+1:]...)
				args = args[1:]
				if len(args) != 0 && args[0] != "peer" {
					return nil, fmt.Errorf("unexpected argument %q after remove", args[0])
				}
				at = -1
			case "endpoint", "allowed-ips", "persistent-keepalive", "preshared-key":
				if len(args) < 2 {
					return nil, fmt.Errorf("%s requires a value", directive)
				}
				value := args[1]
				args = args[2:]

				switch directive {
				case "endpoint":
					desired[at].SetEndpoint(value)
				case "allowed-ips":
					desired[at].SetAllowedIps(strings.Split(value, ","))
				case "persistent-keepalive":
					seconds, err := parseKeepalive(value)
					if err != nil {
						return nil, err
					}
					desired[at].SetPersistentKeepaliveSec(seconds)
				case "preshared-key":
					if value == "none" {
						desired[at].SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
						desired[at].ClearPresharedKey()
					} else if decoded, err := base64.StdEncoding.DecodeString(value); err != nil || len(decoded) != 32 {
						return nil, errors.New("invalid preshared-key: must be base64 encoding of exactly 32 bytes")
					} else {
						desired[at].SetPresharedKey(decoded)
						desired[at].SetPresharedKeyAction(controlapiv1.PresharedKeyAction_SET)
					}
				}
			default:
				return nil, fmt.Errorf("unexpected argument %q", directive)
			}
			if at < 0 {
				break
			}
		}
	}
	return desired, nil
}

func parseKeepalive(value string) (uint32, error) {
	if value == "off" {
		return 0, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid persistent-keepalive %q", value)
	}
	return uint32(seconds), nil
}

func desiredFromConfig(peers []config.Peer, clearMissingPSK bool) []*controlapiv1.PeerSpec {
	desired := make([]*controlapiv1.PeerSpec, len(peers))
	for i, peer := range peers {
		allowed := make([]string, len(peer.AllowedIPs))
		for j, prefix := range peer.AllowedIPs {
			allowed[j] = prefix.String()
		}
		desired[i] = controlapiv1.PeerSpec_builder{}.Build()
		desired[i].SetPublicKey(base64.StdEncoding.EncodeToString(peer.PublicKey[:]))
		desired[i].SetEndpoint(peer.Endpoint)
		desired[i].SetAllowedIps(allowed)
		desired[i].SetPersistentKeepaliveSec(uint32(peer.PersistentKeepalive))
		desired[i].SetMetricsId(peer.MetricsID)
		if peer.PresharedKey != nil {
			desired[i].SetPresharedKey(peer.PresharedKey[:])
			desired[i].SetPresharedKeyAction(controlapiv1.PresharedKeyAction_SET)
		} else if clearMissingPSK {
			desired[i].SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
		}
	}
	return desired
}

func desiredFromStatus(peers []*controlapiv1.PeerStatus) []*controlapiv1.PeerSpec {
	desired := make([]*controlapiv1.PeerSpec, len(peers))
	for i, peer := range peers {
		desired[i] = controlapiv1.PeerSpec_builder{}.Build()
		desired[i].SetPublicKey(peer.GetPublicKey())
		desired[i].SetEndpoint(peer.GetEndpoint())
		desired[i].SetAllowedIps(peer.GetAllowedIps())
		desired[i].SetPersistentKeepaliveSec(peer.GetPersistentKeepaliveSec())
		desired[i].SetMetricsId(peer.GetMetricsId())
		if peer.HasPresharedKey() {
			desired[i].SetPresharedKey(peer.GetPresharedKey())
			desired[i].SetPresharedKeyAction(controlapiv1.PresharedKeyAction_SET)
		}
	}
	return desired
}

// mergePeers overlays additions onto base by public key, as addconf does.
func mergePeers(base, additions []*controlapiv1.PeerSpec) []*controlapiv1.PeerSpec {
	merged := append([]*controlapiv1.PeerSpec(nil), base...)

	for _, addition := range additions {
		replaced := false

		for i, peer := range merged {
			if peer.GetPublicKey() == addition.GetPublicKey() {
				if addition.GetMetricsId() == "" && peer.GetMetricsId() != "" {
					addition.SetMetricsId(peer.GetMetricsId())
				}
				merged[i] = addition
				replaced = true

				break
			}
		}
		if !replaced {
			if addition.GetPresharedKeyAction() == controlapiv1.PresharedKeyAction_PRESERVE {
				addition.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
			}
			merged = append(merged, addition)
		}
	}
	return merged
}

func submit(ctx context.Context, ifname, socket string, instanceID []byte, generation uint64,
	desired []*controlapiv1.PeerSpec, apply applier, stdout io.Writer) error {
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, requestID); err != nil {
		return err
	}
	target := controlapiv1.InterfaceRef_builder{}.Build()
	target.SetInterfaceName(ifname)
	mutation := controlapiv1.MutationContext_builder{}.Build()
	if len(instanceID) != 0 {
		mutation.SetExpectedInstanceId(instanceID)
	}
	mutation.SetExpectedGeneration(generation)
	mutation.SetRequestId(requestID)
	request := controlapiv1.ApplyPeersRequest_builder{Target: target, Mutation: mutation, Peers: desired}.Build()
	response, err := apply(ctx, socket, request)
	if err != nil {
		return err
	}

	failed := 0
	for _, result := range response.GetResults() {
		if result.GetError() != "" {
			failed++

			fmt.Fprintf(stdout, "peer %s: %s\n", result.GetPublicKey(), result.GetError())
		}
	}
	if failed != 0 {
		return fmt.Errorf("%d peer(s) failed and stay disabled", failed)
	}
	fmt.Fprintf(stdout, "applied configuration generation %d\n", response.GetGeneration())
	return nil
}
