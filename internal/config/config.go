package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config/syntax"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

const (
	// DefaultReassemblySlots is the default number of in-flight packet slots.
	DefaultReassemblySlots = 4096
	// DefaultSocketBuffer is requested for each outer UDP send/receive buffer.
	// 3 MiB measures on par with wireguard-go's own 7 MiB bind default at less
	// than half the memory; WGFSocketBuffer can tune it per deployment.
	DefaultSocketBuffer = 3 << 20
	// MinSocketBuffer and MaxSocketBuffer bound WGFSocketBuffer.
	MinSocketBuffer = 64 << 10
	MaxSocketBuffer = 256 << 20
	// DefaultMaxCarrierPayload is the conservative ceiling for an IPv4 outer path.
	DefaultMaxCarrierPayload = 65432
	// MaxCarrierPayload is the protocol ceiling for an IPv6 outer path.
	MaxCarrierPayload = 65448
)

const (
	defaultReassemblyLifetime = 2 * time.Second
	defaultReorderMaxDelay    = 10 * time.Millisecond
	minReassemblyLifetime     = 100 * time.Millisecond
	maxReassemblyLifetime     = 60 * time.Second
)

// ErrInvalidConfig reports a structurally invalid runtime configuration.
var ErrInvalidConfig = errors.New("config: invalid configuration")

// Key is a decoded WireGuard private or public key.
type Key [32]byte

// AutoCount represents either the literal "auto" or a positive count.
type AutoCount struct {
	Auto  bool
	Count int
}

// Interface contains [Interface] settings.
type Interface struct {
	Addresses         []netip.Prefix
	PrivateKey        Key
	ListenPort        uint16
	MTU               int
	MTUDiscovery      string
	MinCarrierPayload int
	MaxCarrierPayload int
	// ReassemblySlots is the per-peer slot count when PeerReassemblySlots is auto.
	ReassemblySlots int
	// PeerReassemblySlots overrides ReassemblySlots for each peer when explicit.
	PeerReassemblySlots AutoCount
	ReassemblyLifetime  time.Duration
	Reorder             bool
	ReorderMaxDelay     time.Duration
	Workers             AutoCount
	TUNQueues           AutoCount
	SocketBuffer        int
	// FwMark is applied as SO_MARK to the outer UDP sockets; zero disables it.
	// wgf quick relies on it for policy-routing loop avoidance.
	FwMark uint32
}

// Peer contains one [Peer] section.
type Peer struct {
	PublicKey           Key
	PresharedKey        *Key
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
}

// Config is a validated v1 configuration.
type Config struct {
	Interface Interface
	Peers     []Peer
}

type section uint8

const (
	sectionNone section = iota
	sectionInterface
	sectionPeer
)

const (
	interfacePrivateKey uint16 = 1 << iota
	interfaceListenPort
	interfaceMTU
	interfaceMTUDiscovery
	interfaceMinCarrierPayload
	interfaceMaxCarrierPayload
	interfaceReassemblySlots
	interfacePeerReassemblySlots
	interfaceReassemblyLifetime
	interfaceReorder
	interfaceReorderMaxDelay
	interfaceWorkers
	interfaceTUNQueues
	interfaceSocketBuffer
	interfaceFwMark
)

const (
	peerPublicKey uint8 = 1 << iota
	peerEndpoint
	peerPersistentKeepalive
	peerPresharedKey
)

type parser struct {
	config          Config
	section         section
	interfaceSeen   bool
	interfaceFields uint16
	peerFields      []uint8
}

// NewPeer validates one runtime-supplied peer definition with the same rules
// as the file parser, so ApplyConfig cannot admit a peer Parse would reject.
func NewPeer(publicKey, endpoint string, allowedIPs []string, keepaliveSeconds uint32) (Peer, error) {
	return NewPeerWithPresharedKey(publicKey, endpoint, allowedIPs, keepaliveSeconds, "")
}

// NewPeerWithPresharedKey validates a runtime-supplied peer definition,
// including an optional base64-encoded 32-byte preshared key.
func NewPeerWithPresharedKey(publicKey, endpoint string, allowedIPs []string, keepaliveSeconds uint32, presharedKey string) (Peer, error) {
	if presharedKey == "" {
		return NewPeerWithPresharedKeyBytes(publicKey, endpoint, allowedIPs, keepaliveSeconds, nil)
	}
	decoded, err := base64.StdEncoding.DecodeString(presharedKey)
	if err != nil {
		return Peer{}, fmt.Errorf("PresharedKey: %w", err)
	}
	return NewPeerWithPresharedKeyBytes(publicKey, endpoint, allowedIPs, keepaliveSeconds, decoded)
}

// NewPeerWithPresharedKeyBytes validates a runtime-supplied peer definition
// with an optional raw 32-byte preshared key.
func NewPeerWithPresharedKeyBytes(publicKey, endpoint string, allowedIPs []string, keepaliveSeconds uint32, presharedKey []byte) (Peer, error) {
	peer := Peer{}
	key, err := parseKey(publicKey)
	if err != nil {
		return Peer{}, fmt.Errorf("PublicKey: %w", err)
	}
	peer.PublicKey = key

	if endpoint != "" {
		if err := validateEndpoint(endpoint); err != nil {
			return Peer{}, fmt.Errorf("Endpoint: %w", err)
		}
		peer.Endpoint = endpoint
	}

	for _, value := range allowedIPs {
		prefixes, err := parsePrefixes(value, true)
		if err != nil {
			return Peer{}, fmt.Errorf("AllowedIPs: %w", err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
	}
	if keepaliveSeconds > 65535 {
		return Peer{}, errors.New("PersistentKeepalive: must be in 0..65535")
	}
	peer.PersistentKeepalive = uint16(keepaliveSeconds)
	if len(presharedKey) != 0 {
		if len(presharedKey) != 32 {
			return Peer{}, errors.New("PresharedKey: must contain exactly 32 bytes")
		}
		var key Key
		copy(key[:], presharedKey)
		peer.PresharedKey = &key
	}

	return peer, nil
}

// Parse reads and validates a v1 INI configuration.
func Parse(reader io.Reader) (*Config, error) {
	p := parser{config: defaultConfig()}
	err := syntax.Scan(reader, func(source syntax.Line) error {
		lineNumber := source.Number
		line := source.Text
		if line == "" {
			return nil
		}
		if source.IsSection {
			if err := p.parseSection(line); err != nil {
				return lineError(lineNumber, err)
			}
			return nil
		}
		if !source.IsField {
			return lineError(lineNumber, errors.New("expected key = value"))
		}
		key, value := source.Key, source.Value
		if key == "" || value == "" {
			return lineError(lineNumber, errors.New("empty key or value"))
		}

		if err := p.parseField(key, value); err != nil {
			return lineError(lineNumber, err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidConfig) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: read: %w", ErrInvalidConfig, err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return &p.config, nil
}

// ParseFile opens and parses path.
func ParseFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return Parse(file)
}

func defaultConfig() Config {
	return Config{Interface: Interface{
		MTU:                 limits.DefaultInnerMTU,
		MTUDiscovery:        "auto",
		MinCarrierPayload:   limits.DefaultCarrierPayload,
		MaxCarrierPayload:   DefaultMaxCarrierPayload,
		ReassemblySlots:     DefaultReassemblySlots,
		PeerReassemblySlots: AutoCount{Auto: true},
		ReassemblyLifetime:  defaultReassemblyLifetime,
		Reorder:             true,
		ReorderMaxDelay:     defaultReorderMaxDelay,
		Workers:             AutoCount{Auto: true},
		TUNQueues:           AutoCount{Auto: true},
		SocketBuffer:        DefaultSocketBuffer,
	}}
}

func (p *parser) parseSection(line string) error {
	if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
		return errors.New("malformed section")
	}
	name := strings.TrimSpace(line[1 : len(line)-1])
	switch name {
	case "Interface":
		if p.interfaceSeen || len(p.config.Peers) != 0 {
			return errors.New("duplicate or misplaced [Interface] section")
		}

		p.interfaceSeen = true
		p.section = sectionInterface
	case "Peer":
		if !p.interfaceSeen {
			return errors.New("[Peer] precedes [Interface]")
		}
		p.config.Peers = append(p.config.Peers, Peer{})
		p.peerFields = append(p.peerFields, 0)
		p.section = sectionPeer
	default:
		return fmt.Errorf("unknown section %q", name)
	}
	return nil
}

func (p *parser) parseField(key, value string) error {
	switch p.section {
	case sectionInterface:
		return p.parseInterfaceField(key, value)
	case sectionPeer:
		return p.parsePeerField(key, value)
	default:
		return errors.New("field appears before a section")
	}
}

func (p *parser) parseInterfaceField(name, value string) error {
	field, repeated := uint16(0), false

	switch name {
	case "Address":
		repeated = true
		prefixes, err := parsePrefixes(value, false)
		if err != nil {
			return fmt.Errorf("Address: %w", err)
		}
		p.config.Interface.Addresses = append(p.config.Interface.Addresses, prefixes...)
	case "PrivateKey":
		field = interfacePrivateKey
		key, err := parseKey(value)
		if err != nil {
			return fmt.Errorf("PrivateKey: %w", err)
		}
		p.config.Interface.PrivateKey = key
	case "ListenPort":
		field = interfaceListenPort
		port, err := parseUint16(value)
		if err != nil {
			return fmt.Errorf("ListenPort: %w", err)
		}
		p.config.Interface.ListenPort = port
	case "MTU":
		field = interfaceMTU
		count, err := parsePositiveInt(value)
		if err != nil {
			return fmt.Errorf("MTU: %w", err)
		}
		p.config.Interface.MTU = count
	case "WGFMTUDiscovery":
		field = interfaceMTUDiscovery

		if value != "auto" {
			return errors.New("WGFMTUDiscovery: v1 only supports auto")
		}
		p.config.Interface.MTUDiscovery = value
	case "WGFMinCarrierPayload":
		field = interfaceMinCarrierPayload
		count, err := parsePositiveInt(value)
		if err != nil {
			return fmt.Errorf("WGFMinCarrierPayload: %w", err)
		}
		p.config.Interface.MinCarrierPayload = count
	case "WGFMaxCarrierPayload":
		field = interfaceMaxCarrierPayload
		count, err := parsePositiveInt(value)
		if err != nil {
			return fmt.Errorf("WGFMaxCarrierPayload: %w", err)
		}
		p.config.Interface.MaxCarrierPayload = count
	case "FwMark":
		field = interfaceFwMark
		mark, err := parseFwMark(value)
		if err != nil {
			return fmt.Errorf("FwMark: %w", err)
		}
		p.config.Interface.FwMark = mark
	case "WGFSocketBuffer":
		field = interfaceSocketBuffer

		count, err := parsePositiveInt(value)
		if err != nil {
			return fmt.Errorf("WGFSocketBuffer: %w", err)
		}
		if count < MinSocketBuffer || count > MaxSocketBuffer {
			return fmt.Errorf("WGFSocketBuffer: %d is outside %d..%d bytes", count, MinSocketBuffer, MaxSocketBuffer)
		}
		p.config.Interface.SocketBuffer = count
	case "WGFReassemblySlots":
		field = interfaceReassemblySlots
		count, err := parsePositiveInt(value)
		if err != nil {
			return fmt.Errorf("WGFReassemblySlots: %w", err)
		}
		p.config.Interface.ReassemblySlots = count
	case "WGFPeerReassemblySlots":
		field = interfacePeerReassemblySlots
		count, err := parseAutoCount(value)
		if err != nil {
			return fmt.Errorf("WGFPeerReassemblySlots: %w", err)
		}
		p.config.Interface.PeerReassemblySlots = count
	case "WGFReassemblyLifetime":
		field = interfaceReassemblyLifetime

		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("WGFReassemblyLifetime: %w", err)
		}
		p.config.Interface.ReassemblyLifetime = duration
	case "WGFReorder":
		field = interfaceReorder
		boolean, err := parseBool(value)
		if err != nil {
			return fmt.Errorf("WGFReorder: %w", err)
		}
		p.config.Interface.Reorder = boolean
	case "WGFReorderMaxDelay":
		field = interfaceReorderMaxDelay
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("WGFReorderMaxDelay: %w", err)
		}
		p.config.Interface.ReorderMaxDelay = duration
	case "WGFWorkers":
		field = interfaceWorkers
		count, err := parseAutoCount(value)
		if err != nil {
			return fmt.Errorf("WGFWorkers: %w", err)
		}
		p.config.Interface.Workers = count
	case "WGFTUNQueues":
		field = interfaceTUNQueues
		count, err := parseAutoCount(value)
		if err != nil {
			return fmt.Errorf("WGFTUNQueues: %w", err)
		}
		p.config.Interface.TUNQueues = count
	default:
		return fmt.Errorf("unknown [Interface] field %q", name)
	}
	if !repeated {
		if p.interfaceFields&field != 0 {
			return fmt.Errorf("duplicate [Interface] field %q", name)
		}
		p.interfaceFields |= field
	}
	return nil
}

func (p *parser) parsePeerField(name, value string) error {
	index := len(p.config.Peers) - 1
	peer := &p.config.Peers[index]
	field, repeated := uint8(0), false

	switch name {
	case "PublicKey":
		field = peerPublicKey
		key, err := parseKey(value)
		if err != nil {
			return fmt.Errorf("PublicKey: %w", err)
		}
		peer.PublicKey = key
	case "Endpoint":
		field = peerEndpoint

		if err := validateEndpoint(value); err != nil {
			return fmt.Errorf("Endpoint: %w", err)
		}
		peer.Endpoint = value
	case "PresharedKey":
		field = peerPresharedKey
		key, err := parsePresharedKey(value)
		if err != nil {
			return fmt.Errorf("PresharedKey: %w", err)
		}
		peer.PresharedKey = &key
	case "AllowedIPs":
		repeated = true
		prefixes, err := parsePrefixes(value, true)
		if err != nil {
			return fmt.Errorf("AllowedIPs: %w", err)
		}

		peer.AllowedIPs = append(peer.AllowedIPs, prefixes...)
	case "PersistentKeepalive":
		field = peerPersistentKeepalive

		if value == "off" {
			peer.PersistentKeepalive = 0
		} else {
			seconds, err := parseUint16(value)
			if err != nil {
				return fmt.Errorf("PersistentKeepalive: %w", err)
			}
			peer.PersistentKeepalive = seconds
		}
	default:
		return fmt.Errorf("unknown [Peer] field %q", name)
	}
	if !repeated {
		if p.peerFields[index]&field != 0 {
			return fmt.Errorf("duplicate [Peer] field %q", name)
		}
		p.peerFields[index] |= field
	}
	return nil
}

func (p *parser) validate() error {
	if !p.interfaceSeen {
		return errors.New("missing [Interface] section")
	}
	if p.interfaceFields&interfacePrivateKey == 0 {
		return errors.New("missing [Interface] PrivateKey")
	}
	iface := &p.config.Interface
	if err := limits.ValidateInnerMTU(iface.MTU); err != nil {
		return err
	}
	if err := limits.ValidateMinCarrierPayload(iface.MTU, iface.MinCarrierPayload); err != nil {
		return err
	}
	if iface.MaxCarrierPayload < iface.MinCarrierPayload || iface.MaxCarrierPayload > MaxCarrierPayload {
		return fmt.Errorf("WGFMaxCarrierPayload must be in %d..%d", iface.MinCarrierPayload, MaxCarrierPayload)
	}
	if iface.ReassemblySlots <= 0 || iface.ReassemblySlots > int(^uint(0)>>1)/iface.MTU {
		return errors.New("WGFReassemblySlots produces an invalid storage size")
	}
	if !iface.PeerReassemblySlots.Auto && iface.PeerReassemblySlots.Count <= 0 {
		return errors.New("WGFPeerReassemblySlots must be positive or auto")
	}
	if !iface.PeerReassemblySlots.Auto && iface.PeerReassemblySlots.Count > iface.ReassemblySlots {
		return errors.New("WGFPeerReassemblySlots exceeds WGFReassemblySlots")
	}
	if !iface.Workers.Auto && iface.Workers.Count <= 0 {
		return errors.New("WGFWorkers must be positive or auto")
	}
	if !iface.TUNQueues.Auto && iface.TUNQueues.Count <= 0 {
		return errors.New("WGFTUNQueues must be positive or auto")
	}
	if iface.ReassemblyLifetime < minReassemblyLifetime || iface.ReassemblyLifetime > maxReassemblyLifetime {
		return fmt.Errorf("WGFReassemblyLifetime must be in %s..%s", minReassemblyLifetime, maxReassemblyLifetime)
	}
	if iface.ReorderMaxDelay <= 0 {
		return errors.New("WGFReorderMaxDelay must be positive")
	}

	seenKeys := make(map[Key]struct{}, len(p.config.Peers))
	for i := range p.config.Peers {
		if p.peerFields[i]&peerPublicKey == 0 {
			return fmt.Errorf("peer %d is missing PublicKey", i+1)
		}
		key := p.config.Peers[i].PublicKey
		if _, exists := seenKeys[key]; exists {
			return fmt.Errorf("peer %d duplicates PublicKey", i+1)
		}
		seenKeys[key] = struct{}{}
	}
	return nil
}

func parseKey(value string) (Key, error) {
	var key Key
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(key) {
		return Key{}, errors.New("must be base64 encoding of exactly 32 bytes")
	}

	copy(key[:], decoded)
	if key == (Key{}) {
		return Key{}, errors.New("all-zero key is not allowed")
	}
	return key, nil
}

func parsePresharedKey(value string) (Key, error) {
	var key Key
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(key) {
		return Key{}, errors.New("must be base64 encoding of exactly 32 bytes")
	}

	copy(key[:], decoded)
	return key, nil
}

func parsePrefixes(value string, mask bool) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")

	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("empty CIDR")
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", part)
		}

		if prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("IPv4-mapped IPv6 CIDR %q is not allowed", part)
		}
		if mask {
			prefix = prefix.Masked()
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func validateEndpoint(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("must be host:port or [IPv6]:port")
	}

	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("port must be in 1..65535")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4In6() {
			return errors.New("IPv4-mapped IPv6 endpoint is not allowed")
		}
		return nil
	}
	if !validHostname(host) {
		return errors.New("host is not a valid IP address or DNS name")
	}
	return nil
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
				(char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func parseUint16(value string) (uint16, error) {
	number, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, errors.New("must be an integer in 0..65535")
	}
	return uint16(number), nil
}

// parseFwMark accepts wg(8) syntax: decimal, 0x-prefixed hex, or "off".
func parseFwMark(value string) (uint32, error) {
	if value == "off" {
		return 0, nil
	}
	mark, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return 0, errors.New("must be a 32-bit integer or off")
	}
	return uint32(mark), nil
}

func parsePositiveInt(value string) (int, error) {
	number, err := strconv.ParseUint(value, 10, strconv.IntSize)
	maxInt := uint64(^uint(0) >> 1)
	if err != nil || number == 0 || number > maxInt {
		return 0, errors.New("must be a positive integer")
	}
	return int(number), nil
}

func parseAutoCount(value string) (AutoCount, error) {
	if value == "auto" {
		return AutoCount{Auto: true}, nil
	}
	count, err := parsePositiveInt(value)
	if err != nil {
		return AutoCount{}, err
	}
	return AutoCount{Count: count}, nil
}

func parseBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("must be true or false")
	}
}

func lineError(line int, err error) error {
	return fmt.Errorf("%w: line %d: %w", ErrInvalidConfig, line, err)
}
