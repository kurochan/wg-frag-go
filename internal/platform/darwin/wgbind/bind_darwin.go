//go:build darwin

package wgbind

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/kurochan/wg-frag-go/internal/transport"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const maxRandomPortRetries = 100

var (
	_ conn.Bind     = (*Bind)(nil)
	_ conn.Endpoint = (*Endpoint)(nil)
)

// Bind is a WireGuard UDP bind for macOS. It rejects packets that would
// require outer IP fragmentation before they reach the network.
type Bind struct {
	mu sync.Mutex

	ipv4 *net.UDPConn
	ipv6 *net.UDPConn
	open bool

	socketBuffer int
	ipv4Buffer   int
	ipv6Buffer   int
	pathHandler  func(transport.PathEvent)
}

// Endpoint is a numeric UDP destination understood by Bind.
type Endpoint struct {
	addr netip.AddrPort
}

// New returns a closed macOS Bind.
func New() *Bind { return &Bind{} }

// SetSocketBuffer requests a buffer for each subsequently opened UDP socket.
func (b *Bind) SetSocketBuffer(bytes int) {
	b.mu.Lock()
	b.socketBuffer = bytes
	b.mu.Unlock()
}

// SocketBufferStatus reports the requested and achieved receive sizes.
func (b *Bind) SocketBufferStatus() (requested, ipv4, ipv6 int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.socketBuffer, b.ipv4Buffer, b.ipv6Buffer
}

// SocketDrops reports zero because macOS does not expose Linux's SO_MEMINFO
// per-socket drop counter.
func (*Bind) SocketDrops() (ipv4, ipv6 uint64) { return 0, 0 }

// SetPathEventHandler installs a callback for transport observations. The
// callback runs outside Bind's mutex.
func (b *Bind) SetPathEventHandler(handler func(transport.PathEvent)) {
	b.mu.Lock()
	b.pathHandler = handler
	b.mu.Unlock()
}

func (b *Bind) notifyPathEvent(event transport.PathEvent) {
	b.mu.Lock()
	handler := b.pathHandler
	b.mu.Unlock()
	if handler != nil {
		handler(event)
	}
}

func configureNoFragment(fd uintptr, family int) error {
	switch family {
	case unix.AF_INET:
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
	case unix.AF_INET6:
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	default:
		return syscall.EAFNOSUPPORT
	}
}

func (b *Bind) listen(network string, port, family int) (*net.UDPConn, uint16, error) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) { optionErr = configureNoFragment(fd, family) }); err != nil {
			return err
		}
		return optionErr
	}}
	packetConn, err := lc.ListenPacket(context.Background(), network, net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return nil, 0, err
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, 0, fmt.Errorf("wgbind: unexpected packet connection type %T", packetConn)
	}
	local, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = udpConn.Close()
		return nil, 0, fmt.Errorf("wgbind: unexpected local address type %T", udpConn.LocalAddr())
	}
	return udpConn, uint16(local.Port), nil
}

// Open binds IPv4 and IPv6 sockets to the same port.
func (b *Bind) Open(requestedPort uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	for attempt := 0; ; attempt++ {
		port := requestedPort
		v4, selectedPort, err4 := b.listen("udp4", int(port), unix.AF_INET)
		if err4 == nil {
			port = selectedPort
		} else if !errors.Is(err4, syscall.EAFNOSUPPORT) {
			return nil, 0, err4
		}
		v6, selectedPort, err6 := b.listen("udp6", int(port), unix.AF_INET6)
		if err6 == nil {
			port = selectedPort
		} else if requestedPort == 0 && v4 != nil && errors.Is(err6, syscall.EADDRINUSE) && attempt < maxRandomPortRetries {
			_ = v4.Close()
			continue
		} else if !errors.Is(err6, syscall.EAFNOSUPPORT) {
			if v4 != nil {
				_ = v4.Close()
			}
			return nil, 0, err6
		}
		if v4 == nil && v6 == nil {
			return nil, 0, syscall.EAFNOSUPPORT
		}
		b.ipv4, b.ipv6 = v4, v6
		b.ipv4Buffer = applySocketBuffer(v4, b.socketBuffer)
		b.ipv6Buffer = applySocketBuffer(v6, b.socketBuffer)
		b.open = true

		receivers := make([]conn.ReceiveFunc, 0, 2)
		if v4 != nil {
			receivers = append(receivers, receive(v4))
		}
		if v6 != nil {
			receivers = append(receivers, receive(v6))
		}
		return receivers, port, nil
	}
}

func applySocketBuffer(socket *net.UDPConn, size int) int {
	if socket == nil || size <= 0 {
		return 0
	}
	_ = socket.SetReadBuffer(size)
	_ = socket.SetWriteBuffer(size)
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0
	}
	achieved := 0
	_ = raw.Control(func(fd uintptr) {
		achieved, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	})
	return achieved
}

func receive(socket *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) < 1 || len(endpoints) < 1 {
			return 0, io.ErrShortBuffer
		}
		size, remote, err := socket.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		sizes[0] = size
		endpoints[0] = &Endpoint{addr: remote}
		return 1, nil
	}
}

// Close closes both sockets and unblocks all receive functions returned by
// Open. It is safe to call Close more than once.
func (b *Bind) Close() error {
	b.mu.Lock()
	v4, v6 := b.ipv4, b.ipv6
	b.ipv4, b.ipv6 = nil, nil
	b.ipv4Buffer, b.ipv6Buffer = 0, 0
	b.open = false
	b.mu.Unlock()
	return errors.Join(closeUDP(v4), closeUDP(v6))
}

func closeUDP(socket *net.UDPConn) error {
	if socket == nil {
		return nil
	}
	return socket.Close()
}

// SetMark is unsupported on macOS because its sockets have no SO_MARK
// equivalent. Route management is intentionally outside the v1 macOS scope.
func (*Bind) SetMark(uint32) error { return nil }

// Send writes each datagram sequentially. macOS does not provide the Linux
// sendmmsg/GSO path used by the Linux transport.
func (b *Bind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	destination, ok := endpoint.(*Endpoint)
	if !ok || destination == nil || !destination.addr.IsValid() {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	socket := b.ipv6
	family := transport.OuterFamilyIPv6
	open := b.open
	if destination.addr.Addr().Is4() {
		socket = b.ipv4
		family = transport.OuterFamilyIPv4
	}
	b.mu.Unlock()
	if !open {
		return net.ErrClosed
	}
	if socket == nil {
		return syscall.EAFNOSUPPORT
	}
	for _, packet := range packets {
		if _, err := socket.WriteToUDPAddrPort(packet, destination.addr); err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				b.notifyPathEvent(transport.PathEvent{
					Kind:              transport.PathEventMessageTooLarge,
					Err:               err,
					Family:            family,
					DatagramSize:      len(packet),
					DatagramSizeKnown: true,
					Endpoint:          destination.addr,
					EndpointKnown:     true,
				})
				continue
			}
			return err
		}
	}
	return nil
}

// ParseEndpoint accepts numeric endpoints and resolves hostnames once when
// WireGuard applies the peer configuration.
func (*Bind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err == nil {
		if address.Addr().Is4In6() {
			return nil, errors.New("wgbind: IPv4-mapped endpoint is unsupported")
		}
		return &Endpoint{addr: address}, nil
	}
	resolved, err := net.ResolveUDPAddr("udp", value)
	if err != nil || resolved == nil {
		return nil, err
	}
	address = netip.AddrPortFrom(resolved.AddrPort().Addr().Unmap(), uint16(resolved.Port))
	if !address.IsValid() || address.Addr().Is4In6() {
		return nil, errors.New("wgbind: resolved endpoint is invalid")
	}
	return &Endpoint{addr: address}, nil
}

func (*Bind) BatchSize() int            { return 1 }
func (*Endpoint) ClearSrc()             {}
func (*Endpoint) SrcToString() string   { return "" }
func (e *Endpoint) DstToString() string { return e.addr.String() }

func (e *Endpoint) DstToBytes() []byte {
	encoded, _ := e.addr.MarshalBinary()
	return encoded
}

func (e *Endpoint) DstIP() netip.Addr { return e.addr.Addr() }
func (*Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
