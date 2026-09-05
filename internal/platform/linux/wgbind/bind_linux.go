//go:build linux

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
	"time"
	"unsafe"

	"github.com/kurochan/wg-frag-go/internal/transport"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	// maxErrorQueueDrainsPerBurst bounds busy work while a socket error queue is
	// repeatedly reported. The receive path keeps ownership of recovery and
	// never exposes queued errors to wireguard-go.
	maxErrorQueueDrainsPerBurst = 8
	errorQueueRetryDelay        = time.Millisecond
	maxRandomPortRetries        = 100
	udpSegmentMaxDatagrams      = 64
	maxIPv4PayloadLen           = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen           = 1<<16 - 1 - 8
	gsoDataSize                 = 2
)

var gsoControlSize = unix.CmsgSpace(gsoDataSize)

var (
	_ conn.Bind     = (*Bind)(nil)
	_ conn.Endpoint = (*Endpoint)(nil)
)

var errBatchSizeFrozen = errors.New("wgbind: batch size cannot change after bind use")

// PathEventKind is the transport-neutral event classification. It is aliased
// here to retain the Linux Bind API while its definition belongs at the
// adapter boundary.
type PathEventKind = transport.PathEventKind

const (
	PathEventUnknown         = transport.PathEventUnknown
	PathEventMessageTooLarge = transport.PathEventMessageTooLarge
)

// OuterFamily is the transport-neutral outer address family.
type OuterFamily = transport.OuterFamily

const (
	OuterFamilyUnknown = transport.OuterFamilyUnknown
	OuterFamilyIPv4    = transport.OuterFamilyIPv4
	OuterFamilyIPv6    = transport.OuterFamilyIPv6
)

// PathEvent is the transport-neutral path event emitted by Bind.
type PathEvent = transport.PathEvent

// Bind is a wireguard-go UDP bind which prohibits outer IP fragmentation.
// It is supplied to device.NewDevice through internal/wgadapter; wireguard-go
// itself does not need to be forked.
type Bind struct {
	mu sync.Mutex

	ipv4             *net.UDPConn
	ipv6             *net.UDPConn
	ipv4PC           *ipv4.PacketConn
	ipv6PC           *ipv6.PacketConn
	ipv4TxOffload    bool
	ipv4RxOffload    bool
	ipv6TxOffload    bool
	ipv6RxOffload    bool
	open             bool
	pathEventHandler func(PathEvent)
	sendErrorHandler func(err error, udpPayloadSize int)
	socketBuffer     int
	batchSize        int
	batchFrozen      bool
	fwmark           uint32
	ipv4Buffer       int
	ipv6Buffer       int

	msgsPool sync.Pool

	configureSocket func(fd uintptr, family int) error
}

// Endpoint is a numeric UDP destination understood by Bind.
//
// This first Linux implementation deliberately does not implement WireGuard's
// sticky-source optimization. Linux routing chooses the source address for
// each send. ClearSrc therefore is a no-op and SrcIP is invalid.
type Endpoint struct {
	addr    netip.AddrPort
	ip      [16]byte
	udpAddr net.UDPAddr
}

func newEndpoint(addr netip.AddrPort) *Endpoint {
	endpoint := &Endpoint{addr: addr}
	if addr.Addr().Is4() {
		bits := addr.Addr().As4()
		copy(endpoint.ip[:4], bits[:])
		endpoint.udpAddr.IP = endpoint.ip[:4]
	} else {
		bits := addr.Addr().As16()
		copy(endpoint.ip[:], bits[:])
		endpoint.udpAddr.IP = endpoint.ip[:]
	}
	endpoint.udpAddr.Port = int(addr.Port())
	endpoint.udpAddr.Zone = addr.Addr().Zone()
	return endpoint
}

func newEndpointFromUDP(addr *net.UDPAddr) *Endpoint {
	return newEndpoint(addr.AddrPort())
}

// New returns a closed Linux Bind.
func New() *Bind {
	b := &Bind{configureSocket: configureNoFragment, batchSize: conn.IdealBatchSize}
	b.msgsPool.New = func() any {
		// The pool capacity follows the configured UDP batch. The WGF TUN
		// wrapper bounds a wireguard-go request for a 256-entry device batch
		// to its native 128-entry read.
		capacity := b.messagePoolCapacity()
		msgs := make([]ipv4.Message, capacity)
		for i := range msgs {
			// A UDP GSO datagram can consist of up to 64 independent
			// WireGuard datagrams. Keep their iovecs in fixed storage so GSO
			// can use scatter/gather rather than copying every datagram into
			// the first buffer.
			msgs[i].Buffers = make(net.Buffers, 1, udpSegmentMaxDatagrams)
			msgs[i].OOB = make([]byte, 0, gsoControlSize)
		}
		return &msgs
	}
	return b
}

// SetBatchSize sets the number of UDP datagrams requested from each receive
// call. It must be called before the bind is opened (and before the bind is
// passed to wireguard-go). The supported configuration values are validated
// by config.Validate; direct users should use 128 or 256.
func (b *Bind) SetBatchSize(size int) error {
	if size != conn.IdealBatchSize && size != conn.IdealBatchSize*2 {
		return fmt.Errorf("wgbind: batch size %d is unsupported (want %d or %d)", size, conn.IdealBatchSize, conn.IdealBatchSize*2)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open || b.batchFrozen {
		return errBatchSizeFrozen
	}
	b.batchSize = size
	return nil
}

func (b *Bind) messagePoolCapacity() int {
	b.mu.Lock()
	size := b.batchSize
	b.batchFrozen = true
	b.mu.Unlock()
	if size < conn.IdealBatchSize {
		return conn.IdealBatchSize
	}
	return size
}

// SetSocketBuffer requests a buffer for each subsequently opened UDP socket.
func (b *Bind) SetSocketBuffer(bytes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.socketBuffer = bytes
}

// SetFwMark requests SO_MARK on each subsequently opened UDP socket, so
// policy-routing rules can exempt tunnel traffic and avoid a route loop.
// Zero leaves sockets unmarked.
func (b *Bind) SetFwMark(mark uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fwmark = mark
}

// SocketBufferStatus reports the requested and achieved receive sizes.
func (b *Bind) SocketBufferStatus() (requested, ipv4, ipv6 int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.socketBuffer, b.ipv4Buffer, b.ipv6Buffer
}

// skMeminfoDrops indexes sk_drops in SO_MEMINFO.
const skMeminfoDrops = 8

// SocketDrops reports kernel receive drops for each open socket.
func (b *Bind) SocketDrops() (ipv4, ipv6 uint64) {
	b.mu.Lock()
	v4, v6 := b.ipv4, b.ipv6
	b.mu.Unlock()
	return socketDrops(v4), socketDrops(v6)
}

func socketDrops(socket *net.UDPConn) uint64 {
	if socket == nil {
		return 0
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0
	}

	var drops uint64
	_ = raw.Control(func(fd uintptr) {
		// Leave room for future SO_MEMINFO entries.
		var info [16]uint32
		size := uint32(unsafe.Sizeof(info))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(unix.SOL_SOCKET),
			uintptr(unix.SO_MEMINFO),
			uintptr(unsafe.Pointer(&info[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 || int(size) < (skMeminfoDrops+1)*4 {
			return
		}
		drops = uint64(info[skMeminfoDrops])
	})
	return drops
}

// applySocketBuffer sets both buffers and reports the achieved receive size.
func applySocketBuffer(socket *net.UDPConn, size int) int {
	if socket == nil || size <= 0 {
		return 0
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0
	}
	achieved := 0
	_ = raw.Control(func(fd uintptr) {
		for _, option := range []struct{ force, plain int }{
			{unix.SO_RCVBUFFORCE, unix.SO_RCVBUF},
			{unix.SO_SNDBUFFORCE, unix.SO_SNDBUF},
		} {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option.force, size); err == nil {
				continue
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option.plain, size)
		}
		// Linux reports twice the requested value.
		if value, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil {
			achieved = value / 2
		}
	})
	return achieved
}

func configureNoFragment(fd uintptr, family int) error {
	switch family {
	case unix.AF_INET:
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			return err
		}
		return unix.SetsockoptInt(
			int(fd),
			unix.IPPROTO_IP,
			unix.IP_MTU_DISCOVER,
			unix.IP_PMTUDISC_PROBE,
		)
	case unix.AF_INET6:
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1); err != nil {
			return err
		}
		return unix.SetsockoptInt(
			int(fd),
			unix.IPPROTO_IPV6,
			unix.IPV6_DONTFRAG,
			1,
		)
	default:
		return syscall.EAFNOSUPPORT
	}
}

// configureUDPOffload enables UDP GRO when the running kernel provides it and
// probes UDP_SEGMENT for transmit GSO. Both options are opportunistic: a
// socket that does not know either option continues to use recvmmsg/sendmmsg
// without ancillary data.
func configureUDPOffload(socket *net.UDPConn) (tx, rx bool) {
	raw, err := socket.SyscallConn()
	if err != nil {
		return false, false
	}

	var optionErr error

	if err := raw.Control(func(fd uintptr) {
		_, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		tx = optionErr == nil

		// UDP_GRO is disabled by default on Linux. Enabling it is safe on
		// kernels that implement it; ENOPROTOOPT/EINVAL simply selects the
		// regular recvmmsg path.
		optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
		rx = optionErr == nil
	}); err != nil {
		return false, false
	}
	return tx, rx
}

func (b *Bind) listen(network string, port int, family int) (*net.UDPConn, uint16, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, raw syscall.RawConn) error {
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				optionErr = b.configureSocket(fd, family)
			}); err != nil {
				return err
			}
			return optionErr
		},
	}
	packetConn, err := lc.ListenPacket(
		context.Background(),
		network,
		net.JoinHostPort("", strconv.Itoa(port)),
	)
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

// Open binds IPv4 and IPv6 sockets to the same port. If an ephemeral IPv4
// port races with another bind before IPv6 opens, Open retries with a new port.
func (b *Bind) Open(requestedPort uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.configureSocket == nil {
		b.configureSocket = configureNoFragment
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

		b.ipv4 = v4
		b.ipv6 = v6
		b.ipv4Buffer = applySocketBuffer(v4, b.socketBuffer)
		b.ipv6Buffer = applySocketBuffer(v6, b.socketBuffer)
		if b.fwmark != 0 {
			err := setMark(v4, b.fwmark)
			if err == nil {
				err = setMark(v6, b.fwmark)
			}
			if err != nil {
				if v4 != nil {
					_ = v4.Close()
				}
				if v6 != nil {
					_ = v6.Close()
				}
				b.ipv4, b.ipv6 = nil, nil
				return nil, 0, fmt.Errorf("wgbind: set fwmark: %w", err)
			}
		}
		if v4 != nil {
			b.ipv4TxOffload, b.ipv4RxOffload = configureUDPOffload(v4)
			b.ipv4PC = ipv4.NewPacketConn(v4)
		}
		if v6 != nil {
			b.ipv6TxOffload, b.ipv6RxOffload = configureUDPOffload(v6)
			b.ipv6PC = ipv6.NewPacketConn(v6)
		}
		b.batchFrozen = true
		b.open = true

		receivers := make([]conn.ReceiveFunc, 0, 2)
		if v4 != nil {
			receivers = append(receivers, b.receive(v4, b.ipv4PC, b.ipv4RxOffload))
		}
		if v6 != nil {
			receivers = append(receivers, b.receive(v6, b.ipv6PC, b.ipv6RxOffload))
		}
		return receivers, port, nil
	}
}

type batchReader interface {
	ReadBatch(messages []ipv4.Message, limit int) (int, error)
}

type batchWriter interface {
	WriteBatch(messages []ipv4.Message, limit int) (int, error)
}

func (b *Bind) receive(socket *net.UDPConn, reader batchReader, rxOffload bool) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(packets) < 1 || len(sizes) < len(packets) || len(endpoints) < len(packets) {
			return 0, io.ErrShortBuffer
		}

		msgs := b.msgsPool.Get().(*[]ipv4.Message)
		defer b.putMessages(msgs)
		if len(packets) > len(*msgs) {
			return 0, io.ErrShortBuffer
		}
		for i := range packets {
			msg := &(*msgs)[i]
			msg.Buffers = msg.Buffers[:1]
			msg.Buffers[0] = packets[i]
			msg.OOB = msg.OOB[:cap(msg.OOB)]
			msg.Addr = nil
			msg.N, msg.NN, msg.Flags = 0, 0, 0
		}

		readAt := 0

		if rxOffload {
			// A UDP_GRO datagram can represent at most 64 wire datagrams.
			// Read only floor(capacity/64) kernel messages into the reserved
			// tail.  The split output is written from index zero, so this is
			// the largest input batch whose worst-case 64x expansion cannot
			// overwrite an unread message.  A smaller caller-provided batch
			// still reads one message and lets the splitter return a bounded
			// overflow error if that message expands beyond its buffers.
			readSlots := len(packets) / udpSegmentMaxDatagrams
			if readSlots == 0 {
				readSlots = 1
			}
			readAt = len(packets) - readSlots
		}
		n, err := b.readBatchRecovering(socket, reader, (*msgs)[readAt:len(packets)])
		if err != nil {
			if errors.Is(err, syscall.ENOSYS) {
				size, remote, readErr := socket.ReadFromUDPAddrPort(packets[0])
				if readErr != nil {
					if errors.Is(readErr, net.ErrClosed) {
						return 0, net.ErrClosed
					}
					return 0, readErr
				}
				sizes[0] = size
				endpoints[0] = newEndpoint(remote)
				return 1, nil
			}
			if errors.Is(err, net.ErrClosed) {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		if n < 0 || n > len(packets)-readAt {
			return 0, fmt.Errorf("wgbind: recvmmsg returned invalid message count %d", n)
		}

		for i := readAt; i < readAt+n; i++ {
			msg := &(*msgs)[i]
			if msg.N < 0 || len(msg.Buffers) == 0 || msg.N > len(msg.Buffers[0]) ||
				msg.NN < 0 || msg.NN > len(msg.OOB) {
				return 0, fmt.Errorf("wgbind: recvmmsg returned invalid message metadata at index %d", i)
			}
		}

		if rxOffload {
			n, err = splitCoalescedMessages(*msgs, readAt, n, len(packets))
			if err != nil {
				return 0, err
			}
		}

		for i := 0; i < n; i++ {
			msg := &(*msgs)[i]
			sizes[i] = msg.N
			if msg.N == 0 {
				continue
			}
			addr, ok := msg.Addr.(*net.UDPAddr)
			if !ok {
				return 0, fmt.Errorf("wgbind: unexpected peer address type %T", msg.Addr)
			}
			endpoints[i] = newEndpointFromUDP(addr)
		}
		return n, nil
	}
}

func (b *Bind) readBatchRecovering(socket *net.UDPConn, reader batchReader, messages []ipv4.Message) (int, error) {
	queued := 0
	for {
		n, err := reader.ReadBatch(messages, 0)
		if !isQueuedSocketError(err) {
			return n, err
		}

		b.drainSendErrors(socket, err)
		queued++
		if queued >= maxErrorQueueDrainsPerBurst {
			// A persistent MSG_ERRQUEUE condition must not turn this loop into a
			// CPU spin. Sleep only on the exceptional path; normal reads retain
			// the blocking behavior expected by wireguard-go.
			time.Sleep(errorQueueRetryDelay)
			queued = 0
		}
	}
}

func (b *Bind) putMessages(msgs *[]ipv4.Message) {
	for i := range *msgs {
		msg := &(*msgs)[i]
		clear(msg.Buffers)
		msg.Buffers = msg.Buffers[:1]
		msg.OOB = msg.OOB[:0]
		msg.Addr = nil
		msg.N, msg.NN, msg.Flags = 0, 0, 0
	}
	b.msgsPool.Put(msgs)
}

func splitCoalescedMessages(msgs []ipv4.Message, firstMsgAt, numMsgs, capacity int) (n int, err error) {
	if firstMsgAt < 0 || numMsgs < 0 || firstMsgAt > len(msgs) || numMsgs > len(msgs)-firstMsgAt {
		return 0, fmt.Errorf("wgbind: invalid coalesced message range [%d, %d)", firstMsgAt, firstMsgAt+numMsgs)
	}

	for i := firstMsgAt; i < firstMsgAt+numMsgs; i++ {
		if i >= len(msgs) {
			return n, fmt.Errorf("wgbind: recvmmsg returned invalid message count %d", numMsgs)
		}
		msg := &msgs[i]
		if msg.N == 0 {
			return n, nil
		}
		gsoSize, err := getGROSize(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		numToSplit := 1
		end := msg.N
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		start := 0

		for j := 0; j < numToSplit; j++ {
			if n > i || n >= capacity || n >= len(msgs) {
				return n, fmt.Errorf("wgbind: UDP_GRO output exceeds receive batch size")
			}
			if end > msg.N {
				end = msg.N
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].NN = 0
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			n++
		}
		if i != n-1 {
			msg.N = 0
		}
	}
	return n, nil
}

func getGROSize(control []byte) (int, error) {
	for len(control) > unix.SizeofCmsghdr {
		hdr, data, remainder, err := unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return 0, fmt.Errorf("wgbind: parse UDP_GRO control message: %w", err)
		}
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && len(data) >= gsoDataSize {
			var gso uint16
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&gso)), gsoDataSize), data[:gsoDataSize])
			return int(gso), nil
		}
		control = remainder
	}
	return 0, nil
}

func setGSOSize(control *[]byte, gsoSize uint16) {
	existingLen := len(*control)
	if cap(*control)-existingLen < gsoControlSize {
		return
	}
	*control = (*control)[:cap(*control)]
	data := (*control)[existingLen:]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&data[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(gsoDataSize))
	copy(data[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), gsoDataSize))
	*control = (*control)[:existingLen+gsoControlSize]
}

// Close closes both sockets and unblocks all receive functions returned by
// Open. It is safe to call Close more than once.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	v4 := b.ipv4
	v6 := b.ipv6
	b.ipv4 = nil
	b.ipv6 = nil
	b.ipv4PC = nil
	b.ipv6PC = nil
	b.ipv4TxOffload = false
	b.ipv4RxOffload = false
	b.ipv6TxOffload = false
	b.ipv6RxOffload = false
	b.ipv4Buffer = 0
	b.ipv6Buffer = 0
	b.open = false

	var errs []error
	if v4 != nil {
		if err := v4.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if v6 != nil {
		if err := v6.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SetMark applies SO_MARK to each currently open socket.
func (b *Bind) SetMark(mark uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := setMark(b.ipv4, mark); err != nil {
		return err
	}
	return setMark(b.ipv6, mark)
}

// SetErrorHandler installs an optional callback for transport errors observed
// by Send, invoked outside Bind's mutex; nil clears it. udpPayloadSize is the
// datagram the error is definitively attributed to, or zero for a stashed
// error whose datagram is unknown. Linux can report an oversized send on the
// next socket operation, so without the size the controller would fail a
// valid probe for an earlier probe's error.
//
// Deprecated: use SetPathEventHandler for family and attribution metadata.
func (b *Bind) SetErrorHandler(handler func(err error, udpPayloadSize int)) {
	b.mu.Lock()
	b.sendErrorHandler = handler
	b.mu.Unlock()
}

// SetPathEventHandler installs an optional transport-neutral path-event
// callback. The callback runs outside Bind's mutex; nil clears it.
func (b *Bind) SetPathEventHandler(handler func(PathEvent)) {
	b.mu.Lock()
	b.pathEventHandler = handler
	b.mu.Unlock()
}

func (b *Bind) notifyPathEvent(event PathEvent) {
	b.mu.Lock()
	pathHandler := b.pathEventHandler
	handler := b.sendErrorHandler
	b.mu.Unlock()
	if pathHandler != nil {
		pathHandler(event)
	}
	if handler != nil {
		handler(event.Err, event.DatagramSize)
	}
}

func pathEventKind(err error) PathEventKind {
	if errors.Is(err, syscall.EMSGSIZE) {
		return PathEventMessageTooLarge
	}
	return PathEventUnknown
}

// sendBatch isolates EMSGSIZE to the failed datagram and keeps later messages
// flowing. Queued errors are drained from MSG_ERRQUEUE when available.
func (b *Bind) sendBatch(socket *net.UDPConn, writer batchWriter, msgs []ipv4.Message) (sent int, err error) {
	return b.sendBatchContext(socket, writer, msgs, sendEventContext{})
}

type sendEventContext struct {
	family        OuterFamily
	endpoint      netip.AddrPort
	endpointKnown bool
}

func (c sendEventContext) synchronousEvent(err error, size int) PathEvent {
	event := PathEvent{
		Kind:              pathEventKind(err),
		Err:               err,
		Family:            c.family,
		DatagramSize:      size,
		DatagramSizeKnown: true,
	}
	if c.endpointKnown {
		event.Endpoint = c.endpoint
		event.EndpointKnown = true
	}
	return event
}

func (b *Bind) sendBatchContext(
	socket *net.UDPConn,
	writer batchWriter,
	msgs []ipv4.Message,
	context sendEventContext,
) (sent int, err error) {
	for start := 0; start < len(msgs); {
		n, writeErr := writer.WriteBatch(msgs[start:], 0)
		if n > len(msgs)-start {
			return sent, fmt.Errorf("wgbind: invalid batch write count %d", n)
		}
		// A failed sendmmsg may report -1 rather than 0; both mean no progress,
		// and the error classification below decides what happens next.
		if n > 0 {
			sent += n
			start += n
		}
		if writeErr == nil {
			if n > 0 {
				continue
			}
			return sent, io.ErrNoProgress
		}
		if !errors.Is(writeErr, syscall.EMSGSIZE) {
			return sent, writeErr
		}
		// Skipping the rejected datagram is what makes this loop terminate:
		// IP_RECVERR queues a fresh error for every rejected send, so gating
		// progress on the drain count would retry the same datagram forever.
		if b.drainSendErrorsContext(socket, writeErr, context.family) == 0 && start < len(msgs) {
			b.notifyPathEvent(context.synchronousEvent(writeErr, messageSize(msgs[start])))
		}
		if start < len(msgs) {
			start++
		}
	}
	return sent, nil
}

// queuedSocketErrors are the errno values Linux reports for a UDP socket once
// IP_RECVERR is set. Without that option the kernel discards them, so they must
// never reach wireguard-go: its receive loop treats any error as terminal and
// would stop serving the peer for the rest of the process's life.
var queuedSocketErrors = []error{
	syscall.EMSGSIZE,
	syscall.ECONNREFUSED,
	syscall.EHOSTUNREACH,
	syscall.ENETUNREACH,
	syscall.EHOSTDOWN,
	syscall.ENETDOWN,
	syscall.EPROTO,
}

func isQueuedSocketError(err error) bool {
	for _, candidate := range queuedSocketErrors {
		if errors.Is(err, candidate) {
			return true
		}
	}
	return false
}

// drainSendErrors reports queued failed datagrams and returns the count
// drained. Only an oversized datagram reaches the PMTU handler; an ICMP
// unreachable says nothing about the path MTU.
func (b *Bind) drainSendErrors(socket *net.UDPConn, cause error) int {
	return b.drainSendErrorsContext(socket, cause, OuterFamilyUnknown)
}

func (b *Bind) drainSendErrorsContext(socket *net.UDPConn, cause error, family OuterFamily) int {
	if socket == nil {
		return 0
	}
	notify := errors.Is(cause, syscall.EMSGSIZE)
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0
	}
	drained := 0
	_ = raw.Control(func(fd uintptr) {
		var buf [1]byte

		var oob [512]byte
		for {
			_, _, _, _, err := unix.Recvmsg(int(fd), buf[:], oob[:], unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT|unix.MSG_TRUNC)
			if err != nil {
				return
			}

			drained++

			if notify {
				// MSG_ERRQUEUE does not identify which send in the current
				// batch failed. Report family only; endpoint and size remain
				// explicitly unknown rather than using the current destination.
				b.notifyPathEvent(PathEvent{Kind: PathEventMessageTooLarge, Err: cause, Family: family})
			}
		}
	})
	return drained
}

func setMark(socket *net.UDPConn, mark uint32) error {
	if socket == nil {
		return nil
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	return optionErr
}

// Send writes one wireguard-go batch with sendmmsg. When UDP_SEGMENT is
// available, compatible adjacent datagrams are coalesced into one GSO
// datagram; a kernel/NIC that rejects GSO is permanently downgraded to plain
// sendmmsg for that socket.
func (b *Bind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	if len(packets) == 0 {
		return nil
	}
	destination, ok := endpoint.(*Endpoint)
	if !ok || destination == nil || !destination.addr.IsValid() || destination.udpAddr.IP == nil {
		return conn.ErrWrongEndpointType
	}

	b.mu.Lock()
	open := b.open
	socket := b.ipv6
	writer := batchWriter(b.ipv6PC)
	offload := b.ipv6TxOffload
	is6 := true

	if destination.addr.Addr().Is4() {
		socket = b.ipv4
		writer = b.ipv4PC
		offload = b.ipv4TxOffload
		is6 = false
	}
	b.mu.Unlock()

	if !open {
		return net.ErrClosed
	}
	if socket == nil {
		return syscall.EAFNOSUPPORT
	}
	if writer == nil {
		return net.ErrClosed
	}

	msgs := b.msgsPool.Get().(*[]ipv4.Message)
	defer b.putMessages(msgs)
	if len(packets) > len(*msgs) {
		return io.ErrShortBuffer
	}
	addr := &destination.udpAddr
	eventContext := sendEventContext{
		family:        OuterFamilyIPv6,
		endpoint:      destination.addr,
		endpointKnown: true,
	}
	if destination.addr.Addr().Is4() {
		eventContext.family = OuterFamilyIPv4
	}
	if offload {
		n := coalesceMessages(addr, packets, *msgs, is6)
		sent, err := b.sendBatchContext(socket, writer, (*msgs)[:n], eventContext)
		if err != nil {
			if errors.Is(err, syscall.ENOSYS) && sent == 0 {
				return b.writeSequential(socket, packets, destination.addr, eventContext.family)
			}
			if !shouldDisableUDPGSO(err) || sent != 0 {
				return err
			}
			b.setTxOffload(is6, false)
			// Retry all datagrams without UDP_SEGMENT. The first attempt is
			// treated as not having sent anything when sendmmsg rejects the
			// cmsg; this is the kernel contract for these option errors.
			for i := range packets {
				msg := &(*msgs)[i]
				msg.Buffers = msg.Buffers[:1]
				msg.Buffers[0] = packets[i]
				msg.OOB = msg.OOB[:0]
				msg.Addr = addr
			}

			var plainSent int
			plainSent, err = b.sendBatchContext(socket, writer, (*msgs)[:len(packets)], eventContext)
			if errors.Is(err, syscall.ENOSYS) && plainSent == 0 {
				return b.writeSequential(socket, packets, destination.addr, eventContext.family)
			}
			return err
		}
		return nil
	}
	for i := range packets {
		msg := &(*msgs)[i]
		msg.Buffers = msg.Buffers[:1]
		msg.Buffers[0] = packets[i]
		msg.OOB = msg.OOB[:0]
		msg.Addr = addr
	}
	_, err := b.sendBatchContext(socket, writer, (*msgs)[:len(packets)], eventContext)
	if errors.Is(err, syscall.ENOSYS) {
		return b.writeSequential(socket, packets, destination.addr, eventContext.family)
	}
	return err
}

// messageSize is the datagram size EMSGSIZE applies to: the segment size for
// a GSO message, the whole payload otherwise.
func messageSize(msg ipv4.Message) int {
	if len(msg.Buffers) == 0 {
		return 0
	}
	return len(msg.Buffers[0])
}

func (b *Bind) writeSequential(
	socket *net.UDPConn,
	packets [][]byte,
	destination netip.AddrPort,
	family OuterFamily,
) error {
	for _, packet := range packets {
		_, err := socket.WriteToUDPAddrPort(packet, destination)
		if err == nil {
			continue
		}
		if !errors.Is(err, syscall.EMSGSIZE) {
			return err
		}
		if b.drainSendErrorsContext(socket, err, family) == 0 {
			b.notifyPathEvent(
				sendEventContext{family: family, endpoint: destination, endpointKnown: true}.
					synchronousEvent(err, len(packet)),
			)

			continue
		}
		if _, err := socket.WriteToUDPAddrPort(packet, destination); err != nil {
			if !errors.Is(err, syscall.EMSGSIZE) {
				return err
			}
			b.notifyPathEvent(
				sendEventContext{family: family, endpoint: destination, endpointKnown: true}.
					synchronousEvent(err, len(packet)),
			)
		}
	}
	return nil
}

func (b *Bind) setTxOffload(is6, enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if is6 {
		b.ipv6TxOffload = enabled
	} else {
		b.ipv4TxOffload = enabled
	}
}

func shouldDisableUDPGSO(err error) bool {
	return errors.Is(err, syscall.EIO) || errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOTSUP)
}

func coalesceMessages(addr *net.UDPAddr, packets [][]byte, msgs []ipv4.Message, is6 bool) int {
	maxPayloadLen := maxIPv4PayloadLen
	if is6 {
		maxPayloadLen = maxIPv6PayloadLen
	}
	base := -1
	baseLen := 0
	gsoSize := 0
	dgramCount := 0
	endBatch := false

	for i, packet := range packets {
		if i > 0 {
			if len(packet)+baseLen <= maxPayloadLen && len(packet) <= gsoSize &&
				dgramCount < udpSegmentMaxDatagrams && !endBatch {
				msgs[base].Buffers = append(msgs[base].Buffers, packet)
				baseLen += len(packet)
				dgramCount++

				if len(packet) < gsoSize {
					endBatch = true
				}

				continue
			}
		}
		if dgramCount > 1 {
			setGSOSize(&msgs[base].OOB, uint16(gsoSize))
		}
		endBatch = false
		base++
		gsoSize = len(packet)
		dgramCount = 1
		baseLen = len(packet)
		msgs[base].Buffers = msgs[base].Buffers[:1]
		msgs[base].Buffers[0] = packet
		msgs[base].OOB = msgs[base].OOB[:0]
		msgs[base].Addr = addr
	}
	if base >= 0 && dgramCount > 1 {
		setGSOSize(&msgs[base].OOB, uint16(gsoSize))
	}
	return base + 1
}

// ParseEndpoint accepts numeric endpoints and resolves DNS names once at UAPI
// configuration time, matching wireguard-go's standard bind behavior. A later
// endpoint update re-resolves the name through another UAPI operation.
func (*Bind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err == nil {
		if address.Addr().Is4In6() {
			return nil, fmt.Errorf("wgbind: IPv4-mapped endpoint is unsupported")
		}
		return newEndpoint(address), nil
	}
	resolved, err := net.ResolveUDPAddr("udp", value)
	if err != nil || resolved == nil {
		return nil, err
	}
	address = netip.AddrPortFrom(resolved.AddrPort().Addr().Unmap(), uint16(resolved.Port))
	if !address.IsValid() || address.Addr().Is4In6() {
		return nil, fmt.Errorf("wgbind: resolved endpoint is invalid")
	}
	return newEndpoint(address), nil
}

// BatchSize reports the configured Linux UDP batch. Kernel/option probing only
// changes whether ancillary GSO/GRO data is used; sendmmsg and recvmmsg remain
// available independently. The message pool retains at least the native
// wireguard-go batch for the TUN/send side.
func (b *Bind) BatchSize() int {
	b.mu.Lock()
	size := b.batchSize
	b.batchFrozen = true
	b.mu.Unlock()
	if size <= 0 {
		return conn.IdealBatchSize
	}
	return size
}
func (*Endpoint) ClearSrc()             {}
func (*Endpoint) SrcToString() string   { return "" }
func (e *Endpoint) DstToString() string { return e.addr.String() }

func (e *Endpoint) DstToBytes() []byte {
	encoded, _ := e.addr.MarshalBinary()
	return encoded
}

func (e *Endpoint) DstIP() netip.Addr { return e.addr.Addr() }
func (*Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
