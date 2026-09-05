//go:build linux

package wgbind

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

func TestOpenConfiguresNoFragmentSockets(t *testing.T) {
	t.Parallel()
	bind := New()
	_, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	if bind.ipv4 != nil {
		got := getSocketOption(t, bind.ipv4, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
		if got != unix.IP_PMTUDISC_PROBE {
			t.Errorf("IP_MTU_DISCOVER = %d, want IP_PMTUDISC_PROBE (%d)", got, unix.IP_PMTUDISC_PROBE)
		}
	}
	if bind.ipv6 != nil {
		got := getSocketOption(t, bind.ipv6, unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG)
		if got != 1 {
			t.Errorf("IPV6_DONTFRAG = %d, want 1", got)
		}
	}
}

func TestOpenFailsWhenSocketConfigurationFails(t *testing.T) {
	t.Parallel()
	want := errors.New("socket configuration failed")
	bind := New()
	bind.configureSocket = func(uintptr, int) error { return want }

	_, _, err := bind.Open(0)
	if !errors.Is(err, want) {
		t.Fatalf("Open() error = %v, want %v", err, want)
	}
}

func TestOpenTwice(t *testing.T) {
	t.Parallel()
	bind := New()
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	if _, _, err := bind.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open() error = %v, want ErrBindAlreadyOpen", err)
	}
}

func TestCloseAndReopen(t *testing.T) {
	t.Parallel()
	bind := New()
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestSendReceiveIPv4(t *testing.T) {
	t.Parallel()
	testSendReceive(t, "udp4", "127.0.0.1")
}

func TestSendAcceptsWireGuardBatch(t *testing.T) {
	t.Parallel()
	bind := New()
	_, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	peerPort := peer.LocalAddr().(*net.UDPAddr).Port
	endpoint, err := bind.ParseEndpoint(net.JoinHostPort("127.0.0.1", fmt.Sprint(peerPort)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("one"), []byte("two")}, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		buffer := make([]byte, 16)
		n, _, err := peer.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buffer[:n]); got != want {
			t.Fatalf("packet = %q, want %q", got, want)
		}
	}
}

func TestSendRejectsUninitializedEndpoint(t *testing.T) {
	t.Parallel()
	bind := New()
	if err := bind.Send([][]byte{[]byte("packet")}, (*Endpoint)(nil)); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("typed nil endpoint error = %v, want ErrWrongEndpointType", err)
	}
	if err := bind.Send([][]byte{[]byte("packet")}, &Endpoint{}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("zero endpoint error = %v, want ErrWrongEndpointType", err)
	}
}

func TestPathEventHandlerReportsSynchronousMetadata(t *testing.T) {
	t.Parallel()
	bind := New()
	var (
		gotPath   PathEvent
		gotLegacy struct {
			err  error
			size int
		}
	)

	bind.SetPathEventHandler(func(event PathEvent) { gotPath = event })
	bind.SetErrorHandler(func(err error, size int) {
		gotLegacy = struct {
			err  error
			size int
		}{err, size}
	})
	endpoint := netip.MustParseAddrPort("192.0.2.1:51820")
	msgs := []ipv4.Message{{Buffers: net.Buffers{make([]byte, 1472)}}, {Buffers: net.Buffers{make([]byte, 100)}}}
	writer := &scriptedBatchWriter{results: []func([]ipv4.Message) (int, error){
		func([]ipv4.Message) (int, error) { return 0, syscall.EMSGSIZE },
		func(msgs []ipv4.Message) (int, error) { return len(msgs), nil },
	}}
	if sent, err := bind.sendBatchContext(nil, writer, msgs, sendEventContext{
		family:        OuterFamilyIPv4,
		endpoint:      endpoint,
		endpointKnown: true,
	}); err != nil || sent != 1 {
		t.Fatalf("sendBatchContext() = (%d, %v), want (1, nil)", sent, err)
	}
	if gotPath.Kind != PathEventMessageTooLarge || !errors.Is(gotPath.Err, syscall.EMSGSIZE) ||
		gotPath.Family != OuterFamilyIPv4 || !gotPath.DatagramSizeKnown || gotPath.DatagramSize != 1472 ||
		!gotPath.EndpointKnown || gotPath.Endpoint != endpoint {
		t.Fatalf("path event = %+v, want synchronous IPv4 metadata", gotPath)
	}
	if !errors.Is(gotLegacy.err, syscall.EMSGSIZE) || gotLegacy.size != 1472 {
		t.Fatalf("legacy event = %+v, want EMSGSIZE/1472", gotLegacy)
	}
}

func TestPathEventHandlerPreservesUnknownQueuedAttribution(t *testing.T) {
	t.Parallel()
	bind := New()
	var got PathEvent

	bind.SetPathEventHandler(func(event PathEvent) { got = event })
	bind.notifyPathEvent(PathEvent{Kind: PathEventMessageTooLarge, Err: syscall.EMSGSIZE, Family: OuterFamilyIPv6})
	if got.Kind != PathEventMessageTooLarge || got.Family != OuterFamilyIPv6 || got.DatagramSizeKnown || got.DatagramSize != 0 ||
		got.EndpointKnown || got.Endpoint.IsValid() {
		t.Fatalf("queued path event = %+v, want unknown size/endpoint", got)
	}
}

func TestCoalesceMessagesUsesScatterGather(t *testing.T) {
	t.Parallel()
	packets := [][]byte{make([]byte, 100), make([]byte, 100), make([]byte, 100)}
	msgs := make([]ipv4.Message, len(packets))
	for i := range msgs {
		msgs[i].Buffers = make(net.Buffers, 1, udpSegmentMaxDatagrams)
		msgs[i].OOB = make([]byte, 0, gsoControlSize)
	}
	n := coalesceMessages(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, packets, msgs, false)
	if n != 1 {
		t.Fatalf("coalesceMessages count = %d, want 1", n)
	}
	if got := msgs[0].Buffers; len(got) != len(packets) {
		t.Fatalf("scatter/gather segments = %d, want %d", len(got), len(packets))
	} else {
		for i := range packets {
			if len(got[i]) != len(packets[i]) || &got[i][0] != &packets[i][0] {
				t.Fatalf("segment %d does not alias its source packet", i)
			}
		}
	}
}

func TestBatchSizeUsesLinuxIdealBatch(t *testing.T) {
	t.Parallel()
	if got := New().BatchSize(); got != conn.IdealBatchSize {
		t.Fatalf("BatchSize() = %d, want %d", got, conn.IdealBatchSize)
	}
}

func TestBatchSizeCanBeConfiguredAboveNativeTUNBatch(t *testing.T) {
	t.Parallel()
	bind := New()
	if err := bind.SetBatchSize(256); err != nil {
		t.Fatalf("SetBatchSize() error = %v", err)
	}
	if got := bind.BatchSize(); got != 256 {
		t.Fatalf("BatchSize() = %d, want 256", got)
	}
	msgs := bind.msgsPool.Get().(*[]ipv4.Message)
	defer bind.putMessages(msgs)
	if got := len(*msgs); got != 256 {
		t.Fatalf("message pool capacity = %d, want 256", got)
	}
}

func TestBatchSizeCannotChangeAfterOpen(t *testing.T) {
	t.Parallel()
	bind := New()
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	if err := bind.SetBatchSize(256); !errors.Is(err, errBatchSizeFrozen) {
		t.Fatalf("SetBatchSize() error = %v, want %v", err, errBatchSizeFrozen)
	}
	if got := bind.BatchSize(); got != conn.IdealBatchSize {
		t.Fatalf("BatchSize() = %d after rejected update, want %d", got, conn.IdealBatchSize)
	}
}

func TestReceiveSplitsFullConfiguredGROBatch(t *testing.T) {
	t.Parallel()
	bind := New()
	if err := bind.SetBatchSize(256); err != nil {
		t.Fatal(err)
	}
	receiver := bind.receive(nil, fullGROBatchReader{}, true)
	packets := make([][]byte, 256)
	for i := range packets {
		packets[i] = make([]byte, 256)
	}
	sizes := make([]int, len(packets))
	endpoints := make([]conn.Endpoint, len(packets))
	n, err := receiver(packets, sizes, endpoints)
	if err != nil {
		t.Fatalf("receive() error = %v", err)
	}
	if n != len(packets) {
		t.Fatalf("receive() returned %d packets, want %d", n, len(packets))
	}
	for i := range packets {
		if sizes[i] != 4 || packets[i][0] != byte(i/64) || packets[i][1] != byte(i%64) {
			t.Fatalf("packet %d = (%d, %x), want size 4 and marker (%d, %d)", i, sizes[i], packets[i], i/64, i%64)
		}
	}
}

func TestBatchSizeRemainsFrozenAfterUse(t *testing.T) {
	for _, use := range []string{"query", "pool", "close"} {
		t.Run(use, func(t *testing.T) {
			bind := New()
			switch use {
			case "query":
				_ = bind.BatchSize()
			case "pool":
				msgs := bind.msgsPool.Get().(*[]ipv4.Message)
				bind.putMessages(msgs)
			case "close":
				if _, _, err := bind.Open(0); err != nil {
					t.Fatal(err)
				}
				if err := bind.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := bind.SetBatchSize(256); !errors.Is(err, errBatchSizeFrozen) {
				t.Fatalf("SetBatchSize after %s = %v, want frozen", use, err)
			}
		})
	}
}

type fullGROBatchReader struct{}

func (fullGROBatchReader) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	if len(messages) != 4 {
		return 0, fmt.Errorf("ReadBatch received %d messages, want 4", len(messages))
	}
	for i := range messages {
		buffer := messages[i].Buffers[0]
		for j := 0; j < 64; j++ {
			buffer[j*4] = byte(i)
			buffer[j*4+1] = byte(j)
		}
		messages[i].N = len(buffer)
		messages[i].OOB = messages[i].OOB[:0]
		setGSOSize(&messages[i].OOB, 4)
		// Receive ancillary data uses UDP_GRO, not the UDP_SEGMENT type
		// used by the send-side helper that constructs this header.
		header := (*unix.Cmsghdr)(unsafe.Pointer(&messages[i].OOB[0]))
		header.Type = unix.UDP_GRO
		messages[i].NN = len(messages[i].OOB)
		messages[i].Addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}
	}
	return len(messages), nil
}

func TestReceiveAcceptsWireGuardBatch(t *testing.T) {
	t.Parallel()
	bind := New()
	_, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	if bind.ipv4 == nil {
		t.Skip("IPv4 is unavailable")
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	destination := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
	for _, payload := range []string{"one", "two", "three"} {
		if _, err := peer.WriteToUDP([]byte(payload), destination); err != nil {
			t.Fatal(err)
		}
	}
	packets := make([][]byte, bind.BatchSize())
	for i := range packets {
		packets[i] = make([]byte, 64)
	}
	sizes := make([]int, bind.BatchSize())
	endpoints := make([]conn.Endpoint, bind.BatchSize())
	// Force the plain recvmmsg path here; when GRO is enabled the receiver
	// intentionally reserves message slots for up to 64 coalesced datagrams.
	receiver := bind.receive(bind.ipv4, bind.ipv4PC, false)
	n, err := receiver(packets, sizes, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("receive() returned %d packets, want at least 3", n)
	}
	for _, want := range []string{"one", "two", "three"} {
		found := false
		for j := 0; j < n; j++ {
			if string(packets[j][:sizes[j]]) == want {
				found = true

				break
			}
		}
		if !found {
			t.Errorf("packet %q missing from receive batch", want)
		}
	}
}

type recoveringBatchReader struct {
	queuedErrors int
	calls        int
}

func (r *recoveringBatchReader) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	r.calls++
	if r.calls <= r.queuedErrors {
		return 0, syscall.ECONNREFUSED
	}
	messages[0].N = copy(messages[0].Buffers[0], []byte("recovered"))
	messages[0].Addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}
	return 1, nil
}

func TestReceiveRecoversQueuedSocketErrors(t *testing.T) {
	t.Parallel()
	bind := New()
	reader := &recoveringBatchReader{queuedErrors: maxErrorQueueDrainsPerBurst + 1}
	receiver := bind.receive(nil, reader, false)
	packets := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	n, err := receiver(packets, sizes, endpoints)
	if err != nil {
		t.Fatalf("receive() error = %v", err)
	}
	if n != 1 || string(packets[0][:sizes[0]]) != "recovered" {
		t.Fatalf("receive() = (%d, %q), want recovered packet", n, packets[0][:sizes[0]])
	}
	if reader.calls != maxErrorQueueDrainsPerBurst+2 {
		t.Fatalf("ReadBatch calls = %d, want %d", reader.calls, maxErrorQueueDrainsPerBurst+2)
	}
}

func TestSendReceiveIPv6(t *testing.T) {
	t.Parallel()
	testSendReceive(t, "udp6", "::1")
}

func testSendReceive(t *testing.T, network, loopback string) {
	t.Helper()

	bind := New()
	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	var receiver conn.ReceiveFunc
	if network == "udp4" {
		if bind.ipv4 == nil {
			t.Skip("IPv4 is unavailable")
		}
		receiver = receivers[0]
	} else {
		if bind.ipv6 == nil {
			t.Skip("IPv6 is unavailable")
		}
		receiver = receivers[len(receivers)-1]
	}

	peer, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(loopback), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(%q) error = %v", network, err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	destination := &net.UDPAddr{IP: net.ParseIP(loopback), Port: int(port)}
	if _, err := peer.WriteToUDP([]byte("request"), destination); err != nil {
		t.Fatalf("peer WriteToUDP() error = %v", err)
	}

	packets := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	n, err := receiver(packets, sizes, endpoints)
	if err != nil {
		t.Fatalf("receive() error = %v", err)
	}
	if n != 1 || string(packets[0][:sizes[0]]) != "request" {
		t.Fatalf("receive() = (%d, %q), want (1, request)", n, packets[0][:sizes[0]])
	}

	if err := bind.Send([][]byte{[]byte("response")}, endpoints[0]); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	response := make([]byte, 64)
	size, _, err := peer.ReadFromUDP(response)
	if err != nil {
		t.Fatalf("peer ReadFromUDP() error = %v", err)
	}
	if string(response[:size]) != "response" {
		t.Fatalf("peer received %q, want response", response[:size])
	}
}

func TestReceiveReturnsNetErrClosed(t *testing.T) {
	t.Parallel()
	bind := New()
	receivers, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := receivers[0](
			[][]byte{make([]byte, 64)},
			make([]int, 1),
			make([]conn.Endpoint, 1),
		)
		result <- err
	}()

	if err := bind.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive after Close() error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not unblock after Close")
	}
}

func TestSendReportsAndContainsEMSGSIZE(t *testing.T) {
	t.Parallel()
	bind := New()
	_, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	endpoint, err := bind.ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatalf("ParseEndpoint() error = %v", err)
	}
	type report struct {
		err  error
		size int
	}
	observed := make(chan report, 4)

	bind.SetErrorHandler(func(err error, size int) { observed <- report{err, size} })
	// An oversized datagram is reported to the PMTU handler and skipped; it
	// must not fail the Send call, or wireguard-go would also drop every
	// unrelated datagram queued behind a failed probe.
	if err := bind.Send([][]byte{make([]byte, 65536)}, endpoint); err != nil {
		t.Fatalf("Send() error = %v, want oversized datagram skipped", err)
	}

	select {
	case got := <-observed:
		if !errors.Is(got.err, syscall.EMSGSIZE) {
			t.Fatalf("error handler = %v, want EMSGSIZE", got.err)
		}
		if got.size != 65536 {
			t.Fatalf("reported size = %d, want the oversized datagram's 65536", got.size)
		}
	case <-time.After(time.Second):
		t.Fatal("error handler was not called")
	}
}

type scriptedBatchWriter struct {
	results []func(msgs []ipv4.Message) (int, error)
	calls   int
}

func (w *scriptedBatchWriter) WriteBatch(msgs []ipv4.Message, flags int) (int, error) {
	step := w.results[w.calls]
	w.calls++
	return step(msgs)
}

func TestSendBatchSkipsSynchronouslyOversizedHead(t *testing.T) {
	t.Parallel()
	bind := New()
	var reports []int
	bind.SetErrorHandler(func(_ error, size int) { reports = append(reports, size) })
	msgs := make([]ipv4.Message, 3)
	for i := range msgs {
		msgs[i].Buffers = net.Buffers{make([]byte, 1472)}
	}

	// No socket means nothing on the error queue, so a synchronous EMSGSIZE
	// belongs to the head message: report it, skip it, keep sending.
	writer := &scriptedBatchWriter{results: []func([]ipv4.Message) (int, error){
		func([]ipv4.Message) (int, error) { return 0, syscall.EMSGSIZE },
		func(m []ipv4.Message) (int, error) { return len(m), nil },
	}}
	sent, err := bind.sendBatch(nil, writer, msgs)
	if err != nil || sent != 2 {
		t.Fatalf("sendBatch() = (%d, %v), want (2, nil)", sent, err)
	}
	if len(reports) != 1 || reports[0] != 1472 {
		t.Fatalf("reports = %v, want the skipped head's size", reports)
	}

	// Non-EMSGSIZE errors still abort with the partial count.
	writer = &scriptedBatchWriter{results: []func([]ipv4.Message) (int, error){
		func(m []ipv4.Message) (int, error) { return 1, nil },
		func([]ipv4.Message) (int, error) { return 0, syscall.ENETUNREACH },
	}}
	sent, err = bind.sendBatch(nil, writer, msgs)
	if !errors.Is(err, syscall.ENETUNREACH) || sent != 1 {
		t.Fatalf("hard error = (%d, %v), want (1, ENETUNREACH)", sent, err)
	}
}

func TestSendBatchDoesNotIndexPastCompletedBatch(t *testing.T) {
	t.Parallel()
	bind := New()
	msgs := []ipv4.Message{{Buffers: net.Buffers{make([]byte, 8)}}}
	writer := &scriptedBatchWriter{results: []func([]ipv4.Message) (int, error){
		func(m []ipv4.Message) (int, error) { return len(m), syscall.EMSGSIZE },
	}}
	if sent, err := bind.sendBatch(nil, writer, msgs); err != nil || sent != 1 {
		t.Fatalf("sendBatch() = (%d, %v), want (1, nil)", sent, err)
	}

	writer = &scriptedBatchWriter{results: []func([]ipv4.Message) (int, error){
		func([]ipv4.Message) (int, error) { return 2, nil },
	}}
	if _, err := bind.sendBatch(nil, writer, msgs); err == nil {
		t.Fatal("sendBatch accepted an invalid write count")
	}
}

func TestParseEndpointResolvesHostname(t *testing.T) {
	t.Parallel()
	bind := New()
	endpoint, err := bind.ParseEndpoint("localhost:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint() error = %v", err)
	}
	if endpoint.DstToString() == "" {
		t.Fatal("resolved endpoint has no destination")
	}
}

func getSocketOption(t *testing.T, socket *net.UDPConn, level, option int) int {
	t.Helper()
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn() error = %v", err)
	}
	var (
		value     int
		optionErr error
	)
	if err := raw.Control(func(fd uintptr) {
		value, optionErr = unix.GetsockoptInt(int(fd), level, option)
	}); err != nil {
		t.Fatalf("RawConn.Control() error = %v", err)
	}
	if optionErr != nil {
		t.Fatalf("GetsockoptInt(%d, %d) error = %v", level, option, optionErr)
	}
	return value
}

func TestSocketBufferIsAppliedAndReported(t *testing.T) {
	t.Parallel()
	const requested = 1 << 20
	bind := New()
	bind.SetSocketBuffer(requested)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	got, v4, v6 := bind.SocketBufferStatus()
	if got != requested {
		t.Fatalf("requested = %d, want %d", got, requested)
	}
	for _, socket := range []struct {
		conn     *net.UDPConn
		achieved int
	}{{bind.ipv4, v4}, {bind.ipv6, v6}} {
		if socket.conn == nil {
			continue
		}
		if socket.achieved == 0 {
			t.Fatal("open socket has no reported receive buffer")
		}
		if socket.achieved > requested {
			t.Fatalf("achieved buffer %d exceeds requested %d", socket.achieved, requested)
		}
	}
}

func TestSocketBufferZeroKeepsKernelDefault(t *testing.T) {
	t.Parallel()
	bind := New()
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	requested, v4, v6 := bind.SocketBufferStatus()
	if requested != 0 || v4 != 0 || v6 != 0 {
		t.Fatalf("SocketBufferStatus() = (%d, %d, %d), want zeros", requested, v4, v6)
	}
}

func TestSocketDropsCountsReceiveBufferOverruns(t *testing.T) {
	t.Parallel()
	bind := New()
	// A deliberately tiny receive buffer so a burst is guaranteed to overrun
	// it; this is the condition SocketDrops must make visible.
	bind.SetSocketBuffer(2048)
	_, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	if bind.ipv4 == nil {
		t.Skip("IPv4 is unavailable")
	}
	if v4, _ := bind.SocketDrops(); v4 != 0 {
		t.Fatalf("initial drops = %d, want 0", v4)
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	destination := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
	payload := make([]byte, 1400)
	// Never drained, so the buffer fills and the kernel starts dropping.
	for i := 0; i < 4096; i++ {
		if _, err := sender.WriteToUDP(payload, destination); err != nil {
			break
		}
	}
	v4, _ := bind.SocketDrops()
	if v4 == 0 {
		t.Fatal("SocketDrops() = 0 after overrunning the receive buffer")
	}
	t.Logf("observed %d dropped datagrams", v4)
}
