//go:build darwin

package wgbind

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/transport"
	"golang.zx2c4.com/wireguard/conn"
)

func TestBindSendReceiveIPv4(t *testing.T) {
	t.Parallel()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()

	bind := New()
	bind.SetSocketBuffer(64 << 10)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bind.Close() }()
	if got := bind.BatchSize(); got != 1 {
		t.Fatalf("BatchSize() = %d, want 1", got)
	}
	endpoint, err := bind.ParseEndpoint(receiver.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("carrier")}, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "carrier" {
		t.Fatalf("received %q, want carrier", got)
	}
}

func TestBindRejectsWrongEndpoint(t *testing.T) {
	t.Parallel()
	bind := New()
	err := bind.Send(nil, wrongEndpoint{})
	if !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("Send() error = %v, want ErrWrongEndpointType", err)
	}
}

func TestPathEventHandler(t *testing.T) {
	t.Parallel()
	bind := New()
	got := make(chan transport.PathEvent, 1)
	bind.SetPathEventHandler(func(event transport.PathEvent) { got <- event })
	want := transport.PathEvent{Kind: transport.PathEventMessageTooLarge, Endpoint: netip.MustParseAddrPort("192.0.2.1:51820"), EndpointKnown: true}
	bind.notifyPathEvent(want)
	if event := <-got; event != want {
		t.Fatalf("event = %#v, want %#v", event, want)
	}
}

type wrongEndpoint struct{}

func (wrongEndpoint) ClearSrc()           {}
func (wrongEndpoint) SrcToString() string { return "" }
func (wrongEndpoint) DstToString() string { return "" }
func (wrongEndpoint) DstToBytes() []byte  { return nil }
func (wrongEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (wrongEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
