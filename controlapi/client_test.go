package controlapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/platform/runtimedir"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc"
)

type testControlService struct {
	controlapiv1.UnimplementedControlServiceServer
	calls atomic.Int32
}

func (s *testControlService) ListInterfaces(context.Context, *controlapiv1.ListInterfacesRequest) (*controlapiv1.ListInterfacesResponse, error) {
	s.calls.Add(1)
	return controlapiv1.ListInterfacesResponse_builder{}.Build(), nil
}

func (s *testControlService) GetInterface(context.Context, *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	s.calls.Add(1)
	return controlapiv1.GetInterfaceResponse_builder{}.Build(), nil
}

func (s *testControlService) CreateInterface(context.Context, *controlapiv1.CreateInterfaceRequest) (*controlapiv1.CreateInterfaceResponse, error) {
	s.calls.Add(1)
	return controlapiv1.CreateInterfaceResponse_builder{}.Build(), nil
}

func (s *testControlService) DeleteInterface(context.Context, *controlapiv1.DeleteInterfaceRequest) (*controlapiv1.DeleteInterfaceResponse, error) {
	s.calls.Add(1)
	return controlapiv1.DeleteInterfaceResponse_builder{}.Build(), nil
}

func (s *testControlService) ApplyPeers(context.Context, *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	s.calls.Add(1)
	return controlapiv1.ApplyPeersResponse_builder{}.Build(), nil
}

func (s *testControlService) RestartInterface(context.Context, *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
	s.calls.Add(1)
	return controlapiv1.RestartInterfaceResponse_builder{}.Build(), nil
}

func TestClientCallsAllRPCs(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "wgf-api")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socketPath := filepath.Join(root, "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	service := &testControlService{}
	controlapiv1.RegisterControlServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	client, err := DialUnix(context.Background(), socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	if _, err := client.ListInterfaces(ctx, controlapiv1.ListInterfacesRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetInterface(ctx, controlapiv1.GetInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateInterface(ctx, controlapiv1.CreateInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteInterface(ctx, controlapiv1.DeleteInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ApplyPeers(ctx, controlapiv1.ApplyPeersRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RestartInterface(ctx, controlapiv1.RestartInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if got := service.calls.Load(); got != 6 {
		t.Fatalf("RPC calls = %d, want 6", got)
	}
	if _, err := client.Raw(); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsInvalidArguments(t *testing.T) {
	t.Parallel()
	//nolint:staticcheck // Verify the public nil-context contract explicitly.
	if _, err := DialUnix(nil, "/tmp/control.sock"); !errors.Is(err, ErrNilContext) {
		t.Fatalf("DialUnix(nil) = %v, want ErrNilContext", err)
	}
	if _, err := DialUnix(context.Background(), ""); !errors.Is(err, ErrEmptySocketPath) {
		t.Fatalf("DialUnix(empty) = %v, want ErrEmptySocketPath", err)
	}
	var client *Client
	if _, err := client.ListInterfaces(context.Background(), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Client.ListInterfaces() = %v, want ErrClosed", err)
	}
	zero := &Client{}
	if _, err := zero.ListInterfaces(context.Background(), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero Client.ListInterfaces() = %v, want ErrClosed", err)
	}
	if _, err := zero.Raw(); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero Client.Raw() = %v, want ErrClosed", err)
	}
}

func TestClientCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	client, err := DialUnix(context.Background(), "/tmp/wgf-no-such-socket")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Raw(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Raw() after Close() = %v, want ErrClosed", err)
	}
}

func TestValidInterfaceName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"wgf0", "wgf-test_1", "wgf+test.1", "wgf=1"} {
		if !ValidInterfaceName(name) {
			t.Errorf("ValidInterfaceName(%q) = false", name)
		}
	}
	for _, name := range []string{"", ".", "..", "wgf/name", "wgf name", "0123456789abcdef"} {
		if ValidInterfaceName(name) {
			t.Errorf("ValidInterfaceName(%q) = true", name)
		}
	}
}

func TestSocketPathDoesNotAliasPathLikeInterfaceNames(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"../wgf0", "wgf0/other", "/tmp/wgf0", "..", ""} {
		path := SocketPath(input)
		if filepath.Dir(path) != runtimedir.Default || filepath.Base(path) == "wgf0.sock" || path == SocketPath("_") {
			t.Fatalf("SocketPath(%q) escaped or aliased: %q", input, path)
		}
	}
	if got := SocketPath("wgf0"); got != filepath.Join(runtimedir.Default, "wgf0.sock") {
		t.Fatalf("SocketPath(valid) = %q", got)
	}
}

func TestManagerSocketPathIn(t *testing.T) {
	t.Parallel()
	if got := ManagerSocketPathIn("/tmp/wgf-runtime"); got != "/tmp/wgf-runtime/manager/control.sock" {
		t.Fatalf("ManagerSocketPathIn() = %q", got)
	}
}
