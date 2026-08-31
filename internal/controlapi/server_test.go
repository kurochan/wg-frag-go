package controlapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// shortSocketPath avoids the 104-byte sun_path limit that t.TempDir exceeds
// on macOS.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "wgf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "wgf0.sock")
}

func testGetInterface(context.Context, *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	peer := controlapiv1.PeerStatus_builder{}.Build()
	peer.SetEndpoint("192.0.2.1:51820")
	peer.SetDataReady(true)
	ref := controlapiv1.InterfaceRef_builder{}.Build()
	ref.SetInterfaceName("wgf0")
	status := controlapiv1.InterfaceStatus_builder{}.Build()
	status.SetRef(ref)
	status.SetListenPort(51820)
	status.SetMtu(9612)
	status.SetPeers([]*controlapiv1.PeerStatus{peer})
	response := controlapiv1.GetInterfaceResponse_builder{}.Build()
	response.SetStatus(status)
	return response, nil
}

type testService struct {
	controlapiv1.UnimplementedControlServiceServer
	getInterface func(context.Context, *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error)
}

func (service *testService) GetInterface(ctx context.Context, request *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	return service.getInterface(ctx, request)
}

func testConfig(socket string) Config {
	return Config{SocketPath: socket, Service: &testService{getInterface: testGetInterface}}
}

func dialTestService(t *testing.T, socket string) controlapiv1.ControlServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix:"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return controlapiv1.NewControlServiceClient(conn)
}

func TestStatusRoundTripOverUnixSocket(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	server, err := New(testConfig(socket))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	if info, err := os.Stat(filepath.Dir(socket)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory mode = %v, %v; want 0700", info.Mode().Perm(), err)
	}
	client := dialTestService(t, socket)
	request := controlapiv1.GetInterfaceRequest_builder{}.Build()
	status, err := client.GetInterface(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if status.GetStatus().GetRef().GetInterfaceName() != "wgf0" || len(status.GetStatus().GetPeers()) != 1 || !status.GetStatus().GetPeers()[0].GetDataReady() {
		t.Fatalf("status = %+v", status)
	}
}

func TestNewRefusesLiveSocketAndReclaimsStaleOne(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	first, err := New(testConfig(socket))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(testConfig(socket)); err == nil {
		t.Fatal("New() accepted a socket another instance is serving")
	}
	// Simulate a dead daemon: stop serving without invoking Server.Close,
	// which is the cleanup path being tested separately below.
	first.grpc.Stop()
	_ = first.listener.Close()
	first.releaseLock()
	second, err := New(testConfig(socket))
	if err != nil {
		t.Fatalf("New() did not reclaim a stale socket: %v", err)
	}
	second.Close()
}

func TestNewRefusesNonSocketPath(t *testing.T) {
	t.Parallel()
	path := shortSocketPath(t)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(testConfig(path)); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("New() error = %v, want refusal to delete a non-socket", err)
	}
}

func TestRemoveStaleSocketRejectsReplacedPath(t *testing.T) {
	t.Parallel()
	path := shortSocketPath(t)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if current.Mode()&os.ModeSocket != 0 {
		t.Fatal("replacement unexpectedly remained a socket")
	}
	if err := verifyStaleSocketIdentity(path, info); err == nil {
		t.Fatal("verifyStaleSocketIdentity accepted a replaced path")
	}
}

func TestConcurrentNewHasSingleSocketOwner(t *testing.T) {
	t.Parallel()
	path := shortSocketPath(t)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	_ = unix.Close(fd)

	const attempts = 8
	servers := make(chan *Server, attempts)
	errorsSeen := make(chan error, attempts)
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			server, err := New(testConfig(path))
			if err != nil {
				errorsSeen <- err
				return
			}
			servers <- server
		}()
	}
	group.Wait()
	close(servers)
	close(errorsSeen)

	owned := 0
	for server := range servers {
		owned++
		server.Close()
	}
	if owned != 1 {
		t.Fatalf("concurrent New() owners = %d, want 1", owned)
	}
	for err := range errorsSeen {
		if err == nil {
			t.Fatal("concurrent New() returned a nil error")
		}
	}
}

func TestNewRefusesInsecureSocketDirectory(t *testing.T) {
	t.Parallel()
	directory, err := os.MkdirTemp("/tmp", "wgf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(testConfig(filepath.Join(directory, "wgf0.sock"))); err == nil {
		t.Fatal("New() accepted an insecure socket directory")
	}
}

func TestNewRefusesSocketDirectorySymlink(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "wgf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := New(testConfig(filepath.Join(link, "wgf0.sock"))); err == nil {
		t.Fatal("New() followed a symlink in the socket directory")
	}
}

func TestPrepareSocketDirectoryRejectsWritableAncestor(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "wgf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(unsafe, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketDirectory(private); err == nil {
		t.Fatal("prepareSocketDirectory accepted a group/other-writable ancestor")
	}
}

func TestPrepareSocketDirectoryAcceptsPrivateTempDirectory(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	if err := prepareSocketDirectory(filepath.Dir(socket)); err != nil {
		t.Fatalf("prepareSocketDirectory() rejected private temp directory: %v", err)
	}
}

func TestNewCreatesMissingSocketDirectoryOwnerOnly(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "wgf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "missing", "nested")
	server, err := New(testConfig(filepath.Join(directory, "wgf0.sock")))
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("created socket directory mode = %04o, want no group/other permissions", info.Mode().Perm())
	}
}

func TestCloseRemovesSocket(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	server, err := New(testConfig(socket))
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after Close() = %v, want removed", err)
	}
}

func TestCloseWaitsForInFlightRPC(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server, err := New(Config{SocketPath: socket, Service: &blockingService{
		started: started,
		release: release,
	}})
	if err != nil {
		t.Fatal(err)
	}
	client := dialTestService(t, socket)
	t.Cleanup(server.Close)
	rpcDone := make(chan error, 1)
	go func() {
		_, rpcErr := client.GetInterface(context.Background(), controlapiv1.GetInterfaceRequest_builder{}.Build())
		rpcDone <- rpcErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("RPC did not reach callback")
	}
	closeDone := make(chan struct{})
	go func() {
		server.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("Server.Close returned before in-flight RPC completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-rpcDone:
		if err != nil {
			t.Fatalf("in-flight RPC: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight RPC did not complete")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Server.Close did not complete after RPC")
	}
}

func TestCloseForcesStuckRPCToStopAfterGracePeriod(t *testing.T) {
	t.Parallel()

	socket := shortSocketPath(t)
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	server, err := New(Config{SocketPath: socket, Service: &blockingService{
		started: started,
		release: release,
	}})
	if err != nil {
		t.Fatal(err)
	}
	server.gracePeriod = 20 * time.Millisecond
	client := dialTestService(t, socket)
	rpcDone := make(chan error, 1)
	go func() {
		_, rpcErr := client.GetInterface(context.Background(), controlapiv1.GetInterfaceRequest_builder{}.Build())
		rpcDone <- rpcErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("RPC did not reach callback")
	}

	closeDone := make(chan struct{})
	go func() {
		server.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Server.Close remained blocked after the grace period")
	}
	select {
	case err := <-rpcDone:
		if err == nil {
			t.Fatal("forced server stop returned a successful RPC")
		}
	case <-time.After(time.Second):
		t.Fatal("forced server stop did not release the client RPC")
	}
}

type blockingService struct {
	controlapiv1.UnimplementedControlServiceServer
	started chan<- struct{}
	release <-chan struct{}
}

func (service *blockingService) GetInterface(context.Context, *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	close(service.started)
	<-service.release
	return controlapiv1.GetInterfaceResponse_builder{}.Build(), nil
}
