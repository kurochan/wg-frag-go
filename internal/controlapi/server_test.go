package controlapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/platform/runtimedir"
	"golang.org/x/sys/unix"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
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

func testStatus(context.Context, bool) (*controlapiv1.GetStatusResponse, error) {
	peer := controlapiv1.PeerStatus_builder{}.Build()
	peer.SetEndpoint("192.0.2.1:51820")
	peer.SetDataReady(true)
	status := controlapiv1.GetStatusResponse_builder{}.Build()
	status.SetInterfaceName("wgf0")
	status.SetListenPort(51820)
	status.SetMtu(9612)
	status.SetPeers([]*controlapiv1.PeerStatus{peer})
	return status, nil
}

func TestStatusRoundTripOverUnixSocket(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	server, err := New(Config{SocketPath: socket, Status: testStatus})
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
	status, err := GetStatus(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	if status.GetInterfaceName() != "wgf0" || len(status.GetPeers()) != 1 || !status.GetPeers()[0].GetDataReady() {
		t.Fatalf("status = %+v", status)
	}
}

func TestNewRefusesLiveSocketAndReclaimsStaleOne(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	first, err := New(Config{SocketPath: socket, Status: testStatus})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{SocketPath: socket, Status: testStatus}); err == nil {
		t.Fatal("New() accepted a socket another instance is serving")
	}
	// Simulate a dead daemon: stop serving without invoking Server.Close,
	// which is the cleanup path being tested separately below.
	first.grpc.Stop()
	_ = first.listener.Close()
	first.releaseLock()
	second, err := New(Config{SocketPath: socket, Status: testStatus})
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
	if _, err := New(Config{SocketPath: path, Status: testStatus}); err == nil || errors.Is(err, os.ErrNotExist) {
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
			server, err := New(Config{SocketPath: path, Status: testStatus})
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
	if _, err := New(Config{SocketPath: filepath.Join(directory, "wgf0.sock"), Status: testStatus}); err == nil {
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
	if _, err := New(Config{SocketPath: filepath.Join(link, "wgf0.sock"), Status: testStatus}); err == nil {
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
	server, err := New(Config{SocketPath: filepath.Join(directory, "wgf0.sock"), Status: testStatus})
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

func TestCloseRemovesSocket(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	server, err := New(Config{SocketPath: socket, Status: testStatus})
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after Close() = %v, want removed", err)
	}
}
