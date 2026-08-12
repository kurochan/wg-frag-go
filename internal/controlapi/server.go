package controlapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrInvalidConfig reports an incomplete server configuration.
var ErrInvalidConfig = errors.New("controlapi: invalid config")

// StatusFunc assembles the current user-facing interface status. It runs on a
// gRPC handler goroutine, so implementations must be safe for concurrent use.
type StatusFunc func(ctx context.Context, includeSecrets bool) (*controlapiv1.GetStatusResponse, error)

// ApplyFunc applies a complete desired peer set. Like StatusFunc it runs on a
// gRPC handler goroutine.
type ApplyFunc func(
	ctx context.Context,
	request *controlapiv1.ApplyConfigRequest,
) (*controlapiv1.ApplyConfigResponse, error)

// Config describes one interface's server.
type Config struct {
	SocketPath string
	Status     StatusFunc
	// Apply is optional; a nil Apply serves a status-only API.
	Apply ApplyFunc
}

// Server owns the Unix socket listener and its gRPC service.
type Server struct {
	listener    net.Listener
	grpc        *grpc.Server
	socketPath  string
	releaseLock func()
	closeOnce   sync.Once
}

type service struct {
	controlapiv1.UnimplementedControlAPIServer

	status StatusFunc
	apply  ApplyFunc
}

func (s *service) GetStatus(
	ctx context.Context,
	request *controlapiv1.GetStatusRequest,
) (*controlapiv1.GetStatusResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "controlapi: nil GetStatus request")
	}
	return s.status(ctx, request.GetIncludeSecrets())
}

func (s *service) ApplyConfig(
	ctx context.Context,
	request *controlapiv1.ApplyConfigRequest,
) (*controlapiv1.ApplyConfigResponse, error) {
	if s.apply == nil {
		return nil, errors.New("controlapi: configuration changes are not enabled")
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "controlapi: nil ApplyConfig request")
	}
	return s.apply(ctx, request)
}

// staleSocketProbeTimeout bounds the liveness probe against an existing socket
// so a wedged peer daemon cannot block startup indefinitely.
const staleSocketProbeTimeout = 2 * time.Second

// New binds a private Unix socket and starts serving in the background.
func New(config Config) (*Server, error) {
	if config.SocketPath == "" || config.Status == nil {
		return nil, ErrInvalidConfig
	}
	directory := filepath.Dir(config.SocketPath)
	if err := prepareSocketDirectory(directory); err != nil {
		return nil, fmt.Errorf("controlapi: socket directory: %w", err)
	}
	_, releaseLock, err := acquireSocketLock(config.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("controlapi: socket lock: %w", err)
	}
	if err := removeStaleSocket(config.SocketPath); err != nil {
		releaseLock()
		return nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", config.SocketPath)
	if err != nil {
		releaseLock()
		return nil, fmt.Errorf("controlapi: listen: %w", err)
	}
	if err := os.Chmod(config.SocketPath, 0o600); err != nil {
		_ = listener.Close()
		releaseLock()
		return nil, fmt.Errorf("controlapi: socket permissions: %w", err)
	}
	server := &Server{
		listener:    listener,
		grpc:        grpc.NewServer(),
		socketPath:  config.SocketPath,
		releaseLock: releaseLock,
	}
	controlapiv1.RegisterControlAPIServer(server.grpc, &service{status: config.Status, apply: config.Apply})

	go func() { _ = server.grpc.Serve(listener) }()
	return server, nil
}

func (s *Server) stop() {
	s.closeOnce.Do(func() {
		s.grpc.Stop()
		_ = s.listener.Close()
		_ = os.Remove(s.socketPath)
		if s.releaseLock != nil {
			s.releaseLock()
		}
	})
}

// Close stops the server and removes the socket.
func (s *Server) Close() {
	s.stop()
}

// removeStaleSocket reclaims a socket left by a dead daemon. Only a socket
// nobody answers is removed: a connectable one means another instance owns
// this interface, and any other file type is not ours to delete.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("controlapi: inspect socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("controlapi: %s exists and is not a socket", path)
	}

	probeCtx, cancelProbe := context.WithTimeout(context.Background(), staleSocketProbeTimeout)
	defer cancelProbe()

	if conn, err := (&net.Dialer{}).DialContext(probeCtx, "unix", path); err == nil {
		_ = conn.Close()
		return fmt.Errorf("controlapi: %s is already served by another instance", path)
	} else if errors.Is(err, os.ErrNotExist) {
		// Another owner removed the stale entry after Lstat; let net.Listen
		// create the path below.
		return nil
	} else if !isConnectionRefused(err) {
		// A socket that cannot be probed for a reason other than a refused
		// connection may still belong to a live process (for example due to a
		// transient resource or permission error). Never unlink it blindly.
		return fmt.Errorf("controlapi: probe socket: %w", err)
	}
	if err := verifyStaleSocketIdentity(path, info); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("controlapi: remove stale socket: %w", err)
	}
	return nil
}

func verifyStaleSocketIdentity(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("controlapi: recheck socket: %w", err)
	}
	if !os.SameFile(expected, current) || current.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("controlapi: socket changed while probing")
	}
	return nil
}
