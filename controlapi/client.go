// Package controlapi exposes a manager Service over local Unix-domain gRPC
// and provides a client for that transport.
//
// The service is available only over a Unix-domain socket. The daemon owns
// authentication through the socket's filesystem permissions; callers should
// keep the socket path within the system runtime directory.
package controlapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"

	"github.com/kurochan/wg-frag-go/internal/interfacename"
	"github.com/kurochan/wg-frag-go/internal/platform/runtimedir"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	// ErrEmptySocketPath reports a missing Unix socket path.
	ErrEmptySocketPath = errors.New("controlapi: empty socket path")
	// ErrNilContext reports a nil context passed to a client operation.
	ErrNilContext = errors.New("controlapi: nil context")
	// ErrClosed reports an operation on a closed client.
	ErrClosed = errors.New("controlapi: client is closed")
)

// Client calls the local ControlService.
type Client struct {
	_       noCopy
	conn    *grpc.ClientConn
	service controlapiv1.ControlServiceClient
	mu      sync.RWMutex
	closed  bool
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// DialUnix creates a client for a Unix-domain control socket. The connection
// is established lazily by gRPC; the first RPC observes a missing socket.
func DialUnix(ctx context.Context, socketPath string, opts ...grpc.DialOption) (*Client, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if socketPath == "" {
		return nil, ErrEmptySocketPath
	}
	options := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}),
	}
	options = append(options, opts...)
	conn, err := grpc.NewClient("unix:"+socketPath, options...)
	if err != nil {
		return nil, fmt.Errorf("controlapi: dial %s: %w", socketPath, err)
	}
	return &Client{conn: conn, service: controlapiv1.NewControlServiceClient(conn)}, nil
}

// Close releases the client connection. It is safe to call more than once.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

func (c *Client) checkContext(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	if c == nil || c.conn == nil || c.service == nil {
		return ErrClosed
	}
	c.mu.RLock()
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	return nil
}

// ListInterfaces returns the interfaces currently managed by the daemon.
func (c *Client) ListInterfaces(ctx context.Context, request *controlapiv1.ListInterfacesRequest, opts ...grpc.CallOption) (*controlapiv1.ListInterfacesResponse, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	return c.service.ListInterfaces(ctx, request, opts...)
}

// GetInterface returns one interface's observable status.
func (c *Client) GetInterface(ctx context.Context, request *controlapiv1.GetInterfaceRequest, opts ...grpc.CallOption) (*controlapiv1.GetInterfaceResponse, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	return c.service.GetInterface(ctx, request, opts...)
}

// CreateInterface creates and starts an interface from its complete runtime
// specification.
func (c *Client) CreateInterface(ctx context.Context, request *controlapiv1.CreateInterfaceRequest, opts ...grpc.CallOption) (*controlapiv1.CreateInterfaceResponse, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	return c.service.CreateInterface(ctx, request, opts...)
}

// DeleteInterface stops and removes an interface.
func (c *Client) DeleteInterface(ctx context.Context, request *controlapiv1.DeleteInterfaceRequest, opts ...grpc.CallOption) (*controlapiv1.DeleteInterfaceResponse, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	return c.service.DeleteInterface(ctx, request, opts...)
}

// ApplyPeers updates an interface's peer set without restarting its runtime.
func (c *Client) ApplyPeers(ctx context.Context, request *controlapiv1.ApplyPeersRequest, opts ...grpc.CallOption) (*controlapiv1.ApplyPeersResponse, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	return c.service.ApplyPeers(ctx, request, opts...)
}

// RestartInterface replaces an interface's runtime configuration.
func (c *Client) RestartInterface(ctx context.Context, request *controlapiv1.RestartInterfaceRequest, opts ...grpc.CallOption) (*controlapiv1.RestartInterfaceResponse, error) {
	if err := c.checkContext(ctx); err != nil {
		return nil, err
	}
	return c.service.RestartInterface(ctx, request, opts...)
}

// Raw returns the generated client for callers that need gRPC call options or
// interceptors not covered by the convenience methods.
func (c *Client) Raw() (controlapiv1.ControlServiceClient, error) {
	if c == nil || c.conn == nil || c.service == nil {
		return nil, ErrClosed
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, ErrClosed
	}
	return c.service, nil
}

// SocketPath returns the canonical per-interface socket location. Invalid
// names map to an inert path and cannot alias a real interface socket.
func SocketPath(interfaceName string) string {
	name := interfaceName
	if !ValidInterfaceName(name) {
		name = "wgf-invalid-name"
	}
	return filepath.Join(runtimedir.Default, name+".sock")
}

// ManagerSocketPath returns the canonical multi-interface manager socket.
func ManagerSocketPath() string {
	return ManagerSocketPathIn(runtimedir.Default)
}

// ManagerSocketPathIn returns the multi-interface manager socket below a
// runtime directory. It is primarily useful for discovery and tests that use
// a non-default runtime directory.
func ManagerSocketPathIn(runtimeDirectory string) string {
	return filepath.Join(runtimeDirectory, "manager", "control.sock")
}

// ValidInterfaceName reports whether name is safe for both native TUN names
// and the canonical per-interface control socket path.
func ValidInterfaceName(name string) bool {
	return interfacename.Valid(name)
}
