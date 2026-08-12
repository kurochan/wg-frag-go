package controlapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	// ErrEmptySocketPath rejects client calls without a Unix socket target.
	ErrEmptySocketPath = errors.New("controlapi: empty socket path")
	// ErrNilContext rejects client calls that cannot honor cancellation.
	ErrNilContext = errors.New("controlapi: nil context")
)

// invalidSocketName is longer than Linux's 15-byte interface-name limit, so
// malformed input cannot alias a real interface's socket.
const invalidSocketName = "wgf-invalid-name"

func dial(socketPath string) (*grpc.ClientConn, error) {
	if socketPath == "" {
		return nil, ErrEmptySocketPath
	}
	conn, err := grpc.NewClient("unix:"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("controlapi: dial %s: %w", socketPath, err)
	}
	return conn, nil
}

// GetStatus performs one status request against an interface socket. The
// private Unix socket supplies the local access boundary.
func GetStatus(ctx context.Context, socketPath string) (*controlapiv1.GetStatusResponse, error) {
	return getStatus(ctx, socketPath, false)
}

// GetStatusWithSecrets is restricted to owner-controlled showconf paths.
func GetStatusWithSecrets(ctx context.Context, socketPath string) (*controlapiv1.GetStatusResponse, error) {
	return getStatus(ctx, socketPath, true)
}

func getStatus(ctx context.Context, socketPath string, includeSecrets bool) (*controlapiv1.GetStatusResponse, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	conn, err := dial(socketPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request := controlapiv1.GetStatusRequest_builder{}.Build()
	request.SetIncludeSecrets(includeSecrets)
	return controlapiv1.NewControlAPIClient(conn).GetStatus(ctx, request)
}

// ApplyConfig submits one complete desired peer set.
func ApplyConfig(
	ctx context.Context,
	socketPath string,
	request *controlapiv1.ApplyConfigRequest,
) (*controlapiv1.ApplyConfigResponse, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	conn, err := dial(socketPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return controlapiv1.NewControlAPIClient(conn).ApplyConfig(ctx, request)
}

// SocketPath returns the canonical per-interface socket location. Invalid
// interface names map to an inert path and cannot alias another interface.
func SocketPath(ifname string) string {
	// Keep path-like input from selecting another interface's socket. This API
	// cannot report invalid names, so they map to an inert socket name.
	name := ifname
	if !validInterfaceName(name) {
		name = invalidSocketName
	}
	return filepath.Join("/run/wg-frag", name+".sock")
}

func validInterfaceName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 15 || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '=' || r == '+' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}
