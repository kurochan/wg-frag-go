//go:build !linux && !darwin

package manager

import (
	"context"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

// Manager is the unsupported-platform stub. It keeps the public API
// compilable on platforms without a supported TUN backend.
type Manager struct{}

// New reports that the manager is unavailable on the current platform.
func New(options Options) (*Manager, error) {
	if options.MaxInterfaces < 0 {
		return nil, NewError(CodeInvalidArgument, "max interfaces must not be negative")
	}
	return nil, NewError(CodeUnavailable, "manager is not supported on this platform")
}

var _ Service = (*Manager)(nil)
var _ Lifecycle = (*Manager)(nil)

func unsupported(ctx context.Context) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	return NewError(CodeUnavailable, "manager is not supported on this platform")
}

func (*Manager) ListInterfaces(ctx context.Context, _ *controlapiv1.ListInterfacesRequest) (*controlapiv1.ListInterfacesResponse, error) {
	return nil, unsupported(ctx)
}

func (*Manager) GetInterface(ctx context.Context, _ *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	return nil, unsupported(ctx)
}

func (*Manager) CreateInterface(ctx context.Context, _ *controlapiv1.CreateInterfaceRequest) (*controlapiv1.CreateInterfaceResponse, error) {
	return nil, unsupported(ctx)
}

func (*Manager) DeleteInterface(ctx context.Context, _ *controlapiv1.DeleteInterfaceRequest) (*controlapiv1.DeleteInterfaceResponse, error) {
	return nil, unsupported(ctx)
}

func (*Manager) ApplyPeers(ctx context.Context, _ *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	return nil, unsupported(ctx)
}

func (*Manager) RestartInterface(ctx context.Context, _ *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
	return nil, unsupported(ctx)
}

// Close releases no resources on unsupported platforms.
func (*Manager) Close(ctx context.Context) error {
	return validateContext(ctx)
}

// InterfaceCount returns zero because no interfaces can be created.
func (*Manager) InterfaceCount() int { return 0 }

// EffectiveListenPort reports that no interface can run.
func (*Manager) EffectiveListenPort(string) (uint16, error) {
	return 0, NewError(CodeUnavailable, "manager is not supported on this platform")
}

// DumpStats has no effect on unsupported platforms.
func (*Manager) DumpStats() {}
