package manager

import (
	"context"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

// Service is the transport-independent control API for managed interfaces.
//
// Implementations must not retain or mutate request messages after a method
// returns. Methods may be called concurrently. Invalid requests return an
// error classified as CodeInvalidArgument.
//
// The protobuf types are also the RPC wire contract. Keeping them here avoids
// separate in-process and gRPC models that could drift apart.
type Service interface {
	ListInterfaces(ctx context.Context, request *controlapiv1.ListInterfacesRequest) (*controlapiv1.ListInterfacesResponse, error)
	GetInterface(ctx context.Context, request *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error)
	CreateInterface(ctx context.Context, request *controlapiv1.CreateInterfaceRequest) (*controlapiv1.CreateInterfaceResponse, error)
	DeleteInterface(ctx context.Context, request *controlapiv1.DeleteInterfaceRequest) (*controlapiv1.DeleteInterfaceResponse, error)
	ApplyPeers(ctx context.Context, request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error)
	RestartInterface(ctx context.Context, request *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error)
}

// Lifecycle is a Service that also owns the lifecycle of its managed
// interfaces. Close stops all owned runtimes and releases their resources.
//
// Close must be safe to call more than once. Once Close begins, new Service
// calls should fail with CodeUnavailable; an in-flight call may finish before
// Close returns. Implementations should honor the context for shutdown.
type Lifecycle interface {
	Service
	Close(ctx context.Context) error
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return NewError(CodeInvalidArgument, "nil context")
	}
	return nil
}
