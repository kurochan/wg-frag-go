package controlapi

import (
	"context"
	"errors"

	internalcontrolapi "github.com/kurochan/wg-frag-go/internal/controlapi"
	"github.com/kurochan/wg-frag-go/manager"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ServerConfig describes a Unix-domain control server.
type ServerConfig struct {
	SocketPath string
	Service    manager.Service
}

// Server exposes a manager Service through the local gRPC control protocol.
// It owns only the listener and gRPC server; closing it does not close the
// manager or any managed interface.
type Server struct {
	server *internalcontrolapi.Server
}

// ServeUnix binds socketPath and starts serving service in the background.
func ServeUnix(config ServerConfig) (*Server, error) {
	if config.Service == nil {
		return nil, internalcontrolapi.ErrInvalidConfig
	}
	server, err := internalcontrolapi.New(internalcontrolapi.Config{
		SocketPath: config.SocketPath,
		Service:    &grpcService{service: config.Service},
	})
	if err != nil {
		return nil, err
	}
	return &Server{server: server}, nil
}

// Close stops accepting calls and briefly waits for admitted calls to return.
// Calls that do not finish within the server grace period are canceled. Close
// does not close the underlying manager Service.
func (server *Server) Close() {
	if server != nil && server.server != nil {
		server.server.Close()
	}
}

type grpcService struct {
	controlapiv1.UnimplementedControlServiceServer
	service manager.Service
}

func (service *grpcService) ListInterfaces(ctx context.Context, request *controlapiv1.ListInterfacesRequest) (*controlapiv1.ListInterfacesResponse, error) {
	response, err := service.service.ListInterfaces(ctx, request)
	return response, grpcError(err)
}

func (service *grpcService) GetInterface(ctx context.Context, request *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	response, err := service.service.GetInterface(ctx, request)
	return response, grpcError(err)
}

func (service *grpcService) CreateInterface(ctx context.Context, request *controlapiv1.CreateInterfaceRequest) (*controlapiv1.CreateInterfaceResponse, error) {
	response, err := service.service.CreateInterface(ctx, request)
	return response, grpcError(err)
}

func (service *grpcService) DeleteInterface(ctx context.Context, request *controlapiv1.DeleteInterfaceRequest) (*controlapiv1.DeleteInterfaceResponse, error) {
	response, err := service.service.DeleteInterface(ctx, request)
	return response, grpcError(err)
}

func (service *grpcService) ApplyPeers(ctx context.Context, request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	response, err := service.service.ApplyPeers(ctx, request)
	return response, grpcError(err)
}

func (service *grpcService) RestartInterface(ctx context.Context, request *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
	response, err := service.service.RestartInterface(ctx, request)
	return response, grpcError(err)
}

func grpcError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	if status.Code(err) != codes.Unknown {
		return err
	}
	code := codes.Internal
	switch manager.CodeOf(err) {
	case manager.CodeInvalidArgument:
		code = codes.InvalidArgument
	case manager.CodeNotFound:
		code = codes.NotFound
	case manager.CodeAlreadyExists:
		code = codes.AlreadyExists
	case manager.CodeAborted:
		code = codes.Aborted
	case manager.CodeFailedPrecondition:
		code = codes.FailedPrecondition
	case manager.CodeResourceExhausted:
		code = codes.ResourceExhausted
	case manager.CodeUnavailable:
		code = codes.Unavailable
	case manager.CodeInternal, manager.CodeOK:
		code = codes.Internal
	}
	message := err.Error()
	var typed *manager.Error
	if errors.As(err, &typed) && typed != nil {
		message = typed.Message()
	}
	return status.Error(code, message)
}
