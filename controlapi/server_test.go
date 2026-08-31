package controlapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kurochan/wg-frag-go/manager"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServeUnixAndClientRoundTripAllOperations(t *testing.T) {
	t.Parallel()

	root, err := os.MkdirTemp("/tmp", "wgf-public-controlapi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	service := &testControlService{}
	socketPath := filepath.Join(root, "control.sock")
	server, err := ServeUnix(ServerConfig{SocketPath: socketPath, Service: service})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)

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
		t.Fatalf("service calls = %d, want 6", got)
	}
}

func TestGRPCServiceDelegatesAllRPCs(t *testing.T) {
	t.Parallel()

	service := &testControlService{}
	adapter := &grpcService{service: service}
	ctx := context.Background()
	if _, err := adapter.ListInterfaces(ctx, controlapiv1.ListInterfacesRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.GetInterface(ctx, controlapiv1.GetInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.CreateInterface(ctx, controlapiv1.CreateInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.DeleteInterface(ctx, controlapiv1.DeleteInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ApplyPeers(ctx, controlapiv1.ApplyPeersRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.RestartInterface(ctx, controlapiv1.RestartInterfaceRequest_builder{}.Build()); err != nil {
		t.Fatal(err)
	}
	if got := service.calls.Load(); got != 6 {
		t.Fatalf("RPC calls = %d, want 6", got)
	}
}

func TestGRPCErrorMapsManagerCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code manager.Code
		want codes.Code
	}{
		{name: "invalid argument", code: manager.CodeInvalidArgument, want: codes.InvalidArgument},
		{name: "not found", code: manager.CodeNotFound, want: codes.NotFound},
		{name: "already exists", code: manager.CodeAlreadyExists, want: codes.AlreadyExists},
		{name: "aborted", code: manager.CodeAborted, want: codes.Aborted},
		{name: "failed precondition", code: manager.CodeFailedPrecondition, want: codes.FailedPrecondition},
		{name: "resource exhausted", code: manager.CodeResourceExhausted, want: codes.ResourceExhausted},
		{name: "unavailable", code: manager.CodeUnavailable, want: codes.Unavailable},
		{name: "internal", code: manager.CodeInternal, want: codes.Internal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := grpcError(manager.NewError(test.code, "failed"))
			if got := status.Code(err); got != test.want {
				t.Fatalf("status.Code() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestGRPCErrorPreservesStatusAndMapsUnknown(t *testing.T) {
	t.Parallel()

	existing := status.Error(codes.PermissionDenied, "denied")
	if got := grpcError(existing); !errors.Is(got, existing) {
		t.Fatalf("grpcError() = %v, want original status", got)
	}
	if got := status.Code(grpcError(errors.New("boom"))); got != codes.Internal {
		t.Fatalf("unknown status = %s, want %s", got, codes.Internal)
	}
}

func TestGRPCErrorMapsContextErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{name: "canceled", err: context.Canceled, want: codes.Canceled},
		{name: "deadline", err: context.DeadlineExceeded, want: codes.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := status.Code(grpcError(test.err)); got != test.want {
				t.Fatalf("status.Code() = %s, want %s", got, test.want)
			}
		})
	}
}
