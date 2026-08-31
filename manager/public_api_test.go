//go:build linux || darwin

package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

func TestServiceMethodsRejectNilContext(t *testing.T) {
	t.Parallel()

	m := newManagerForTest(managerPlatform{}, 1, nil)
	var nilContext context.Context
	tests := []struct {
		name string
		call func() error
	}{
		{name: "list", call: func() error { _, err := m.ListInterfaces(nilContext, nil); return err }},
		{name: "get", call: func() error { _, err := m.GetInterface(nilContext, nil); return err }},
		{name: "create", call: func() error { _, err := m.CreateInterface(nilContext, nil); return err }},
		{name: "delete", call: func() error { _, err := m.DeleteInterface(nilContext, nil); return err }},
		{name: "apply peers", call: func() error { _, err := m.ApplyPeers(nilContext, nil); return err }},
		{name: "restart", call: func() error { _, err := m.RestartInterface(nilContext, nil); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.call(); CodeOf(err) != CodeInvalidArgument {
				t.Fatalf("nil context error = %v, want InvalidArgument", err)
			}
		})
	}
}

func TestManagerCloseIsIdempotentAfterContextTimeout(t *testing.T) {
	harness := newManagerTestHarness(1)
	_, _ = managerTestCreate(t, harness, "wgf0", 120)
	runtime := harness.runtimes[0]
	runtime.closeStarted = make(chan struct{})
	runtime.closeRelease = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := harness.manager.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close(canceled) = %v, want context canceled", err)
	}
	select {
	case <-runtime.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("manager cleanup did not start")
	}
	if runtime.closeCalls != 1 {
		t.Fatalf("runtime close calls before release = %d, want 1", runtime.closeCalls)
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- harness.manager.Close(context.Background()) }()
	select {
	case err := <-secondDone:
		t.Fatalf("second Close returned before cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(runtime.closeRelease)
	if err := <-secondDone; err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	if runtime.closeCalls != 1 || harness.anchor.closeCalls != 1 {
		t.Fatalf("cleanup calls = runtime %d/anchor %d, want 1/1", runtime.closeCalls, harness.anchor.closeCalls)
	}
	if err := harness.manager.Close(context.Background()); err != nil {
		t.Fatalf("third Close() = %v", err)
	}
}

func TestManagerCloseReturnsSameCleanupError(t *testing.T) {
	harness := newManagerTestHarness(1)
	_, _ = managerTestCreate(t, harness, "wgf0", 2)
	want := errors.New("anchor close failed")
	harness.anchor.closeErr = want
	first := harness.manager.Close(context.Background())
	second := harness.manager.Close(context.Background())
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("Close errors = %v/%v, want same cleanup error", first, second)
	}
}

var _ Service = ServiceStub{}

// ServiceStub keeps the public contract test independent from a runtime.
type ServiceStub struct{}

func (ServiceStub) ListInterfaces(context.Context, *controlapiv1.ListInterfacesRequest) (*controlapiv1.ListInterfacesResponse, error) {
	return nil, nil
}

func (ServiceStub) GetInterface(context.Context, *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	return nil, nil
}

func (ServiceStub) CreateInterface(context.Context, *controlapiv1.CreateInterfaceRequest) (*controlapiv1.CreateInterfaceResponse, error) {
	return nil, nil
}

func (ServiceStub) DeleteInterface(context.Context, *controlapiv1.DeleteInterfaceRequest) (*controlapiv1.DeleteInterfaceResponse, error) {
	return nil, nil
}

func (ServiceStub) ApplyPeers(context.Context, *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	return nil, nil
}

func (ServiceStub) RestartInterface(context.Context, *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
	return nil, nil
}
