//go:build linux || darwin

package manager

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/daemonruntime"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

type Manager struct {
	mu          sync.RWMutex
	closeMu     sync.Mutex
	closeOnce   sync.Once
	closeStart  sync.Once
	closeDone   chan struct{}
	closeErr    error
	interfaces  map[string]*interfaceSupervisor
	byPublicKey map[[32]byte]*interfaceSupervisor
	platform    managerPlatform
	logger      *slog.Logger
	max         int
	counters    *counterStore
	mutations   *mutationCache
	start       runtimeStarter
	closing     bool
	operations  sync.WaitGroup
}

// New creates a manager using the current operating system's TUN and UDP
// implementation. A Manager does not start any interface until
// CreateInterface is called.
func New(options Options) (*Manager, error) {
	if options.MaxInterfaces < 0 {
		return nil, NewError(CodeInvalidArgument, "max interfaces must not be negative")
	}
	factory := daemonruntime.DefaultFactory(options.Logger)
	manager := newManagerForTest(managerPlatform{openAnchor: factory.OpenAnchor}, options.maxInterfaces(), options.Logger)
	manager.start = func(supervisor *interfaceSupervisor, cfg *config.Config) (managedRuntime, error) {
		running, err := factory.Start(supervisor.name, supervisor.anchor, cfg)
		if err != nil {
			return nil, err
		}
		return &runtimeAdapter{runtime: running}, nil
	}
	return manager, nil
}

func newManagerForTest(platform managerPlatform, maxInterfaces int, logger *slog.Logger) *Manager {
	if maxInterfaces <= 0 {
		maxInterfaces = DefaultMaxInterfaces
	}
	manager := &Manager{
		closeDone:   make(chan struct{}),
		interfaces:  make(map[string]*interfaceSupervisor),
		byPublicKey: make(map[[32]byte]*interfaceSupervisor),
		platform:    platform,
		logger:      logger,
		max:         maxInterfaces,
		counters:    newCounterStore(counterStoreCapacity(maxInterfaces)),
		mutations:   newMutationCache(requestCacheEntries, requestCacheLifetime),
	}
	manager.start = func(*interfaceSupervisor, *config.Config) (managedRuntime, error) {
		return nil, errors.New("manager: runtime starter is not configured")
	}
	return manager
}

var _ Service = (*Manager)(nil)
var _ Lifecycle = (*Manager)(nil)

// ListInterfaces returns all interfaces currently owned by the manager.
func (manager *Manager) ListInterfaces(ctx context.Context, request *controlapiv1.ListInterfacesRequest) (*controlapiv1.ListInterfacesResponse, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	return manager.listInterfaces(ctx, request)
}

// GetInterface returns the observable state of one managed interface.
func (manager *Manager) GetInterface(ctx context.Context, request *controlapiv1.GetInterfaceRequest) (*controlapiv1.GetInterfaceResponse, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	return manager.getInterface(ctx, request)
}

// CreateInterface validates and starts an interface.
func (manager *Manager) CreateInterface(ctx context.Context, request *controlapiv1.CreateInterfaceRequest) (*controlapiv1.CreateInterfaceResponse, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	return manager.createInterface(ctx, request)
}

// DeleteInterface stops and removes an interface.
func (manager *Manager) DeleteInterface(ctx context.Context, request *controlapiv1.DeleteInterfaceRequest) (*controlapiv1.DeleteInterfaceResponse, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	return manager.deleteInterface(ctx, request)
}

// ApplyPeers replaces an interface's complete desired peer set without
// restarting its runtime generation.
func (manager *Manager) ApplyPeers(ctx context.Context, request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	return manager.applyPeers(ctx, request)
}

// RestartInterface replaces the runtime generation while retaining the TUN
// anchor and interface identity.
func (manager *Manager) RestartInterface(ctx context.Context, request *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	return manager.restartInterface(ctx, request)
}

// InterfaceCount returns the number of interfaces currently owned by the
// manager.
func (manager *Manager) InterfaceCount() int {
	if manager == nil {
		return 0
	}
	return manager.interfaceCount()
}

// EffectiveListenPort returns the UDP port selected for a running interface.
func (manager *Manager) EffectiveListenPort(interfaceName string) (uint16, error) {
	if manager == nil {
		return 0, NewError(CodeUnavailable, "nil manager")
	}
	manager.mu.RLock()
	supervisor := manager.interfaces[interfaceName]
	manager.mu.RUnlock()
	if supervisor == nil {
		return 0, NewError(CodeNotFound, "interface not found")
	}
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	supervisor.mu.RLock()
	running := supervisor.running
	supervisor.mu.RUnlock()
	if running == nil {
		return 0, NewError(CodeFailedPrecondition, "interface is not running")
	}
	return running.effectiveListenPort()
}

// DumpStats emits a low-frequency diagnostic snapshot for every running
// interface through the manager logger.
func (manager *Manager) DumpStats() {
	if manager == nil {
		return
	}
	for _, supervisor := range manager.supervisors() {
		supervisor.opMu.Lock()
		supervisor.mu.RLock()
		running := supervisor.running
		supervisor.mu.RUnlock()
		if running != nil {
			running.dumpStats()
		}
		supervisor.opMu.Unlock()
	}
}

// Close stops every interface owned by the manager. Once Close starts, new
// control operations fail with CodeUnavailable. If ctx expires, shutdown
// continues in the background and Close returns the context error.
func (manager *Manager) Close(ctx context.Context) error {
	if manager == nil {
		return nil
	}
	if ctx == nil {
		return NewError(CodeInvalidArgument, "nil close context")
	}
	manager.closeMu.Lock()
	if manager.closeDone == nil {
		manager.closeDone = make(chan struct{})
	}
	done := manager.closeDone
	manager.closeMu.Unlock()
	manager.closeStart.Do(func() { go func() { _ = manager.close() }() })
	select {
	case <-done:
		manager.closeMu.Lock()
		err := manager.closeErr
		manager.closeMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (manager *Manager) beginOperation() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closing {
		return NewError(CodeUnavailable, "interface manager is shutting down")
	}
	manager.operations.Add(1)
	return nil
}

func (manager *Manager) endOperation() {
	manager.operations.Done()
}

func (manager *Manager) counterBase(key [32]byte) *controlapiv1.ShimCounters {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.counters.get(key)
}

func (manager *Manager) interfaceCount() int {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return len(manager.interfaces)
}

func (manager *Manager) supervisors() []*interfaceSupervisor {
	manager.mu.RLock()
	items := make([]*interfaceSupervisor, 0, len(manager.interfaces))
	for _, supervisor := range manager.interfaces {
		items = append(items, supervisor)
	}
	manager.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	return items
}

func (manager *Manager) close() error {
	manager.closeMu.Lock()
	if manager.closeDone == nil {
		manager.closeDone = make(chan struct{})
	}
	done := manager.closeDone
	manager.closeMu.Unlock()
	manager.closeOnce.Do(func() {
		err := manager.stopAll()
		manager.closeMu.Lock()
		manager.closeErr = err
		manager.closeMu.Unlock()
		close(done)
	})
	<-done
	manager.closeMu.Lock()
	err := manager.closeErr
	manager.closeMu.Unlock()
	return err
}

func (manager *Manager) stopAll() error {
	manager.mu.Lock()
	manager.closing = true
	manager.mu.Unlock()
	manager.operations.Wait()
	items := manager.supervisors()
	var errs []error
	for _, supervisor := range items {
		if err := supervisor.stopAndDelete(); err != nil {
			errs = append(errs, err)
			continue
		}
		manager.removeSupervisor(supervisor)
	}
	return errors.Join(errs...)
}
