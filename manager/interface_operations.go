//go:build linux || darwin

package manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	"github.com/kurochan/wg-frag-go/internal/interfacename"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/protobuf/proto"
)

func (manager *Manager) create(name string, cfg *config.Config) (*interfaceSupervisor, error) {
	if cfg == nil {
		return nil, errors.New("nil interface configuration")
	}
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	plan, err := wgadapter.PreparePeers(cfg)
	if err != nil {
		return nil, err
	}
	if !interfacename.Valid(name) {
		return nil, NewError(CodeInvalidArgument, "invalid interface name")
	}

	supervisor := &interfaceSupervisor{
		manager:   manager,
		name:      name,
		lifecycle: controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_CREATING,
		config:    config.Clone(cfg),
		publicKey: plan.LocalPublicKey,
	}
	if _, err := rand.Read(supervisor.instanceID[:]); err != nil {
		return nil, fmt.Errorf("generate interface instance ID: %w", err)
	}

	manager.mu.Lock()
	if len(manager.interfaces) >= manager.max {
		manager.mu.Unlock()
		return nil, Errorf(CodeResourceExhausted, "interface limit %d reached", manager.max)
	}
	if _, exists := manager.interfaces[name]; exists {
		manager.mu.Unlock()
		return nil, Errorf(CodeAlreadyExists, "interface %q already exists", name)
	}
	if manager.byPublicKey[supervisor.publicKey] != nil {
		manager.mu.Unlock()
		return nil, NewError(CodeAlreadyExists, "interface public key is already active")
	}
	manager.interfaces[name] = supervisor
	manager.byPublicKey[supervisor.publicKey] = supervisor
	manager.mu.Unlock()

	if err := supervisor.startInitial(); err != nil {
		if supervisor.cleanupComplete() {
			manager.removeSupervisor(supervisor)
		}
		return nil, err
	}
	if manager.logger != nil {
		manager.logger.Info(
			"interface started",
			"interface", supervisor.name,
			"native_interface", supervisor.anchor.Name(),
			"mtu", supervisor.config.Interface.MTU,
			"peers", len(supervisor.config.Peers),
		)
	}
	return supervisor, nil
}

func (manager *Manager) lookup(ref *controlapiv1.InterfaceRef) (*interfaceSupervisor, error) {
	if ref == nil || ref.GetInterfaceName() == "" {
		return nil, NewError(CodeInvalidArgument, "missing interface target")
	}
	manager.mu.RLock()
	supervisor := manager.interfaces[ref.GetInterfaceName()]
	manager.mu.RUnlock()
	if supervisor == nil {
		return nil, NewError(CodeNotFound, "interface not found")
	}
	if instance := ref.GetInterfaceInstanceId(); len(instance) != 0 && !bytes.Equal(instance, supervisor.instanceID[:]) {
		return nil, NewError(CodeAborted, "interface instance changed")
	}
	return supervisor, nil
}

func (manager *Manager) listInterfaces(
	_ context.Context,
	_ *controlapiv1.ListInterfacesRequest,
) (*controlapiv1.ListInterfacesResponse, error) {
	if err := manager.beginOperation(); err != nil {
		return nil, err
	}
	defer manager.endOperation()
	items := manager.supervisors()
	statuses := make([]*controlapiv1.InterfaceStatus, 0, len(items))
	for _, supervisor := range items {
		current, err := supervisor.status(false)
		if err != nil {
			current = supervisor.diagnosticErrorStatus(err, false)
		}
		statuses = append(statuses, current)
	}
	response := controlapiv1.ListInterfacesResponse_builder{}.Build()
	response.SetInterfaces(statuses)
	return response, nil
}

func (manager *Manager) getInterface(
	_ context.Context,
	request *controlapiv1.GetInterfaceRequest,
) (*controlapiv1.GetInterfaceResponse, error) {
	if err := manager.beginOperation(); err != nil {
		return nil, err
	}
	defer manager.endOperation()
	if request == nil {
		return nil, NewError(CodeInvalidArgument, "nil GetInterface request")
	}
	supervisor, err := manager.lookup(request.GetTarget())
	if err != nil {
		return nil, err
	}
	current, err := supervisor.status(request.GetIncludeSecrets())
	if err != nil {
		current = supervisor.diagnosticErrorStatus(err, request.GetIncludeSecrets())
	}
	response := controlapiv1.GetInterfaceResponse_builder{}.Build()
	response.SetStatus(current)
	return response, nil
}

func (manager *Manager) createInterface(
	ctx context.Context,
	request *controlapiv1.CreateInterfaceRequest,
) (*controlapiv1.CreateInterfaceResponse, error) {
	if err := manager.beginOperation(); err != nil {
		return nil, err
	}
	defer manager.endOperation()
	if request == nil || request.GetSpec() == nil {
		return nil, NewError(CodeInvalidArgument, "missing interface spec")
	}
	requestID, err := parseRequestID(request.GetRequestId())
	if err != nil {
		return nil, NewError(CodeInvalidArgument, err.Error())
	}
	canonical := proto.Clone(request).(*controlapiv1.CreateInterfaceRequest)
	canonical.SetRequestId(nil)
	hash, err := mutationRequestHash("CreateInterface", canonical)
	if err != nil {
		return nil, err
	}
	result, err := manager.mutations.execute(ctx, requestID, hash, func() (proto.Message, error) {
		cfg, configErr := controlconfig.Create(request.GetSpec(), nil)
		if configErr != nil {
			return nil, NewError(CodeInvalidArgument, configErr.Error())
		}
		if _, configErr = wgadapter.PreparePeers(cfg); configErr != nil {
			return nil, NewError(CodeInvalidArgument, configErr.Error())
		}
		supervisor, createErr := manager.create(request.GetSpec().GetInterfaceName(), cfg)
		if createErr != nil {
			return nil, createErr
		}
		current, statusErr := supervisor.status(false)
		if statusErr != nil {
			cleanupErr := supervisor.stopAndDelete()
			if cleanupErr == nil {
				manager.removeSupervisor(supervisor)
				return nil, statusErr
			}
			return nil, errors.Join(statusErr, cleanupErr)
		}
		response := controlapiv1.CreateInterfaceResponse_builder{}.Build()
		response.SetStatus(current)
		return response, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(*controlapiv1.CreateInterfaceResponse), nil
}

func (manager *Manager) deleteInterface(
	ctx context.Context,
	request *controlapiv1.DeleteInterfaceRequest,
) (*controlapiv1.DeleteInterfaceResponse, error) {
	if err := manager.beginOperation(); err != nil {
		return nil, err
	}
	defer manager.endOperation()
	if request == nil {
		return nil, NewError(CodeInvalidArgument, "nil DeleteInterface request")
	}
	requestID, err := mutationID(request.GetMutation())
	if err != nil {
		return nil, NewError(CodeInvalidArgument, err.Error())
	}
	canonical := proto.Clone(request).(*controlapiv1.DeleteInterfaceRequest)
	canonical.GetMutation().SetRequestId(nil)
	hash, err := mutationRequestHash("DeleteInterface", canonical)
	if err != nil {
		return nil, err
	}
	result, err := manager.mutations.execute(ctx, requestID, hash, func() (proto.Message, error) {
		supervisor, lookupErr := manager.lookup(request.GetTarget())
		if lookupErr != nil {
			return nil, lookupErr
		}
		if deleteErr := manager.deleteSupervisor(supervisor, request.GetMutation()); deleteErr != nil {
			return nil, deleteErr
		}
		return controlapiv1.DeleteInterfaceResponse_builder{}.Build(), nil
	})
	if err != nil {
		return nil, err
	}
	return result.(*controlapiv1.DeleteInterfaceResponse), nil
}

func (manager *Manager) applyPeers(
	ctx context.Context,
	request *controlapiv1.ApplyPeersRequest,
) (*controlapiv1.ApplyPeersResponse, error) {
	if err := manager.beginOperation(); err != nil {
		return nil, err
	}
	defer manager.endOperation()
	if request == nil {
		return nil, NewError(CodeInvalidArgument, "nil ApplyPeers request")
	}
	requestID, err := mutationID(request.GetMutation())
	if err != nil {
		return nil, NewError(CodeInvalidArgument, err.Error())
	}
	canonical := proto.Clone(request).(*controlapiv1.ApplyPeersRequest)
	canonical.GetMutation().SetRequestId(nil)
	hash, err := mutationRequestHash("ApplyPeers", canonical)
	if err != nil {
		return nil, err
	}
	result, err := manager.mutations.execute(ctx, requestID, hash, func() (proto.Message, error) {
		supervisor, lookupErr := manager.lookup(request.GetTarget())
		if lookupErr != nil {
			return nil, lookupErr
		}
		return supervisor.applyPeerRequest(request)
	})
	if err != nil {
		return nil, err
	}
	return result.(*controlapiv1.ApplyPeersResponse), nil
}

func (manager *Manager) restartInterface(
	ctx context.Context,
	request *controlapiv1.RestartInterfaceRequest,
) (*controlapiv1.RestartInterfaceResponse, error) {
	if err := manager.beginOperation(); err != nil {
		return nil, err
	}
	defer manager.endOperation()
	if request == nil || request.GetSpec() == nil {
		return nil, NewError(CodeInvalidArgument, "missing interface spec")
	}
	requestID, err := mutationID(request.GetMutation())
	if err != nil {
		return nil, NewError(CodeInvalidArgument, err.Error())
	}
	canonical := proto.Clone(request).(*controlapiv1.RestartInterfaceRequest)
	canonical.GetMutation().SetRequestId(nil)
	hash, err := mutationRequestHash("RestartInterface", canonical)
	if err != nil {
		return nil, err
	}
	result, err := manager.mutations.execute(ctx, requestID, hash, func() (proto.Message, error) {
		supervisor, lookupErr := manager.lookup(request.GetTarget())
		if lookupErr != nil {
			return nil, lookupErr
		}
		return supervisor.restartRequest(request)
	})
	if err != nil {
		return nil, err
	}
	return result.(*controlapiv1.RestartInterfaceResponse), nil
}

func (manager *Manager) deleteSupervisor(
	supervisor *interfaceSupervisor,
	mutation *controlapiv1.MutationContext,
) error {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	if err := supervisor.checkMutation(mutation); err != nil {
		return err
	}
	supervisor.mu.RLock()
	lifecycle := supervisor.lifecycle
	supervisor.mu.RUnlock()
	if lifecycle == controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_DELETING {
		return NewError(CodeFailedPrecondition, "interface is already being deleted")
	}
	stopErr := supervisor.stopAndDeleteLocked()
	if stopErr == nil {
		manager.removeSupervisor(supervisor)
	}
	if stopErr == nil && manager.logger != nil {
		manager.logger.Info("interface deleted", "interface", supervisor.name)
	}
	return stopErr
}

func (manager *Manager) reservePublicKeyChange(
	supervisor *interfaceSupervisor,
	oldKey, newKey [32]byte,
) error {
	if oldKey == newKey {
		return nil
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if existing := manager.byPublicKey[newKey]; existing != nil && existing != supervisor {
		return NewError(CodeAlreadyExists, "interface public key is already active")
	}
	if existing := manager.byPublicKey[oldKey]; existing != supervisor {
		return NewError(CodeInternal, "interface public key ownership changed")
	}
	// Keep the old key reserved until the new runtime has started. This
	// prevents another interface from claiming it during the transition.
	manager.byPublicKey[newKey] = supervisor
	manager.byPublicKey[oldKey] = supervisor
	return nil
}

func (manager *Manager) commitPublicKeyChange(
	supervisor *interfaceSupervisor,
	oldKey, newKey [32]byte,
) {
	if oldKey == newKey {
		return
	}
	manager.mu.Lock()
	if manager.byPublicKey[oldKey] == supervisor {
		delete(manager.byPublicKey, oldKey)
	}
	manager.mu.Unlock()
}

func (manager *Manager) restorePublicKeyChange(
	supervisor *interfaceSupervisor,
	oldKey, newKey [32]byte,
) {
	if oldKey == newKey {
		return
	}
	manager.mu.Lock()
	if manager.byPublicKey[newKey] == supervisor {
		delete(manager.byPublicKey, newKey)
	}
	if manager.byPublicKey[oldKey] == nil || manager.byPublicKey[oldKey] == supervisor {
		manager.byPublicKey[oldKey] = supervisor
	}
	manager.mu.Unlock()
}

func (manager *Manager) removeSupervisor(supervisor *interfaceSupervisor) {
	manager.mu.Lock()
	if manager.interfaces[supervisor.name] == supervisor {
		delete(manager.interfaces, supervisor.name)
	}
	for key, owner := range manager.byPublicKey {
		if owner == supervisor {
			delete(manager.byPublicKey, key)
		}
	}
	manager.mu.Unlock()
}
