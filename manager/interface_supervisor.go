//go:build linux || darwin

package manager

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

type interfaceSupervisor struct {
	opMu sync.Mutex
	mu   sync.RWMutex

	manager      *Manager
	name         string
	instanceID   [16]byte
	lifecycle    controlapiv1.InterfaceLifecycle
	lifecycleErr string
	generation   uint64
	config       *config.Config
	publicKey    [32]byte
	anchor       runtimeTUNAnchor
	running      managedRuntime
	lastStatus   *controlapiv1.InterfaceStatus
}

func (supervisor *interfaceSupervisor) startInitial() error {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()

	if supervisor.manager.platform.openAnchor == nil {
		return errors.New("manager: TUN anchor opener is not configured")
	}
	anchor, err := supervisor.manager.platform.openAnchor(supervisor.name, supervisor.config.Interface.MTU)
	if err != nil {
		return fmt.Errorf("create TUN anchor: %w", err)
	}
	supervisor.anchor = anchor
	running, err := supervisor.startGeneration(supervisor.config)
	if err != nil {
		closeErr := anchor.Close()
		if closeErr == nil {
			supervisor.anchor = nil
			supervisor.mu.Lock()
			supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR
			supervisor.lifecycleErr = err.Error()
			supervisor.mu.Unlock()
		} else {
			joined := errors.Join(err, fmt.Errorf("close TUN anchor: %w", closeErr))
			supervisor.mu.Lock()
			supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR
			supervisor.lifecycleErr = joined.Error()
			supervisor.mu.Unlock()
			return joined
		}
		return err
	}
	supervisor.mu.Lock()
	supervisor.running = running
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING
	supervisor.lifecycleErr = ""
	supervisor.mu.Unlock()
	go supervisor.watch(running)
	return nil
}

func (supervisor *interfaceSupervisor) cleanupComplete() bool {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	supervisor.mu.RLock()
	defer supervisor.mu.RUnlock()
	return supervisor.anchor == nil && supervisor.running == nil
}

func (supervisor *interfaceSupervisor) startGeneration(cfg *config.Config) (managedRuntime, error) {
	return supervisor.manager.start(supervisor, cfg)
}

func (supervisor *interfaceSupervisor) applyPeerRequest(
	request *controlapiv1.ApplyPeersRequest,
) (*controlapiv1.ApplyPeersResponse, error) {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	if err := supervisor.checkMutation(request.GetMutation()); err != nil {
		return nil, err
	}

	supervisor.mu.RLock()
	running := supervisor.running
	lifecycle := supervisor.lifecycle
	currentConfig := config.Clone(supervisor.config)
	supervisor.mu.RUnlock()
	if lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING || running == nil {
		return nil, NewError(CodeFailedPrecondition, "interface is not running")
	}
	desired, err := controlconfig.PeersFromSpec(request.GetPeers(), currentConfig)
	if err != nil {
		return nil, NewError(CodeInvalidArgument, err.Error())
	}
	if err := config.ValidatePeers(desired); err != nil {
		return nil, NewError(CodeInvalidArgument, err.Error())
	}
	response, err := running.applyPeers(request)
	if err != nil {
		return nil, err
	}
	supervisor.mu.Lock()
	supervisor.generation++
	response.SetGeneration(supervisor.generation)
	supervisor.config = running.configSnapshot()
	supervisor.mu.Unlock()
	return response, nil
}

func (supervisor *interfaceSupervisor) checkMutation(mutation *controlapiv1.MutationContext) error {
	if mutation == nil {
		return NewError(CodeInvalidArgument, "missing mutation context")
	}
	if _, err := parseRequestID(mutation.GetRequestId()); err != nil {
		return NewError(CodeInvalidArgument, err.Error())
	}
	if !bytes.Equal(mutation.GetExpectedInstanceId(), supervisor.instanceID[:]) {
		return NewError(CodeAborted, "interface instance changed")
	}
	supervisor.mu.RLock()
	generation := supervisor.generation
	supervisor.mu.RUnlock()
	if mutation.GetExpectedGeneration() != generation {
		return Errorf(CodeAborted, "generation conflict: expected %d, current %d", mutation.GetExpectedGeneration(), generation)
	}
	return nil
}

func (supervisor *interfaceSupervisor) restartRequest(
	request *controlapiv1.RestartInterfaceRequest,
) (*controlapiv1.RestartInterfaceResponse, error) {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	if request.GetSpec().GetInterfaceName() != supervisor.name {
		return nil, NewError(CodeInvalidArgument, "interface name cannot change during restart")
	}
	if err := supervisor.checkMutation(request.GetMutation()); err != nil {
		return nil, err
	}
	supervisor.mu.RLock()
	lifecycle := supervisor.lifecycle
	currentConfig := config.Clone(supervisor.config)
	supervisor.mu.RUnlock()
	if lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING &&
		lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR {
		return nil, Errorf(CodeFailedPrecondition, "interface cannot restart while %s", lifecycle)
	}
	next, err := controlconfig.Create(request.GetSpec(), currentConfig)
	if err != nil {
		return nil, NewError(CodeInvalidArgument, err.Error())
	}
	if err := supervisor.restartLocked(next); err != nil {
		return nil, err
	}
	current, err := supervisor.statusLocked(false)
	if err != nil {
		return nil, err
	}
	response := controlapiv1.RestartInterfaceResponse_builder{}.Build()
	response.SetStatus(current)
	return response, nil
}

func (supervisor *interfaceSupervisor) restartLocked(next *config.Config) error {
	plan, err := wgadapter.PreparePeers(next)
	if err != nil {
		return NewError(CodeInvalidArgument, err.Error())
	}
	newKey := plan.LocalPublicKey
	supervisor.mu.RLock()
	oldKey := supervisor.publicKey
	supervisor.mu.RUnlock()
	supervisor.mu.Lock()
	oldConfig := config.Clone(supervisor.config)
	oldRunning := supervisor.running
	oldGeneration := supervisor.generation
	oldLifecycle := supervisor.lifecycle
	oldLifecycleErr := supervisor.lifecycleErr
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RESTARTING
	supervisor.lifecycleErr = ""
	supervisor.mu.Unlock()
	if err := supervisor.manager.reservePublicKeyChange(supervisor, oldKey, newKey); err != nil {
		supervisor.mu.Lock()
		supervisor.lifecycle = oldLifecycle
		supervisor.lifecycleErr = oldLifecycleErr
		supervisor.mu.Unlock()
		return err
	}

	if oldRunning != nil {
		closeErr := oldRunning.close()
		if closeErr != nil {
			supervisor.manager.restorePublicKeyChange(supervisor, oldKey, newKey)
			err := fmt.Errorf("stop previous runtime: %w", closeErr)
			supervisor.mu.Lock()
			supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR
			supervisor.lifecycleErr = err.Error()
			supervisor.mu.Unlock()
			return err
		}
		supervisor.captureCountersFor(oldRunning, oldKey)
		supervisor.mu.Lock()
		if supervisor.running == oldRunning {
			supervisor.running = nil
		}
		supervisor.mu.Unlock()
	}

	running, err := supervisor.startGeneration(next)
	if err != nil {
		supervisor.manager.restorePublicKeyChange(supervisor, oldKey, newKey)
		return supervisor.rollback(oldConfig, oldGeneration, err)
	}
	supervisor.mu.Lock()
	supervisor.running = running
	supervisor.config = config.Clone(next)
	supervisor.publicKey = newKey
	supervisor.generation = oldGeneration + 1
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING
	supervisor.lifecycleErr = ""
	supervisor.lastStatus = nil
	supervisor.mu.Unlock()
	supervisor.manager.commitPublicKeyChange(supervisor, oldKey, newKey)
	go supervisor.watch(running)
	if supervisor.manager.logger != nil {
		supervisor.manager.logger.Info(
			"interface restarted",
			"interface", supervisor.name,
			"generation", oldGeneration+1,
			"mtu", next.Interface.MTU,
			"peers", len(next.Peers),
		)
	}
	return nil
}

func (supervisor *interfaceSupervisor) rollback(oldConfig *config.Config, generation uint64, cause error) error {
	supervisor.mu.Lock()
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ROLLING_BACK
	supervisor.lifecycleErr = cause.Error()
	supervisor.mu.Unlock()
	running, rollbackErr := supervisor.startGeneration(oldConfig)
	if rollbackErr != nil {
		joined := errors.Join(cause, fmt.Errorf("rollback runtime: %w", rollbackErr))
		supervisor.setError(joined)
		return joined
	}
	supervisor.mu.Lock()
	supervisor.running = running
	supervisor.config = config.Clone(oldConfig)
	// A successful rollback still creates a new runtime generation. Advancing
	// it prevents a mutation based on the stopped runtime from being accepted.
	supervisor.generation = generation + 1
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING
	supervisor.lifecycleErr = ""
	supervisor.mu.Unlock()
	go supervisor.watch(running)
	if supervisor.manager.logger != nil {
		supervisor.manager.logger.Warn(
			"interface restart failed; previous configuration restored",
			"interface", supervisor.name,
			"generation", generation+1,
			"error", cause,
		)
	}
	return fmt.Errorf("restart failed; previous runtime restored: %w", cause)
}

func (supervisor *interfaceSupervisor) watch(running managedRuntime) {
	err := running.wait()
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	supervisor.mu.RLock()
	isCurrent := supervisor.running == running &&
		supervisor.lifecycle == controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING
	supervisor.mu.RUnlock()
	if !isCurrent {
		return
	}
	supervisor.captureCounters(running)
	if err == nil {
		err = errors.New("runtime stopped unexpectedly")
	}
	supervisor.setError(err)
	if supervisor.manager.logger != nil {
		supervisor.manager.logger.Error("interface runtime stopped", "interface", supervisor.name, "error", err)
	}
}

func (supervisor *interfaceSupervisor) setError(err error) {
	supervisor.mu.Lock()
	supervisor.running = nil
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR
	supervisor.lifecycleErr = err.Error()
	supervisor.mu.Unlock()
}

func (supervisor *interfaceSupervisor) stopAndDelete() error {
	supervisor.opMu.Lock()
	defer supervisor.opMu.Unlock()
	return supervisor.stopAndDeleteLocked()
}

func (supervisor *interfaceSupervisor) stopAndDeleteLocked() error {
	supervisor.mu.Lock()
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_DELETING
	running := supervisor.running
	anchor := supervisor.anchor
	supervisor.mu.Unlock()
	var errs []error
	if running != nil {
		closeErr := running.close()
		if closeErr != nil {
			errs = append(errs, closeErr)
		} else {
			supervisor.captureCounters(running)
			supervisor.mu.Lock()
			if supervisor.running == running {
				supervisor.running = nil
			}
			supervisor.mu.Unlock()
		}
	}
	if anchor != nil {
		closeErr := anchor.Close()
		if closeErr != nil {
			errs = append(errs, closeErr)
		} else {
			supervisor.mu.Lock()
			if supervisor.anchor == anchor {
				supervisor.anchor = nil
			}
			supervisor.mu.Unlock()
		}
	}
	if err := errors.Join(errs...); err != nil {
		supervisor.mu.Lock()
		supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR
		supervisor.lifecycleErr = err.Error()
		supervisor.mu.Unlock()
		return err
	}
	return nil
}
