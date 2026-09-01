//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"time"

	"github.com/kurochan/wg-frag-go/controlapi"
	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	"github.com/kurochan/wg-frag-go/internal/quick"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

const (
	reloadMutationRetryDelay = 100 * time.Millisecond
	quickReloadTimeout       = 2 * time.Minute
)

// restartApplier is injected by tests; the default submits to the daemon
// socket through the public control client.
type restartApplier func(
	ctx context.Context,
	socketPath string,
	request *controlapiv1.RestartInterfaceRequest,
) (*controlapiv1.RestartInterfaceResponse, error)

// quickReload rereads the persistent quick configuration and applies only
// runtime-owned changes. Route and hook state remains under quick's control,
// so changes to those fields require a stop/start operation.
func quickReload(args []string, stdout, stderr io.Writer) error {
	return quickReloadWith(args, stdout, stderr, getStatus, applyPeers, restartInterface)
}

func quickReloadWith(
	args []string,
	stdout, stderr io.Writer,
	get statusGetter,
	apply applier,
	restart restartApplier,
) error {
	if len(args) != 1 {
		return errors.New("usage: wgf quick reload <interface|config-file>")
	}
	target, err := resolveStartedTarget(args[0])
	if err != nil {
		return err
	}
	ifname, path := target.ifname, target.path
	if warning := legacyConfigWarning(target); warning != "" {
		fmt.Fprintln(stderr, warning)
	}
	if warning := quick.WarnLoosePermissions(path); warning != "" {
		fmt.Fprintln(stderr, warning)
	}

	unlock, err := acquireQuickLock(stderr, "reload", ifname)
	if err != nil {
		return err
	}
	defer unlock()
	reloadCtx, cancelReload := context.WithTimeout(context.Background(), quickReloadTimeout)
	defer cancelReload()

	oldInput, err := os.ReadFile(inputPath(ifname))
	if err != nil {
		return fmt.Errorf("read active quick configuration: %w", err)
	}
	oldSnapshot, err := os.ReadFile(snapshotPath(ifname))
	if err != nil {
		return fmt.Errorf("read active runtime configuration: %w", err)
	}
	// #nosec G703 -- The config path is explicitly selected by the operator.
	newInput, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	oldParsed, err := quick.Parse(string(oldInput))
	if err != nil {
		return fmt.Errorf("parse active quick configuration: %w", err)
	}
	newParsed, err := quick.Parse(string(newInput))
	if err != nil {
		return fmt.Errorf("parse configuration: %w", err)
	}
	oldRuntime, err := quick.Parse(string(oldSnapshot))
	if err != nil {
		return fmt.Errorf("parse active runtime configuration: %w", err)
	}
	manifest, err := readQuickManifest(ifname)
	if err != nil {
		return fmt.Errorf("read active quick resource manifest: %w", err)
	}
	if manifest.Phase != "active" {
		return errors.New("quick reload: interface is being torn down")
	}
	manifestAddresses, err := manifest.addresses()
	if err != nil {
		return fmt.Errorf("parse active quick resource manifest: %w", err)
	}
	if !reflect.DeepEqual(oldParsed.Config.Interface.Addresses, manifestAddresses) {
		return errors.New("active quick state is inconsistent; use `systemctl restart`")
	}
	if err := quickReloadResourcesEqual(oldParsed, newParsed); err != nil {
		return err
	}
	if !reflect.DeepEqual(newParsed.Config.Interface.Addresses, manifestAddresses) {
		return errors.New("interface addresses changed; use `systemctl restart` to apply them")
	}
	oldRoutes, err := manifest.routePlan()
	if err != nil {
		return fmt.Errorf("parse active quick routes: %w", err)
	}
	if !quickReloadRouteShapeEqual(oldRoutes, quick.PlanRoutes(oldParsed.Options, oldParsed.Config)) {
		return errors.New("active quick routes are inconsistent; use `systemctl restart`")
	}
	if !quickReloadRouteShapeEqual(oldRoutes, quick.PlanRoutes(newParsed.Options, newParsed.Config)) {
		return errors.New("quick-managed routes changed; use `systemctl restart` to apply them")
	}
	if _, err := wgadapter.PreparePeers(newParsed.Config); err != nil {
		return err
	}

	// An automatically selected quick mark is stored only in the runtime
	// snapshot. Keep using it when building the API request and new snapshot.
	desired := config.Clone(newParsed.Config)
	if manifest.FwMark != 0 && oldRuntime.Config.Interface.FwMark != manifest.FwMark {
		return errors.New("active quick mark is inconsistent; use `systemctl restart`")
	}
	if err := quickReloadFwMarkCompatible(
		oldParsed.Config.Interface.FwMark,
		oldRuntime.Config.Interface.FwMark,
		desired.Interface.FwMark,
	); err != nil {
		return err
	}
	if desired.Interface.FwMark == 0 {
		desired.Interface.FwMark = oldRuntime.Config.Interface.FwMark
	}
	status, err := get(reloadCtx, controlapi.SocketPath(ifname), ifname)
	if err != nil {
		return fmt.Errorf("is `wgf run %s` running? %w", ifname, err)
	}
	mutation, err := reloadMutation(status)
	if err != nil {
		return err
	}
	socket := controlapi.SocketPath(ifname)
	desiredPublic, err := derivePublicKey([32]byte(newParsed.Config.Interface.PrivateKey))
	if err != nil {
		return err
	}
	needsRestart := !restartSettingsEqual(ifname, status, desired) ||
		status.GetPublicKey() != encodePublicKey(desiredPublic)
	if err := validateReloadMetricsBinding(oldRuntime.Config, desired, needsRestart); err != nil {
		return err
	}

	var generation uint64
	if needsRestart {
		generation, err = reloadRestart(
			reloadCtx, socket, ifname, status, desired, mutation, restart,
		)
	} else {
		generation, err = reloadApplyPeers(
			reloadCtx, socket, ifname, desired.Peers, mutation, apply,
		)
	}
	if err != nil {
		// ApplyPeers can report per-peer failures after publishing the new
		// desired table. Restore the complete previous peer set before
		// returning the reload error so reload remains all-or-nothing.
		if !needsRestart && generation != 0 {
			rollbackErr := reloadRollbackWithTimeout(
				socket, ifname, status, oldRuntime.Config,
				generation, false, apply, restart,
			)
			if rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("reload rollback: %w", rollbackErr))
			}
		}
		return err
	}

	newSnapshot := quick.InjectFwMark(newParsed.Runtime, desired.Interface.FwMark)
	if err := persistReloadState(ifname, newInput, []byte(newSnapshot), oldInput); err != nil {
		rollbackErr := reloadRollbackWithTimeout(
			socket, ifname, status, oldRuntime.Config,
			generation, needsRestart, apply, restart,
		)
		if rollbackErr != nil {
			return errors.Join(err, rollbackErr)
		}
		return err
	}

	fmt.Fprintf(stdout, "reloaded %s (generation %d)\n", ifname, generation)
	if len(newParsed.Options.DNS) != 0 {
		fmt.Fprintln(stderr, "warning: DNS is not supported by wgf quick and was ignored")
	}
	return nil
}

func quickReloadFwMarkCompatible(configured, current, desired uint32) error {
	if configured != 0 && desired == 0 {
		return errors.New("FwMark was removed; use `systemctl restart` to apply it")
	}
	if desired != 0 && desired != current {
		return errors.New("FwMark changed; use `systemctl restart` to apply it")
	}
	return nil
}

func validateReloadMetricsBinding(oldConfig, desired *config.Config, needsRestart bool) error {
	if oldConfig == nil || desired == nil || !desired.Interface.Metrics || !desired.Interface.MetricsListen.Auto {
		return nil
	}
	if oldConfig.Interface.ListenPort != desired.Interface.ListenPort ||
		(needsRestart && desired.Interface.ListenPort == 0) {
		return errors.New("automatic metrics port may change; use `systemctl restart` to apply this configuration")
	}
	return nil
}

func encodePublicKey(key [32]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func quickReloadResourcesEqual(oldParsed, newParsed quick.Parsed) error {
	if !reflect.DeepEqual(oldParsed.Options, newParsed.Options) {
		return errors.New("quick-managed settings changed; use `systemctl restart` to apply them")
	}
	if !reflect.DeepEqual(oldParsed.Config.Interface.Addresses, newParsed.Config.Interface.Addresses) {
		return errors.New("interface addresses changed; use `systemctl restart` to apply them")
	}
	oldInterface := oldParsed.Config.Interface
	newInterface := newParsed.Config.Interface
	if oldInterface.Metrics != newInterface.Metrics ||
		!reflect.DeepEqual(oldInterface.MetricsListen, newInterface.MetricsListen) ||
		!reflect.DeepEqual(oldInterface.MetricsInclude, newInterface.MetricsInclude) ||
		!reflect.DeepEqual(oldInterface.MetricsExclude, newInterface.MetricsExclude) {
		return errors.New("process metrics settings changed; use `systemctl restart` to apply them")
	}
	oldRoutes := quick.PlanRoutes(oldParsed.Options, oldParsed.Config)
	newRoutes := quick.PlanRoutes(newParsed.Options, newParsed.Config)
	if !reflect.DeepEqual(oldRoutes, newRoutes) {
		return errors.New("quick-managed routes changed; use `systemctl restart` to apply them")
	}
	return nil
}

func quickReloadRouteShapeEqual(left, right quick.RoutePlan) bool {
	// Auto-selected table and mark values belong to the existing quick
	// resource set. Only the route prefixes, explicit table, and rule families
	// are relevant when deciding whether that set can be reused.
	left.FwMark = 0
	left.DefaultTable = 0
	right.FwMark = 0
	right.DefaultTable = 0
	return reflect.DeepEqual(left, right)
}

func reloadMutation(status *controlapiv1.InterfaceStatus) (*controlapiv1.MutationContext, error) {
	if status == nil || status.GetRef() == nil || len(status.GetRef().GetInterfaceInstanceId()) != 16 {
		return nil, errors.New("controlapi: status has an invalid interface instance ID")
	}
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, requestID); err != nil {
		return nil, fmt.Errorf("generate reload request ID: %w", err)
	}
	mutation := controlapiv1.MutationContext_builder{}.Build()
	mutation.SetRequestId(requestID)
	mutation.SetExpectedInstanceId(status.GetRef().GetInterfaceInstanceId())
	mutation.SetExpectedGeneration(status.GetGeneration())
	return mutation, nil
}

func reloadApplyPeers(
	ctx context.Context,
	socket, ifname string,
	peers []config.Peer,
	mutation *controlapiv1.MutationContext,
	apply applier,
) (uint64, error) {
	target := controlapiv1.InterfaceRef_builder{}.Build()
	target.SetInterfaceName(ifname)
	request := controlapiv1.ApplyPeersRequest_builder{
		Target:   target,
		Mutation: mutation,
		Peers:    desiredFromConfig(peers, true),
	}.Build()
	response, err := awaitReloadMutation(ctx, func() (*controlapiv1.ApplyPeersResponse, error) {
		return apply(ctx, socket, request)
	})
	if err != nil {
		return 0, err
	}
	if response == nil {
		return 0, errors.New("controlapi: ApplyPeers returned no response")
	}
	for _, result := range response.GetResults() {
		if result.GetError() != "" {
			return response.GetGeneration(), fmt.Errorf("peer %s: %s", result.GetPublicKey(), result.GetError())
		}
	}
	return response.GetGeneration(), nil
}

func reloadRestart(
	ctx context.Context,
	socket, ifname string,
	status *controlapiv1.InterfaceStatus,
	desired *config.Config,
	mutation *controlapiv1.MutationContext,
	restart restartApplier,
) (uint64, error) {
	public, err := derivePublicKey([32]byte(desired.Interface.PrivateKey))
	if err != nil {
		return 0, err
	}
	includePrivateKey := status.GetPublicKey() != encodePublicKey(public)
	return submitReloadRestart(ctx, socket, ifname, desired, mutation, includePrivateKey, restart)
}

func reloadRollback(
	ctx context.Context,
	socket, ifname string,
	status *controlapiv1.InterfaceStatus,
	oldConfig *config.Config,
	generation uint64,
	wasRestart bool,
	apply applier,
	restart restartApplier,
) error {
	mutation, err := reloadMutationForGeneration(status, generation)
	if err != nil {
		return err
	}
	if wasRestart {
		_, err = submitReloadRestart(ctx, socket, ifname, oldConfig, mutation, true, restart)
		return err
	}
	_, err = reloadApplyPeers(ctx, socket, ifname, oldConfig.Peers, mutation, apply)
	return err
}

func reloadRollbackWithTimeout(
	socket, ifname string,
	status *controlapiv1.InterfaceStatus,
	oldConfig *config.Config,
	generation uint64,
	wasRestart bool,
	apply applier,
	restart restartApplier,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), quickReloadTimeout)
	defer cancel()
	return reloadRollback(ctx, socket, ifname, status, oldConfig, generation, wasRestart, apply, restart)
}

func submitReloadRestart(
	ctx context.Context,
	socket, ifname string,
	desired *config.Config,
	mutation *controlapiv1.MutationContext,
	includePrivateKey bool,
	restart restartApplier,
) (uint64, error) {
	spec := controlconfig.SpecFromConfig(ifname, desired, true)
	if includePrivateKey {
		spec.SetPrivateKey(append([]byte(nil), desired.Interface.PrivateKey[:]...))
	} else {
		spec.ClearPrivateKey()
	}
	target := controlapiv1.InterfaceRef_builder{}.Build()
	target.SetInterfaceName(ifname)
	request := controlapiv1.RestartInterfaceRequest_builder{
		Target:   target,
		Mutation: mutation,
		Spec:     spec,
	}.Build()
	response, err := awaitReloadMutation(ctx, func() (*controlapiv1.RestartInterfaceResponse, error) {
		return restart(ctx, socket, request)
	})
	if err != nil {
		return 0, err
	}
	if response == nil || response.GetStatus() == nil {
		return 0, errors.New("controlapi: RestartInterface returned no status")
	}
	return response.GetStatus().GetGeneration(), nil
}

func reloadMutationForGeneration(status *controlapiv1.InterfaceStatus, generation uint64) (*controlapiv1.MutationContext, error) {
	mutation, err := reloadMutation(status)
	if err != nil {
		return nil, err
	}
	mutation.SetExpectedGeneration(generation)
	return mutation, nil
}

// An admitted mutation continues after its RPC deadline. Replaying the exact
// request is the only way to resolve that result without applying it twice.
func awaitReloadMutation[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	var zero T
	for {
		result, err := operation()
		if err == nil {
			return result, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return zero, ctxErr
		}
		if !ambiguousMutationError(err) {
			return result, err
		}
		timer := time.NewTimer(reloadMutationRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
}

func ambiguousMutationError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch grpcstatus.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable:
		return true
	default:
		return false
	}
}

func persistReloadState(ifname string, input, snapshot, oldInput []byte) error {
	if err := quick.WriteAtomic(inputPath(ifname), input); err != nil {
		return fmt.Errorf("write active quick configuration: %w", err)
	}
	if err := quick.WriteAtomic(snapshotPath(ifname), snapshot); err != nil {
		restoreErr := quick.WriteAtomic(inputPath(ifname), oldInput)
		if restoreErr != nil {
			return errors.Join(
				fmt.Errorf("write active runtime configuration: %w", err),
				fmt.Errorf("restore active quick configuration: %w", restoreErr),
			)
		}
		return fmt.Errorf("write active runtime configuration: %w", err)
	}
	return nil
}
