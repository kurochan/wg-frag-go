//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/quick"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func quickTestConfig(tableLine string) string {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	peerKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	return "[Interface]\nPrivateKey = " + privateKey + "\n" + tableLine +
		"[Peer]\nPublicKey = " + peerKey + "\nAllowedIPs = 0.0.0.0/0\n"
}

func TestLoadQuickDownStateRejectsBrokenRuntimeConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	input := filepath.Join(dir, "runtime.conf")
	fallback := filepath.Join(dir, "original.conf")
	route := filepath.Join(dir, "route")
	if err := os.WriteFile(input, []byte("[Interface]\nPrivateKey = not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadQuickDownState(input, fallback, route); err == nil {
		t.Fatal("loadQuickDownState accepted an invalid runtime config")
	}
}

func TestLoadQuickDownStateDoesNotIgnoreMissingRouteState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	input := filepath.Join(dir, "runtime.conf")
	if err := os.WriteFile(input, []byte(quickTestConfig("Table = auto\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadQuickDownState(input, filepath.Join(dir, "unused.conf"), filepath.Join(dir, "missing.route"))
	if err == nil || !strings.Contains(err.Error(), "read route state") {
		t.Fatalf("loadQuickDownState error = %v, want missing route state", err)
	}
}

func TestLoadQuickDownStateFallsBackToOriginalConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	input := filepath.Join(dir, "missing-runtime.conf")
	fallback := filepath.Join(dir, "original.conf")
	route := filepath.Join(dir, "unused.route")
	config := quickTestConfig("Table = off\nPreDown = echo down\n")
	if err := os.WriteFile(fallback, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	options, planned, err := loadQuickDownState(input, fallback, route)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.PreDown) != 1 || options.PreDown[0] != "echo down" {
		t.Fatalf("PreDown = %#v", options.PreDown)
	}
	if planned.FwMark != 0 || len(planned.Specific) != 0 || planned.SpecificTable != 0 ||
		len(planned.Defaults) != 0 || planned.DefaultTable != 0 || planned.RulesV4 || planned.RulesV6 {
		t.Fatalf("planned routes = %+v, want empty", planned)
	}
}

func TestReadDaemonPidTreatsMissingFilesAsStopped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pid, err := readDaemonPidFromPaths("wgf0", filepath.Join(dir, "missing.pid"), filepath.Join(dir, "missing.sock"))
	if err != nil || pid != 0 {
		t.Fatalf("readDaemonPidFromPaths() = (%d, %v), want (0, nil)", pid, err)
	}
}

func TestReadDaemonPidRejectsLiveDaemonWithoutPidFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "wgf0.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	_, err = readDaemonPidFromPaths("wgf0", filepath.Join(dir, "missing.pid"), socket)
	if err == nil || !strings.Contains(err.Error(), "control socket is live") {
		t.Fatalf("readDaemonPidFromPaths() error = %v, want live-socket error", err)
	}
}

func TestQuickManifestRoundTripOwnsResources(t *testing.T) {
	t.Parallel()
	parsed, err := quick.Parse(quickTestConfig("Table = off\n"))
	if err != nil {
		t.Fatal(err)
	}
	plan := quick.PlanRoutes(parsed.Options, parsed.Config)
	manifest := newQuickManifest(parsed, plan)
	manifest.Phase = "tearing_down"
	roundTrip, err := manifest.routePlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(roundTrip.Specific) != len(plan.Specific) || roundTrip.SpecificTable != plan.SpecificTable {
		t.Fatalf("route plan = %+v, want %+v", roundTrip, plan)
	}
	addresses, err := manifest.addresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != len(parsed.Config.Interface.Addresses) {
		t.Fatalf("addresses = %v, want %v", addresses, parsed.Config.Interface.Addresses)
	}
}

func TestTeardownBlackholeRulesProtectOwnedPrefixes(t *testing.T) {
	t.Parallel()
	plan := quick.RoutePlan{
		Specific:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Defaults:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		FwMark:       51820,
		DefaultTable: 51820,
		RulesV4:      true,
	}
	rules := teardownBlackholeRules(plan)
	if len(rules) != 2 {
		t.Fatalf("blackhole rules = %d, want default and specific rules", len(rules))
	}
	if !rules[0].Invert || rules[0].Mark != plan.FwMark || rules[0].Dst != nil {
		t.Fatalf("default blackhole rule = %+v", rules[0])
	}
	if rules[1].Dst == nil || rules[1].Dst.String() != "10.0.0.0/8" {
		t.Fatalf("specific blackhole rule = %+v", rules[1])
	}
}

func TestQuickReloadResourcesEqualAllowsRuntimeOnlyChanges(t *testing.T) {
	t.Parallel()
	old, err := quick.Parse(quickTestConfig("Table = auto\n"))
	if err != nil {
		t.Fatal(err)
	}
	updatedText := strings.Replace(quickTestConfig("Table = auto\n"),
		"AllowedIPs = 0.0.0.0/0", "Endpoint = 192.0.2.10:51820\nAllowedIPs = 0.0.0.0/0", 1)
	updated, err := quick.Parse(updatedText)
	if err != nil {
		t.Fatal(err)
	}
	if err := quickReloadResourcesEqual(old, updated); err != nil {
		t.Fatalf("runtime-only reload rejected: %v", err)
	}
}

func TestQuickReloadResourcesEqualRejectsQuickStateChanges(t *testing.T) {
	t.Parallel()
	old, err := quick.Parse(quickTestConfig("Table = auto\n"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "table",
			text: quickTestConfig("Table = off\n"),
			want: "quick-managed settings",
		},
		{
			name: "address",
			text: strings.Replace(quickTestConfig("Table = auto\n"),
				"[Peer]", "Address = 10.0.0.1/24\n\n[Peer]", 1),
			want: "interface addresses",
		},
		{
			name: "allowed-ips",
			text: strings.Replace(quickTestConfig("Table = auto\n"),
				"0.0.0.0/0", "10.0.0.0/24", 1),
			want: "quick-managed routes",
		},
		{
			name: "metrics",
			text: strings.Replace(quickTestConfig("Table = auto\n"),
				"PrivateKey", "WGFMetrics = on\nPrivateKey", 1),
			want: "process metrics",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updated, err := quick.Parse(test.text)
			if err != nil {
				t.Fatal(err)
			}
			if err := quickReloadResourcesEqual(old, updated); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("quickReloadResourcesEqual() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestQuickReloadAllowsMakingAutoSelectedFwMarkExplicit(t *testing.T) {
	t.Parallel()
	old, err := quick.Parse(quickTestConfig("Table = auto\n"))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := quick.Parse(strings.Replace(
		quickTestConfig("Table = auto\n"),
		"PrivateKey", "FwMark = 51820\nPrivateKey", 1,
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := quickReloadResourcesEqual(old, updated); err != nil {
		t.Fatalf("resource comparison rejected explicit auto mark: %v", err)
	}
	if err := quickReloadFwMarkCompatible(0, 51820, updated.Config.Interface.FwMark); err != nil {
		t.Fatalf("active mark comparison rejected matching mark: %v", err)
	}
	if err := quickReloadFwMarkCompatible(0, 51820, 51821); err == nil {
		t.Fatal("active mark comparison accepted a changed mark")
	}
	if err := quickReloadFwMarkCompatible(51820, 51820, 0); err == nil {
		t.Fatal("active mark comparison accepted removal of an explicit mark")
	}
}

func TestReloadMutationCopiesStatusIdentity(t *testing.T) {
	t.Parallel()
	status := testStatusResponse(9, nil)
	ref := controlapiv1.InterfaceRef_builder{}.Build()
	ref.SetInterfaceName("wgf0")
	ref.SetInterfaceInstanceId(bytes.Repeat([]byte{1}, 16))
	status.SetRef(ref)
	mutation, err := reloadMutation(status)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mutation.GetExpectedInstanceId(), ref.GetInterfaceInstanceId()) ||
		mutation.GetExpectedGeneration() != 9 || len(mutation.GetRequestId()) != 16 {
		t.Fatalf("mutation = %+v", mutation)
	}
}

func TestReloadApplyPeersBuildsCompleteMutation(t *testing.T) {
	t.Parallel()
	var request *controlapiv1.ApplyPeersRequest
	apply := func(_ context.Context, _ string, got *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
		request = got
		return testApplyResponse(11), nil
	}
	mutation := controlapiv1.MutationContext_builder{}.Build()
	mutation.SetExpectedGeneration(10)
	peer := config.Peer{MetricsID: "edge-a"}
	generation, err := reloadApplyPeers(context.Background(), "/run/wgf.sock", "wgf0", []config.Peer{peer}, mutation, apply)
	if err != nil {
		t.Fatal(err)
	}
	if generation != 11 || request.GetTarget().GetInterfaceName() != "wgf0" ||
		request.GetMutation() != mutation || len(request.GetPeers()) != 1 ||
		request.GetPeers()[0].GetMetricsId() != "edge-a" {
		t.Fatalf("reload request = %+v, generation=%d", request, generation)
	}
}

func TestReloadApplyPeersRetriesAmbiguousResultWithSameRequest(t *testing.T) {
	t.Parallel()

	mutation := controlapiv1.MutationContext_builder{}.Build()
	mutation.SetRequestId(bytes.Repeat([]byte{7}, 16))
	var first *controlapiv1.ApplyPeersRequest
	calls := 0
	apply := func(_ context.Context, _ string, request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
		calls++
		if calls == 1 {
			first = request
			return nil, context.DeadlineExceeded
		}
		if request != first {
			t.Fatal("retry rebuilt the mutation request")
		}
		return testApplyResponse(12), nil
	}

	generation, err := reloadApplyPeers(
		context.Background(), "/run/wgf.sock", "wgf0", nil, mutation, apply,
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || generation != 12 {
		t.Fatalf("retry result = calls %d, generation %d; want 2, 12", calls, generation)
	}
}

func TestAwaitReloadMutationStopsWhenCallerCancels(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := awaitReloadMutation(ctx, func() (struct{}, error) {
		calls++
		cancel()
		return struct{}{}, context.DeadlineExceeded
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("await result = calls %d, error %v; want 1, context canceled", calls, err)
	}
}

func TestAwaitReloadMutationStopsAtDeadlineWhenDaemonIsUnavailable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	calls := 0
	_, err := awaitReloadMutation(ctx, func() (struct{}, error) {
		calls++
		return struct{}{}, grpcstatus.Error(codes.Unavailable, "daemon stopped")
	})
	if !errors.Is(err, context.DeadlineExceeded) || calls == 0 {
		t.Fatalf("await result = calls %d, error %v; want deadline exceeded", calls, err)
	}
}

func TestValidateReloadMetricsBinding(t *testing.T) {
	t.Parallel()

	oldConfig := config.Default()
	oldConfig.Interface.Metrics = true
	oldConfig.Interface.MetricsListen = config.MetricsListen{Auto: true}
	oldConfig.Interface.ListenPort = 51820
	desired := config.Clone(&oldConfig)
	if err := validateReloadMetricsBinding(&oldConfig, desired, true); err != nil {
		t.Fatalf("fixed-port restart rejected: %v", err)
	}
	desired.Interface.ListenPort = 51821
	if err := validateReloadMetricsBinding(&oldConfig, desired, true); err == nil {
		t.Fatal("listen port change unexpectedly accepted")
	}
	desired.Interface.ListenPort = 0
	oldConfig.Interface.ListenPort = 0
	if err := validateReloadMetricsBinding(&oldConfig, desired, true); err == nil {
		t.Fatal("automatic UDP port restart unexpectedly accepted")
	}
	if err := validateReloadMetricsBinding(&oldConfig, desired, false); err != nil {
		t.Fatalf("peer-only reload rejected: %v", err)
	}
}

func TestReloadRestartOmitsUnchangedPrivateKey(t *testing.T) {
	t.Parallel()
	desired := config.Default()
	desired.Interface.PrivateKey = controlConfigKey(1)
	public, err := derivePublicKey([32]byte(desired.Interface.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	status := testStatusResponse(3, nil)
	status.SetPublicKey(encodePublicKey(public))
	mutation := controlapiv1.MutationContext_builder{}.Build()
	var request *controlapiv1.RestartInterfaceRequest
	restart := func(_ context.Context, _ string, got *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
		request = got
		response := controlapiv1.RestartInterfaceResponse_builder{}.Build()
		response.SetStatus(testStatusResponse(4, nil))
		return response, nil
	}
	if _, err := reloadRestart(context.Background(), "/run/wgf.sock", "wgf0", status, &desired, mutation, restart); err != nil {
		t.Fatal(err)
	}
	if request == nil || request.GetSpec().HasPrivateKey() {
		t.Fatalf("restart spec unexpectedly carried unchanged private key: %+v", request)
	}
}

func TestReloadRestartIncludesChangedPrivateKey(t *testing.T) {
	t.Parallel()
	desired := config.Default()
	desired.Interface.PrivateKey = controlConfigKey(1)
	status := testStatusResponse(3, nil)
	status.SetPublicKey(encodedControlConfigKey(2))
	mutation := controlapiv1.MutationContext_builder{}.Build()
	var request *controlapiv1.RestartInterfaceRequest
	restart := func(_ context.Context, _ string, got *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
		request = got
		response := controlapiv1.RestartInterfaceResponse_builder{}.Build()
		response.SetStatus(testStatusResponse(4, nil))
		return response, nil
	}
	if _, err := reloadRestart(context.Background(), "/run/wgf.sock", "wgf0", status, &desired, mutation, restart); err != nil {
		t.Fatal(err)
	}
	if request == nil || !request.GetSpec().HasPrivateKey() ||
		!bytes.Equal(request.GetSpec().GetPrivateKey(), desired.Interface.PrivateKey[:]) {
		t.Fatalf("restart spec omitted changed private key: %+v", request)
	}
}

func TestReloadRestartRollbackRestoresPrivateKey(t *testing.T) {
	t.Parallel()
	oldConfig := config.Default()
	oldConfig.Interface.PrivateKey = controlConfigKey(1)
	status := testStatusResponse(3, nil)
	status.SetPublicKey(encodedControlConfigKey(1))
	ref := controlapiv1.InterfaceRef_builder{}.Build()
	ref.SetInterfaceName("wgf0")
	ref.SetInterfaceInstanceId(bytes.Repeat([]byte{1}, 16))
	status.SetRef(ref)
	var request *controlapiv1.RestartInterfaceRequest
	restart := func(_ context.Context, _ string, got *controlapiv1.RestartInterfaceRequest) (*controlapiv1.RestartInterfaceResponse, error) {
		request = got
		response := controlapiv1.RestartInterfaceResponse_builder{}.Build()
		response.SetStatus(testStatusResponse(5, nil))
		return response, nil
	}
	if err := reloadRollback(
		context.Background(), "/run/wgf.sock", "wgf0", status, &oldConfig,
		4, true, nil, restart,
	); err != nil {
		t.Fatal(err)
	}
	if request == nil || !request.GetSpec().HasPrivateKey() ||
		!bytes.Equal(request.GetSpec().GetPrivateKey(), oldConfig.Interface.PrivateKey[:]) {
		t.Fatalf("rollback omitted old private key: %+v", request)
	}
}

func TestReloadRollbackUsesIndependentTimeout(t *testing.T) {
	t.Parallel()
	oldConfig := config.Default()
	status := testStatusResponse(3, nil)
	ref := controlapiv1.InterfaceRef_builder{}.Build()
	ref.SetInterfaceName("wgf0")
	ref.SetInterfaceInstanceId(bytes.Repeat([]byte{1}, 16))
	status.SetRef(ref)
	apply := func(ctx context.Context, _ string, _ *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < quickReloadTimeout-time.Second {
			t.Fatalf("rollback context deadline = %v, want a fresh %s budget", deadline, quickReloadTimeout)
		}
		return testApplyResponse(5), nil
	}
	if err := reloadRollbackWithTimeout(
		"/run/wgf.sock", "wgf0", status, &oldConfig, 4, false, apply, nil,
	); err != nil {
		t.Fatal(err)
	}
}

func TestRunHooksTimeoutKillsProcessGroup(t *testing.T) {
	t.Parallel()
	marker := filepath.Join(t.TempDir(), "escaped-child")
	command := "(sleep 0.2; touch '" + strings.ReplaceAll(marker, "'", "'\\''") + "') & wait"

	err := runHooksWithTimeout("PreUp", []string{command}, "wgf0", &bytes.Buffer{}, &bytes.Buffer{}, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "hook timed out") {
		t.Fatalf("runHooksWithTimeout error = %v, want timeout", err)
	}

	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("timed-out hook child created %s", marker)
	}
}

func TestResolveQuickTargetDerivesNameFromPath(t *testing.T) {
	t.Parallel()
	target, err := resolveQuickTarget("/opt/wgf/wgf0.conf")
	if err != nil {
		t.Fatal(err)
	}
	if target.ifname != "wgf0" || target.path != "/opt/wgf/wgf0.conf" || !target.explicit || target.legacy {
		t.Fatalf("resolveQuickTarget() = %+v", target)
	}
	if _, err := resolveQuickTarget("/opt/wgf/not a name.conf"); err == nil {
		t.Fatal("invalid interface name in path succeeded")
	}
}

func TestSaveDestinationAcceptsLegacyOrigin(t *testing.T) {
	t.Parallel()
	canonical := quick.ConfigPath("wgf0")

	output, migrateFrom, err := saveDestination("wgf0", canonical)
	if err != nil || output != canonical || migrateFrom != "" {
		t.Fatalf("saveDestination(canonical) = (%q, %q, %v)", output, migrateFrom, err)
	}

	legacy := quick.LegacyConfigPath("wgf0")
	output, migrateFrom, err = saveDestination("wgf0", legacy)
	if err != nil || output != canonical || migrateFrom != legacy {
		t.Fatalf("saveDestination(legacy) = (%q, %q, %v)", output, migrateFrom, err)
	}

	if _, _, err := saveDestination("wgf0", "/opt/wgf/wgf0.conf"); err == nil {
		t.Fatal("non-canonical origin succeeded")
	}
}

func TestRemoveLegacyConfigKeepsFileWhenCanonicalExisted(t *testing.T) {
	t.Parallel()
	legacy := filepath.Join(t.TempDir(), "wgf0.conf")
	if err := os.WriteFile(legacy, []byte("legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	removeLegacyConfig(legacy, "/etc/wgf/wgf0.conf", true, &stdout, &stderr)
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy config was removed: %v", err)
	}
	if !strings.Contains(stderr.String(), "already existed") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	stderr.Reset()
	removeLegacyConfig(legacy, "/etc/wgf/wgf0.conf", false, &stdout, &stderr)
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy config still present: %v", err)
	}
	if !strings.Contains(stdout.String(), "removed legacy") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	// A missing legacy file warns instead of failing the teardown that saved.
	stderr.Reset()
	removeLegacyConfig(legacy, "/etc/wgf/wgf0.conf", false, &stdout, &stderr)
	if !strings.Contains(stderr.String(), "could not remove") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
