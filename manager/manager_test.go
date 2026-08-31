//go:build linux || darwin

package manager

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	"github.com/kurochan/wg-frag-go/internal/metrics"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"golang.zx2c4.com/wireguard/tun"
	"google.golang.org/protobuf/proto"
)

func managerTestKey(value byte) [32]byte {
	var key [32]byte
	for index := range key {
		key[index] = value
	}
	return key
}

func managerTestCounters(txCarriers, rxCarriers uint64) *controlapiv1.ShimCounters {
	counters := controlapiv1.ShimCounters_builder{}.Build()
	counters.SetTxCarriers(txCarriers)
	counters.SetRxDataCarriers(rxCarriers)
	return counters
}

func TestCounterStoreContinuesForRecreatedIdentity(t *testing.T) {
	t.Parallel()

	key := managerTestKey(1)
	store := newCounterStore(4)
	store.add(key, managerTestCounters(7, 11), nil)
	store.add(key, managerTestCounters(5, 13), nil)

	got := store.get(key)
	if got.GetTxCarriers() != 12 || got.GetRxDataCarriers() != 24 {
		t.Fatalf("counters after identity reuse = tx %d/rx %d, want tx 12/rx 24", got.GetTxCarriers(), got.GetRxDataCarriers())
	}

	// get returns a copy, so a status consumer cannot mutate the retained base.
	got.SetTxCarriers(0)
	if retained := store.get(key).GetTxCarriers(); retained != 12 {
		t.Fatalf("retained tx carriers = %d after mutating returned snapshot, want 12", retained)
	}

	if first, second := config.MetricsInterfaceID(config.Key(key)), config.MetricsInterfaceID(config.Key(key)); first != second {
		t.Fatalf("same public key produced different interface IDs: %q and %q", first, second)
	}
}

func TestTransitionStatusIncludesSecretsOnlyWhenRequested(t *testing.T) {
	t.Parallel()

	manager := newManagerForTest(managerPlatform{}, 1, nil)
	cfg := managerTestConfig(3, 1500)
	presharedKey := config.Key(managerTestKey(5))
	cfg.Peers[0].PresharedKey = &presharedKey
	supervisor := &interfaceSupervisor{
		manager:      manager,
		name:         "wgf0",
		lifecycle:    controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR,
		lifecycleErr: "runtime failed",
		config:       cfg,
		publicKey:    managerTestKey(3),
	}

	withoutSecrets, err := supervisor.status(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutSecrets.GetPeers()) != 1 || withoutSecrets.GetPeers()[0].HasPresharedKey() ||
		withoutSecrets.GetSpec().GetPeers()[0].HasPresharedKey() {
		t.Fatalf("transition status exposed or omitted peer state without secrets: %v", withoutSecrets)
	}

	withSecrets, err := supervisor.status(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(withSecrets.GetPeers()) != 1 ||
		!bytes.Equal(withSecrets.GetPeers()[0].GetPresharedKey(), presharedKey[:]) ||
		!bytes.Equal(withSecrets.GetSpec().GetPeers()[0].GetPresharedKey(), presharedKey[:]) {
		t.Fatalf("transition status omitted requested preshared key: %v", withSecrets)
	}
}

func TestCounterStoreEvictsOldestInactiveIdentity(t *testing.T) {
	t.Parallel()

	store := newCounterStore(4)
	protected := managerTestKey(1)
	active := map[[32]byte]*interfaceSupervisor{protected: {}}
	for value := byte(1); value <= 5; value++ {
		store.add(managerTestKey(value), managerTestCounters(uint64(value), 0), active)
	}
	if len(store.entries) != 4 {
		t.Fatalf("retained identities = %d, want 4", len(store.entries))
	}
	if got := store.get(protected).GetTxCarriers(); got != 1 {
		t.Fatalf("protected identity tx carriers = %d, want 1", got)
	}
	if got := store.get(managerTestKey(2)).GetTxCarriers(); got != 0 {
		t.Fatalf("oldest inactive identity tx carriers = %d, want evicted", got)
	}
	if got := store.get(managerTestKey(5)).GetTxCarriers(); got != 5 {
		t.Fatalf("new identity tx carriers = %d, want 5", got)
	}
}

func TestManagerMetricsSchemaIsStableForSingleAndMultipleInterfaces(t *testing.T) {
	t.Parallel()

	single := newManagerForTest(managerPlatform{}, 1, nil)
	addManagerMetricSupervisor(single, "wgf0", managerTestKey(10), managerTestCounters(7, 9))
	singleText := renderManagerMetrics(t, single.metricsSnapshot())

	multiple := newManagerForTest(managerPlatform{}, 2, nil)
	addManagerMetricSupervisor(multiple, "wgf0", managerTestKey(10), managerTestCounters(7, 9))
	addManagerMetricSupervisor(multiple, "wgf1", managerTestKey(11), managerTestCounters(13, 17))
	multipleText := renderManagerMetrics(t, multiple.metricsSnapshot())

	for _, want := range []string{
		"wgf_manager_interfaces 1\n",
		"wgf_tx_carriers_total{interface=\"wgf0\",interface_id=\"",
		"wgf_rx_data_carriers_total{interface=\"wgf0\",interface_id=\"",
	} {
		if !strings.Contains(singleText, want) {
			t.Fatalf("single-interface metrics missing %q:\n%s", want, singleText)
		}
	}
	for _, want := range []string{
		"wgf_manager_interfaces 2\n",
		"wgf_tx_carriers_total{interface=\"wgf0\",interface_id=\"",
		"wgf_tx_carriers_total{interface=\"wgf1\",interface_id=\"",
		"wgf_rx_data_carriers_total{interface=\"wgf0\",interface_id=\"",
		"wgf_rx_data_carriers_total{interface=\"wgf1\",interface_id=\"",
	} {
		if !strings.Contains(multipleText, want) {
			t.Fatalf("multi-interface metrics missing %q:\n%s", want, multipleText)
		}
	}

	if strings.Contains(singleText, "peer_id=") || strings.Contains(multipleText, "peer_id=") {
		t.Fatal("interface-scoped metrics unexpectedly contain peer_id")
	}
}

func TestManagerMetricsKeepIdentityAndCountersAcrossDeleteRecreate(t *testing.T) {
	t.Parallel()

	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 12)
	key := supervisor.publicKey
	peerID := config.MetricsPeerID(supervisor.config.Peers[0])
	harness.runtimes[0].counters = managerTestCounters(7, 9)

	before := renderManagerMetrics(t, harness.manager.metricsSnapshot())
	interfaceLabels := "interface=\"wgf0\",interface_id=\"" + config.MetricsInterfaceID(config.Key(key)) + "\""
	for _, want := range []string{
		"wgf_tx_carriers_total{" + interfaceLabels + "} 7\n",
		"wgf_peer_pmtu_searching{" + interfaceLabels + ",peer_id=\"" + peerID + "\"} 1\n",
	} {
		if !strings.Contains(before, want) {
			t.Fatalf("initial metrics missing %q:\n%s", want, before)
		}
	}

	if _, err := harness.manager.deleteInterface(t.Context(), managerTestDeleteRequest(supervisor, 72)); err != nil {
		t.Fatalf("delete interface: %v", err)
	}
	recreatedConfig := managerTestConfig(12, 1500)
	if _, err := harness.manager.createInterface(
		t.Context(),
		managerTestCreateRequest(73, managerTestInterfaceSpec("wgf0", recreatedConfig)),
	); err != nil {
		t.Fatalf("recreate interface: %v", err)
	}
	recreated := harness.manager.interfaces["wgf0"]
	if recreated == nil {
		t.Fatal("recreated interface is missing")
	}
	if recreated.publicKey != key {
		t.Fatal("recreated interface changed its public-key identity")
	}
	harness.runtimes[1].counters = managerTestCounters(5, 11)

	after := renderManagerMetrics(t, harness.manager.metricsSnapshot())
	for _, want := range []string{
		"wgf_tx_carriers_total{" + interfaceLabels + "} 12\n",
		"wgf_rx_data_carriers_total{" + interfaceLabels + "} 20\n",
	} {
		if !strings.Contains(after, want) {
			t.Fatalf("recreated metrics missing %q:\n%s", want, after)
		}
	}
}

func addManagerMetricSupervisor(manager *Manager, name string, key [32]byte, counters *controlapiv1.ShimCounters) {
	supervisor := &interfaceSupervisor{
		manager:   manager,
		name:      name,
		publicKey: key,
		lifecycle: controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR,
	}
	manager.interfaces[name] = supervisor
	manager.byPublicKey[key] = supervisor
	manager.counters.add(key, counters, manager.byPublicKey)
}

func renderManagerMetrics(t *testing.T, snapshot metrics.Snapshot) string {
	t.Helper()
	selector, err := metrics.NewSelector(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := metrics.WriteOpenMetrics(&output, selector, snapshot); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func managerTestRequestID(value byte) [16]byte {
	var id [16]byte
	for index := range id {
		id[index] = value
	}
	return id
}

func TestMutationCacheReplaysAndRejectsConflict(t *testing.T) {
	t.Parallel()

	cache := newMutationCache(4, requestCacheLifetime)
	requestID := managerTestRequestID(1)
	hash := [32]byte{1}
	want := testApplyResponse(9)
	var calls int
	operation := func() (proto.Message, error) {
		calls++
		return want, nil
	}
	got, err := cache.execute(t.Context(), requestID, hash, operation)
	if err != nil {
		t.Fatalf("initial mutation returned error: %v", err)
	}
	replay, err := cache.execute(t.Context(), requestID, hash, operation)
	if err != nil {
		t.Fatalf("replay returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("operation calls after replay = %d, want 1", calls)
	}
	if !proto.Equal(got, want) || !proto.Equal(replay, want) {
		t.Fatalf("cached response mismatch: initial %v, replay %v, want %v", got, replay, want)
	}
	replay.(*controlapiv1.ApplyPeersResponse).SetGeneration(100)
	uncorrupted, err := cache.execute(t.Context(), requestID, hash, operation)
	if err != nil || uncorrupted.(*controlapiv1.ApplyPeersResponse).GetGeneration() != 9 {
		t.Fatalf("cached response was mutated through replay: %v, err %v", uncorrupted, err)
	}

	_, err = cache.execute(t.Context(), requestID, [32]byte{2}, operation)
	if CodeOf(err) != CodeAlreadyExists {
		t.Fatalf("conflicting request error = %v, want AlreadyExists", err)
	}
}

func TestMutationCacheExpiresCompletedEntry(t *testing.T) {
	t.Parallel()

	cache := newMutationCache(4, time.Minute)
	requestID := managerTestRequestID(2)
	hash := [32]byte{3}
	old := &mutationCacheEntry{
		hash:     hash,
		result:   testApplyResponse(3),
		finished: true,
		at:       time.Now().Add(-cache.lifetime - time.Second),
		done:     make(chan struct{}),
	}
	close(old.done)
	cache.entries[requestID] = old

	var calls int
	got, err := cache.execute(t.Context(), requestID, hash, func() (proto.Message, error) {
		calls++
		return testApplyResponse(4), nil
	})
	if err != nil {
		t.Fatalf("expired request returned error: %v", err)
	}
	if calls != 1 || got.(*controlapiv1.ApplyPeersResponse).GetGeneration() != 4 {
		t.Fatalf("expired request was not re-executed: calls %d, result %v", calls, got)
	}
	if _, exists := cache.entries[requestID]; !exists {
		t.Fatal("re-executed request was not retained")
	}
}

func TestMutationCacheCoalescesConcurrentReplay(t *testing.T) {
	t.Parallel()
	cache := newMutationCache(4, time.Minute)
	requestID := managerTestRequestID(3)
	hash := [32]byte{4}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	operation := func() (proto.Message, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return testApplyResponse(5), nil
	}
	results := make(chan proto.Message, 2)
	errorsSeen := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := cache.execute(t.Context(), requestID, hash, operation)
			results <- result
			errorsSeen <- err
		}()
	}
	<-started
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent operation calls before release = %d, want 1", got)
	}
	close(release)
	for range 2 {
		if err := <-errorsSeen; err != nil {
			t.Fatal(err)
		}
		if result := <-results; result.(*controlapiv1.ApplyPeersResponse).GetGeneration() != 5 {
			t.Fatalf("concurrent replay result = %v", result)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent operation calls = %d, want 1", got)
	}
}

func TestMutationCacheReplaysErrors(t *testing.T) {
	t.Parallel()
	cache := newMutationCache(4, time.Minute)
	requestID := managerTestRequestID(4)
	hash := [32]byte{5}
	want := NewError(CodeUnavailable, "temporary failure")
	var calls atomic.Int32
	operation := func() (proto.Message, error) {
		calls.Add(1)
		return nil, want
	}
	if _, err := cache.execute(t.Context(), requestID, hash, operation); CodeOf(err) != CodeUnavailable {
		t.Fatalf("initial error = %v, want Unavailable", err)
	}
	if _, err := cache.execute(t.Context(), requestID, hash, operation); CodeOf(err) != CodeUnavailable {
		t.Fatalf("replayed error = %v, want Unavailable", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("operation calls after error replay = %d, want 1", got)
	}
}

func TestMutationCacheRepanicsAndCompletesEntry(t *testing.T) {
	t.Parallel()
	cache := newMutationCache(4, time.Minute)
	requestID := managerTestRequestID(5)
	hash := [32]byte{6}
	var calls atomic.Int32
	operation := func() (proto.Message, error) {
		calls.Add(1)
		panic("injected panic")
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != "injected panic" {
				t.Fatalf("recovered panic = %v, want injected panic", recovered)
			}
		}()
		_, _ = cache.execute(t.Context(), requestID, hash, operation)
	}()
	if _, err := cache.execute(t.Context(), requestID, hash, operation); CodeOf(err) != CodeInternal {
		t.Fatalf("replayed panic error = %v, want Internal", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("operation calls after panic replay = %d, want 1", got)
	}
}

func TestMutationCacheCompletesEntryAfterGoexit(t *testing.T) {
	t.Parallel()
	cache := newMutationCache(4, time.Minute)
	requestID := managerTestRequestID(6)
	hash := [32]byte{7}
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		_, _ = cache.execute(context.Background(), requestID, hash, func() (proto.Message, error) {
			runtime.Goexit()
			return nil, nil
		})
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("Goexit did not release the mutation entry")
	}
	if _, err := cache.execute(t.Context(), requestID, hash, nil); CodeOf(err) != CodeInternal {
		t.Fatalf("replayed Goexit error = %v, want Internal", err)
	}
}

type managerTestAnchor struct {
	name       string
	leaseMTUs  []int
	closeCalls int
	closeErr   error
}

func (anchor *managerTestAnchor) Name() string {
	return anchor.name
}

func (anchor *managerTestAnchor) Lease(mtu int) (tun.Device, error) {
	anchor.leaseMTUs = append(anchor.leaseMTUs, mtu)
	return nil, nil
}

func (anchor *managerTestAnchor) Close() error {
	anchor.closeCalls++
	return anchor.closeErr
}

type managerTestRuntime struct {
	name           string
	cfg            *config.Config
	counters       *controlapiv1.ShimCounters
	publicKey      [32]byte
	done           chan struct{}
	closeOnce      sync.Once
	closeCalls     int
	closeErr       error
	closeStarted   chan struct{}
	closeRelease   chan struct{}
	closeStartOnce sync.Once
	statusErr      error
	applyCalls     int
	applied        []*controlapiv1.PeerSpec
}

func newManagerTestRuntime(cfg *config.Config, counters *controlapiv1.ShimCounters) *managerTestRuntime {
	return &managerTestRuntime{
		cfg:      config.Clone(cfg),
		counters: proto.Clone(counters).(*controlapiv1.ShimCounters),
		done:     make(chan struct{}),
	}
}

func (runtime *managerTestRuntime) close() error {
	runtime.closeCalls++
	if runtime.closeStarted != nil {
		runtime.closeStartOnce.Do(func() { close(runtime.closeStarted) })
		<-runtime.closeRelease
	}
	runtime.closeOnce.Do(func() { close(runtime.done) })
	return runtime.closeErr
}

func (runtime *managerTestRuntime) wait() error {
	<-runtime.done
	return nil
}

func (runtime *managerTestRuntime) status(bool) (*controlapiv1.InterfaceStatus, error) {
	if runtime.statusErr != nil {
		return nil, runtime.statusErr
	}
	status := controlapiv1.InterfaceStatus_builder{}.Build()
	status.SetPublicKey(base64.StdEncoding.EncodeToString(runtime.publicKey[:]))
	status.SetListenPort(uint32(runtime.cfg.Interface.ListenPort))
	status.SetMtu(uint32(runtime.cfg.Interface.MTU))
	status.SetCounters(proto.Clone(runtime.counters).(*controlapiv1.ShimCounters))
	return status, nil
}

func (runtime *managerTestRuntime) counterSnapshot() *controlapiv1.ShimCounters {
	return proto.Clone(runtime.counters).(*controlapiv1.ShimCounters)
}

func (runtime *managerTestRuntime) applyPeers(request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	runtime.applyCalls++
	runtime.applied = make([]*controlapiv1.PeerSpec, len(request.GetPeers()))
	for index, peer := range request.GetPeers() {
		runtime.applied[index] = proto.Clone(peer).(*controlapiv1.PeerSpec)
	}
	peers, err := controlconfig.PeersFromSpec(request.GetPeers(), runtime.cfg)
	if err != nil {
		return nil, err
	}
	runtime.cfg.Peers = peers
	return testApplyResponse(0), nil
}

func (runtime *managerTestRuntime) configSnapshot() *config.Config {
	return config.Clone(runtime.cfg)
}

func (runtime *managerTestRuntime) metricsSnapshot() metrics.Snapshot {
	samples := counterMetricSamples(runtime.counters)
	for _, peer := range runtime.cfg.Peers {
		labels := map[string]string{"peer_id": config.MetricsPeerID(peer)}
		samples = append(samples,
			metrics.Sample{Name: "wgf_peer_pmtu_carrier_payload_bytes", Labels: labels, Value: 613},
			metrics.Sample{Name: "wgf_peer_pmtu_searching", Labels: labels, Value: 1},
			metrics.Sample{Name: "wgf_peer_data_forwarding_enabled", Labels: labels, Value: 0},
		)
	}
	return metrics.Snapshot{InterfaceSnapshots: []metrics.InterfaceSnapshot{{
		Name:    runtime.name,
		ID:      config.MetricsInterfaceID(config.Key(runtime.publicKey)),
		Samples: samples,
	}}}
}

func (runtime *managerTestRuntime) effectiveListenPort() (uint16, error) {
	return runtime.cfg.Interface.ListenPort, nil
}

func (*managerTestRuntime) dumpStats() {}

type managerTestHarness struct {
	manager      *Manager
	anchor       *managerTestAnchor
	runtimes     []*managerTestRuntime
	startErrors  []error
	statusErrors []error
	startCalls   int
}

func newManagerTestHarness(maxInterfaces int) *managerTestHarness {
	harness := &managerTestHarness{}
	platform := managerPlatform{
		openAnchor: func(name string, _ int) (runtimeTUNAnchor, error) {
			harness.anchor = &managerTestAnchor{name: name}
			return harness.anchor, nil
		},
	}
	harness.manager = newManagerForTest(platform, maxInterfaces, nil)
	harness.manager.start = func(supervisor *interfaceSupervisor, cfg *config.Config) (managedRuntime, error) {
		call := harness.startCalls
		harness.startCalls++
		if call < len(harness.startErrors) && harness.startErrors[call] != nil {
			if supervisor.anchor != nil {
				if _, err := supervisor.anchor.Lease(cfg.Interface.MTU); err != nil {
					return nil, err
				}
			}
			return nil, harness.startErrors[call]
		}
		if supervisor.anchor != nil {
			if _, err := supervisor.anchor.Lease(cfg.Interface.MTU); err != nil {
				return nil, err
			}
		}
		plan, err := wgadapter.PreparePeers(cfg)
		if err != nil {
			return nil, err
		}
		runtime := newManagerTestRuntime(cfg, controlapiv1.ShimCounters_builder{}.Build())
		runtime.name = supervisor.name
		runtime.publicKey = plan.LocalPublicKey
		if call < len(harness.statusErrors) {
			runtime.statusErr = harness.statusErrors[call]
		}
		harness.runtimes = append(harness.runtimes, runtime)
		return runtime, nil
	}
	return harness
}

func managerTestConfig(seed byte, mtu int) *config.Config {
	privateKey := managerTestKey(seed)
	peerKey := managerTestKey(seed + 1)
	peer, err := config.NewPeer(
		base64.StdEncoding.EncodeToString(peerKey[:]),
		"",
		[]string{"10.0.0.0/24"},
		0,
	)
	if err != nil {
		panic(err)
	}
	cfg := config.Default()
	cfg.Interface.PrivateKey = config.Key(privateKey)
	cfg.Interface.ListenPort = 51820
	cfg.Interface.MTU = mtu
	cfg.Peers = []config.Peer{peer}
	return &cfg
}

func managerTestCreateRequest(requestID byte, spec *controlapiv1.InterfaceSpec) *controlapiv1.CreateInterfaceRequest {
	request := controlapiv1.CreateInterfaceRequest_builder{}.Build()
	id := managerTestRequestID(requestID)
	request.SetRequestId(append([]byte(nil), id[:]...))
	request.SetSpec(spec)
	return request
}

func managerTestMutationFor(supervisor *interfaceSupervisor, requestID byte) *controlapiv1.MutationContext {
	mutation := controlapiv1.MutationContext_builder{}.Build()
	id := managerTestRequestID(requestID)
	mutation.SetRequestId(append([]byte(nil), id[:]...))
	mutation.SetExpectedInstanceId(append([]byte(nil), supervisor.instanceID[:]...))
	mutation.SetExpectedGeneration(supervisor.generation)
	return mutation
}

func managerTestRestartRequest(supervisor *interfaceSupervisor, requestID byte, cfg *config.Config) *controlapiv1.RestartInterfaceRequest {
	request := controlapiv1.RestartInterfaceRequest_builder{}.Build()
	request.SetTarget(supervisor.ref())
	request.SetMutation(managerTestMutationFor(supervisor, requestID))
	request.SetSpec(managerTestInterfaceSpec(supervisor.name, cfg))
	return request
}

func managerTestInterfaceSpec(name string, cfg *config.Config) *controlapiv1.InterfaceSpec {
	spec := controlconfig.SpecFromConfig(name, cfg, true)
	privateKey := append([]byte(nil), cfg.Interface.PrivateKey[:]...)
	spec.SetPrivateKey(privateKey)
	return spec
}

func managerTestDeleteRequest(supervisor *interfaceSupervisor, requestID byte) *controlapiv1.DeleteInterfaceRequest {
	request := controlapiv1.DeleteInterfaceRequest_builder{}.Build()
	request.SetTarget(supervisor.ref())
	request.SetMutation(managerTestMutationFor(supervisor, requestID))
	return request
}

func managerTestCreate(t *testing.T, harness *managerTestHarness, name string, seed byte) (*interfaceSupervisor, *controlapiv1.CreateInterfaceResponse) {
	t.Helper()
	cfg := managerTestConfig(seed, 1500)
	spec := managerTestInterfaceSpec(name, cfg)
	response, err := harness.manager.createInterface(context.Background(), managerTestCreateRequest(seed+10, spec))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	supervisor := harness.manager.interfaces[name]
	if supervisor == nil || response.GetStatus() == nil {
		t.Fatalf("create %s returned no supervisor/status", name)
	}
	return supervisor, response
}

func TestManagerCreateListGet(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(2)
	t.Cleanup(func() { _ = harness.manager.close() })

	supervisor, created := managerTestCreate(t, harness, "wgf0", 20)
	if got := created.GetStatus().GetRef().GetInterfaceName(); got != "wgf0" {
		t.Fatalf("created interface name = %q, want wgf0", got)
	}
	if got := created.GetStatus().GetNativeInterfaceName(); got != "wgf0" {
		t.Fatalf("created native interface name = %q, want wgf0", got)
	}
	listed, err := harness.manager.listInterfaces(context.Background(), controlapiv1.ListInterfacesRequest_builder{}.Build())
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	if len(listed.GetInterfaces()) != 1 || listed.GetInterfaces()[0].GetRef().GetInterfaceName() != "wgf0" {
		t.Fatalf("listed interfaces = %v, want one wgf0", listed.GetInterfaces())
	}
	request := controlapiv1.GetInterfaceRequest_builder{}.Build()
	request.SetTarget(supervisor.ref())
	got, err := harness.manager.getInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("get interface: %v", err)
	}
	if got.GetStatus().GetLifecycle() != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING {
		t.Fatalf("get lifecycle = %s, want RUNNING", got.GetStatus().GetLifecycle())
	}
	if spec := got.GetStatus().GetSpec(); spec == nil || spec.GetMtu() != 1500 || spec.HasPrivateKey() {
		t.Fatalf("get spec = %v, want non-secret current configuration", spec)
	}
}

func TestManagerListContinuesPastInterfaceStatusFailure(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(2)
	t.Cleanup(func() { _ = harness.manager.close() })
	managerTestCreate(t, harness, "wgf0", 31)
	managerTestCreate(t, harness, "wgf1", 33)
	harness.runtimes[0].statusErr = errors.New("status failed")
	harness.runtimes[0].counters = managerTestCounters(7, 11)

	listed, err := harness.manager.listInterfaces(context.Background(), controlapiv1.ListInterfacesRequest_builder{}.Build())
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	if len(listed.GetInterfaces()) != 2 {
		t.Fatalf("listed interfaces = %d, want 2", len(listed.GetInterfaces()))
	}
	byName := make(map[string]*controlapiv1.InterfaceStatus)
	for _, status := range listed.GetInterfaces() {
		byName[status.GetRef().GetInterfaceName()] = status
	}
	if got := byName["wgf0"]; got.GetLifecycle() != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR ||
		!strings.Contains(got.GetLifecycleError(), "status failed") {
		t.Fatalf("failed interface status = %v", got)
	} else if got.GetCounters().GetTxCarriers() != 7 || got.GetCounters().GetRxDataCarriers() != 11 {
		t.Fatalf("failed interface counters = %v, want current runtime counters", got.GetCounters())
	}
	if got := byName["wgf1"]; got.GetLifecycle() != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING {
		t.Fatalf("healthy interface status = %v", got)
	}
	get := controlapiv1.GetInterfaceRequest_builder{Target: harness.manager.interfaces["wgf0"].ref()}.Build()
	got, err := harness.manager.getInterface(context.Background(), get)
	if err != nil {
		t.Fatalf("get failed interface: %v", err)
	}
	if got.GetStatus().GetLifecycle() != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR ||
		got.GetStatus().GetCounters().GetTxCarriers() != 7 {
		t.Fatalf("get failed interface status = %v", got.GetStatus())
	}
}

func TestManagerCreateStatusFailureCleansUpInterface(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	harness.statusErrors = []error{errors.New("status failed")}
	t.Cleanup(func() { _ = harness.manager.close() })

	cfg := managerTestConfig(19, 1500)
	_, err := harness.manager.createInterface(
		context.Background(),
		managerTestCreateRequest(29, managerTestInterfaceSpec("wgf0", cfg)),
	)
	if err == nil || !strings.Contains(err.Error(), "status failed") {
		t.Fatalf("create error = %v, want status failure", err)
	}
	if harness.manager.interfaceCount() != 0 || len(harness.manager.byPublicKey) != 0 {
		t.Fatalf(
			"failed create retained manager entries: interfaces=%d keys=%d",
			harness.manager.interfaceCount(),
			len(harness.manager.byPublicKey),
		)
	}
	if harness.anchor.closeCalls != 1 || harness.runtimes[0].closeCalls != 1 {
		t.Fatalf(
			"failed create cleanup calls = anchor %d/runtime %d, want 1/1",
			harness.anchor.closeCalls,
			harness.runtimes[0].closeCalls,
		)
	}
}

func TestManagerCreateRetainsAnchorAfterInitialCleanupFailure(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	harness.startErrors = []error{errors.New("runtime start failed")}
	t.Cleanup(func() {
		if harness.anchor != nil {
			harness.anchor.closeErr = nil
		}
		_ = harness.manager.close()
	})
	// The anchor is created by create(), so configure the failure after the
	// first start attempt has installed it.
	harness.manager.platform.openAnchor = func(name string, _ int) (runtimeTUNAnchor, error) {
		harness.anchor = &managerTestAnchor{name: name, closeErr: errors.New("anchor close failed")}
		return harness.anchor, nil
	}
	cfg := managerTestConfig(18, 1500)
	if _, err := harness.manager.create("wgf0", cfg); err == nil || !strings.Contains(err.Error(), "close TUN anchor") {
		t.Fatalf("create error = %v, want joined anchor cleanup error", err)
	}
	supervisor := harness.manager.interfaces["wgf0"]
	if supervisor == nil || supervisor.anchor == nil || supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR {
		t.Fatal("failed initial cleanup did not retain an ERROR supervisor and anchor")
	}
	harness.anchor.closeErr = nil
	if err := supervisor.stopAndDelete(); err != nil {
		t.Fatalf("anchor cleanup retry: %v", err)
	}
	harness.manager.removeSupervisor(supervisor)
	if harness.manager.interfaceCount() != 0 {
		t.Fatal("cleanup retry left the failed create in the manager")
	}
}

func TestManagerCreateRejectsInvalidPrivateKeyAsInvalidArgument(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })

	cfg := managerTestConfig(20, 1500)
	spec := managerTestInterfaceSpec("wgf0", cfg)
	spec.SetPrivateKey(make([]byte, 32))
	_, err := harness.manager.createInterface(
		context.Background(),
		managerTestCreateRequest(30, spec),
	)
	if CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("create error = %v, want InvalidArgument", err)
	}
	if harness.startCalls != 0 || harness.manager.interfaceCount() != 0 {
		t.Fatalf("invalid create changed runtime state: starts=%d interfaces=%d", harness.startCalls, harness.manager.interfaceCount())
	}
}

func TestManagerGetNeverReturnsPrivateKeyWhenSecretsRequested(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 21)
	request := controlapiv1.GetInterfaceRequest_builder{}.Build()
	request.SetTarget(supervisor.ref())
	request.SetIncludeSecrets(true)
	response, err := harness.manager.getInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("get interface with secrets: %v", err)
	}
	if response.GetStatus().GetSpec().HasPrivateKey() {
		t.Fatal("private key was returned in the interface spec")
	}
}

func TestManagerApplyPeersUpdatesGenerationAndReplays(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 22)
	peerKey := managerTestKey(23)
	request := controlapiv1.ApplyPeersRequest_builder{}.Build()
	request.SetTarget(supervisor.ref())
	request.SetMutation(managerTestMutationFor(supervisor, 122))
	peer := testDesiredPeer(base64.StdEncoding.EncodeToString(peerKey[:]), "192.0.2.1:51820", []string{"10.1.0.0/24"})
	peer.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
	request.SetPeers([]*controlapiv1.PeerSpec{peer})
	first, err := harness.manager.applyPeers(context.Background(), request)
	if err != nil {
		t.Fatalf("apply peers: %v", err)
	}
	if first.GetGeneration() != 1 || supervisor.generation != 1 {
		t.Fatalf("generation = response %d/supervisor %d, want 1", first.GetGeneration(), supervisor.generation)
	}
	runtime := harness.runtimes[0]
	if runtime.applyCalls != 1 || len(runtime.applied) != 1 || runtime.applied[0].GetEndpoint() != "192.0.2.1:51820" {
		t.Fatalf("applied peers = calls %d/peers %v, want one applied peer", runtime.applyCalls, runtime.applied)
	}
	if len(supervisor.config.Peers) != 1 || supervisor.config.Peers[0].Endpoint != "192.0.2.1:51820" {
		t.Fatalf("manager peer config = %+v, want applied endpoint", supervisor.config.Peers)
	}
	second, err := harness.manager.applyPeers(context.Background(), request)
	if err != nil {
		t.Fatalf("apply peers replay: %v", err)
	}
	if !proto.Equal(first, second) || runtime.applyCalls != 1 || supervisor.generation != 1 {
		t.Fatalf("apply replay = %v/%v, calls=%d generation=%d", first, second, runtime.applyCalls, supervisor.generation)
	}
}

func TestManagerApplyPeersRejectsInvalidPeerAsInvalidArgument(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 23)

	request := controlapiv1.ApplyPeersRequest_builder{}.Build()
	request.SetTarget(supervisor.ref())
	request.SetMutation(managerTestMutationFor(supervisor, 123))
	peer := controlapiv1.PeerSpec_builder{}.Build()
	peer.SetPublicKey("not-a-wireguard-key")
	peer.SetPresharedKeyAction(controlapiv1.PresharedKeyAction_CLEAR)
	request.SetPeers([]*controlapiv1.PeerSpec{peer})

	if _, err := harness.manager.applyPeers(context.Background(), request); CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("invalid peer error = %v, want InvalidArgument", err)
	}
	if harness.runtimes[0].applyCalls != 0 || supervisor.generation != 0 {
		t.Fatalf("invalid peer reached runtime: calls=%d generation=%d", harness.runtimes[0].applyCalls, supervisor.generation)
	}
}

func TestManagerRejectsStaleInstanceAndGeneration(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 24)

	staleRef := supervisor.ref()
	staleRef.SetInterfaceInstanceId(make([]byte, 16))
	get := controlapiv1.GetInterfaceRequest_builder{}.Build()
	get.SetTarget(staleRef)
	if _, err := harness.manager.getInterface(context.Background(), get); CodeOf(err) != CodeAborted {
		t.Fatalf("stale instance get error = %v, want Aborted", err)
	}

	apply := controlapiv1.ApplyPeersRequest_builder{}.Build()
	apply.SetTarget(supervisor.ref())
	mutation := managerTestMutationFor(supervisor, 124)
	mutation.SetExpectedInstanceId(make([]byte, 16))
	apply.SetMutation(mutation)
	if _, err := harness.manager.applyPeers(context.Background(), apply); CodeOf(err) != CodeAborted {
		t.Fatalf("stale instance apply error = %v, want Aborted", err)
	}

	valid := controlapiv1.ApplyPeersRequest_builder{}.Build()
	valid.SetTarget(supervisor.ref())
	valid.SetMutation(managerTestMutationFor(supervisor, 125))
	if _, err := harness.manager.applyPeers(context.Background(), valid); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	staleGeneration := controlapiv1.ApplyPeersRequest_builder{}.Build()
	staleGeneration.SetTarget(supervisor.ref())
	oldMutation := managerTestMutationFor(supervisor, 126)
	oldMutation.SetExpectedGeneration(0)
	staleGeneration.SetMutation(oldMutation)
	if _, err := harness.manager.applyPeers(context.Background(), staleGeneration); CodeOf(err) != CodeAborted {
		t.Fatalf("stale generation apply error = %v, want Aborted", err)
	}

	restart := managerTestRestartRequest(supervisor, 128, managerTestConfig(24, 9000))
	restart.GetMutation().SetExpectedInstanceId(make([]byte, 16))
	if _, err := harness.manager.restartInterface(context.Background(), restart); CodeOf(err) != CodeAborted {
		t.Fatalf("stale instance restart error = %v, want Aborted", err)
	}
	staleRestartGeneration := managerTestRestartRequest(supervisor, 129, managerTestConfig(24, 9000))
	staleRestartGeneration.GetMutation().SetExpectedGeneration(0)
	if _, err := harness.manager.restartInterface(context.Background(), staleRestartGeneration); CodeOf(err) != CodeAborted {
		t.Fatalf("stale generation restart error = %v, want Aborted", err)
	}

	deleteRequest := controlapiv1.DeleteInterfaceRequest_builder{}.Build()
	deleteRequest.SetTarget(supervisor.ref())
	deleteMutation := managerTestMutationFor(supervisor, 127)
	deleteMutation.SetExpectedInstanceId(make([]byte, 16))
	deleteRequest.SetMutation(deleteMutation)
	if _, err := harness.manager.deleteInterface(context.Background(), deleteRequest); CodeOf(err) != CodeAborted {
		t.Fatalf("stale instance delete error = %v, want Aborted", err)
	}
	if harness.manager.interfaceCount() != 1 {
		t.Fatal("stale delete removed the interface")
	}
}

func TestManagerRejectsMutationsCapturedBeforeDeleteCompletes(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 25)

	supervisor.mu.Lock()
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_DELETING
	supervisor.mu.Unlock()

	if _, err := supervisor.restartRequest(
		managerTestRestartRequest(supervisor, 130, managerTestConfig(25, 9000)),
	); CodeOf(err) != CodeFailedPrecondition {
		t.Fatalf("restart while deleting error = %v, want FailedPrecondition", err)
	}
	if err := harness.manager.deleteSupervisor(
		supervisor,
		managerTestMutationFor(supervisor, 131),
	); CodeOf(err) != CodeFailedPrecondition {
		t.Fatalf("second delete error = %v, want FailedPrecondition", err)
	}
	if harness.runtimes[0].closeCalls != 0 || harness.anchor.closeCalls != 0 {
		t.Fatalf(
			"rejected mutations closed resources: runtime=%d anchor=%d",
			harness.runtimes[0].closeCalls,
			harness.anchor.closeCalls,
		)
	}
}

func TestManagerRejectsDuplicatePublicKey(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(2)
	t.Cleanup(func() { _ = harness.manager.close() })
	cfg := managerTestConfig(30, 1500)
	if _, err := harness.manager.create("wgf0", cfg); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := harness.manager.create("wgf1", config.Clone(cfg)); err == nil || !strings.Contains(err.Error(), "public key is already active") {
		t.Fatalf("duplicate public key error = %v", err)
	}
}

func TestManagerRestartKeepsAnchorAndIncrementsGeneration(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 40)
	anchor := harness.anchor
	oldRuntime := harness.runtimes[0]
	next := managerTestConfig(40, 9000)
	response, err := harness.manager.restartInterface(context.Background(), managerTestRestartRequest(supervisor, 41, next))
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if response.GetStatus().GetGeneration() != 1 || supervisor.generation != 1 {
		t.Fatalf("generation = response %d/supervisor %d, want 1", response.GetStatus().GetGeneration(), supervisor.generation)
	}
	if harness.anchor != anchor || supervisor.anchor != anchor {
		t.Fatal("restart replaced the persistent TUN anchor")
	}
	if len(anchor.leaseMTUs) != 2 || anchor.leaseMTUs[0] != 1500 || anchor.leaseMTUs[1] != 9000 {
		t.Fatalf("anchor leases = %v, want [1500 9000]", anchor.leaseMTUs)
	}
	if oldRuntime.closeCalls != 1 || len(harness.runtimes) != 2 {
		t.Fatalf("old runtime close calls = %d, runtimes = %d", oldRuntime.closeCalls, len(harness.runtimes))
	}
}

func TestManagerRestartReservesBothPublicKeysDuringTransition(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(2)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 42)
	oldKey := supervisor.publicKey
	next := managerTestConfig(43, 1500)
	oldRuntime := harness.runtimes[0]
	oldRuntime.closeStarted = make(chan struct{})
	oldRuntime.closeRelease = make(chan struct{})
	restarted := make(chan error, 1)
	go func() {
		_, err := harness.manager.restartInterface(
			context.Background(),
			managerTestRestartRequest(supervisor, 43, next),
		)
		restarted <- err
	}()
	select {
	case <-oldRuntime.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("restart did not reach the old runtime close")
	}
	transition, err := supervisor.status(false)
	if err != nil {
		t.Fatalf("status during restart: %v", err)
	}
	if transition.GetGeneration() != 0 || transition.GetSpec().GetMtu() != 1500 {
		t.Fatalf(
			"restart transition exposed generation/MTU %d/%d, want old 0/1500",
			transition.GetGeneration(), transition.GetSpec().GetMtu(),
		)
	}
	if _, err := harness.manager.create("wgf-old", managerTestConfig(42, 1500)); CodeOf(err) != CodeAlreadyExists {
		t.Fatalf("create with reserved old public key error = %v, want AlreadyExists", err)
	}
	if _, err := harness.manager.create("wgf-new", next); CodeOf(err) != CodeAlreadyExists {
		t.Fatalf("create with reserved new public key error = %v, want AlreadyExists", err)
	}
	close(oldRuntime.closeRelease)
	select {
	case err := <-restarted:
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("restart did not complete")
	}
	plan, err := wgadapter.PreparePeers(next)
	if err != nil {
		t.Fatal(err)
	}
	if got := harness.manager.byPublicKey[plan.LocalPublicKey]; got != supervisor {
		t.Fatal("new public key was not committed")
	}
	if got := harness.manager.byPublicKey[oldKey]; got != nil {
		t.Fatal("old public key remained reserved after restart")
	}
}

func TestManagerRestartRetainsRuntimeAfterCloseFailure(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 44)
	oldRuntime := harness.runtimes[0]
	oldRuntime.counters = managerTestCounters(7, 11)
	oldRuntime.closeErr = errors.New("runtime close failed")

	request := managerTestRestartRequest(supervisor, 45, managerTestConfig(44, 9000))
	if _, err := harness.manager.restartInterface(context.Background(), request); err == nil {
		t.Fatal("restart unexpectedly succeeded")
	}
	if supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR ||
		supervisor.running != oldRuntime || supervisor.generation != 0 {
		t.Fatalf(
			"failed restart state = lifecycle %s, running retained %t, generation %d",
			supervisor.lifecycle, supervisor.running == oldRuntime, supervisor.generation,
		)
	}
	if got := harness.manager.counterBase(supervisor.publicKey).GetTxCarriers(); got != 0 {
		t.Fatalf("captured counters after failed close = %d, want 0", got)
	}

	oldRuntime.closeErr = nil
	retry := managerTestRestartRequest(supervisor, 46, managerTestConfig(44, 9000))
	if _, err := harness.manager.restartInterface(context.Background(), retry); err != nil {
		t.Fatalf("restart retry: %v", err)
	}
	if supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING ||
		supervisor.running == oldRuntime || supervisor.generation != 1 {
		t.Fatalf("restart retry state = lifecycle %s, generation %d", supervisor.lifecycle, supervisor.generation)
	}
	if got := harness.manager.counterBase(supervisor.publicKey).GetTxCarriers(); got != 7 {
		t.Fatalf("captured counters after retry = %d, want 7", got)
	}
}

func TestManagerRestartRequestReplayIsIdempotent(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 45)
	request := managerTestRestartRequest(supervisor, 46, managerTestConfig(45, 9000))
	first, err := harness.manager.restartInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	second, err := harness.manager.restartInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("restart replay: %v", err)
	}
	if !proto.Equal(first, second) || supervisor.generation != 1 || len(harness.runtimes) != 2 {
		t.Fatalf("restart replay/result = %v/%v, generation=%d runtimes=%d", first, second, supervisor.generation, len(harness.runtimes))
	}
}

func TestManagerRestartReservationFailureRestoresErrorLifecycle(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(2)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 47)
	_, _ = managerTestCreate(t, harness, "wgf1", 48)
	supervisor.mu.Lock()
	supervisor.lifecycle = controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR
	supervisor.lifecycleErr = "runtime failed"
	supervisor.mu.Unlock()

	_, err := harness.manager.restartInterface(
		context.Background(),
		managerTestRestartRequest(supervisor, 49, managerTestConfig(48, 9000)),
	)
	if CodeOf(err) != CodeAlreadyExists {
		t.Fatalf("restart error = %v, want AlreadyExists", err)
	}
	if supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR ||
		supervisor.lifecycleErr != "runtime failed" || supervisor.running == nil {
		t.Fatalf("restored state = lifecycle %s, error %q, running %t", supervisor.lifecycle, supervisor.lifecycleErr, supervisor.running != nil)
	}
}

func TestManagerRestartFailureRollsBackPreviousRuntime(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	harness.startErrors = []error{nil, errors.New("new runtime failed"), nil}
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 50)
	oldRuntime := harness.runtimes[0]
	oldConfig := config.Clone(supervisor.config)
	response, err := harness.manager.restartInterface(context.Background(), managerTestRestartRequest(supervisor, 51, managerTestConfig(50, 9000)))
	if err == nil || !strings.Contains(err.Error(), "previous runtime restored") {
		t.Fatalf("restart error = %v, want rollback error", err)
	}
	if response != nil {
		t.Fatalf("failed restart response = %v, want nil", response)
	}
	if supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_RUNNING || supervisor.running == nil {
		t.Fatalf("lifecycle after rollback = %s, running = %v", supervisor.lifecycle, supervisor.running != nil)
	}
	if supervisor.generation != 1 || supervisor.config.Interface.MTU != oldConfig.Interface.MTU {
		t.Fatalf("rollback generation/MTU = %d/%d, want 1/%d", supervisor.generation, supervisor.config.Interface.MTU, oldConfig.Interface.MTU)
	}
	if oldRuntime.closeCalls != 1 || len(harness.runtimes) != 2 {
		t.Fatalf("rollback runtime calls = old close %d, runtimes %d", oldRuntime.closeCalls, len(harness.runtimes))
	}
}

func TestManagerRestartRollbackFailureLeavesGetAvailable(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	harness.startErrors = []error{nil, errors.New("new runtime failed"), errors.New("rollback runtime failed")}
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 60)
	_, err := harness.manager.restartInterface(context.Background(), managerTestRestartRequest(supervisor, 61, managerTestConfig(60, 9000)))
	if err == nil || !strings.Contains(err.Error(), "rollback runtime") {
		t.Fatalf("restart error = %v, want rollback failure", err)
	}
	if supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR || supervisor.running != nil {
		t.Fatalf("lifecycle after rollback failure = %s, running = %v", supervisor.lifecycle, supervisor.running != nil)
	}
	get := controlapiv1.GetInterfaceRequest_builder{}.Build()
	get.SetTarget(supervisor.ref())
	response, getErr := harness.manager.getInterface(context.Background(), get)
	if getErr != nil {
		t.Fatalf("get after rollback failure: %v", getErr)
	}
	if response.GetStatus().GetLifecycle() != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR {
		t.Fatalf("get lifecycle = %s, want ERROR", response.GetStatus().GetLifecycle())
	}
}

func TestManagerDeleteRequestReplayIsIdempotent(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 70)
	request := managerTestDeleteRequest(supervisor, 71)
	first, err := harness.manager.deleteInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	second, err := harness.manager.deleteInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("delete replay: %v", err)
	}
	if !proto.Equal(first, second) || len(harness.manager.interfaces) != 0 {
		t.Fatalf("delete replay/result = %v/%v, interfaces = %d", first, second, len(harness.manager.interfaces))
	}
	if harness.anchor.closeCalls != 1 || harness.runtimes[0].closeCalls != 1 {
		t.Fatalf("delete close calls = anchor %d/runtime %d, want 1/1", harness.anchor.closeCalls, harness.runtimes[0].closeCalls)
	}
}

func TestManagerDeleteRetainsResourcesAfterCleanupFailure(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { harness.anchor.closeErr = nil; _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 75)
	harness.anchor.closeErr = errors.New("anchor close failed")
	request := managerTestDeleteRequest(supervisor, 76)
	if _, err := harness.manager.deleteInterface(context.Background(), request); err == nil {
		t.Fatal("delete unexpectedly succeeded with anchor cleanup failure")
	}
	if harness.manager.interfaces[supervisor.name] != supervisor || supervisor.anchor == nil {
		t.Fatal("failed cleanup lost the supervisor or anchor reference")
	}
	if supervisor.lifecycle != controlapiv1.InterfaceLifecycle_INTERFACE_LIFECYCLE_ERROR {
		t.Fatalf("lifecycle after cleanup failure = %s, want ERROR", supervisor.lifecycle)
	}
	harness.anchor.closeErr = nil
	retry := managerTestDeleteRequest(supervisor, 77)
	if _, err := harness.manager.deleteInterface(context.Background(), retry); err != nil {
		t.Fatalf("delete retry: %v", err)
	}
	if harness.manager.interfaces[supervisor.name] != nil || supervisor.anchor != nil {
		t.Fatal("successful cleanup retained the supervisor or anchor")
	}
}

func TestManagerDeleteRetryCapturesRuntimeCountersOnce(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 78)
	runtime := harness.runtimes[0]
	runtime.counters = managerTestCounters(7, 11)
	runtime.closeErr = errors.New("runtime close failed")

	if _, err := harness.manager.deleteInterface(context.Background(), managerTestDeleteRequest(supervisor, 79)); err == nil {
		t.Fatal("delete unexpectedly succeeded")
	}
	if got := harness.manager.counterBase(supervisor.publicKey).GetTxCarriers(); got != 0 {
		t.Fatalf("captured counters after failed close = %d, want 0", got)
	}
	runtime.closeErr = nil
	if _, err := harness.manager.deleteInterface(context.Background(), managerTestDeleteRequest(supervisor, 80)); err != nil {
		t.Fatalf("delete retry: %v", err)
	}
	base := harness.manager.counterBase(supervisor.publicKey)
	if base.GetTxCarriers() != 7 || base.GetRxDataCarriers() != 11 {
		t.Fatalf("captured counters = tx %d/rx %d, want 7/11", base.GetTxCarriers(), base.GetRxDataCarriers())
	}
}

func TestManagerCloseRejectsNewOperationsAndWaitsForInFlight(t *testing.T) {
	t.Parallel()
	manager := newManagerForTest(managerPlatform{}, 1, nil)
	if err := manager.beginOperation(); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- manager.close() }()
	select {
	case err := <-closed:
		t.Fatalf("manager closed before in-flight operation ended: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := manager.beginOperation(); CodeOf(err) != CodeUnavailable {
		t.Fatalf("operation after shutdown error = %v, want Unavailable", err)
	}
	manager.endOperation()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("manager close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager close did not wait for operation completion")
	}
}

func TestManagerCreateRequestReplayIsIdempotent(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	cfg := managerTestConfig(80, 1500)
	request := managerTestCreateRequest(81, managerTestInterfaceSpec("wgf0", cfg))
	first, err := harness.manager.createInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := harness.manager.createInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("create replay: %v", err)
	}
	if !proto.Equal(first, second) || len(harness.manager.interfaces) != 1 || harness.startCalls != 1 {
		t.Fatalf("create replay/result = %v/%v, interfaces = %d, starts = %d", first, second, len(harness.manager.interfaces), harness.startCalls)
	}
}

func TestManagerPublicKeyChangeStartsNewCounterSeries(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 90)
	harness.runtimes[0].counters = managerTestCounters(7, 11)
	oldKey := supervisor.publicKey
	next := managerTestConfig(91, 1500)
	if _, err := harness.manager.restartInterface(context.Background(), managerTestRestartRequest(supervisor, 92, next)); err != nil {
		t.Fatalf("restart with new public key: %v", err)
	}
	newKey := supervisor.publicKey
	if newKey == oldKey {
		t.Fatal("public key did not change")
	}
	if got := harness.manager.counterBase(oldKey).GetTxCarriers(); got != 7 {
		t.Fatalf("old counter series tx carriers = %d, want 7", got)
	}
	if got := harness.manager.counterBase(newKey).GetTxCarriers(); got != 0 {
		t.Fatalf("new counter series tx carriers = %d, want 0", got)
	}
}

func TestManagerDeleteRecreateContinuesSamePublicKeyCounters(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 100)
	harness.runtimes[0].counters = managerTestCounters(19, 23)
	if _, err := harness.manager.deleteInterface(context.Background(), managerTestDeleteRequest(supervisor, 101)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	cfg := managerTestConfig(100, 1500)
	if _, err := harness.manager.createInterface(
		context.Background(), managerTestCreateRequest(102, managerTestInterfaceSpec("wgf0", cfg)),
	); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	recreated := harness.manager.interfaces["wgf0"]
	status, err := recreated.status(false)
	if err != nil {
		t.Fatal(err)
	}
	if got := status.GetCounters(); got.GetTxCarriers() != 19 || got.GetRxDataCarriers() != 23 {
		t.Fatalf("recreated counters = tx %d/rx %d, want 19/23", got.GetTxCarriers(), got.GetRxDataCarriers())
	}
}

func TestManagerRestartPreservesOmittedPrivateKey(t *testing.T) {
	t.Parallel()
	harness := newManagerTestHarness(1)
	t.Cleanup(func() { _ = harness.manager.close() })
	supervisor, _ := managerTestCreate(t, harness, "wgf0", 110)
	oldKey := supervisor.publicKey
	next := managerTestConfig(110, 9000)
	request := controlapiv1.RestartInterfaceRequest_builder{}.Build()
	request.SetTarget(supervisor.ref())
	request.SetMutation(managerTestMutationFor(supervisor, 111))
	request.SetSpec(controlconfig.SpecFromConfig(supervisor.name, next, false))
	if _, err := harness.manager.restartInterface(context.Background(), request); err != nil {
		t.Fatalf("restart with omitted private key: %v", err)
	}
	if supervisor.publicKey != oldKey || supervisor.config.Interface.PrivateKey != next.Interface.PrivateKey {
		t.Fatal("restart did not preserve the current private key")
	}
}
