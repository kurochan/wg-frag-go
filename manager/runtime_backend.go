//go:build linux || darwin

package manager

import (
	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/daemonruntime"
	"github.com/kurochan/wg-frag-go/internal/metrics"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

type runtimeTUNAnchor = daemonruntime.TUNAnchor

type managedRuntime interface {
	close() error
	wait() error
	status(includeSecrets bool) (*controlapiv1.InterfaceStatus, error)
	counterSnapshot() *controlapiv1.ShimCounters
	applyPeers(request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error)
	configSnapshot() *config.Config
	metricsSnapshot() metrics.Snapshot
	effectiveListenPort() (uint16, error)
	dumpStats()
}

type runtimeStarter func(*interfaceSupervisor, *config.Config) (managedRuntime, error)

type managerPlatform struct {
	openAnchor func(string, int) (runtimeTUNAnchor, error)
}

type runtimeAdapter struct {
	runtime *daemonruntime.Runtime
}

func (adapter *runtimeAdapter) close() error { return adapter.runtime.Close() }
func (adapter *runtimeAdapter) wait() error  { return adapter.runtime.Wait() }
func (adapter *runtimeAdapter) status(includeSecrets bool) (*controlapiv1.InterfaceStatus, error) {
	return adapter.runtime.Status(includeSecrets)
}
func (adapter *runtimeAdapter) counterSnapshot() *controlapiv1.ShimCounters {
	return adapter.runtime.CounterSnapshot()
}
func (adapter *runtimeAdapter) applyPeers(request *controlapiv1.ApplyPeersRequest) (*controlapiv1.ApplyPeersResponse, error) {
	return adapter.runtime.ApplyPeers(request)
}
func (adapter *runtimeAdapter) configSnapshot() *config.Config {
	return adapter.runtime.ConfigSnapshot()
}
func (adapter *runtimeAdapter) metricsSnapshot() metrics.Snapshot {
	return adapter.runtime.MetricsSnapshot()
}
func (adapter *runtimeAdapter) effectiveListenPort() (uint16, error) {
	return adapter.runtime.EffectiveListenPort()
}
func (adapter *runtimeAdapter) dumpStats() { adapter.runtime.DumpStats() }
