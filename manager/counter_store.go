//go:build linux || darwin

package manager

import (
	"container/list"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/protobuf/proto"
)

const retainedCounterIdentities = 256

type counterStoreEntry struct {
	counters *controlapiv1.ShimCounters
	element  *list.Element
}

// counterStore retains recent inactive identities in addition to every active
// identity. This preserves normal delete/recreate continuity without allowing
// unbounded interface-key churn to grow process memory forever.
type counterStore struct {
	entries  map[[32]byte]*counterStoreEntry
	order    *list.List
	capacity int
}

func newCounterStore(capacity int) *counterStore {
	return &counterStore{
		entries:  make(map[[32]byte]*counterStoreEntry),
		order:    list.New(),
		capacity: capacity,
	}
}

func counterStoreCapacity(maxInterfaces int) int {
	maxInt := int(^uint(0) >> 1)
	if maxInterfaces > maxInt-retainedCounterIdentities {
		return maxInt
	}
	return maxInterfaces + retainedCounterIdentities
}

func (store *counterStore) add(
	key [32]byte,
	counters *controlapiv1.ShimCounters,
	active map[[32]byte]*interfaceSupervisor,
) {
	if counters == nil {
		return
	}
	if current := store.entries[key]; current != nil {
		current.counters = addShimCounters(current.counters, counters)
		store.order.MoveToBack(current.element)
		return
	}
	for store.capacity > 0 && len(store.entries) >= store.capacity {
		if !store.evictOldestInactive(active) {
			return
		}
	}
	element := store.order.PushBack(key)
	store.entries[key] = &counterStoreEntry{
		counters: addShimCounters(nil, counters),
		element:  element,
	}
}

func (store *counterStore) get(key [32]byte) *controlapiv1.ShimCounters {
	entry := store.entries[key]
	if entry == nil {
		return controlapiv1.ShimCounters_builder{}.Build()
	}
	return proto.Clone(entry.counters).(*controlapiv1.ShimCounters)
}

func (store *counterStore) evictOldestInactive(active map[[32]byte]*interfaceSupervisor) bool {
	for element := store.order.Front(); element != nil; element = element.Next() {
		key := element.Value.([32]byte)
		if active[key] != nil {
			continue
		}
		store.order.Remove(element)
		delete(store.entries, key)
		return true
	}
	return false
}

func (manager *Manager) retainCounters(publicKey [32]byte, counters *controlapiv1.ShimCounters) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.counters.add(publicKey, counters, manager.byPublicKey)
}

func addShimCounters(left, right *controlapiv1.ShimCounters) *controlapiv1.ShimCounters {
	result := controlapiv1.ShimCounters_builder{}.Build()
	result.SetTxCarriers(left.GetTxCarriers() + right.GetTxCarriers())
	result.SetTxPacketDrops(left.GetTxPacketDrops() + right.GetTxPacketDrops())
	result.SetTxNativeFragmentDrops(left.GetTxNativeFragmentDrops() + right.GetTxNativeFragmentDrops())
	result.SetTxRouteDrops(left.GetTxRouteDrops() + right.GetTxRouteDrops())
	result.SetTxPeerMtuDrops(left.GetTxPeerMtuDrops() + right.GetTxPeerMtuDrops())
	result.SetTxPtbSent(left.GetTxPtbSent() + right.GetTxPtbSent())
	result.SetControlExploratoryEvictions(left.GetControlExploratoryEvictions() + right.GetControlExploratoryEvictions())
	result.SetControlCoalesces(left.GetControlCoalesces() + right.GetControlCoalesces())
	result.SetControlRateSuppressionEpisodes(left.GetControlRateSuppressionEpisodes() + right.GetControlRateSuppressionEpisodes())
	result.SetControlIngressRateLimited(left.GetControlIngressRateLimited() + right.GetControlIngressRateLimited())
	result.SetRxDataCarriers(left.GetRxDataCarriers() + right.GetRxDataCarriers())
	result.SetRxInnerDelivered(left.GetRxInnerDelivered() + right.GetRxInnerDelivered())
	result.SetRxPacketRejects(left.GetRxPacketRejects() + right.GetRxPacketRejects())
	result.SetRxNativeFragmentDrops(left.GetRxNativeFragmentDrops() + right.GetRxNativeFragmentDrops())
	result.SetRxSourceSpoofDrops(left.GetRxSourceSpoofDrops() + right.GetRxSourceSpoofDrops())
	result.SetRxNativeWriteDrops(left.GetRxNativeWriteDrops() + right.GetRxNativeWriteDrops())
	result.SetCarrierQueueOverflows(left.GetCarrierQueueOverflows() + right.GetCarrierQueueOverflows())
	result.SetPreconfirmDrops(left.GetPreconfirmDrops() + right.GetPreconfirmDrops())
	result.SetReassemblyExpirations(left.GetReassemblyExpirations() + right.GetReassemblyExpirations())
	result.SetUdpSocketDrops(left.GetUdpSocketDrops() + right.GetUdpSocketDrops())
	result.SetControlQueueDrops(left.GetControlQueueDrops() + right.GetControlQueueDrops())
	result.SetControlMaterializationDrops(left.GetControlMaterializationDrops() + right.GetControlMaterializationDrops())
	return result
}
