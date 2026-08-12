package memoryplan

import "testing"

func TestCalculateIncludesAllComponents(t *testing.T) {
	got, err := Calculate(Config{MTU: 1500, Peers: 2, ReassemblySlots: 4, MaxCarrierPayload: 1400, CarrierQueueSlots: 8, ControlQueueSlots: 16, ReorderCapacity: 64, ReorderLanes: 1, TUNBatchSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalBytes != got.ReassemblyBytes+got.SenderBytes+got.CarrierBytes+got.ControlBytes+got.ReorderBytes+got.TUNBatchBytes {
		t.Fatalf("total = %d, components = %+v", got.TotalBytes, got)
	}
}

func TestCalculateRejectsOverflow(t *testing.T) {
	if _, err := Calculate(Config{MTU: int(^uint(0) >> 1), Peers: int(^uint(0) >> 1), ReassemblySlots: 2, MaxCarrierPayload: 1, CarrierQueueSlots: 1, ControlQueueSlots: 1, ReorderCapacity: 1, ReorderLanes: 1, TUNBatchSize: 1}); err == nil {
		t.Fatal("overflowing configuration succeeded")
	}
}
