// Package memoryplan estimates WGF's fixed dataplane reservations.
package memoryplan

import "errors"

// Config describes logical fixed buffers owned by the shim. The estimate does
// not include Go allocator overhead, wireguard-go, kernel buffers, or runtime
// memory.
type Config struct {
	MTU               int
	Peers             int
	ReassemblySlots   int
	MaxCarrierPayload int
	CarrierQueueSlots int
	ControlQueueSlots int
	ReorderCapacity   int
	ReorderLanes      int
	TUNBatchSize      int
}

// Estimate contains each reservation component and their checked sum.
type Estimate struct {
	ReassemblyBytes uint64
	SenderBytes     uint64
	CarrierBytes    uint64
	ControlBytes    uint64
	ReorderBytes    uint64
	TUNBatchBytes   uint64
	TotalBytes      uint64
}

var ErrInvalidConfig = errors.New("memoryplan: invalid configuration")

const (
	reassemblyMetadataBytes = 64
	senderMetadataBytes     = 64
	reorderEntryBytes       = 32
	batchMetadataBytes      = 16
)

func Calculate(c Config) (Estimate, error) {
	if c.MTU <= 0 || c.Peers <= 0 || c.ReassemblySlots <= 0 || c.MaxCarrierPayload <= 0 ||
		c.CarrierQueueSlots <= 0 || c.ControlQueueSlots <= 0 || c.ReorderCapacity <= 0 ||
		c.ReorderLanes <= 0 || c.TUNBatchSize <= 0 {
		return Estimate{}, ErrInvalidConfig
	}
	var out Estimate
	var err error
	if out.ReassemblyBytes, err = product(uint64(c.Peers), uint64(c.ReassemblySlots), uint64(c.MTU+reassemblyMetadataBytes)); err != nil {
		return Estimate{}, err
	}
	if out.SenderBytes, err = product(uint64(c.Peers), uint64(c.MaxCarrierPayload+senderMetadataBytes)); err != nil {
		return Estimate{}, err
	}
	if out.CarrierBytes, err = product(uint64(c.CarrierQueueSlots), uint64(c.MaxCarrierPayload)); err != nil {
		return Estimate{}, err
	}
	if out.ControlBytes, err = product(uint64(c.ControlQueueSlots), uint64(c.MaxCarrierPayload)); err != nil {
		return Estimate{}, err
	}
	if out.ReorderBytes, err = product(uint64(c.Peers), uint64(c.ReorderLanes), uint64(c.ReorderCapacity), reorderEntryBytes); err != nil {
		return Estimate{}, err
	}
	if out.TUNBatchBytes, err = product(uint64(c.TUNBatchSize), uint64(c.MTU+batchMetadataBytes)); err != nil {
		return Estimate{}, err
	}
	parts := []uint64{out.ReassemblyBytes, out.SenderBytes, out.CarrierBytes, out.ControlBytes, out.ReorderBytes, out.TUNBatchBytes}
	for _, part := range parts {
		if ^uint64(0)-out.TotalBytes < part {
			return Estimate{}, ErrInvalidConfig
		}
		out.TotalBytes += part
	}
	return out, nil
}

func product(values ...uint64) (uint64, error) {
	out := uint64(1)
	for _, value := range values {
		if value != 0 && out > ^uint64(0)/value {
			return 0, ErrInvalidConfig
		}
		out *= value
	}
	return out, nil
}
