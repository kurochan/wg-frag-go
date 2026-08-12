package datapath

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/lane"
)

func newWrapSender(t *testing.T, reuse time.Duration, initialSequence uint32) (*Sender, *carrierCollector) {
	t.Helper()
	carriers := &carrierCollector{}
	sequences := [lane.Lanes]uint32{}
	sequences[0] = initialSequence
	sender, err := NewSender(SenderConfig{
		DataSessionID:         1,
		CarrierSource:         netip.MustParseAddr("fe80::2"),
		CarrierDest:           netip.MustParseAddr("fe80::1"),
		CarrierPayload:        613,
		MinPack:               128,
		RemotePeerMTU:         1500,
		InitialSequences:      &sequences,
		SequenceReuseLifetime: reuse,
	}, carriers)
	if err != nil {
		t.Fatal(err)
	}
	return sender, carriers
}

func TestSenderPausesLaneAfterSequenceWrap(t *testing.T) {
	t.Parallel()
	sender, _ := newWrapSender(t, time.Hour, ^uint32(0))
	if err := sender.Add(ipv4Packet(10, 0)); err != nil {
		t.Fatalf("Add() at max sequence: %v", err)
	}
	if err := sender.Add(ipv4Packet(10, 1)); !errors.Is(err, ErrLaneWrap) {
		t.Fatalf("Add() after wrap = %v, want ErrLaneWrap", err)
	}
	if err := sender.Add(ipv4Packet(10, 2)); !errors.Is(err, ErrLaneWrap) {
		t.Fatalf("Add() while paused = %v, want ErrLaneWrap", err)
	}
}

func TestSenderReopensLaneAfterReuseLifetime(t *testing.T) {
	t.Parallel()
	sender, _ := newWrapSender(t, time.Nanosecond, ^uint32(0))
	if err := sender.Add(ipv4Packet(10, 0)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if err := sender.Add(ipv4Packet(10, 1)); err != nil {
		t.Fatalf("Add() after pause elapsed: %v", err)
	}
	if got := sender.Sequences()[0]; got != 1 {
		t.Fatalf("sequence after reuse = %d, want 1", got)
	}
}

func TestSenderWrapPauseSurvivesReplacement(t *testing.T) {
	t.Parallel()
	sender, _ := newWrapSender(t, time.Hour, ^uint32(0))
	if err := sender.Add(ipv4Packet(10, 0)); err != nil {
		t.Fatal(err)
	}
	sequences := sender.Sequences()
	wrapBlocks := sender.WrapBlocks()
	carriers := &carrierCollector{}
	replacement, err := NewSender(SenderConfig{
		DataSessionID:         1,
		CarrierSource:         netip.MustParseAddr("fe80::2"),
		CarrierDest:           netip.MustParseAddr("fe80::1"),
		CarrierPayload:        1400,
		MinPack:               128,
		RemotePeerMTU:         1500,
		InitialSequences:      &sequences,
		InitialWrapBlocks:     &wrapBlocks,
		SequenceReuseLifetime: time.Hour,
	}, carriers)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Add(ipv4Packet(10, 1)); !errors.Is(err, ErrLaneWrap) {
		t.Fatalf("Add() on replacement = %v, want ErrLaneWrap", err)
	}
}
