package shimtun

import (
	"testing"
	"time"

	corecontrol "github.com/kurochan/wg-frag-go/internal/core/control"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	wirev1 "github.com/kurochan/wg-frag-go/proto/wire/v1"
	"google.golang.org/protobuf/proto"
)

func schedulerFrame(t *testing.T, codec corecontrol.Codec, message *wirev1.Control, target int) []byte {
	t.Helper()
	if target != 0 {
		base := proto.Clone(message).(*wirev1.Control)
		for padding := 0; padding <= target; padding++ {
			base.SetPadding(make([]byte, padding))
			if corecontrol.HeaderSize+proto.Size(base) == target {
				message = base

				break
			}
		}
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, corecontrol.HeaderSize+len(payload))
	if _, err := codec.MarshalTo(frame, payload); err != nil {
		t.Fatal(err)
	}
	return frame
}

func controlMessage(id uint64, body any) *wirev1.Control {
	epoch := uint64(1)
	builder := wirev1.Control_builder{MessageId: &id, ControlEpoch: &epoch}
	switch value := body.(type) {
	case *wirev1.MtuProbe:
		builder.MtuProbe = value
	case *wirev1.MtuProbeAck:
		builder.MtuProbeAck = value
	case *wirev1.Ping:
		builder.Ping = value
	case *wirev1.Pong:
		builder.Pong = value
	case *wirev1.ResetSequence:
		builder.ResetSequence = value
	case *wirev1.PeerMTU:
		builder.PeerMtu = value
	case *wirev1.CapabilitiesHello:
		builder.CapabilitiesHello = value
	case *wirev1.CapabilitiesAck:
		builder.CapabilitiesAck = value
	case *wirev1.ResetSequenceAck:
		builder.ResetSequenceAck = value
	case *wirev1.PeerMTUAck:
		builder.PeerMtuAck = value
	case *wirev1.StateSyncRequired:
		builder.StateSyncRequired = value
	}
	return builder.Build()
}

func ping(sequence uint32) *wirev1.Ping {
	return (wirev1.Ping_builder{Sequence: &sequence}).Build()
}

func pong(sequence uint32) *wirev1.Pong {
	return (wirev1.Pong_builder{Sequence: &sequence}).Build()
}

func resetSequence(session uint32) *wirev1.ResetSequence {
	return (wirev1.ResetSequence_builder{DataSessionId: &session}).Build()
}

func peerMTU(mtu uint32) *wirev1.PeerMTU {
	return (wirev1.PeerMTU_builder{InnerMtu: &mtu}).Build()
}

func mtuProbe() *wirev1.MtuProbe {
	return (wirev1.MtuProbe_builder{}).Build()
}

func TestControlSchedulerRingEvictionAndCoalesce(t *testing.T) {
	codec, err := corecontrol.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	s := newControlScheduler(16, []peerroute.PeerID{0, 1})
	for i := 0; i < controlExploratoryLimit; i++ {
		frame := schedulerFrame(t, codec, controlMessage(uint64(i+1), mtuProbe()), 64+i)
		dropped, _, _, err := s.enqueue(0, frame, codec)
		if err != nil || dropped {
			t.Fatalf("probe enqueue %d: dropped=%v err=%v", i, dropped, err)
		}
	}
	for i := 0; i < 8; i++ {
		frame := schedulerFrame(t, codec, controlMessage(uint64(100+i), ping(uint32(i))), 0)
		dropped, _, _, err := s.enqueue(1, frame, codec)
		if err != nil || dropped {
			t.Fatalf("critical enqueue %d: dropped=%v err=%v", i, dropped, err)
		}
	}
	// The ring is full; this critical descriptor evicts the oldest probe.
	frame := schedulerFrame(t, codec, controlMessage(500, resetSequence(7)), 0)
	dropped, evicted, _, err := s.enqueue(0, frame, codec)
	if err != nil || dropped || !evicted || s.exploratory != controlExploratoryLimit-1 {
		t.Fatalf("critical eviction: dropped=%v evicted=%v err=%v exploratory=%d", dropped, evicted, err, s.exploratory)
	}
	for s.exploratory > 0 {
		s.remove(s.oldestExploratory())
	}
	// Fill with a known critical kind, then verify an exact duplicate coalesces.
	for s.count < len(s.descriptors) {
		frame := schedulerFrame(t, codec, controlMessage(uint64(600+s.count), peerMTU(1500)), 0)
		if dropped, _, _, err := s.enqueue(0, frame, codec); err != nil || dropped {
			t.Fatalf("fill critical: dropped=%v err=%v", dropped, err)
		}
	}
	coalesce := schedulerFrame(t, codec, controlMessage(609, peerMTU(1500)), 0)
	dropped, _, coalesced, err := s.enqueue(0, coalesce, codec)
	if err != nil || dropped || !coalesced {
		t.Fatalf("critical coalesce: dropped=%v coalesced=%v err=%v", dropped, coalesced, err)
	}
}

func TestControlSchedulerAdmissionPreservesOtherPeerCriticalCapacity(t *testing.T) {
	codec, err := corecontrol.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	s := newControlScheduler(16, []peerroute.PeerID{0, 1})
	for i := 0; i < 8; i++ {
		frame := schedulerFrame(t, codec, controlMessage(uint64(i+1), pong(uint32(i))), 0)
		if dropped, _, _, err := s.enqueue(0, frame, codec); err != nil || dropped {
			t.Fatalf("enqueue peer 0 #%d: dropped=%v err=%v", i, dropped, err)
		}
	}
	frame := schedulerFrame(t, codec, controlMessage(99, pong(99)), 0)
	if dropped, _, _, err := s.enqueue(0, frame, codec); err != nil || !dropped {
		t.Fatalf("peer 0 over admission limit: dropped=%v err=%v", dropped, err)
	}
	hello := schedulerFrame(t, codec, controlMessage(100, (&wirev1.CapabilitiesHello_builder{}).Build()), 0)
	if dropped, _, _, err := s.enqueue(1, hello, codec); err != nil || dropped {
		t.Fatalf("peer 1 critical Hello: dropped=%v err=%v", dropped, err)
	}
}

func TestControlSchedulerAdmissionScalesBeyondFourPeers(t *testing.T) {
	codec, err := corecontrol.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	peers := []peerroute.PeerID{0, 1, 2, 3, 4}
	s := newControlScheduler(16, peers)
	for _, peer := range peers[:4] {
		for i := 0; i < 4; i++ {
			frame := schedulerFrame(t, codec, controlMessage(uint64(100+int(peer)*4+i), ping(uint32(i))), 0)
			dropped, _, _, err := s.enqueue(peer, frame, codec)
			if err != nil || dropped != (i == 3) {
				t.Fatalf("enqueue peer %d #%d: dropped=%v err=%v, want dropped=%t", peer, i, dropped, err, i == 3)
			}
		}
	}
	if s.count != 12 {
		t.Fatalf("scheduler count = %d, want 12 after four descriptors per peer", s.count)
	}
	// The fifth peer must still receive a critical descriptor; the per-peer
	// admission limit is floor(16/5), not floor(16/4).
	hello := schedulerFrame(t, codec, controlMessage(999, (&wirev1.CapabilitiesHello_builder{}).Build()), 0)
	if dropped, _, _, err := s.enqueue(4, hello, codec); err != nil || dropped {
		t.Fatalf("peer 4 Hello: dropped=%v err=%v", dropped, err)
	}
}

func TestControlSchedulerProbeMaterialization(t *testing.T) {
	codec, err := corecontrol.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	frame := schedulerFrame(t, codec, controlMessage(1, mtuProbe()), 613)
	s := newControlScheduler(16, []peerroute.PeerID{0})
	if dropped, _, _, err := s.enqueue(0, frame, codec); err != nil || dropped {
		t.Fatalf("enqueue probe: dropped=%v err=%v", dropped, err)
	}
	desc, index, ok := s.choose(time.Unix(0, 0))
	if !ok || desc.targetSize != len(frame) || len(desc.message.GetPadding()) != 0 {
		t.Fatalf("descriptor = ok:%v target:%d padding:%d", ok, desc.targetSize, len(desc.message.GetPadding()))
	}
	dst := make([]byte, codec.MaxFrameSize())
	got, err := materializeControl(desc, dst, codec)
	if err != nil || got != len(frame) {
		t.Fatalf("materialize = (%d,%v), want (%d,nil)", got, err, len(frame))
	}
	if _, err := codec.Parse(dst[:got]); err != nil {
		t.Fatalf("materialized frame parse: %v", err)
	}
	if s.pop(index).targetSize != len(frame) {
		t.Fatal("popped descriptor changed")
	}
}

func TestControlSchedulerPeerRoundRobinAndRateLimit(t *testing.T) {
	codec, err := corecontrol.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	s := newControlScheduler(16, []peerroute.PeerID{0, 1})
	for i := 0; i < 8; i++ {
		for _, peer := range []peerroute.PeerID{0, 1} {
			frame := schedulerFrame(t, codec, controlMessage(uint64(100+i*2+int(peer)), ping(uint32(i))), 0)
			if dropped, _, _, err := s.enqueue(peer, frame, codec); err != nil || dropped {
				t.Fatalf("enqueue peer %d: dropped=%v err=%v", peer, dropped, err)
			}
		}
	}
	now := time.Unix(10, 0)
	for i := 0; i < 16; i++ {
		desc, index, ok := s.choose(now)
		if !ok {
			t.Fatalf("choose %d unexpectedly rate limited", i)
		}
		if desc.peer != peerroute.PeerID(i%2) {
			t.Fatalf("round robin %d peer=%d", i, desc.peer)
		}
		s.pop(index)
	}
	if _, _, ok := s.choose(now); ok {
		t.Fatal("scheduler exceeded burst after ring drained")
	}
	limited := newControlScheduler(16, []peerroute.PeerID{0})
	for i := 0; i < 16; i++ {
		frame := schedulerFrame(t, codec, controlMessage(uint64(1000+i), ping(uint32(i))), 0)
		if dropped, _, _, err := limited.enqueue(0, frame, codec); err != nil || dropped {
			t.Fatalf("enqueue limited %d: dropped=%v err=%v", i, dropped, err)
		}
	}
	for i := 0; i < 8; i++ {
		_, index, ok := limited.choose(now)
		if !ok {
			t.Fatalf("peer burst choose %d unexpectedly limited", i)
		}
		limited.pop(index)
	}
	if _, _, ok := limited.choose(now); ok {
		t.Fatal("peer scheduler exceeded burst of eight")
	}
}

func TestControlSchedulerPeerBucketsRemainBounded(t *testing.T) {
	s := newControlScheduler(16, []peerroute.PeerID{0})
	s.updatePeers([]peerroute.PeerID{100, 200})
	s.updatePeers([]peerroute.PeerID{200})
	if len(s.peerRate) != 1 {
		t.Fatalf("peer bucket count = %d, want 1", len(s.peerRate))
	}
	if s.peerRate[200] == nil {
		t.Fatal("active peer bucket was removed")
	}
}
