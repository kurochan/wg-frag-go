package controlplane

import (
	"testing"
	"time"

	controlstate "github.com/kurochan/wg-frag-go/internal/core/control/state"
	wirev1 "github.com/kurochan/wg-frag-go/proto/wire/v1"
)

func newStartupRetryTestEngine(t testing.TB, clock *fakeClock, entropy *fakeEntropy) *Engine {
	t.Helper()
	engine, err := New(Config{State: controlstate.Config{
		MaxCarrierPayload:    613,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy:              entropy,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestFirstAcceptedRemoteHelloRearmsCapabilityRetry(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine := newStartupRetryTestEngine(t, clock, &fakeEntropy{values: []uint64{
		0x1001, // local epoch
		0x1002, // local DATA session
		uint64(initialRetryDelay - time.Nanosecond),
		uint64(2*initialRetryDelay - time.Nanosecond),
		uint64(4*initialRetryDelay - time.Nanosecond),
		uint64(8*initialRetryDelay - time.Nanosecond),
		uint64(initialRetryDelay - time.Nanosecond), // first remote Hello rearm
		uint64(2*initialRetryDelay - time.Nanosecond),
		uint64(4*initialRetryDelay - time.Nanosecond),
		uint64(8*initialRetryDelay - time.Nanosecond),
		2_500_000_000, // attempt 4: cap before jitter must yield 500ms
	}})
	initial, err := engine.Start()
	if err != nil || len(initial) != 1 {
		t.Fatalf("Start() = (%d outputs, %v)", len(initial), err)
	}
	localHello := decodeControl(t, initial[0].Frame)

	// Simulate an unavailable transport: every retry is emitted but does not
	// reach the peer, so the request's exponential backoff becomes long.
	for attempt := 0; attempt < 3; attempt++ {
		clock.now = engine.outstanding.retryDeadline
		retry, err := engine.Tick(clock.now)
		if err != nil || len(retry) != 1 {
			t.Fatalf("retry %d = (%d outputs, %v)", attempt, len(retry), err)
		}
	}
	oldDeadline := engine.outstanding.retryDeadline
	if remaining := oldDeadline.Sub(clock.now); remaining <= initialRetryDelay {
		t.Fatalf("test setup did not create a long retry deadline: %s", remaining)
	}

	remoteHello := controlMessage(0x2001, 1, 0, capabilities(1, 16, 613, 0, 0, 2000))
	responses, err := engine.HandleInbound(encodeControl(t, engine.codec, remoteHello))
	if err != nil || len(responses) != 1 {
		t.Fatalf("first remote Hello = (%d outputs, %v)", len(responses), err)
	}
	if responses[0].Frame == nil || decodeControl(t, responses[0].Frame).GetCapabilitiesAck() == nil {
		t.Fatal("first remote Hello did not produce CapabilitiesAck")
	}
	if !engine.outstanding.retryDeadline.Before(oldDeadline) {
		t.Fatalf("first remote Hello did not rearm retry: old=%s new=%s", oldDeadline, engine.outstanding.retryDeadline)
	}
	if got := engine.outstanding.retryDeadline.Sub(clock.now); got > initialRetryDelay {
		t.Fatalf("rearmed retry delay = %s, want at most %s", got, initialRetryDelay)
	}

	clock.now = engine.outstanding.retryDeadline
	retry, err := engine.Tick(clock.now)
	if err != nil || len(retry) != 1 {
		t.Fatalf("rearmed retry = (%d outputs, %v)", len(retry), err)
	}
	resent := decodeControl(t, retry[0].Frame)
	if resent.GetCapabilitiesHello() == nil || resent.GetMessageId() != localHello.GetMessageId() ||
		resent.GetControlEpoch() != localHello.GetControlEpoch() {
		t.Fatalf("rearmed retry changed Hello identity: got epoch=%x id=%d, want epoch=%x id=%d",
			resent.GetControlEpoch(), resent.GetMessageId(), localHello.GetControlEpoch(), localHello.GetMessageId())
	}

	// A duplicate Hello from the same remote epoch must not keep moving the
	// retry deadline forward or reset the retry attempt on every duplicate.
	deadline := engine.outstanding.retryDeadline
	attempt := engine.outstanding.retryAttempt
	if _, err := engine.HandleInbound(encodeControl(t, engine.codec, remoteHello)); err != nil {
		t.Fatalf("duplicate remote Hello = %v", err)
	}
	if engine.outstanding.retryDeadline != deadline || engine.outstanding.retryAttempt != attempt {
		t.Fatalf("duplicate remote Hello changed retry state: deadline %s -> %s, attempt %d -> %d",
			deadline, engine.outstanding.retryDeadline, attempt, engine.outstanding.retryAttempt)
	}

	// The rearmed Hello may also be lost. The startup cap must continue to
	// apply to that same outstanding request while preserving its identity.
	for wantAttempt := uint(2); wantAttempt <= 4; wantAttempt++ {
		clock.now = engine.outstanding.retryDeadline
		retry, err := engine.Tick(clock.now)
		if err != nil || len(retry) != 1 {
			t.Fatalf("post-Hello retry attempt %d = (%d outputs, %v)", wantAttempt, len(retry), err)
		}
		resent = decodeControl(t, retry[0].Frame)
		if resent.GetMessageId() != localHello.GetMessageId() || resent.GetControlEpoch() != localHello.GetControlEpoch() {
			t.Fatalf("post-Hello retry changed Hello identity at attempt %d: got epoch=%x id=%d, want epoch=%x id=%d",
				wantAttempt, resent.GetControlEpoch(), resent.GetMessageId(), localHello.GetControlEpoch(), localHello.GetMessageId())
		}
	}
	if got := engine.outstanding.retryDeadline.Sub(clock.now); got > capabilitiesRetryMaxDelay {
		t.Fatalf("post-Hello startup retry delay = %s, want at most %s", got, capabilitiesRetryMaxDelay)
	}
}

func TestFirstAcceptedRemoteHelloDoesNotPostponeEarlyRetry(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1100, 0)}
	entropy := &fakeEntropy{values: []uint64{
		0x1101, // local epoch
		0x1102, // local DATA session
		0,      // initial retry: one nanosecond
		uint64(initialRetryDelay - time.Nanosecond), // rearm candidate
	}}
	engine := newStartupRetryTestEngine(t, clock, entropy)
	if _, err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	oldDeadline := engine.outstanding.retryDeadline
	if got := oldDeadline.Sub(clock.now); got >= initialRetryDelay {
		t.Fatalf("initial retry delay = %s, want less than %s", got, initialRetryDelay)
	}

	remoteHello := controlMessage(0x2101, 1, 0, capabilities(1, 16, 613, 0, 0, 2000))
	if _, err := engine.HandleInbound(encodeControl(t, engine.codec, remoteHello)); err != nil {
		t.Fatal(err)
	}
	if engine.outstanding.retryDeadline != oldDeadline {
		t.Fatalf("rearm postponed an earlier retry: old=%s new=%s", oldDeadline, engine.outstanding.retryDeadline)
	}
}

func TestRejectedRemoteHelloDoesNotRearmCapabilityRetry(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1200, 0)}
	entropy := &fakeEntropy{values: []uint64{
		0x1201, // local epoch
		0x1202, // local DATA session
		uint64(initialRetryDelay - time.Nanosecond),
	}}
	engine := newStartupRetryTestEngine(t, clock, entropy)
	if _, err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	consumedBefore := entropy.next

	version := uint32(2)
	fragments := uint32(16)
	maxPayload := uint32(613)
	lifetime := uint32(2000)
	rejected := controlMessage(0x2201, 1, 0, (&wirev1.CapabilitiesHello_builder{
		DataProtocolVersion:  &version,
		MaxFragments:         &fragments,
		MaxCarrierPayload:    &maxPayload,
		ReassemblyLifetimeMs: &lifetime,
	}).Build())
	responses, err := engine.HandleInbound(encodeControl(t, engine.codec, rejected))
	if err != nil || len(responses) != 1 {
		t.Fatalf("rejected remote Hello = (%d outputs, %v), want one rejection Ack", len(responses), err)
	}
	if got := decodeControl(t, responses[0].Frame).GetCapabilitiesAck().GetResult(); got != wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION {
		t.Fatalf("rejected Hello result = %s, want incompatible version", got)
	}
	if entropy.next != consumedBefore {
		t.Fatalf("rejected Hello consumed rearm entropy: before=%d after=%d", consumedBefore, entropy.next)
	}
	if engine.Status() != StatusError || engine.outstanding.initialized {
		t.Fatalf("rejected Hello state = status:%s outstanding:%t, want terminal without retry", engine.Status(), engine.outstanding.initialized)
	}
	if retry, err := engine.Tick(clock.now.Add(time.Minute)); err != nil || len(retry) != 0 {
		t.Fatalf("Tick() after rejected Hello = (%d outputs, %v), want no retry", len(retry), err)
	}
}

func TestFirstRemoteHelloRearmConvergesBothEnginesAfterOneWayLoss(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1300, 0)}
	aEntropy := &fakeEntropy{values: []uint64{
		0x1301, // local epoch
		0x1302, // local DATA session
		uint64(initialRetryDelay - time.Nanosecond), // initial retry
		uint64(2*initialRetryDelay - time.Nanosecond),
		uint64(4*initialRetryDelay - time.Nanosecond),
		uint64(8*initialRetryDelay - time.Nanosecond),
		uint64(initialRetryDelay - time.Nanosecond), // first remote Hello rearm
	}}
	a := newStartupRetryTestEngine(t, clock, aEntropy)
	b := newStartupRetryTestEngine(t, clock, &fakeEntropy{values: []uint64{0x2301, 0x2302}})
	aInitial, err := a.Start()
	if err != nil || len(aInitial) != 1 {
		t.Fatalf("A Start() = (%d outputs, %v)", len(aInitial), err)
	}
	bInitial, err := b.Start()
	if err != nil || len(bInitial) != 1 {
		t.Fatalf("B Start() = (%d outputs, %v)", len(bInitial), err)
	}
	remoteHello := bInitial[0].Frame

	// A's first three Hellos are lost while the peer's initial Hello is held
	// back. This creates the long retry deadline that the first remote Hello
	// must repair.
	for attempt := 0; attempt < 3; attempt++ {
		clock.now = a.outstanding.retryDeadline
		if retry, err := a.Tick(clock.now); err != nil || len(retry) != 1 {
			t.Fatalf("A lost retry %d = (%d outputs, %v)", attempt, len(retry), err)
		}
	}
	if got := a.outstanding.retryDeadline.Sub(clock.now); got <= initialRetryDelay {
		t.Fatalf("A retry backoff = %s, want longer than initial delay", got)
	}

	// Deliver B's Hello after the one-way loss. Its Ack reaches B, then A's
	// rearmed Hello reaches B and the normal CONTROL exchange drains both gates.
	ack, err := a.HandleInbound(remoteHello)
	if err != nil || len(ack) != 1 {
		t.Fatalf("A first remote Hello = (%d outputs, %v)", len(ack), err)
	}
	if _, err := b.HandleInbound(ack[0].Frame); err != nil {
		t.Fatalf("B CapabilitiesAck = %v", err)
	}
	clock.now = a.outstanding.retryDeadline
	retry, err := a.Tick(clock.now)
	if err != nil || len(retry) != 1 {
		t.Fatalf("A rearmed Hello = (%d outputs, %v)", len(retry), err)
	}

	type delivery struct {
		to    *Engine
		frame []byte
	}
	queue := []delivery{{to: b, frame: retry[0].Frame}}
	for step := 0; len(queue) != 0 && step < 128; step++ {
		item := queue[0]
		queue = queue[1:]
		outputs, err := item.to.HandleInbound(item.frame)
		if err != nil {
			t.Fatalf("CONTROL step %d: %v", step, err)
		}
		destination := a
		if item.to == a {
			destination = b
		}
		for _, output := range outputs {
			queue = append(queue, delivery{to: destination, frame: output.Frame})
		}
	}
	if len(queue) != 0 || !a.DataSendAllowed() || !b.DataSendAllowed() {
		t.Fatalf("one-way-loss exchange did not converge: queue=%d a=%v b=%v", len(queue), a.DataSendAllowed(), b.DataSendAllowed())
	}
}

func TestCapabilitiesRetryCapsJitterBeforeStartupWindowExpires(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1400, 0)}
	engine := newStartupRetryTestEngine(t, clock, &fakeEntropy{values: []uint64{2_500_000_000}})
	engine.outstanding = outstandingRequest{
		kind:        requestCapabilities,
		initialized: true,
		sentAt:      clock.now,
	}
	clock.now = engine.outstanding.sentAt.Add(capabilitiesRetryStartupWindow - time.Nanosecond)

	// The cap must be applied before the random modulo. With a 3.2s
	// exponential delay and this entropy value, applying it after jitter would
	// produce 2.5s instead of the startup-window result of 500ms.
	if got, want := engine.retryDelayForOutstanding(clock.now, 4), 500*time.Millisecond; got != want {
		t.Fatalf("startup capability retry delay = %s, want %s", got, want)
	}
}

func TestCapabilitiesRetryRestoresNormalCapAfterStartupWindow(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1500, 0)}
	engine := newStartupRetryTestEngine(t, clock, &fakeEntropy{values: []uint64{2_500_000_000}})
	engine.outstanding = outstandingRequest{
		kind:        requestCapabilities,
		initialized: true,
		sentAt:      clock.now,
	}
	clock.now = engine.outstanding.sentAt.Add(capabilitiesRetryStartupWindow)

	// At the exact boundary the existing exponential/full-jitter behavior is
	// restored. The same attempt and entropy therefore yield 2.5s.
	if got, want := engine.retryDelayForOutstanding(clock.now, 4), 2_500*time.Millisecond; got != want {
		t.Fatalf("post-startup capability retry delay = %s, want %s", got, want)
	}
}
