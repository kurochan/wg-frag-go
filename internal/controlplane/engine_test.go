package controlplane

import (
	"bytes"
	"errors"
	"testing"
	"time"

	corecontrol "github.com/kurochan/wg-frag-go/internal/core/control"
	controlstate "github.com/kurochan/wg-frag-go/internal/core/control/state"
	"github.com/kurochan/wg-frag-go/internal/core/pmtu"
	wirev1 "github.com/kurochan/wg-frag-go/proto/wire/v1"
	"google.golang.org/protobuf/proto"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type fakeEntropy struct {
	values []uint64
	next   int
}

func (e *fakeEntropy) Uint64() (uint64, error) {
	if e.next >= len(e.values) {
		return 0, errors.New("test entropy exhausted")
	}
	value := e.values[e.next]
	e.next++
	return value, nil
}

// countingEntropy never runs out, for tests that restart an exchange an
// unpredictable number of times.
type countingEntropy struct{ next uint64 }

func (e *countingEntropy) Uint64() (uint64, error) {
	e.next++
	return e.next, nil
}

func TestDualEngineHandshakeReachesDataReady(t *testing.T) {
	t.Parallel()
	a := newTestEngine(t, 0xa001, 0xa002)
	b := newTestEngine(t, 0xb001, 0xb002)

	initial, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	if len(initial) != 1 {
		t.Fatalf("Start() outputs = %d, want 1", len(initial))
	}
	hello := decodeControl(t, initial[0].Frame)
	if hello.GetCapabilitiesHello() == nil || hello.GetControlEpoch() != 0xa001 || hello.GetMessageId() != 1 || hello.GetReplyTo() != 0 {
		t.Fatalf("initial Hello metadata = epoch:%x message:%d reply:%d body:%s", hello.GetControlEpoch(), hello.GetMessageId(), hello.GetReplyTo(), controlBodyName(hello))
	}

	fromB, err := b.HandleInbound(initial[0].Frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromB) != 2 {
		t.Fatalf("Hello response outputs = %d, want Ack + reverse Hello", len(fromB))
	}
	ack := decodeControl(t, fromB[0].Frame)
	if ack.GetCapabilitiesAck() == nil || ack.GetControlEpoch() != hello.GetControlEpoch() || ack.GetReplyTo() != hello.GetMessageId() {
		t.Fatalf("CapabilitiesAck did not echo request epoch/id: %#v", ack)
	}

	type delivery struct {
		to    *Engine
		frame []byte
	}
	queue := []delivery{
		{to: a, frame: fromB[0].Frame},
		{to: a, frame: fromB[1].Frame},
	}
	sawBaseProbe := false
	for steps := 0; len(queue) != 0 && steps < 100; steps++ {
		item := queue[0]
		queue = queue[1:]
		message := decodeControl(t, item.frame)
		if message.GetMtuProbe() != nil {
			sawBaseProbe = true
			if len(item.frame) != 613 {
				t.Fatalf("BASE MtuProbe frame size = %d, want 613", len(item.frame))
			}
		}

		outputs, err := item.to.HandleInbound(item.frame)
		if err != nil {
			t.Fatalf("HandleInbound(%s): %v", controlBodyName(message), err)
		}
		destination := b
		if item.to == b {
			destination = a
		}
		for _, output := range outputs {
			queue = append(queue, delivery{to: destination, frame: output.Frame})
		}
	}
	if len(queue) != 0 {
		t.Fatal("CONTROL exchange did not converge")
	}
	if !sawBaseProbe {
		t.Fatal("CONTROL exchange never emitted BASE MtuProbe")
	}
	if !a.DataSendAllowed() || !b.DataSendAllowed() {
		t.Fatalf("DATA gate: a=%v b=%v", a.DataSendAllowed(), b.DataSendAllowed())
	}
}

func TestDualEngineStartsPMTUSearchAfterBase(t *testing.T) {
	t.Parallel()
	a := newSizedTestEngine(t, 0xa101, 0xa102, 2_000)
	b := newSizedTestEngine(t, 0xb101, 0xb102, 2_000)
	initial, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	// Pretend B retained the last successful inbound probe from A across a
	// local restart. A should use it only as the first post-BASE search hint.
	b.lastReceivedCarrierPayload = 1_400
	type delivery struct {
		to    *Engine
		frame []byte
	}
	queue := make([]delivery, 0, 4)
	for _, output := range initial {
		queue = append(queue, delivery{to: b, frame: output.Frame})
	}
	sawLargeProbe := false
	firstLargeProbe := uint32(0)
	sawResetHint := false
	for steps := 0; len(queue) != 0 && steps < 500; steps++ {
		item := queue[0]
		queue = queue[1:]
		message := decodeControlWithMax(t, item.frame, 2_000)
		if item.to == a && message.GetResetSequenceAck() != nil && message.GetResetSequenceAck().GetLastReceivedCarrierPayload() == 1_400 {
			sawResetHint = true
		}
		if message.GetMtuProbe() != nil && len(item.frame) > 613 {
			sawLargeProbe = true
			if firstLargeProbe == 0 && item.to == b {
				firstLargeProbe = uint32(len(item.frame))
			}
		}
		outputs, err := item.to.HandleInbound(item.frame)
		if err != nil {
			t.Fatalf("HandleInbound(%s): %v", controlBodyName(message), err)
		}
		destination := b
		if item.to == b {
			destination = a
		}
		for _, output := range outputs {
			queue = append(queue, delivery{to: destination, frame: output.Frame})
		}
	}
	if len(queue) != 0 {
		t.Fatal("CONTROL + DPLPMTUD exchange did not converge")
	}
	if !sawLargeProbe {
		t.Fatal("DPLPMTUD did not emit a padded probe")
	}
	if !sawResetHint || firstLargeProbe != 1_400 {
		t.Fatalf("PMTU hint: reset_ack=%t first_large_probe=%d, want true/1400", sawResetHint, firstLargeProbe)
	}
	// Candidates are aligned to WireGuard's 16-byte padding, so a 2000-byte
	// ceiling confirms the largest payload sharing its outer datagram size.
	if a.ConfirmedCarrierPayload() != 1_992 || b.ConfirmedCarrierPayload() != 1_992 {
		t.Fatalf("confirmed payload: a=%d b=%d", a.ConfirmedCarrierPayload(), b.ConfirmedCarrierPayload())
	}
}

func TestPMTUSearchInheritsPingRTT(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine := newSizedTestEngine(t, 0xa201, 0xa202, 2_000)
	engine.clock = clock
	remote := controlMessage(0xb201, 1, 0, capabilities(1, 16, 2_000, 0, 0, 2_000))
	if decision := engine.state.ObserveCapabilitiesHello(remote); decision.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("remote capabilities = %s", decision.Result)
	}
	engine.srtt = 50 * time.Millisecond
	if err := engine.startPMTU(); err != nil {
		t.Fatal(err)
	}
	probe, ok := engine.pmtu.Next(clock.now)
	if !ok {
		t.Fatal("PMTU search did not emit a probe")
	}
	if engine.pmtu.Tick(clock.now.Add(199 * time.Millisecond)) {
		t.Fatal("PMTU probe timed out before four SRTT")
	}
	if !engine.pmtu.Tick(clock.now.Add(200 * time.Millisecond)) {
		t.Fatal("PMTU probe did not time out at four SRTT")
	}
	if engine.pmtu.Acknowledge(probe.Attempt, probe.PayloadSize, clock.now) {
		t.Fatal("timed-out PMTU probe was acknowledged")
	}
}

func TestRejectsMalformedAndUnexpectedResponse(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, 0x1001, 0x1002)
	if _, err := engine.HandleInbound([]byte{0, 0}); !errors.Is(err, ErrMalformedControl) {
		t.Fatalf("short frame error = %v", err)
	}

	codec, err := corecontrol.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	emptyBody := controlMessage(1, 1, 0, nil)
	frame := encodeControl(t, codec, emptyBody)
	if _, err := engine.HandleInbound(frame); !errors.Is(err, ErrMalformedControl) {
		t.Fatalf("missing body error = %v", err)
	}

	started, err := engine.Start()
	if err != nil {
		t.Fatal(err)
	}
	hello := decodeControl(t, started[0].Frame)
	version := uint32(1)
	result := wirev1.ResultCode_RESULT_CODE_ACCEPTED
	wrongEpoch := controlMessage(hello.GetControlEpoch()+1, 1, hello.GetMessageId(), (&wirev1.CapabilitiesAck_builder{
		SelectedDataProtocolVersion: &version,
		Result:                      &result,
	}).Build())
	if _, err := engine.HandleInbound(encodeControl(t, codec, wrongEpoch)); !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("wrong response epoch error = %v", err)
	}
}

func TestCapabilitiesAckRejectionIsTerminalAndDiagnosable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result wirev1.ResultCode
		reason string
	}{
		{name: "incompatible version", result: wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION, reason: CapabilitiesIncompatibleVersionReason},
		{name: "missing required feature", result: wirev1.ResultCode_RESULT_CODE_MISSING_REQUIRED_FEATURE, reason: CapabilitiesMissingRequiredReason},
		{name: "invalid parameter", result: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER, reason: CapabilitiesInvalidParameterReason},
		{name: "unknown enum", result: wirev1.ResultCode(99), reason: CapabilitiesInvalidResultReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestEngine(t, 0x1301, 0x1302)
			initial, err := engine.Start()
			if err != nil || len(initial) != 1 {
				t.Fatalf("Start() = (%d outputs, %v)", len(initial), err)
			}
			hello := decodeControl(t, initial[0].Frame)
			version := uint32(1)
			features := uint64(0)
			ack := controlMessage(hello.GetControlEpoch(), 2, hello.GetMessageId(), (&wirev1.CapabilitiesAck_builder{
				SelectedDataProtocolVersion: &version,
				SelectedFeatureBits:         &features,
				Result:                      &tc.result,
			}).Build())
			out, err := engine.HandleInbound(encodeControl(t, engine.codec, ack))
			if err != nil || len(out) != 0 {
				t.Fatalf("rejected CapabilitiesAck = (%d outputs, %v), want terminal transition", len(out), err)
			}
			if engine.Status() != StatusError || engine.StatusReason() != tc.reason {
				t.Fatalf("terminal status = (%s, %q), want ERROR/%q", engine.Status(), engine.StatusReason(), tc.reason)
			}
			if engine.DataSendAllowed() || engine.outstanding.initialized {
				t.Fatal("terminal capability rejection left DATA or retry correlation open")
			}
			if retry, err := engine.Tick(time.Unix(2_000, 0)); err != nil || len(retry) != 0 {
				t.Fatalf("Tick() after terminal rejection = (%d outputs, %v), want no retry", len(retry), err)
			}
			if retry, err := engine.ResetRetry(); err != nil || len(retry) != 0 {
				t.Fatalf("ResetRetry() after terminal rejection = (%d outputs, %v), want no retry", len(retry), err)
			}
		})
	}
}

func TestCapabilitiesAckAcceptedWithInvalidFieldsIsTerminal(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, 0x1401, 0x1402)
	initial, err := engine.Start()
	if err != nil || len(initial) != 1 {
		t.Fatalf("Start() = (%d outputs, %v)", len(initial), err)
	}
	hello := decodeControl(t, initial[0].Frame)
	version := uint32(2)
	features := uint64(0)
	result := wirev1.ResultCode_RESULT_CODE_ACCEPTED
	ack := controlMessage(hello.GetControlEpoch(), 2, hello.GetMessageId(), (&wirev1.CapabilitiesAck_builder{
		SelectedDataProtocolVersion: &version,
		SelectedFeatureBits:         &features,
		Result:                      &result,
	}).Build())
	if out, err := engine.HandleInbound(encodeControl(t, engine.codec, ack)); err != nil || len(out) != 0 {
		t.Fatalf("invalid accepted CapabilitiesAck = (%d outputs, %v)", len(out), err)
	}
	if engine.Status() != StatusError || engine.StatusReason() != CapabilitiesInvalidParameterReason {
		t.Fatalf("status = (%s, %q), want ERROR/%q", engine.Status(), engine.StatusReason(), CapabilitiesInvalidParameterReason)
	}
}

func TestIncompatibleCapabilitiesHelloEntersTerminalError(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, 0x1701, 0x1702)
	if _, err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	version := uint32(2)
	fragments := uint32(16)
	maxPayload := uint32(613)
	lifetime := uint32(2_000)
	hello := controlMessage(0x2701, 1, 0, (&wirev1.CapabilitiesHello_builder{
		DataProtocolVersion:  &version,
		MaxFragments:         &fragments,
		MaxCarrierPayload:    &maxPayload,
		ReassemblyLifetimeMs: &lifetime,
	}).Build())
	out, err := engine.HandleInbound(encodeControl(t, engine.codec, hello))
	if err != nil || len(out) != 1 || decodeControl(t, out[0].Frame).GetCapabilitiesAck().GetResult() != wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION {
		t.Fatalf("incompatible Hello = (%d outputs, %v), want one rejection Ack", len(out), err)
	}
	if engine.Status() != StatusError || engine.StatusReason() != CapabilitiesIncompatibleVersionReason || engine.DataSendAllowed() {
		t.Fatalf("status = (%s, %q, allowed=%t), want terminal incompatible ERROR", engine.Status(), engine.StatusReason(), engine.DataSendAllowed())
	}
}

func TestValidNewCapabilitiesHelloClearsTerminalError(t *testing.T) {
	t.Parallel()
	engine := newCountingTestEngine(t, 0x1801, 0x1802)
	if _, err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	version := uint32(2)
	fragments := uint32(16)
	maxPayload := uint32(613)
	lifetime := uint32(2_000)
	bad := controlMessage(0x2801, 1, 0, (&wirev1.CapabilitiesHello_builder{
		DataProtocolVersion:  &version,
		MaxFragments:         &fragments,
		MaxCarrierPayload:    &maxPayload,
		ReassemblyLifetimeMs: &lifetime,
	}).Build())
	if _, err := engine.HandleInbound(encodeControl(t, engine.codec, bad)); err != nil {
		t.Fatal(err)
	}
	if engine.Status() != StatusError {
		t.Fatal("invalid Hello did not enter terminal ERROR")
	}

	good := controlMessage(0x2802, 1, 0, capabilities(1, 16, 613, 0, 0, 2_000))
	out, err := engine.HandleInbound(encodeControl(t, engine.codec, good))
	if err != nil || len(out) != 2 {
		t.Fatalf("valid new Hello = (%d outputs, %v), want Ack + fresh Hello", len(out), err)
	}
	if engine.Status() == StatusError || engine.StatusReason() != "" {
		t.Fatalf("valid new Hello did not clear terminal state: status=%s reason=%q", engine.Status(), engine.StatusReason())
	}
	if decodeControl(t, out[1].Frame).GetCapabilitiesHello() == nil {
		t.Fatal("terminal recovery did not start a fresh local exchange")
	}
}

func TestResetSequenceCollisionRotatesExchangeBeforeRetry(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1_500, 0)}
	a, b := newLinkedEngines(t, clock)
	old := a.LocalExchangeID()
	session := uint32(old.DataSessionID)
	request, err := a.sendRequest(requestReset, buildControl(0, 0, a.localEpoch, (&wirev1.ResetSequence_builder{
		DataSessionId: &session,
	}).Build()), 0, 0)
	if err != nil || len(request) != 1 {
		t.Fatalf("ResetSequence send = (%d outputs, %v)", len(request), err)
	}
	ack, err := b.HandleInbound(request[0].Frame)
	if err != nil || len(ack) != 1 {
		t.Fatalf("peer ResetSequence = (%d outputs, %v)", len(ack), err)
	}
	if decodeControl(t, ack[0].Frame).GetResetSequenceAck().GetResult() != wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION {
		t.Fatal("peer did not reject the reused session with SESSION_COLLISION")
	}
	if out, err := a.HandleInbound(ack[0].Frame); err != nil || len(out) != 0 {
		t.Fatalf("collision handling = (%d outputs, %v), want no immediate Hello", len(out), err)
	}
	rotated := a.LocalExchangeID()
	if rotated == old || a.outstanding.initialized {
		t.Fatalf("collision did not rotate exchange/clear request: old=%+v new=%+v outstanding=%t", old, rotated, a.outstanding.initialized)
	}
	if a.state.LocalExchangeRetryAt().IsZero() || a.state.LocalExchangeRetryReady() {
		t.Fatal("collision retry did not install a backoff deadline")
	}

	clock.now = a.state.LocalExchangeRetryAt().Add(-time.Nanosecond)
	if out, err := a.Tick(clock.now); err != nil || len(out) != 0 {
		t.Fatalf("early collision retry = (%d outputs, %v), want none", len(out), err)
	}
	clock.now = a.state.LocalExchangeRetryAt()
	out, err := a.Tick(clock.now)
	if err != nil || len(out) != 1 || decodeControl(t, out[0].Frame).GetCapabilitiesHello() == nil {
		t.Fatalf("backoff collision retry = (%d outputs, %v), want one Hello", len(out), err)
	}
	if got := decodeControl(t, out[0].Frame).GetControlEpoch(); got != rotated.ControlEpoch {
		t.Fatalf("retry Hello epoch = %x, want rotated %x", got, rotated.ControlEpoch)
	}
}

func TestPeerMTUAckRejectionIsTerminal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result wirev1.ResultCode
		reason string
	}{
		{name: "invalid parameter", result: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER, reason: PeerMTUInvalidParameterReason},
		{name: "unknown enum", result: wirev1.ResultCode(99), reason: PeerMTUInvalidResultReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := newTestEngine(t, 0x1501, 0x1502)
			initial, err := engine.Start()
			if err != nil || len(initial) != 1 {
				t.Fatalf("Start() = (%d outputs, %v)", len(initial), err)
			}
			requestBody := engine.state.LocalPeerMTU()
			request, err := engine.sendRequest(requestPeerMTU, buildControl(0, 0, engine.localEpoch, &requestBody), 0, 0)
			if err != nil || len(request) != 1 {
				t.Fatalf("PeerMTU send = (%d outputs, %v)", len(request), err)
			}
			mtu := requestBody.GetInnerMtu()
			ack := controlMessage(engine.localEpoch, 2, decodeControl(t, request[0].Frame).GetMessageId(), (&wirev1.PeerMTUAck_builder{
				InnerMtu: &mtu,
				Result:   &tc.result,
			}).Build())
			out, err := engine.HandleInbound(encodeControl(t, engine.codec, ack))
			if err != nil || len(out) != 0 {
				t.Fatalf("rejected PeerMTUAck = (%d outputs, %v)", len(out), err)
			}
			if engine.Status() != StatusError || engine.StatusReason() != tc.reason {
				t.Fatalf("status = (%s, %q), want ERROR/%q", engine.Status(), engine.StatusReason(), tc.reason)
			}
			if retry, err := engine.Tick(time.Unix(2_000, 0)); err != nil || len(retry) != 0 {
				t.Fatalf("Tick() after PeerMTU rejection = (%d outputs, %v)", len(retry), err)
			}
		})
	}
}

func TestRetiredCapabilitiesHelloIsDroppedBeforeStateMutation(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1_600, 0)}
	engine, _ := newLinkedEngines(t, clock)
	oldEpoch := engine.remoteEpoch
	first := controlMessage(0x2202, 1, 0, capabilities(1, 16, 613, 0, 0, 2_000))
	if first.GetControlEpoch() == oldEpoch {
		t.Fatal("test remote epoch unexpectedly matches current epoch")
	}
	if out, err := engine.HandleInbound(encodeControl(t, engine.codec, first)); err != nil || len(out) == 0 {
		t.Fatalf("first remote Hello = (%d outputs, %v)", len(out), err)
	}
	if !engine.state.IsRemoteEpochRetired(oldEpoch) {
		t.Fatal("remote epoch was not retained after transition")
	}
	current := engine.remoteEpoch
	stale := controlMessage(oldEpoch, 99, 0, capabilities(1, 16, 613, 0, 0, 2_000))
	if out, err := engine.HandleInbound(encodeControl(t, engine.codec, stale)); err != nil || len(out) != 0 {
		t.Fatalf("retired remote Hello = (%d outputs, %v), want silent drop", len(out), err)
	}
	if engine.remoteEpoch != current {
		t.Fatalf("retired Hello changed current remote epoch: got %x want %x", engine.remoteEpoch, current)
	}
}

func newTestEngine(t testing.TB, epoch, session uint64) *Engine {
	return newSizedTestEngine(t, epoch, session, 613)
}

// wgCanonicalizeCarrierPayload is test-only coverage for the production
// adapter's WireGuard 16-byte plaintext bucket behavior.
func wgCanonicalizeCarrierPayload(payload uint32) uint32 {
	return (payload+40)/16*16 - 40
}

// wgTransportDatagramSize is test-only coverage for the synthetic IPv6,
// WireGuard, and UDP overhead used by the adapter's transport strategy.
func wgTransportDatagramSize(payload uint32) int {
	return 32 + (int(payload)+40+15)/16*16
}

func newSizedTestEngine(t testing.TB, epoch, session uint64, maxPayload uint32) *Engine {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine, err := New(Config{State: controlstate.Config{
		MaxCarrierPayload:    maxPayload,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy:              &fakeEntropy{values: []uint64{epoch, session}},
	}, CanonicalizeCarrierPayload: wgCanonicalizeCarrierPayload, TransportDatagramSize: wgTransportDatagramSize})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func newCountingTestEngine(t testing.TB, epoch, session uint64) *Engine {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine, err := New(Config{State: controlstate.Config{
		MaxCarrierPayload:    613,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy:              &countingEntropy{next: epoch},
	}, CanonicalizeCarrierPayload: wgCanonicalizeCarrierPayload, TransportDatagramSize: wgTransportDatagramSize})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func FuzzHandleInbound(f *testing.F) {
	remote := newSizedTestEngine(f, 0xfeed, 0xbeef, 2_000)
	initial, err := remote.Start()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(initial[0].Frame)
	f.Add([]byte{})
	f.Add([]byte{0, 0, corecontrol.ProtocolVersion, 0})
	resetSession := uint32(1)
	resetSeed := controlMessage(0xfeed, 2, 0, (&wirev1.ResetSequence_builder{DataSessionId: &resetSession}).Build())
	seedCodec, err := corecontrol.NewCodec(2_000)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encodeControl(f, seedCodec, resetSeed))

	f.Fuzz(func(t *testing.T, frame []byte) {
		engine := newSizedTestEngine(t, 0x1001, 0x1002, 2_000)
		if _, err := engine.Start(); err != nil {
			t.Fatal(err)
		}
		outbound, _ := engine.HandleInbound(frame)
		codec, err := corecontrol.NewCodec(2_000)
		if err != nil {
			t.Fatal(err)
		}
		for _, output := range outbound {
			if _, err := codec.Parse(output.Frame); err != nil {
				t.Fatalf("engine emitted invalid CONTROL frame: %v", err)
			}
		}
	})
}

func decodeControl(t *testing.T, frame []byte) *wirev1.Control {
	return decodeControlWithMax(t, frame, 613)
}

func decodeControlWithMax(t *testing.T, frame []byte, maxPayload int) *wirev1.Control {
	t.Helper()
	codec, err := corecontrol.NewCodec(maxPayload)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.Parse(frame)
	if err != nil {
		t.Fatal(err)
	}
	message := new(wirev1.Control)
	if err := proto.Unmarshal(payload, message); err != nil {
		t.Fatal(err)
	}
	return message
}

func encodeControl(t testing.TB, codec corecontrol.Codec, message *wirev1.Control) []byte {
	t.Helper()
	payload, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, corecontrol.HeaderSize+len(payload))
	if _, err := codec.MarshalTo(frame, payload); err != nil {
		t.Fatal(err)
	}
	return frame
}

func capabilities(version, fragments, maxPayload uint32, supported, required uint64, lifetime uint32) *wirev1.CapabilitiesHello {
	return (&wirev1.CapabilitiesHello_builder{
		DataProtocolVersion:  &version,
		MaxFragments:         &fragments,
		MaxCarrierPayload:    &maxPayload,
		SupportedFeatureBits: &supported,
		RequiredFeatureBits:  &required,
		ReassemblyLifetimeMs: &lifetime,
	}).Build()
}

func controlMessage(epoch, messageID, replyTo uint64, body any) *wirev1.Control {
	builder := wirev1.Control_builder{
		MessageId:    &messageID,
		ReplyTo:      &replyTo,
		ControlEpoch: &epoch,
	}
	switch body := body.(type) {
	case *wirev1.CapabilitiesHello:
		builder.CapabilitiesHello = body
	case *wirev1.CapabilitiesAck:
		builder.CapabilitiesAck = body
	case *wirev1.ResetSequence:
		builder.ResetSequence = body
	case *wirev1.ResetSequenceAck:
		builder.ResetSequenceAck = body
	case *wirev1.PeerMTU:
		builder.PeerMtu = body
	case *wirev1.PeerMTUAck:
		builder.PeerMtuAck = body
	case *wirev1.Ping:
		builder.Ping = body
	case *wirev1.Pong:
		builder.Pong = body
	case *wirev1.MtuProbe:
		builder.MtuProbe = body
	case *wirev1.MtuProbeAck:
		builder.MtuProbeAck = body
	case *wirev1.StateSyncRequired:
		builder.StateSyncRequired = body
	case nil:
	default:
		panic("unsupported test CONTROL body")
	}
	return builder.Build()
}

func controlBodyName(control *wirev1.Control) string {
	switch {
	case control.GetCapabilitiesHello() != nil:
		return "CapabilitiesHello"
	case control.GetCapabilitiesAck() != nil:
		return "CapabilitiesAck"
	case control.GetResetSequence() != nil:
		return "ResetSequence"
	case control.GetResetSequenceAck() != nil:
		return "ResetSequenceAck"
	case control.GetPeerMtu() != nil:
		return "PeerMTU"
	case control.GetPeerMtuAck() != nil:
		return "PeerMTUAck"
	case control.GetPing() != nil:
		return "Ping"
	case control.GetPong() != nil:
		return "Pong"
	case control.GetMtuProbe() != nil:
		return "MtuProbe"
	case control.GetMtuProbeAck() != nil:
		return "MtuProbeAck"
	case control.GetStateSyncRequired() != nil:
		return "StateSyncRequired"
	default:
		return "<unset>"
	}
}

func TestTickRetransmitsUnansweredRequestWithBackoff(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine, err := New(Config{State: controlstate.Config{
		MaxCarrierPayload:    613,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy: &fakeEntropy{values: []uint64{
			uint64(initialRetryDelay - time.Nanosecond),
			uint64(2*initialRetryDelay - time.Nanosecond),
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.Start()
	if err != nil || len(initial) != 1 {
		t.Fatalf("Start() = (%d outputs, %v)", len(initial), err)
	}
	hello := decodeControl(t, initial[0].Frame)
	originalHelloFrame := cloneBytes(initial[0].Frame)

	// Before the deadline nothing is resent.
	clock.now = clock.now.Add(150 * time.Millisecond)
	if out, err := engine.Tick(clock.now); err != nil || len(out) != 0 {
		t.Fatalf("early Tick() = (%d outputs, %v), want none", len(out), err)
	}
	// The outbound frame belongs to the caller. Mutating it after enqueue must
	// not corrupt the engine's retained retry copy.
	initial[0].Frame[0] ^= 0xff

	// A lost Hello is retransmitted verbatim, so the peer's reply_to
	// correlation still matches.
	clock.now = clock.now.Add(100 * time.Millisecond)
	retry, err := engine.Tick(clock.now)
	if err != nil || len(retry) != 1 {
		t.Fatalf("retry Tick() = (%d outputs, %v), want 1", len(retry), err)
	}
	resent := decodeControl(t, retry[0].Frame)
	if resent.GetMessageId() != hello.GetMessageId() || resent.GetControlEpoch() != hello.GetControlEpoch() ||
		resent.GetCapabilitiesHello() == nil {
		t.Fatalf("retransmission changed the request: %#v", resent)
	}

	// The next attempt waits longer than the first.
	clock.now = clock.now.Add(250 * time.Millisecond)
	if out, err := engine.Tick(clock.now); err != nil || len(out) != 0 {
		t.Fatalf("Tick() before backed-off deadline = (%d outputs, %v)", len(out), err)
	}
	clock.now = clock.now.Add(200 * time.Millisecond)
	if out, err := engine.Tick(clock.now); err != nil || len(out) != 1 {
		t.Fatalf("second retry Tick() = (%d outputs, %v), want 1", len(out), err)
	}

	// Once the request is answered, retries stop.
	peer := newTestEngine(t, 0xd001, 0xd002)
	fromPeer, err := peer.HandleInbound(originalHelloFrame)
	if err != nil || len(fromPeer) == 0 {
		t.Fatalf("peer HandleInbound() = (%d outputs, %v)", len(fromPeer), err)
	}
	if _, err := engine.HandleInbound(fromPeer[0].Frame); err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(time.Minute)
	out, err := engine.Tick(clock.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range out {
		if decodeControl(t, message.Frame).GetCapabilitiesHello() != nil {
			t.Fatal("answered Hello was retransmitted")
		}
	}
}

func TestRetryDelayIsBoundedAndJittered(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine, err := New(Config{State: controlstate.Config{
		MaxCarrierPayload:    613,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy:              &fakeEntropy{values: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := uint(0); attempt < 20; attempt++ {
		delay := engine.retryDelay(attempt)
		if delay <= 0 || delay > maxRetryDelay {
			t.Fatalf("retryDelay(%d) = %s, want within (0, %s]", attempt, delay, maxRetryDelay)
		}
	}
}

func TestTickEmitsConfirmationProbesAndFallsBackOnBlackHole(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(2000, 0)}
	var confirmedChanges []uint32
	a, b := newLinkedEnginesWithCallback(t, clock, func(payload uint32) {
		confirmedChanges = append(confirmedChanges, payload)
	})
	confirmed := a.ConfirmedCarrierPayload()
	if confirmed == 0 {
		t.Fatal("engine did not confirm a carrier payload")
	}

	clock.now = clock.now.Add(confirmationInterval)
	out, err := a.Tick(clock.now)
	if err != nil || len(out) != 1 {
		t.Fatalf("Tick() = (%d outputs, %v), want one confirmation probe", len(out), err)
	}
	reply, err := b.HandleInbound(out[0].Frame)
	if err != nil || len(reply) != 1 {
		t.Fatalf("peer did not ack the confirmation probe: (%d, %v)", len(reply), err)
	}
	if _, err := a.HandleInbound(reply[0].Frame); err != nil {
		t.Fatal(err)
	}
	if got := a.ConfirmedCarrierPayload(); got != confirmed {
		t.Fatalf("ConfirmedCarrierPayload() = %d after a healthy confirmation, want %d", got, confirmed)
	}

	var recovery []Outbound

	for attempt := 0; attempt < pmtu.ConfirmationFailureLimit; attempt++ {
		clock.now = clock.now.Add(confirmationInterval)
		if _, err := a.Tick(clock.now); err != nil {
			t.Fatal(err)
		}
		clock.now = clock.now.Add(probeTimeout + time.Second)
		out, err := a.Tick(clock.now)
		if err != nil {
			t.Fatal(err)
		}
		recovery = out
	}
	if a.DataSendAllowed() {
		t.Fatal("DATA is still allowed after a black hole")
	}
	if missing := a.MissingFlags(); missing&(controlstate.FlagPingPong|controlstate.FlagBaseProbe) == 0 {
		t.Fatalf("MissingFlags() = %07b, want the reachability and BASE gates closed", missing)
	}
	if len(recovery) != 1 || decodeControl(t, recovery[0].Frame).GetPing() == nil {
		t.Fatal("black-hole recovery did not restart with a Ping")
	}
	if len(confirmedChanges) == 0 || confirmedChanges[len(confirmedChanges)-1] != 613 {
		t.Fatalf("confirmed payload callback = %v, want final BASE notification", confirmedChanges)
	}

	// The peer answers, so the gates close again and DATA resumes.
	for round := 0; round < 16 && len(recovery) > 0; round++ {
		next := make([]Outbound, 0, len(recovery))
		for _, message := range recovery {
			out, err := b.HandleInbound(message.Frame)
			if err != nil {
				t.Fatal(err)
			}
			next = append(next, out...)
		}
		a, b = b, a
		recovery = next
	}
	if !a.DataSendAllowed() && !b.DataSendAllowed() {
		t.Fatal("neither engine recovered after the path came back")
	}
}

func TestStashedEMSGSIZEConfirmationBlackHoleRestartsGates(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(2500, 0)}

	a, _ := newLinkedEngines(t, clock)
	for attempt := 0; attempt < pmtu.ConfirmationFailureLimit; attempt++ {
		clock.now = clock.now.Add(confirmationInterval)
		probes, err := a.Tick(clock.now)
		if err != nil || len(probes) != 1 {
			t.Fatalf("confirmation Tick() = (%d outputs, %v), want one probe", len(probes), err)
		}
		if _, err := a.ReportSendFailure(clock.now, 0); err != nil {
			t.Fatalf("ReportSendFailure() = %v", err)
		}
	}
	if a.DataSendAllowed() {
		t.Fatal("DATA remained enabled after repeated stashed EMSGSIZE")
	}
	if missing := a.MissingFlags(); missing&(controlstate.FlagPingPong|controlstate.FlagBaseProbe) == 0 {
		t.Fatalf("MissingFlags() = %07b, want path gates closed", missing)
	}
}

func TestResetSequenceDuplicateReplaysExactAck(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t, 0x1001, 0x1002)
	remoteHello := controlMessage(0x2001, 1, 0, capabilities(1, 16, 613, 1, 0, 2_000))
	codec, err := corecontrol.NewCodec(613)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.HandleInbound(encodeControl(t, codec, remoteHello)); err != nil {
		t.Fatal(err)
	}
	resetSession := uint32(77)
	reset := controlMessage(remoteHello.GetControlEpoch(), 2, 0, (&wirev1.ResetSequence_builder{DataSessionId: &resetSession}).Build())
	frame := encodeControl(t, codec, reset)
	first, err := engine.HandleInbound(frame)
	if err != nil || len(first) == 0 {
		t.Fatalf("first ResetSequence = (%d, %v)", len(first), err)
	}
	if decodeControl(t, first[0].Frame).GetResetSequenceAck() == nil {
		t.Fatalf("first response is not ResetSequenceAck: %#v", decodeControl(t, first[0].Frame))
	}
	if got := engine.RemoteDataSessionID(); got != 77 {
		t.Fatalf("remote session after first reset = %d", got)
	}
	second, err := engine.HandleInbound(frame)
	if err != nil || len(second) != 1 {
		t.Fatalf("duplicate ResetSequence = (%d, %v), want one replay", len(second), err)
	}
	if !bytes.Equal(first[0].Frame, second[0].Frame) {
		t.Fatalf("duplicate response changed: first=%x second=%x", first[0].Frame, second[0].Frame)
	}
	if got := engine.RemoteDataSessionID(); got != 77 {
		t.Fatalf("duplicate mutated remote session to %d", got)
	}
}

func TestBaseProbeTimeoutEntersRecoverableErrorAfterProbeTimeout(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(4_000, 0)}
	newEngine := func(epoch uint64) *Engine {
		engine, err := New(Config{State: controlstate.Config{
			MaxCarrierPayload:    613,
			MinCarrierPayload:    613,
			ReassemblyLifetimeMs: 2_000,
			LocalPeerMTU:         1_500,
			StateSyncMinInterval: time.Second,
			Clock:                clock,
			Entropy:              &countingEntropy{next: epoch},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return engine
	}
	a, b := newEngine(0x4101), newEngine(0x4201)
	pending, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	left, right := a, b
	for round := 0; round < 32 && len(pending) > 0; round++ {
		next := make([]Outbound, 0, len(pending))
		for _, output := range pending {
			message := decodeControl(t, output.Frame)
			if message.GetMtuProbe() != nil && left.MissingFlags()&controlstate.FlagBaseProbe != 0 {
				clock.now = clock.now.Add(probeTimeout - time.Nanosecond)
				if out, err := left.Tick(clock.now); err != nil || len(out) != 0 {
					t.Fatalf("early BASE timeout Tick() = (%d, %v)", len(out), err)
				}
				if left.Status() != StatusBase {
					t.Fatalf("status before BASE probe timeout = %s", left.Status())
				}
				clock.now = clock.now.Add(2 * time.Nanosecond)
				if out, err := left.Tick(clock.now); err != nil || len(out) != 0 {
					t.Fatalf("BASE timeout Tick() = (%d, %v)", len(out), err)
				}
				if left.Status() != StatusError || left.DataSendAllowed() {
					t.Fatalf("BASE timeout did not enter fail-closed ERROR: status=%s allowed=%t", left.Status(), left.DataSendAllowed())
				}
				return
			}
			replies, err := right.HandleInbound(output.Frame)
			if err != nil {
				t.Fatal(err)
			}
			next = append(next, replies...)
		}
		left, right = right, left
		pending = next
	}
	t.Fatal("CONTROL exchange did not emit a BASE probe")
}

func TestBaseRecoveryKeepsSlowPongOutstanding(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(4_500, 0)}
	a, b := newLinkedEngines(t, clock)
	a.enterBaseError()
	clock.now = a.baseRetryAt
	recovery, err := a.Tick(clock.now)
	if err != nil || len(recovery) != 1 || decodeControl(t, recovery[0].Frame).GetPing() == nil {
		t.Fatalf("recovery Tick() = (%d outputs, %v), want one Ping", len(recovery), err)
	}

	// The ordinary request retry jitter is below 200 ms. A 150 ms RTT must
	// still complete the same recovery correlation rather than being discarded.
	clock.now = clock.now.Add(150 * time.Millisecond)
	if out, err := a.Tick(clock.now); err != nil || len(out) != 0 {
		t.Fatalf("slow-Pong Tick() = (%d outputs, %v), want no retry", len(out), err)
	}
	if !a.outstanding.initialized || a.outstanding.kind != requestPing {
		t.Fatal("slow-Pong Tick() discarded the recovery Ping")
	}

	reply, err := b.HandleInbound(recovery[0].Frame)
	if err != nil || len(reply) != 1 {
		t.Fatalf("peer recovery Ping = (%d outputs, %v), want one Pong", len(reply), err)
	}
	next, err := a.HandleInbound(reply[0].Frame)
	if err != nil {
		t.Fatal(err)
	}
	if !a.BaseError() || a.Status() != StatusError || a.DataSendAllowed() {
		t.Fatalf("recovery Pong opened path before BASE ACK: status=%s allowed=%t", a.Status(), a.DataSendAllowed())
	}
	if len(next) != 1 || decodeControl(t, next[0].Frame).GetMtuProbe() == nil {
		t.Fatalf("successful recovery did not emit BASE probe: %d outputs", len(next))
	}
	baseAck, err := b.HandleInbound(next[0].Frame)
	if err != nil || len(baseAck) != 1 {
		t.Fatalf("peer BASE probe = (%d outputs, %v), want one ACK", len(baseAck), err)
	}
	if _, err := a.HandleInbound(baseAck[0].Frame); err != nil {
		t.Fatal(err)
	}
	if a.BaseError() || a.Status() == StatusError {
		t.Fatalf("BASE ACK did not complete recovery: status=%s", a.Status())
	}
}

func TestBaseRecoveryKeepsProbeOutstandingAcrossTick(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(9_000, 0)}
	a, b := newLinkedEngines(t, clock)
	a.enterBaseError()
	clock.now = a.baseRetryAt
	recovery, err := a.Tick(clock.now)
	if err != nil || len(recovery) != 1 {
		t.Fatalf("recovery Tick() = (%d, %v)", len(recovery), err)
	}
	pong, err := b.HandleInbound(recovery[0].Frame)
	if err != nil || len(pong) != 1 {
		t.Fatalf("peer Pong = (%d, %v)", len(pong), err)
	}
	probe, err := a.HandleInbound(pong[0].Frame)
	if err != nil || len(probe) != 1 || decodeControl(t, probe[0].Frame).GetMtuProbe() == nil {
		t.Fatalf("Pong handling = (%d, %v), want BASE probe", len(probe), err)
	}
	clock.now = clock.now.Add(100 * time.Millisecond)
	if _, err := a.Tick(clock.now); err != nil {
		t.Fatal(err)
	}
	ack, err := b.HandleInbound(probe[0].Frame)
	if err != nil || len(ack) != 1 {
		t.Fatalf("peer probe ACK = (%d, %v)", len(ack), err)
	}
	clock.now = clock.now.Add(50 * time.Millisecond)
	if _, err := a.HandleInbound(ack[0].Frame); err != nil {
		t.Fatalf("probe ACK handling = %v", err)
	}
	if a.BaseError() {
		t.Fatal("BASE recovery remained in error after delayed probe ACK")
	}
}

func TestBaseRecoveryProbeTimeoutUsesObservedRTT(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(9_100, 0)}
	a, b := newLinkedEngines(t, clock)
	a.enterBaseError()
	clock.now = a.baseRetryAt
	recovery, err := a.Tick(clock.now)
	if err != nil || len(recovery) != 1 {
		t.Fatalf("recovery Tick() = (%d, %v)", len(recovery), err)
	}
	pong, err := b.HandleInbound(recovery[0].Frame)
	if err != nil || len(pong) != 1 {
		t.Fatalf("peer Pong = (%d, %v)", len(pong), err)
	}
	clock.now = clock.now.Add(1500 * time.Millisecond)
	probe, err := a.HandleInbound(pong[0].Frame)
	if err != nil || len(probe) != 1 {
		t.Fatalf("recovery Pong handling = (%d, %v)", len(probe), err)
	}
	if got, want := a.recoveryProbeTimeout(), 6*time.Second; got != want {
		t.Fatalf("recoveryProbeTimeout() = %s, want %s", got, want)
	}
	probeSentAt := clock.now
	clock.now = probeSentAt.Add(2 * time.Second)
	if out, err := a.Tick(clock.now); err != nil || len(out) != 0 {
		t.Fatalf("early recovery probe timeout = (%d, %v)", len(out), err)
	}
	if !a.outstanding.initialized || a.outstanding.kind != requestBaseProbe {
		t.Fatal("recovery probe was discarded before the adaptive timeout")
	}
}

func TestPeerHelloDuringBaseRecoveryRemainsRetryable(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(9_500, 0)}
	a, _ := newLinkedEngines(t, clock)
	a.enterBaseError()
	restarted := newCountingTestEngine(t, 0xabc0, 0xabc1)
	trigger, err := restarted.Start()
	if err != nil || len(trigger) != 1 {
		t.Fatalf("restarted Start() = (%d, %v)", len(trigger), err)
	}
	out, err := a.HandleInbound(trigger[0].Frame)
	if err != nil || len(out) != 2 {
		t.Fatalf("Hello during baseError = (%d, %v)", len(out), err)
	}
	if !a.outstanding.initialized || a.outstanding.kind != requestCapabilities {
		t.Fatal("reverse Hello did not arm requestCapabilities")
	}
	clock.now = clock.now.Add(100 * time.Millisecond)
	if _, err := a.Tick(clock.now); err != nil {
		t.Fatal(err)
	}
	fromPeer, err := restarted.HandleInbound(out[1].Frame)
	if err != nil || len(fromPeer) == 0 {
		t.Fatalf("peer HandleInbound(reverse Hello) = (%d, %v)", len(fromPeer), err)
	}
	clock.now = clock.now.Add(50 * time.Millisecond)
	if _, err := a.HandleInbound(fromPeer[0].Frame); err != nil {
		t.Fatalf("CapabilitiesAck handling = %v", err)
	}
}

func TestPeerRestartDuringBaseRecoveryConverges(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(9_550, 0)}
	a, _ := newLinkedEngines(t, clock)
	a.enterBaseError()
	restarted := newCountingTestEngine(t, 0xadd0, 0xadd1)
	trigger, err := restarted.Start()
	if err != nil || len(trigger) != 1 {
		t.Fatalf("restarted Start() = (%d, %v)", len(trigger), err)
	}
	initial, err := a.HandleInbound(trigger[0].Frame)
	if err != nil || len(initial) != 2 {
		t.Fatalf("Hello during base recovery = (%d, %v)", len(initial), err)
	}

	type delivery struct {
		to    *Engine
		frame []byte
	}
	queue := []delivery{{to: restarted, frame: initial[0].Frame}, {to: restarted, frame: initial[1].Frame}}
	for step := 0; len(queue) != 0 && step < 256; step++ {
		item := queue[0]
		queue = queue[1:]
		replies, err := item.to.HandleInbound(item.frame)
		if err != nil {
			t.Fatalf("restart recovery step %d: %v", step, err)
		}
		for _, reply := range replies {
			destination := a
			if item.to == a {
				destination = restarted
			}
			queue = append(queue, delivery{to: destination, frame: reply.Frame})
		}
	}
	if len(queue) != 0 || !a.DataSendAllowed() || !restarted.DataSendAllowed() {
		t.Fatalf("peer restart did not converge: queue=%d a=%v restarted=%v", len(queue), a.DataSendAllowed(), restarted.DataSendAllowed())
	}
}

func TestBaseRecoveryRetriesReverseHelloAfterTimeout(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(9_600, 0)}
	a, _ := newLinkedEngines(t, clock)
	a.enterBaseError()
	restarted := newCountingTestEngine(t, 0xacc0, 0xacc1)
	trigger, err := restarted.Start()
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.HandleInbound(trigger[0].Frame)
	if err != nil || len(out) != 2 {
		t.Fatalf("Hello during baseError = (%d, %v)", len(out), err)
	}
	clock.now = clock.now.Add(probeTimeout + time.Nanosecond)
	if out, err := a.Tick(clock.now); err != nil || len(out) != 0 {
		t.Fatalf("timeout Tick() = (%d, %v)", len(out), err)
	}
	clock.now = a.baseRetryAt
	retry, err := a.Tick(clock.now)
	if err != nil || len(retry) != 1 || decodeControl(t, retry[0].Frame).GetCapabilitiesHello() == nil {
		t.Fatalf("retry Tick() = (%d, %v), want CapabilitiesHello", len(retry), err)
	}
}

func TestBaseErrorIgnoresUnrelatedControl(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(4_600, 0)}
	a, b := newLinkedEngines(t, clock)
	a.enterBaseError()
	clock.now = a.baseRetryAt
	recovery, err := a.Tick(clock.now)
	if err != nil || len(recovery) != 1 {
		t.Fatalf("recovery Tick() = (%d outputs, %v)", len(recovery), err)
	}

	// A valid request is still answered, but it is not proof that the local
	// recovery Ping reached the peer and must not clear fail-closed ERROR.
	sequence := uint32(99)
	unrelated := controlMessage(a.remoteEpoch, 0xdead, 0, (&wirev1.Ping_builder{Sequence: &sequence}).Build())
	out, err := a.HandleInbound(encodeControl(t, a.codec, unrelated))
	if err != nil || len(out) != 1 || decodeControl(t, out[0].Frame).GetPong() == nil {
		t.Fatalf("unrelated Ping = (%d outputs, %v), want one Pong", len(out), err)
	}
	if !a.BaseError() || !a.outstanding.initialized || a.outstanding.kind != requestPing {
		t.Fatal("unrelated CONTROL cleared or replaced recovery state")
	}

	// Keep the peer live so this test also verifies that only the matching Pong
	// can leave ERROR.
	if _, err := b.HandleInbound(recovery[0].Frame); err != nil {
		t.Fatal(err)
	}
}

func TestResetRetryStartsImmediateRecoveryAndBacksOffAfterFailure(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(4_700, 0)}
	a, _ := newLinkedEngines(t, clock)
	a.enterBaseError()
	recovery, err := a.ResetRetry()
	if err != nil || len(recovery) != 1 || decodeControl(t, recovery[0].Frame).GetPing() == nil {
		t.Fatalf("ResetRetry() = (%d outputs, %v), want one Ping", len(recovery), err)
	}
	if !a.BaseError() || a.DataSendAllowed() {
		t.Fatal("ResetRetry opened DATA before recovery Pong")
	}

	clock.now = clock.now.Add(probeTimeout + time.Nanosecond)
	if out, err := a.Tick(clock.now); err != nil || len(out) != 0 {
		t.Fatalf("failed recovery Tick() = (%d outputs, %v), want no immediate retry", len(out), err)
	}
	if !a.BaseError() || a.outstanding.initialized {
		t.Fatal("failed recovery did not remain in ERROR without an outstanding request")
	}
	if !a.baseRetryAt.After(clock.now) {
		t.Fatal("failed recovery did not schedule a backoff retry")
	}

	clock.now = a.baseRetryAt
	retry, err := a.Tick(clock.now)
	if err != nil || len(retry) != 1 || decodeControl(t, retry[0].Frame).GetPing() == nil {
		t.Fatalf("backoff retry Tick() = (%d outputs, %v), want one Ping", len(retry), err)
	}
	if !a.BaseError() {
		t.Fatal("backoff retry unexpectedly cleared ERROR")
	}
}

func TestMarshalProbeFallsBackBelowVarintBoundary(t *testing.T) {
	t.Parallel()
	engine := newSizedTestEngine(t, 0x1101, 0x1102, 20_000)
	message := controlMessage(2, 1, 0, wirev1.MtuProbe_builder{}.Build())
	// For this opaque-edition message the explicit scalar envelope fields add
	// one byte to the fixed prefix. The padding length varint changes at 16384,
	// making a complete frame size of 16398 impossible (the neighboring sizes
	// are 16397 and 16399).
	requested := 16398
	frame, err := engine.marshal(message, uint32(requested))
	if err != nil {
		t.Fatal(err)
	}
	actual := len(frame)
	if actual >= requested || actual < int(engine.base) {
		t.Fatalf("fallback frame size = %d for requested %d", actual, requested)
	}
	parsed := decodeControlWithMax(t, mustFrame(t, engine, message, uint32(requested)), 20_000)
	if parsed.GetMtuProbe() == nil {
		t.Fatalf("fallback frame lost MtuProbe body")
	}
}

func TestBaseProbeBelowConfiguredBaseDoesNotArmCorrelation(t *testing.T) {
	t.Parallel()
	engine := newSizedTestEngine(t, 0x1201, 0x1202, 2_000)
	// Force the guard independently of normal Config validation so this test
	// exercises the send-side invariant even if a future protobuf body grows.
	engine.base = 614
	message := controlMessage(engine.localEpoch, 0, 0, wirev1.MtuProbe_builder{}.Build())
	if _, err := engine.sendRequest(requestBaseProbe, message, 0, 613); !errors.Is(err, ErrUnrepresentableProbe) {
		t.Fatalf("sendRequest() error = %v, want ErrUnrepresentableProbe", err)
	}
	if engine.outstanding.initialized {
		t.Fatal("BASE probe armed outstanding correlation after below-BASE frame")
	}
}

func mustFrame(t *testing.T, engine *Engine, message *wirev1.Control, target uint32) []byte {
	t.Helper()
	frame, err := engine.marshal(message, target)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// newLinkedEngines drives two engines to DATA-ready in memory.
func newLinkedEngines(t *testing.T, clock *fakeClock) (*Engine, *Engine) {
	return newLinkedEnginesWithCallback(t, clock, nil)
}

func newLinkedEnginesWithCallback(t *testing.T, clock *fakeClock, onConfirmed func(uint32)) (*Engine, *Engine) {
	t.Helper()
	newEngine := func(epoch, session uint64) *Engine {
		engine, err := New(Config{State: controlstate.Config{
			MaxCarrierPayload:    613,
			MinCarrierPayload:    613,
			ReassemblyLifetimeMs: 2000,
			LocalPeerMTU:         1500,
			StateSyncMinInterval: time.Second,
			Clock:                clock,
			// Enough for a restart to roll a fresh epoch and session.
			Entropy: &countingEntropy{next: epoch},
		}, CanonicalizeCarrierPayload: wgCanonicalizeCarrierPayload, TransportDatagramSize: wgTransportDatagramSize, OnConfirmedPayloadChange: onConfirmed})
		if err != nil {
			t.Fatal(err)
		}
		return engine
	}
	a, b := newEngine(0xe001, 0xe002), newEngine(0xf001, 0xf002)
	pending, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 64 && len(pending) > 0; round++ {
		next := make([]Outbound, 0, len(pending))
		for _, message := range pending {
			out, err := b.HandleInbound(message.Frame)
			if err != nil {
				t.Fatal(err)
			}
			next = append(next, out...)
		}
		a, b = b, a
		pending = next
	}
	if !a.DataSendAllowed() || !b.DataSendAllowed() {
		t.Fatalf("engines did not reach DATA-ready: %07b / %07b", a.MissingFlags(), b.MissingFlags())
	}
	return a, b
}

func TestUnknownDataSessionStartsAnExchangeAfterRestart(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(3000, 0)}
	a, _ := newLinkedEngines(t, clock)
	senderSession := a.LocalExchangeID().DataSessionID

	// A freshly restarted receiver: it has no exchange and the peer's DATA is
	// its only trigger.
	restarted, err := New(Config{State: controlstate.Config{
		MaxCarrierPayload:    613,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy:              &countingEntropy{next: 0x9000},
	}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := restarted.ReportUnknownDataSession(senderSession)

	if err != nil || len(out) != 1 {
		t.Fatalf("ReportUnknownDataSession() = (%d, %v), want one frame", len(out), err)
	}
	if decodeControl(t, out[0].Frame).GetCapabilitiesHello() == nil {
		t.Fatal("restart recovery did not begin with a Hello")
	}

	// The peer sees a new epoch and starts over, so both sides converge again.
	pending := out
	for round := 0; round < 32 && len(pending) > 0; round++ {
		next := make([]Outbound, 0, len(pending))
		for _, message := range pending {
			replies, err := a.HandleInbound(message.Frame)
			if err != nil {
				t.Fatal(err)
			}
			next = append(next, replies...)
		}
		a, restarted = restarted, a
		pending = next
	}
	if !a.DataSendAllowed() || !restarted.DataSendAllowed() {
		t.Fatalf("engines did not recover: %07b / %07b", a.MissingFlags(), restarted.MissingFlags())
	}
}

func TestRemoteEpochChangeRestartsExistingLocalExchange(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(3500, 0)}
	local, _ := newLinkedEngines(t, clock)
	oldLocalEpoch := local.LocalExchangeID().ControlEpoch

	restarted, err := New(Config{State: controlstate.Config{
		MaxCarrierPayload:    613,
		MinCarrierPayload:    613,
		ReassemblyLifetimeMs: 2000,
		LocalPeerMTU:         1500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy:              &countingEntropy{next: 0x9900},
	}})
	if err != nil {
		t.Fatal(err)
	}
	trigger, err := restarted.ReportUnknownDataSession(local.LocalExchangeID().DataSessionID)
	if err != nil || len(trigger) != 1 {
		t.Fatalf("restart trigger = (%d outputs, %v)", len(trigger), err)
	}
	outputs, err := local.HandleInbound(trigger[0].Frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 2 || decodeControl(t, outputs[1].Frame).GetCapabilitiesHello() == nil {
		t.Fatalf("remote epoch change outputs = %d, want Ack + reverse Hello", len(outputs))
	}
	if got := decodeControl(t, outputs[1].Frame).GetControlEpoch(); got == oldLocalEpoch {
		t.Fatalf("reverse Hello reused old local epoch %x", got)
	}
	// Complete the restarted peer's exchange to ensure the reverse Hello does
	// not leave either side waiting on the old epoch.
	type delivery struct {
		to    *Engine
		frame []byte
	}
	queue := []delivery{{to: restarted, frame: outputs[0].Frame}, {to: restarted, frame: outputs[1].Frame}}
	for step := 0; len(queue) != 0 && step < 128; step++ {
		item := queue[0]
		queue = queue[1:]
		replies, err := item.to.HandleInbound(item.frame)
		if err != nil {
			t.Fatalf("restart exchange step %d: %v", step, err)
		}
		for _, reply := range replies {
			destination := local
			if item.to == local {
				destination = restarted
			}
			queue = append(queue, delivery{to: destination, frame: reply.Frame})
		}
	}
	if len(queue) != 0 || !local.DataSendAllowed() || !restarted.DataSendAllowed() {
		t.Fatalf("restart exchange did not converge: queue=%d local=%v restarted=%v", len(queue), local.DataSendAllowed(), restarted.DataSendAllowed())
	}
}

func TestUnknownDataSessionIsRateLimitedOnceEstablished(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{now: time.Unix(3000, 0)}
	a, b := newLinkedEngines(t, clock)
	stale := a.LocalExchangeID().DataSessionID + 1

	first, err := b.ReportUnknownDataSession(stale)
	if err != nil || len(first) != 1 {
		t.Fatalf("first report = (%d, %v), want one StateSyncRequired", len(first), err)
	}
	if decodeControl(t, first[0].Frame).GetStateSyncRequired() == nil {
		t.Fatal("established peer did not answer with StateSyncRequired")
	}
	repeat, err := b.ReportUnknownDataSession(stale)
	if err != nil || len(repeat) != 0 {
		t.Fatalf("second report = (%d, %v), want it rate limited", len(repeat), err)
	}
}
