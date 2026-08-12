package state

import (
	"errors"
	"testing"
	"time"

	wirev1 "github.com/kurochan/wg-frag-go/proto/wire/v1"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type fakeEntropy struct {
	values []uint64
	index  int
}

func (e *fakeEntropy) Uint64() (uint64, error) {
	if e.index >= len(e.values) {
		return 0, errors.New("entropy exhausted")
	}
	value := e.values[e.index]
	e.index++
	return value, nil
}

func TestValidateCapabilities(t *testing.T) {
	t.Parallel()
	config := testConfig(newFakeClock(), &fakeEntropy{values: []uint64{1, 2}})
	tests := []struct {
		name   string
		mutate func(*wirev1.CapabilitiesHello)
		want   wirev1.ResultCode
	}{
		{name: "valid", want: wirev1.ResultCode_RESULT_CODE_ACCEPTED},
		{name: "version", mutate: func(c *wirev1.CapabilitiesHello) { c.SetDataProtocolVersion(2) }, want: wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION},
		{name: "fragments", mutate: func(c *wirev1.CapabilitiesHello) { c.SetMaxFragments(15) }, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
		{name: "carrier", mutate: func(c *wirev1.CapabilitiesHello) { c.SetMaxCarrierPayload(612) }, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
		{name: "carrier over IPv6 limit", mutate: func(c *wirev1.CapabilitiesHello) { c.SetMaxCarrierPayload(65_536) }, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
		{name: "lifetime low", mutate: func(c *wirev1.CapabilitiesHello) { c.SetReassemblyLifetimeMs(99) }, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
		{name: "lifetime high", mutate: func(c *wirev1.CapabilitiesHello) { c.SetReassemblyLifetimeMs(60_001) }, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
		{name: "local feature missing", mutate: func(c *wirev1.CapabilitiesHello) { c.SetSupportedFeatureBits(0) }, want: wirev1.ResultCode_RESULT_CODE_MISSING_REQUIRED_FEATURE},
		{name: "remote feature missing", mutate: func(c *wirev1.CapabilitiesHello) { c.SetRequiredFeatureBits(1 << 9) }, want: wirev1.ResultCode_RESULT_CODE_MISSING_REQUIRED_FEATURE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capabilities := validCapabilities()
			if tt.mutate != nil {
				tt.mutate(capabilities)
			}
			decision := ValidateCapabilities(config, capabilities)
			if decision.Result != tt.want {
				t.Fatalf("ValidateCapabilities() = %v, want %v", decision.Result, tt.want)
			}
		})
	}
}

func TestNewRejectsCarrierPayloadOverIPv6Limit(t *testing.T) {
	t.Parallel()
	config := testConfig(newFakeClock(), &fakeEntropy{values: []uint64{1, 2}})
	config.MaxCarrierPayload = 1 << 16
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
	}
}

func TestNegotiatedCarrierPayload(t *testing.T) {
	t.Parallel()
	state := mustState(t, testConfig(newFakeClock(), &fakeEntropy{values: []uint64{1, 2}}))
	if got := state.NegotiatedCarrierPayload(); got != 0 {
		t.Fatalf("pre-capability negotiated payload = %d, want 0", got)
	}
	remote := validCapabilities()
	remote.SetMaxCarrierPayload(2_000)
	if decision := state.ObserveCapabilitiesHello(request(9, 1, remote)); decision.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveCapabilitiesHello() = %#v", decision)
	}
	if got := state.NegotiatedCarrierPayload(); got != 2_000 {
		t.Fatalf("negotiated payload = %d, want 2000", got)
	}
}

func TestOneWayPeerExchangeGate(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{0x1111, 0x2222}}))
	exchange, err := state.BeginLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	if exchange.ControlEpoch != 0x1111 || exchange.DataSessionID != 0x2222 {
		t.Fatalf("BeginLocalExchange() = %#v", exchange)
	}
	assertBlocked(t, state, RequiredFlags)

	remoteEpoch := uint64(0x3333)
	if result := state.ObserveCapabilitiesAck(response(exchange.ControlEpoch, 10, capabilitiesAck(1, 1, wirev1.ResultCode_RESULT_CODE_ACCEPTED)), 10); result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveCapabilitiesAck() = %v", result)
	}
	if state.ReadyFlags()&FlagLocalCapabilities != 0 {
		t.Fatal("local capability became ready before remote Hello")
	}

	hello := request(remoteEpoch, 20, validCapabilities())
	decision := state.ObserveCapabilitiesHello(hello)
	if decision.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED || decision.StartReverseExchange {
		t.Fatalf("ObserveCapabilitiesHello() = %#v", decision)
	}
	if state.ReadyFlags()&(FlagLocalCapabilities|FlagRemoteCapabilities) != FlagLocalCapabilities|FlagRemoteCapabilities {
		t.Fatalf("capability flags = %07b", state.ReadyFlags())
	}

	if result := state.ObserveResetSequenceAck(response(exchange.ControlEpoch, 30, resetAck(uint32(exchange.DataSessionID), wirev1.ResultCode_RESULT_CODE_ACCEPTED)), 30); result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveResetSequenceAck() = %v", result)
	}
	assertBlocked(t, state, FlagLocalPeerMTUAck|FlagRemotePeerMTU|FlagPingPong|FlagBaseProbe)

	if result := state.ObservePeerMTUAck(response(exchange.ControlEpoch, 40, peerMTUAck(1500, wirev1.ResultCode_RESULT_CODE_ACCEPTED)), 40); result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObservePeerMTUAck() = %v", result)
	}
	if result := state.ObservePeerMTU(request(remoteEpoch, 41, peerMTU(9612))); result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObservePeerMTU() = %v", result)
	}
	if state.RemotePeerMTU() != 9612 {
		t.Fatalf("RemotePeerMTU() = %d", state.RemotePeerMTU())
	}
	assertBlocked(t, state, FlagPingPong|FlagBaseProbe)

	if result := state.ObservePong(response(exchange.ControlEpoch, 50, pong(7)), 50, 7); result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObservePong() = %v", result)
	}
	assertBlocked(t, state, FlagBaseProbe)

	if result := state.ObserveBaseProbeAck(response(exchange.ControlEpoch, 60, probeAck(613)), 60); result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveBaseProbeAck() = %v", result)
	}
	if !state.DataSendAllowed() || state.MissingFlags() != 0 {
		t.Fatalf("DATA gate blocked: flags=%07b missing=%07b", state.ReadyFlags(), state.MissingFlags())
	}
}

func TestCapabilitiesHelloStartsReverseExchangeOnce(t *testing.T) {
	t.Parallel()
	state := mustState(t, testConfig(newFakeClock(), &fakeEntropy{values: []uint64{0x1111, 0x2222, 0x3333, 0x4444}}))
	hello := request(0xaaaa, 1, validCapabilities())
	if got := state.ObserveCapabilitiesHello(hello); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED || !got.StartReverseExchange {
		t.Fatalf("dormant ObserveCapabilitiesHello() = %#v", got)
	}
	if _, err := state.BeginLocalExchange(); err != nil {
		t.Fatal(err)
	}
	if got := state.ObserveCapabilitiesHello(hello); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED || got.StartReverseExchange {
		t.Fatalf("duplicate ObserveCapabilitiesHello() = %#v", got)
	}

	restarted := request(0xbbbb, 2, validCapabilities())
	if got := state.ObserveCapabilitiesHello(restarted); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED || !got.StartReverseExchange {
		t.Fatalf("new-epoch ObserveCapabilitiesHello() = %#v", got)
	}
}

func TestRestartLocalExchangeRotatesAndBacksOff(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{1, 100, 2, 101, 0, 3, 102, 1}}))
	first, err := state.BeginLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := state.RestartLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	if retry.ControlEpoch == first.ControlEpoch || retry.DataSessionID == first.DataSessionID {
		t.Fatalf("RestartLocalExchange() reused IDs: first=%#v retry=%#v", first, retry)
	}
	if retry.RetryAfter <= 0 || retry.RetryAfter > InitialLocalExchangeBackoff || retry.RetryAt != clock.Now().Add(retry.RetryAfter) {
		t.Fatalf("retry deadline = %#v, want 0<delay<=%v", retry, InitialLocalExchangeBackoff)
	}
	if state.LocalExchangeRetryReady() {
		t.Fatal("retry became ready before deadline")
	}
	if _, err := state.BeginLocalExchange(); !errors.Is(err, ErrLocalExchangeBackoff) {
		t.Fatalf("early BeginLocalExchange() error = %v, want ErrLocalExchangeBackoff", err)
	}
	if _, err := state.RestartLocalExchange(); !errors.Is(err, ErrLocalExchangeBackoff) {
		t.Fatalf("early RestartLocalExchange() error = %v, want ErrLocalExchangeBackoff", err)
	}
	clock.Advance(retry.RetryAfter)
	second, err := state.RestartLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	if second.RetryAfter <= 0 || second.RetryAfter > 2*InitialLocalExchangeBackoff {
		t.Fatalf("second retry backoff = %v, want 0<delay<=%v", second.RetryAfter, 2*InitialLocalExchangeBackoff)
	}
	if state.LocalExchangeID() != second.LocalExchange {
		t.Fatalf("installed exchange = %#v, returned %#v", state.LocalExchangeID(), second.LocalExchange)
	}
}

func TestAcceptedResetClearsLocalExchangeBackoff(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{1, 100, 2, 101, 0, 3, 102, 0}}))
	if _, err := state.BeginLocalExchange(); err != nil {
		t.Fatal(err)
	}
	retry, err := state.RestartLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(retry.RetryAfter)
	if got := state.ObserveResetSequenceAck(response(retry.ControlEpoch, 7, resetAck(uint32(retry.DataSessionID), wirev1.ResultCode_RESULT_CODE_ACCEPTED)), 7); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveResetSequenceAck() = %v", got)
	}
	if !state.LocalExchangeRetryReady() || !state.LocalExchangeRetryAt().IsZero() {
		t.Fatalf("backoff was not cleared: ready=%t at=%v", state.LocalExchangeRetryReady(), state.LocalExchangeRetryAt())
	}
	next, err := state.RestartLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	if next.RetryAfter <= 0 || next.RetryAfter > InitialLocalExchangeBackoff {
		t.Fatalf("backoff after accepted reset = %v, want 0<delay<=%v", next.RetryAfter, InitialLocalExchangeBackoff)
	}
}

func TestLocalExchangeBackoffEntropyFailureUsesCap(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{1, 100, 2, 101}}))
	if _, err := state.BeginLocalExchange(); err != nil {
		t.Fatal(err)
	}
	retry, err := state.RestartLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	if retry.RetryAfter != InitialLocalExchangeBackoff {
		t.Fatalf("entropy failure backoff = %v, want %v", retry.RetryAfter, InitialLocalExchangeBackoff)
	}
}

func TestRetiredRemoteEpochRejectedUntilExpiry(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{1, 2}}))
	if got := state.ObserveCapabilitiesHello(request(10, 1, validCapabilities())); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("first Hello = %#v", got)
	}
	if got := state.ObserveCapabilitiesHello(request(20, 2, validCapabilities())); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("second Hello = %#v", got)
	}
	if !state.IsRemoteEpochRetired(10) {
		t.Fatal("previous remote epoch was not retired")
	}
	if got := state.ObserveCapabilitiesHello(request(10, 3, validCapabilities())); got.Result != wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		t.Fatalf("retired Hello = %#v", got)
	}
	clock.Advance(retiredEpochLifetime)
	if state.IsRemoteEpochRetired(10) {
		t.Fatal("expired remote epoch remained retired")
	}
	if got := state.ObserveCapabilitiesHello(request(10, 4, validCapabilities())); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("expired Hello = %#v", got)
	}
}

func TestLocalSessionIDNotReusedWhileRetired(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{1, 100, 2, 101, 3, 100}}))
	if _, err := state.BeginLocalExchange(); err != nil {
		t.Fatal(err)
	}
	if _, err := state.BeginLocalExchange(); err != nil {
		t.Fatal(err)
	}
	if got := state.LocalExchangeID().DataSessionID; got != 101 {
		t.Fatalf("second local session = %d, want 101", got)
	}
	clock.Advance(2 * time.Second)
	if _, err := state.BeginLocalExchange(); err != nil {
		t.Fatal(err)
	}
	if got := state.LocalExchangeID().DataSessionID; got != 100 {
		t.Fatalf("expired local session = %d, want 100", got)
	}
}

func TestReceiverRestartAndUnknownSession(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{1, 2}}))

	decision := state.CheckInboundDataSession(77)
	if decision.Accept || !decision.SendStateSyncRequired || decision.ObservedSessionID != 77 {
		t.Fatalf("first unknown decision = %#v", decision)
	}
	var sync wirev1.StateSyncRequired
	if !decision.PopulateStateSyncRequired(&sync) || sync.GetReason() != wirev1.StateSyncRequired_REASON_UNKNOWN_DATA_SESSION || sync.GetObservedDataSessionId() != 77 {
		t.Fatalf("StateSyncRequired = {Reason:%v ObservedDataSessionID:%d}", sync.GetReason(), sync.GetObservedDataSessionId())
	}
	if next := state.CheckInboundDataSession(77); next.SendStateSyncRequired {
		t.Fatal("state sync was not rate limited")
	}
	clock.Advance(time.Second)
	if next := state.CheckInboundDataSession(77); !next.SendStateSyncRequired {
		t.Fatal("state sync did not reopen after interval")
	}

	remoteEpoch := uint64(9)
	if got := state.ObserveCapabilitiesHello(request(remoteEpoch, 1, validCapabilities())); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveCapabilitiesHello() = %#v", got)
	}
	reset := state.ObserveResetSequence(request(remoteEpoch, 2, resetSequence(77)))
	if reset.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED || !reset.SessionChanged {
		t.Fatalf("ObserveResetSequence() = %#v", reset)
	}
	if got := state.CheckInboundDataSession(77); !got.Accept || got.SendStateSyncRequired {
		t.Fatalf("current session decision = %#v", got)
	}
	if got := state.CheckInboundDataSession(78); got.Accept {
		t.Fatalf("noncurrent session accepted: %#v", got)
	}
}

func TestResetSequenceRetainsCurrentAndRetiredIDs(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	state := mustState(t, testConfig(clock, &fakeEntropy{values: []uint64{1, 2}}))
	const epoch = uint64(9)
	if got := state.ObserveCapabilitiesHello(request(epoch, 1, validCapabilities())); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveCapabilitiesHello() = %#v", got)
	}
	accept := func(id uint32, message uint64) wirev1.ResultCode {
		return state.ObserveResetSequence(request(epoch, message, resetSequence(id))).Result
	}
	if got := accept(77, 2); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("first reset = %v", got)
	}
	if got := accept(77, 3); got != wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION {
		t.Fatalf("current duplicate reset = %v", got)
	}
	if got := accept(78, 4); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("replacement reset = %v", got)
	}
	if got := accept(77, 5); got != wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION {
		t.Fatalf("retired reset = %v", got)
	}
	if got := state.RemoteDataSessionID(); got != 78 {
		t.Fatalf("collision mutated current session to %d", got)
	}
	clock.Advance(2 * time.Second)
	if got := accept(77, 6); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("expired retired reset = %v", got)
	}
}

func TestValidatePeerMTU(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		mtu  uint32
		want wirev1.ResultCode
	}{
		{mtu: 1279, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
		{mtu: 1280, want: wirev1.ResultCode_RESULT_CODE_ACCEPTED},
		{mtu: 9612, want: wirev1.ResultCode_RESULT_CODE_ACCEPTED},
		{mtu: 9613, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
	} {
		if got := ValidatePeerMTU(peerMTU(tt.mtu)); got != tt.want {
			t.Errorf("ValidatePeerMTU(%d) = %v, want %v", tt.mtu, got, tt.want)
		}
	}
}

func TestValidateDataSessionID(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		id   uint32
		want wirev1.ResultCode
	}{
		{id: 0, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
		{id: 1, want: wirev1.ResultCode_RESULT_CODE_ACCEPTED},
		{id: 65_535, want: wirev1.ResultCode_RESULT_CODE_ACCEPTED},
		{id: 65_536, want: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER},
	} {
		if got := ValidateDataSessionID(tt.id); got != tt.want {
			t.Errorf("ValidateDataSessionID(%d) = %v, want %v", tt.id, got, tt.want)
		}
	}

	state := mustState(t, testConfig(newFakeClock(), &fakeEntropy{values: []uint64{1, 2}}))
	state.ObserveCapabilitiesHello(request(3, 1, validCapabilities()))
	if got := state.ObserveResetSequence(request(3, 2, resetSequence(0))); got.Result != wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		t.Fatalf("zero ResetSequence result = %v", got.Result)
	}
	if got := state.CheckInboundDataSession(0); got != (SessionDecision{}) {
		t.Fatalf("zero DATA session decision = %#v, want fail-closed without sync", got)
	}
}

func TestInvalidResponseBodyDoesNotAffectValidResponse(t *testing.T) {
	t.Parallel()
	state := mustState(t, testConfig(newFakeClock(), &fakeEntropy{values: []uint64{1, 2}}))
	exchange, err := state.BeginLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	wrongBody := response(exchange.ControlEpoch, 7, pong(1))
	if got := state.ObserveCapabilitiesAck(wrongBody, 7); got != wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		t.Fatalf("ObserveCapabilitiesAck(wrong body) = %v", got)
	}

	validAck := response(exchange.ControlEpoch, 7, capabilitiesAck(1, 1, wirev1.ResultCode_RESULT_CODE_ACCEPTED))
	if got := state.ObserveCapabilitiesAck(validAck, 7); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("valid response after wrong body = %v", got)
	}
}

func TestResponseMustEchoLocalEpoch(t *testing.T) {
	t.Parallel()
	state := mustState(t, testConfig(newFakeClock(), &fakeEntropy{values: []uint64{0x1111, 0x2222}}))
	exchange, err := state.BeginLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	ackBody := capabilitiesAck(1, 1, wirev1.ResultCode_RESULT_CODE_ACCEPTED)
	if got := state.ObserveCapabilitiesAck(response(0x3333, 7, ackBody), 7); got != wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		t.Fatalf("response using remote epoch = %v, want invalid", got)
	}
	if got := state.ObserveCapabilitiesAck(response(exchange.ControlEpoch, 7, ackBody), 7); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("response echoing local epoch = %v, want accepted", got)
	}
}

func TestStateSyncRequiredResetsOnlyMatchingOutboundSession(t *testing.T) {
	t.Parallel()
	state := mustState(t, testConfig(newFakeClock(), &fakeEntropy{values: []uint64{0x1111, 0x2222}}))
	exchange, err := state.BeginLocalExchange()
	if err != nil {
		t.Fatal(err)
	}
	remoteEpoch := uint64(0x3333)
	if got := state.ObserveCapabilitiesHello(request(remoteEpoch, 1, validCapabilities())); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveCapabilitiesHello() = %#v", got)
	}
	if got := state.ObserveCapabilitiesAck(response(exchange.ControlEpoch, 2, capabilitiesAck(1, 1, wirev1.ResultCode_RESULT_CODE_ACCEPTED)), 2); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveCapabilitiesAck() = %v", got)
	}
	if got := state.ObservePeerMTU(request(remoteEpoch, 3, peerMTU(1500))); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObservePeerMTU() = %v", got)
	}
	if got := state.ObserveResetSequence(request(remoteEpoch, 4, resetSequence(99))); got.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("ObserveResetSequence() = %#v", got)
	}

	stale := request(remoteEpoch, 5, stateSyncRequired(wirev1.StateSyncRequired_REASON_UNKNOWN_DATA_SESSION, uint32(exchange.DataSessionID+1)))
	if got := state.ObserveStateSyncRequired(stale); got != wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		t.Fatalf("stale StateSyncRequired = %v", got)
	}
	if state.ReadyFlags()&FlagLocalCapabilities == 0 {
		t.Fatal("stale StateSyncRequired cleared local readiness")
	}

	unknownEpoch := request(remoteEpoch+1, 6, stateSyncRequired(wirev1.StateSyncRequired_REASON_UNKNOWN_DATA_SESSION, uint32(exchange.DataSessionID)))
	if got := state.ObserveStateSyncRequired(unknownEpoch); got != wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		t.Fatalf("unknown-epoch StateSyncRequired = %v", got)
	}

	current := request(remoteEpoch, 7, stateSyncRequired(wirev1.StateSyncRequired_REASON_UNKNOWN_DATA_SESSION, uint32(exchange.DataSessionID)))
	if got := state.ObserveStateSyncRequired(current); got != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		t.Fatalf("current StateSyncRequired = %v", got)
	}
	if state.ReadyFlags()&(FlagLocalCapabilities|FlagLocalResetAck|FlagLocalPeerMTUAck|FlagPingPong|FlagBaseProbe) != 0 {
		t.Fatalf("local outbound flags not cleared: %07b", state.ReadyFlags())
	}
	if state.ReadyFlags()&(FlagRemoteCapabilities|FlagRemotePeerMTU) != FlagRemoteCapabilities|FlagRemotePeerMTU {
		t.Fatalf("remote receive flags were cleared: %07b", state.ReadyFlags())
	}
	if got := state.CheckInboundDataSession(99); !got.Accept {
		t.Fatalf("independent inbound session was cleared: %#v", got)
	}
}

var sessionDecisionSink SessionDecision
var stateSyncSink wirev1.StateSyncRequired

func TestCheckInboundDataSessionDoesNotAllocate(t *testing.T) {
	state := mustState(t, testConfig(newFakeClock(), &fakeEntropy{values: []uint64{1, 2}}))
	allocs := testing.AllocsPerRun(1000, func() {
		sessionDecisionSink = state.CheckInboundDataSession(1)
	})
	if allocs != 0 {
		t.Fatalf("CheckInboundDataSession() allocations = %v, want 0", allocs)
	}
	decision := SessionDecision{
		SendStateSyncRequired: true,
		Reason:                wirev1.StateSyncRequired_REASON_UNKNOWN_DATA_SESSION,
		ObservedSessionID:     1,
	}
	allocs = testing.AllocsPerRun(1000, func() {
		decision.PopulateStateSyncRequired(&stateSyncSink)
	})
	if allocs != 0 {
		t.Fatalf("PopulateStateSyncRequired() allocations = %v, want 0", allocs)
	}
}

func testConfig(clock Clock, entropy Entropy) Config {
	return Config{
		MaxCarrierPayload:    65_432,
		MinCarrierPayload:    613,
		SupportedFeatureBits: 1,
		RequiredFeatureBits:  1,
		ReassemblyLifetimeMs: 2_000,
		LocalPeerMTU:         1_500,
		StateSyncMinInterval: time.Second,
		Clock:                clock,
		Entropy:              entropy,
	}
}

func validCapabilities() *wirev1.CapabilitiesHello {
	version, fragments, maxPayload := uint32(1), uint32(16), uint32(65_432)
	supported, required := uint64(1), uint64(1)
	lifetime := uint32(2_000)
	return (&wirev1.CapabilitiesHello_builder{
		DataProtocolVersion:  &version,
		MaxFragments:         &fragments,
		MaxCarrierPayload:    &maxPayload,
		SupportedFeatureBits: &supported,
		RequiredFeatureBits:  &required,
		ReassemblyLifetimeMs: &lifetime,
	}).Build()
}

func request(epoch, messageID uint64, body any) *wirev1.Control {
	return controlMessage(epoch, messageID, 0, body)
}

func response(epoch, replyTo uint64, body any) *wirev1.Control {
	return controlMessage(epoch, replyTo+1_000, replyTo, body)
}

func controlMessage(epoch, messageID, replyTo uint64, body any) *wirev1.Control {
	builder := wirev1.Control_builder{MessageId: &messageID, ReplyTo: &replyTo, ControlEpoch: &epoch}

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
	default:
		panic("unsupported test CONTROL body")
	}
	return builder.Build()
}

func capabilitiesAck(version uint32, features uint64, result wirev1.ResultCode) *wirev1.CapabilitiesAck {
	return (&wirev1.CapabilitiesAck_builder{
		SelectedDataProtocolVersion: &version,
		SelectedFeatureBits:         &features,
		Result:                      &result,
	}).Build()
}

func resetSequence(id uint32) *wirev1.ResetSequence {
	return (&wirev1.ResetSequence_builder{DataSessionId: &id}).Build()
}

func resetAck(id uint32, result wirev1.ResultCode) *wirev1.ResetSequenceAck {
	return (&wirev1.ResetSequenceAck_builder{DataSessionId: &id, Result: &result}).Build()
}

func peerMTU(mtu uint32) *wirev1.PeerMTU {
	return (&wirev1.PeerMTU_builder{InnerMtu: &mtu}).Build()
}

func peerMTUAck(mtu uint32, result wirev1.ResultCode) *wirev1.PeerMTUAck {
	return (&wirev1.PeerMTUAck_builder{InnerMtu: &mtu, Result: &result}).Build()
}

func pong(sequence uint32) *wirev1.Pong {
	return (&wirev1.Pong_builder{Sequence: &sequence}).Build()
}

func probeAck(size uint32) *wirev1.MtuProbeAck {
	return (&wirev1.MtuProbeAck_builder{ReceivedProbePayloadSize: &size}).Build()
}

func stateSyncRequired(reason wirev1.StateSyncRequired_Reason, session uint32) *wirev1.StateSyncRequired {
	return (&wirev1.StateSyncRequired_builder{Reason: &reason, ObservedDataSessionId: &session}).Build()
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_000, 0)}
}

func mustState(t *testing.T, config Config) *State {
	t.Helper()
	state, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func assertBlocked(t *testing.T, state *State, wantMissing Flags) {
	t.Helper()
	if state.DataSendAllowed() {
		t.Fatal("DATA gate opened early")
	}
	if missing := state.MissingFlags(); missing != wantMissing {
		t.Fatalf("MissingFlags() = %07b, want %07b", missing, wantMissing)
	}
}
