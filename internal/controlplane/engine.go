package controlplane

import (
	"errors"
	"fmt"
	"math"
	"time"

	corecontrol "github.com/kurochan/wg-frag-go/internal/core/control"
	controlstate "github.com/kurochan/wg-frag-go/internal/core/control/state"
	"github.com/kurochan/wg-frag-go/internal/core/pmtu"
	wirev1 "github.com/kurochan/wg-frag-go/proto/wire/v1"
	"google.golang.org/protobuf/proto"
)

var (
	ErrAlreadyStarted       = errors.New("controlplane: engine already started")
	ErrNotStarted           = errors.New("controlplane: engine not started")
	ErrMalformedControl     = errors.New("controlplane: malformed CONTROL")
	ErrUnsupportedBody      = errors.New("controlplane: unsupported CONTROL body")
	ErrUnexpectedResponse   = errors.New("controlplane: unexpected CONTROL response")
	ErrMessageIDExhausted   = errors.New("controlplane: message ID exhausted")
	ErrUnrepresentableProbe = errors.New("controlplane: probe payload size is not representable")
)

// Status aliases let status adapters expose the engine state
// without depending on its internal PMTUD implementation.
type Status = controlstate.Status

const (
	StatusStarting       = controlstate.StatusStarting
	StatusBase           = controlstate.StatusBase
	StatusSearching      = controlstate.StatusSearching
	StatusSearchComplete = controlstate.StatusSearchComplete
	StatusError          = controlstate.StatusError
)

// BaseErrorReason is a stable diagnostic reason for a path that cannot carry
// the minimum CONTROL probe.  It is intentionally not a wire error code.
const (
	BaseErrorReason = "base_probe_failed"

	CapabilitiesIncompatibleVersionReason = "capabilities_incompatible_version"
	CapabilitiesMissingRequiredReason     = "capabilities_missing_required_feature"
	CapabilitiesInvalidParameterReason    = "capabilities_invalid_parameter"
	CapabilitiesInvalidResultReason       = "capabilities_invalid_result"
	ResetSequenceRejectedReason           = "reset_sequence_rejected"
	ResetSequenceInvalidParameterReason   = "reset_sequence_invalid_parameter"
	ResetSequenceInvalidResultReason      = "reset_sequence_invalid_result"
	ResetSequenceRetryExhaustedReason     = "reset_sequence_retry_exhausted"
	PeerMTURejectedReason                 = "peer_mtu_rejected"
	PeerMTUInvalidParameterReason         = "peer_mtu_invalid_parameter"
	PeerMTUInvalidResultReason            = "peer_mtu_invalid_result"
)

// Config configures one peer's CONTROL engine.
type Config struct {
	State controlstate.Config
	// CanonicalizeCarrierPayload maps logical PMTU candidates to a transport's
	// representable payload. Nil keeps the controlplane transport-neutral.
	CanonicalizeCarrierPayload func(payload uint32) uint32
	// TransportDatagramSize maps a logical carrier payload to the transport
	// datagram size reported by send errors. Nil uses identity.
	TransportDatagramSize func(payload uint32) int
	// OnConfirmedPayloadChange is called synchronously whenever the local
	// send-direction DPLPMTUD confirmed payload changes. The callback runs on
	// the same owner goroutine as Engine and must not call back into Engine.
	// It may be nil when the caller polls ConfirmedCarrierPayload instead.
	OnConfirmedPayloadChange func(payload uint32)
}

// Outbound is one complete framed CONTROL carrier payload. Frame ownership is
// transferred to the caller and Engine never aliases or reuses it.
type Outbound struct {
	Frame []byte
}

type requestKind uint8

const (
	requestNone requestKind = iota
	requestCapabilities
	requestReset
	requestPeerMTU
	requestPing
	requestBaseProbe
	requestPMTUProbe
)

// CONTROL retries use exponential backoff with full jitter.
const (
	initialRetryDelay = 200 * time.Millisecond
	maxRetryDelay     = 60 * time.Second
)

const (
	probeTimeout         = 2 * time.Second
	minimumProbeTimeout  = 100 * time.Millisecond
	refreshInterval      = 10 * time.Minute
	confirmationInterval = 60 * time.Second
)

type outstandingRequest struct {
	kind         requestKind
	messageID    uint64
	ping         uint32
	probeSize    uint32
	probeAttempt uint64
	initialized  bool

	// frame is retransmitted verbatim with the same message ID.
	frame         []byte
	retryDeadline time.Time
	retryAttempt  uint
	sentAt        time.Time
}

type resetReplayKey struct {
	epoch   uint64
	message uint64
	kind    requestKind
}

type resetReplayEntry struct {
	key   resetReplayKey
	frame []byte
	used  bool
}

const resetReplayCapacity = 32

// Engine owns the CONTROL startup state for one peer. It intentionally has no
// mutex; the shim must serialize every Engine method that reads or mutates
// state, including Start, HandleInbound, Tick, and transport-failure reports.
type Engine struct {
	state                      *controlstate.State
	codec                      corecontrol.Codec
	base                       uint32
	clock                      controlstate.Clock
	pmtu                       *pmtu.State
	canonicalizeCarrierPayload func(uint32) uint32
	transportDatagramSize      func(uint32) int
	onConfirmedPayloadChange   func(uint32)

	started bool

	entropy          controlstate.Entropy
	localEpoch       uint64
	localMessageID   uint64
	remoteEpoch      uint64
	remoteResponseID uint64
	nextPingSequence uint32
	outstanding      outstandingRequest
	srtt             time.Duration

	baseError        bool
	baseErrorReason  string
	terminalError    bool
	terminalReason   string
	baseRetryAt      time.Time
	baseRetryAttempt uint

	resetReplay     [resetReplayCapacity]resetReplayEntry
	resetReplayNext int
}

// buildControl constructs an opaque-edition Control while retaining explicit
// presence for the scalar envelope fields. The opaque API exposes oneof bodies
// through dedicated builder fields rather than exported wrapper structs.
func buildControl(messageID, replyTo, epoch uint64, body any) *wirev1.Control {
	m, r, e := messageID, replyTo, epoch
	b := wirev1.Control_builder{MessageId: &m, ReplyTo: &r, ControlEpoch: &e}

	switch body := body.(type) {
	case *wirev1.CapabilitiesHello:
		b.CapabilitiesHello = body
	case *wirev1.MtuProbe:
		b.MtuProbe = body
	case *wirev1.MtuProbeAck:
		b.MtuProbeAck = body
	case *wirev1.Ping:
		b.Ping = body
	case *wirev1.Pong:
		b.Pong = body
	case *wirev1.CapabilitiesAck:
		b.CapabilitiesAck = body
	case *wirev1.ResetSequence:
		b.ResetSequence = body
	case *wirev1.ResetSequenceAck:
		b.ResetSequenceAck = body
	case *wirev1.PeerMTU:
		b.PeerMtu = body
	case *wirev1.PeerMTUAck:
		b.PeerMtuAck = body
	case *wirev1.StateSyncRequired:
		b.StateSyncRequired = body
	case nil:
	default:
		panic("controlplane: unsupported CONTROL body")
	}
	return b.Build()
}

// New constructs a fail-closed engine.
func New(config Config) (*Engine, error) {
	state, err := controlstate.New(config.State)
	if err != nil {
		return nil, err
	}
	codec, err := corecontrol.NewCodec(int(config.State.MaxCarrierPayload))
	if err != nil {
		return nil, err
	}
	return &Engine{
		state:                      state,
		codec:                      codec,
		entropy:                    config.State.Entropy,
		base:                       config.State.MinCarrierPayload,
		clock:                      config.State.Clock,
		canonicalizeCarrierPayload: config.CanonicalizeCarrierPayload,
		transportDatagramSize:      config.TransportDatagramSize,
		onConfirmedPayloadChange:   config.OnConfirmedPayloadChange,
		nextPingSequence:           1,
	}, nil
}

// Start begins a demand-driven local exchange and emits CapabilitiesHello.
func (e *Engine) Start() ([]Outbound, error) {
	if e.started {
		return nil, ErrAlreadyStarted
	}
	return e.beginLocalExchange()
}

// DataSendAllowed reports whether every v1 startup gate is complete. Terminal
// negotiation errors always fail closed, even if a stale state flag remains.
func (e *Engine) DataSendAllowed() bool {
	return !e.terminalError && e.state.DataSendAllowed()
}

// Status reports the local CONTROL path state. ERROR remains fail-closed until
// recovery succeeds, or until a terminal negotiation error is reconfigured.
func (e *Engine) Status() Status {
	if e.baseError || e.terminalError {
		return StatusError
	}
	if !e.started {
		return StatusStarting
	}
	flags := e.state.ReadyFlags()
	requiredFlags := controlstate.FlagPingPong | controlstate.FlagBaseProbe
	if flags&requiredFlags != requiredFlags {
		return StatusBase
	}
	if e.pmtu != nil && e.pmtu.Searching() {
		return StatusSearching
	}
	if e.pmtu != nil {
		return StatusSearchComplete
	}
	return StatusBase
}

// StatusReason returns a stable local diagnostic reason, or an empty string
// when the engine is not in ERROR.
func (e *Engine) StatusReason() string {
	if e.terminalError {
		return e.terminalReason
	}
	if !e.baseError {
		return ""
	}
	return e.baseErrorReason
}

// BaseError reports whether this direction is in recoverable BASE ERROR.
func (e *Engine) BaseError() bool { return e.baseError }

// ResetRetry restarts a recoverable BASE ERROR attempt immediately. The
// engine remains fail-closed until that attempt receives a valid Pong. An
// adapter can call it after an endpoint or outer address-family change.
func (e *Engine) ResetRetry() ([]Outbound, error) {
	if !e.baseError {
		return nil, nil
	}
	e.outstanding = outstandingRequest{}
	e.state.ResetPathGates()
	e.baseRetryAttempt = 0
	e.baseRetryAt = e.now()
	return e.tickBaseError(e.now())
}

// LocalExchangeID returns the current local send-direction CONTROL epoch and
// DATA session. It is zero-valued before Start.
func (e *Engine) LocalExchangeID() controlstate.LocalExchange {
	return e.state.LocalExchangeID()
}

// RemoteDataSessionID returns the accepted peer send-direction DATA session,
// or zero until the peer ResetSequence is accepted.
func (e *Engine) RemoteDataSessionID() uint16 { return e.state.RemoteDataSessionID() }

// RemotePeerMTU returns the peer's accepted receive MTU, or zero until the
// PeerMTU exchange completes.
func (e *Engine) RemotePeerMTU() uint32 { return e.state.RemotePeerMTU() }

// RemoteReassemblyLifetimeMs returns the peer's advertised reassembly
// lifetime, or zero until the capability exchange completes.
func (e *Engine) RemoteReassemblyLifetimeMs() uint32 { return e.state.RemoteReassemblyLifetimeMs() }

// MissingFlags reports the DATA gates that remain closed.
func (e *Engine) MissingFlags() controlstate.Flags { return e.state.MissingFlags() }

// ConfirmedCarrierPayload returns the currently usable local send-direction
// carrier payload. Before BASE confirmation it is zero; once BASE succeeds it
// is at least the configured BASE and remains usable during a raise search.
func (e *Engine) ConfirmedCarrierPayload() uint32 {
	if e.pmtu == nil {
		return 0
	}
	return e.pmtu.Confirmed()
}

// PMTUProbeOutstanding reports whether the current control correlation is an
// in-flight exploratory probe. Adapters use this to distinguish a synchronous
// EMSGSIZE for a probe from one caused by ordinary DATA traffic.
func (e *Engine) PMTUProbeOutstanding() bool {
	if e.pmtu == nil || !e.outstanding.initialized || e.outstanding.kind != requestPMTUProbe {
		return false
	}
	_, ok := e.pmtu.Outstanding()
	return ok
}

// PMTUSearching reports whether this direction still has an active DPLPMTUD
// search. It is intended for the single owner that already serializes Engine
// calls, such as runtime diagnostics and integration tests.
func (e *Engine) PMTUSearching() bool {
	return e.pmtu != nil && e.pmtu.Searching()
}

// Tick advances DPLPMTUD timeout and periodic refresh state and returns any
// padded MtuProbe that became ready. Callers should invoke this from their
// existing control timer; it never blocks or performs I/O itself.
func (e *Engine) Tick(now time.Time) ([]Outbound, error) {
	if e.terminalError {
		return nil, nil
	}
	if e.baseError {
		return e.tickBaseError(now)
	}
	if !e.outstanding.initialized && !e.state.LocalExchangeRetryAt().IsZero() &&
		e.state.LocalExchangeRetryReady() {
		return e.sendCapabilitiesHello()
	}
	// The ordinary CONTROL retry loop is useful for capability/session
	// requests, but a BASE timeout is a path failure.  Enter recoverable ERROR
	// instead of retransmitting the same oversized probe forever.
	if e.outstanding.initialized && e.outstanding.kind == requestBaseProbe && e.outstanding.frame != nil {
		// BASE uses the DPLPMTUD timeout (at least 2 seconds), not the ordinary
		// CONTROL request retry deadline.  Do not retransmit the probe during
		// that window: a timeout is the path failure that enters ERROR.
		if now.Before(e.outstanding.sentAt.Add(e.recoveryProbeTimeout())) {
			return nil, nil
		}
		e.enterBaseError()
		return nil, nil
	}
	if retried := e.retryOutstanding(now); retried != nil {
		return retried, nil
	}
	if e.pmtu == nil {
		return nil, nil
	}
	before := e.pmtu.Confirmed()
	if e.pmtu.Tick(now) {
		if e.pmtu.TakeBlackhole() {
			return e.recoverFromBlackhole(before)
		}
		// The timed-out request no longer owns the engine correlation slot. A
		// late ACK cannot complete it; the next candidate gets a fresh ID.
		if e.outstanding.kind == requestPMTUProbe {
			e.outstanding = outstandingRequest{}
		}
		if err := e.emitConfirmedChange(before); err != nil {
			return nil, err
		}
		return e.emitPMTUProbe(now)
	}
	// A capability/session request owns the CONTROL correlation slot. Do not
	// arm a periodic PMTU probe behind it; otherwise State can remain pending
	// after emitPMTUProbe declines to enqueue a second request.
	if e.outstanding.initialized {
		return nil, nil
	}
	if e.pmtu.RefreshDue(now) {
		if err := e.emitConfirmedChange(before); err != nil {
			return nil, err
		}
		return e.emitPMTUProbe(now)
	}
	if e.pmtu.ConfirmationDue(now) {
		if err := e.emitConfirmedChange(before); err != nil {
			return nil, err
		}
		return e.emitPMTUProbe(now)
	}
	return nil, nil
}

// ReportProbeFailure reports a synchronous failure (for example EMSGSIZE) for
// the outstanding DPLPMTUD probe. It returns the next probe, if any.
func (e *Engine) ReportProbeFailure(now time.Time) ([]Outbound, error) {
	if e.outstanding.initialized && e.outstanding.kind == requestBaseProbe {
		e.enterBaseError()
		return nil, nil
	}
	if e.pmtu == nil {
		return nil, nil
	}
	before := e.pmtu.Confirmed()
	if !e.pmtu.FailCurrent(now) {
		return nil, nil
	}
	if e.outstanding.kind == requestPMTUProbe {
		e.outstanding = outstandingRequest{}
	}
	if e.pmtu.TakeBlackhole() {
		return e.recoverFromBlackhole(before)
	}
	if err := e.emitConfirmedChange(before); err != nil {
		return nil, err
	}
	return e.emitPMTUProbe(now)
}

// ReportSendFailure applies a transport EMSGSIZE for a datagram of wireSize
// UDP payload bytes; zero means the failing datagram is unknown (a stashed
// kernel error surfaced by a later send). Only a size match may fail the
// outstanding probe definitively — anything else would let one oversized
// probe's stashed error sink the valid candidate that follows it.
func (e *Engine) ReportSendFailure(now time.Time, wireSize int) ([]Outbound, error) {
	if e.outstanding.initialized && e.outstanding.kind == requestBaseProbe {
		if wireSize == 0 || wireSize == e.transportSize(e.outstanding.probeSize) {
			e.enterBaseError()
		}
		return nil, nil
	}
	if e.baseError && e.outstanding.initialized && e.outstanding.kind == requestPing {
		// A failed reachability retry leaves ERROR active and schedules a new
		// full Ping -> BASE attempt using the same capped jitter policy.
		e.outstanding = outstandingRequest{}
		e.scheduleBaseRetry(now)
		return nil, nil
	}
	if e.pmtu == nil {
		return nil, nil
	}
	if e.PMTUProbeOutstanding() {
		if wireSize == 0 {
			before := e.pmtu.Confirmed()
			if !e.pmtu.SoftFailCurrent(now) {
				return nil, nil
			}
			if e.outstanding.kind == requestPMTUProbe {
				e.outstanding = outstandingRequest{}
			}
			if e.pmtu.TakeBlackhole() {
				return e.recoverFromBlackhole(before)
			}
			if err := e.emitConfirmedChange(before); err != nil {
				return nil, err
			}
			return e.emitPMTUProbe(now)
		}
		if wireSize == e.transportSize(e.outstanding.probeSize) {
			return e.ReportProbeFailure(now)
		}
		return nil, nil
	}
	if wireSize >= e.transportSize(e.base) {
		return e.ReportBlackhole(now)
	}
	return nil, nil
}

// ReportBlackhole drops the confirmed send payload to BASE and starts a new
// non-blocking search while keeping the existing path gates open.
func (e *Engine) ReportBlackhole(now time.Time) ([]Outbound, error) {
	if e.pmtu == nil {
		return nil, nil
	}
	before := e.pmtu.Confirmed()
	e.pmtu.ReportBlackhole(now)
	e.outstanding = outstandingRequest{}
	if err := e.emitConfirmedChange(before); err != nil {
		return nil, err
	}
	return e.emitPMTUProbe(now)
}

// recoverFromBlackhole closes DATA and re-runs the reachability and BASE gates
// after a confirmed size stops making progress.
func (e *Engine) recoverFromBlackhole(before uint32) ([]Outbound, error) {
	// The search already moved its confirmed size to BASE. Notify the adapter
	// before discarding the state so it stops using the old ceiling.
	if e.onConfirmedPayloadChange != nil && before != e.base {
		e.onConfirmedPayloadChange(e.base)
	}
	e.pmtu = nil
	e.outstanding = outstandingRequest{}
	e.state.ResetPathGates()
	return e.progress()
}

// HandleInbound strictly decodes one complete CONTROL carrier payload, applies
// its state transition, and returns zero or more frames for the caller's fixed
// CONTROL ring.
func (e *Engine) HandleInbound(frame []byte) ([]Outbound, error) {
	payload, err := e.codec.Parse(frame)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedControl, err)
	}

	var message wirev1.Control
	options := proto.UnmarshalOptions{
		RecursionLimit: 16,
	}
	if err := options.Unmarshal(payload, &message); err != nil {
		return nil, fmt.Errorf("%w: protobuf: %w", ErrMalformedControl, err)
	}
	if message.GetMessageId() == 0 || message.GetControlEpoch() == 0 || controlBodyUnset(&message) {
		return nil, ErrMalformedControl
	}
	if message.GetMtuProbe() == nil && len(message.GetPadding()) != 0 {
		return nil, ErrMalformedControl
	}
	// A delayed Hello from a retired remote process epoch must not trigger an
	// Ack or mutate capability/session state. Check before normal dispatch.
	if message.GetCapabilitiesHello() != nil && e.state.IsRemoteEpochRetired(message.GetControlEpoch()) {
		return nil, nil
	}
	if e.baseError && e.outstanding.initialized && !e.allowDuringBaseRecovery(&message) {
		return nil, nil
	}
	if key, ok := resetReplayKeyFor(&message); ok && e.remoteEpoch != 0 && key.epoch == e.remoteEpoch {
		if replay, found := e.lookupResetReplay(key); found {
			return []Outbound{{Frame: replay}}, nil
		}
	}

	var (
		out       []Outbound
		handleErr error
	)
	if message.GetCapabilitiesHello() != nil {
		out, handleErr = e.handleCapabilitiesHello(&message)
	} else if message.GetCapabilitiesAck() != nil {
		out, handleErr = e.handleCapabilitiesAck(&message)
	} else if message.GetResetSequence() != nil {
		out, handleErr = e.handleReset(&message)
	} else if message.GetResetSequenceAck() != nil {
		out, handleErr = e.handleResetAck(&message)
	} else if message.GetPeerMtu() != nil {
		out, handleErr = e.handlePeerMTU(&message)
	} else if message.GetPeerMtuAck() != nil {
		out, handleErr = e.handlePeerMTUAck(&message)
	} else if message.GetPing() != nil {
		out, handleErr = e.handlePing(&message)
	} else if message.GetPong() != nil {
		out, handleErr = e.handlePong(&message)
	} else if message.GetMtuProbe() != nil {
		out, handleErr = e.handleMtuProbe(&message, uint32(len(frame)))
	} else if message.GetMtuProbeAck() != nil {
		out, handleErr = e.handleMtuProbeAck(&message)
	} else if message.GetStateSyncRequired() != nil {
		out, handleErr = e.handleStateSyncRequired(&message)
	} else {
		handleErr = ErrUnsupportedBody
	}
	if handleErr != nil {
		return nil, handleErr
	}

	var replayFrame []byte
	if key, ok := resetReplayKeyFor(&message); ok && len(out) > 0 {
		replayFrame = cloneBytes(out[0].Frame)
		e.storeResetReplay(key, replayFrame)
	}
	return out, nil
}

func (e *Engine) allowDuringBaseRecovery(message *wirev1.Control) bool {
	// Requests from the peer are still needed to converge after a peer restart.
	if message.GetReplyTo() == 0 {
		return true
	}
	if !e.outstanding.initialized || message.GetReplyTo() != e.outstanding.messageID ||
		message.GetControlEpoch() != e.localEpoch {
		return false
	}
	switch e.outstanding.kind {
	case requestCapabilities:
		return message.GetCapabilitiesAck() != nil
	case requestReset:
		return message.GetResetSequenceAck() != nil
	case requestPeerMTU:
		return message.GetPeerMtuAck() != nil
	case requestPing:
		return message.GetPong() != nil
	case requestBaseProbe:
		return message.GetMtuProbeAck() != nil
	default:
		return false
	}
}

// controlBodyUnset reports whether the opaque Control contains no recognized
// body. Body presence is identified through generated getters; the opaque API
// intentionally hides the underlying oneof wrapper and WhichBody internals.
func controlBodyUnset(message *wirev1.Control) bool {
	return message == nil ||
		(message.GetCapabilitiesHello() == nil &&
			message.GetMtuProbe() == nil &&
			message.GetMtuProbeAck() == nil &&
			message.GetPing() == nil &&
			message.GetPong() == nil &&
			message.GetCapabilitiesAck() == nil &&
			message.GetResetSequence() == nil &&
			message.GetResetSequenceAck() == nil &&
			message.GetPeerMtu() == nil &&
			message.GetPeerMtuAck() == nil &&
			message.GetStateSyncRequired() == nil)
}

// ReportUnknownDataSession requests a fresh exchange after an unknown session
// is observed on authenticated DATA.
func (e *Engine) ReportUnknownDataSession(sessionID uint16) ([]Outbound, error) {
	if !e.started {
		// A restarted receiver shares no epoch with the peer yet, so
		// StateSyncRequired would be rejected. Its own Hello is what makes the
		// peer start over, and this DATA is the only demand signal it gets.
		return e.beginLocalExchange()
	}
	decision := e.state.CheckInboundDataSession(sessionID)
	var sync wirev1.StateSyncRequired
	if !decision.PopulateStateSyncRequired(&sync) {
		return nil, nil
	}
	messageID, err := nextID(&e.localMessageID)
	if err != nil {
		return nil, err
	}
	frame, err := e.marshal(buildControl(messageID, 0, e.localEpoch, &sync), 0)
	if err != nil {
		return nil, err
	}
	return []Outbound{{Frame: frame}}, nil
}

func (e *Engine) handleStateSyncRequired(message *wirev1.Control) ([]Outbound, error) {
	if message.GetReplyTo() != 0 {
		return nil, ErrMalformedControl
	}
	if e.state.ObserveStateSyncRequired(message) != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		return nil, nil
	}
	return e.beginLocalExchange()
}

func (e *Engine) beginLocalExchange() ([]Outbound, error) {
	exchange, err := e.state.BeginLocalExchange()
	if err != nil {
		return nil, err
	}
	// A fresh local epoch starts a fresh send-direction path gate. Any PMTU
	// result from the previous epoch must not survive into the new BASE probe.
	e.pmtu = nil
	e.started = true
	e.localEpoch = exchange.ControlEpoch
	e.localMessageID = 0
	e.outstanding = outstandingRequest{}
	return e.sendCapabilitiesHello()
}

func (e *Engine) sendCapabilitiesHello() ([]Outbound, error) {
	capabilities := e.state.LocalCapabilities()
	message := buildControl(0, 0, e.localEpoch, &capabilities)
	return e.sendRequest(requestCapabilities, message, 0, 0)
}

func (e *Engine) handleCapabilitiesHello(message *wirev1.Control) ([]Outbound, error) {
	if message.GetReplyTo() != 0 {
		return nil, ErrMalformedControl
	}
	previousRemoteEpoch := e.remoteEpoch
	decision := e.state.ObserveCapabilitiesHello(message)
	remoteEpochChanged := decision.Result == wirev1.ResultCode_RESULT_CODE_ACCEPTED &&
		previousRemoteEpoch != 0 && previousRemoteEpoch != message.GetControlEpoch()
	if decision.Result == wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		if e.remoteEpoch != message.GetControlEpoch() {
			e.remoteEpoch = message.GetControlEpoch()
			e.remoteResponseID = 0
			if previousRemoteEpoch != 0 {
				e.pmtu = nil
			}
		}
	}
	ackBody := (&wirev1.CapabilitiesAck_builder{
		SelectedDataProtocolVersion: &decision.SelectedDataProtocolVersion,
		SelectedFeatureBits:         &decision.SelectedFeatureBits,
		Result:                      &decision.Result,
	}).Build()
	ack := buildControl(0, message.GetMessageId(), message.GetControlEpoch(), ackBody)
	response, err := e.sendResponse(ack)
	if err != nil {
		return nil, err
	}
	out := []Outbound{response}

	if decision.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		e.enterTerminalError(capabilitiesAckReason(decision.Result))
		return out, nil
	}
	terminalRecovered := e.terminalError && (previousRemoteEpoch == 0 || remoteEpochChanged)
	if terminalRecovered {
		// A valid Hello from a new peer process is the explicit reconfiguration
		// boundary that permits recovery from a terminal negotiation error.
		e.clearTerminalError()
	}
	// A peer restart changes the independent receive-direction epoch even when
	// this engine already has a local epoch. Re-start our own exchange as well;
	// otherwise State.clearRemoteEpoch leaves local capability gates closed with
	// no request outstanding, and the two peers can never become DATA-ready
	// again.
	if terminalRecovered || decision.StartReverseExchange || remoteEpochChanged {
		if !e.state.LocalExchangeRetryAt().IsZero() && !e.state.LocalExchangeRetryReady() {
			// A collision retry already installed a new local epoch/session. Do not
			// call BeginLocalExchange again before its deadline; Tick will send the
			// pending Hello when the state-owned backoff expires.
			return out, nil
		}
		reverse, err := e.beginLocalExchange()
		if err != nil {
			return nil, err
		}
		return append(out, reverse...), nil
	}
	progressed, err := e.progress()
	return append(out, progressed...), err
}

func (e *Engine) handleCapabilitiesAck(message *wirev1.Control) ([]Outbound, error) {
	if err := e.requireResponse(message, requestCapabilities); err != nil {
		return nil, err
	}
	ack := message.GetCapabilitiesAck()
	if !validCapabilitiesAckResult(ack.GetResult()) {
		e.enterTerminalError(CapabilitiesInvalidResultReason)
		return nil, nil
	}
	result := e.state.ObserveCapabilitiesAck(message, e.outstanding.messageID)
	if result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		e.enterTerminalError(capabilitiesAckReason(result))
		return nil, nil
	}
	e.outstanding = outstandingRequest{}
	return e.progress()
}

func validCapabilitiesAckResult(result wirev1.ResultCode) bool {
	switch result {
	case wirev1.ResultCode_RESULT_CODE_ACCEPTED,
		wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION,
		wirev1.ResultCode_RESULT_CODE_MISSING_REQUIRED_FEATURE,
		wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER:
		return true
	default:
		return false
	}
}

func capabilitiesAckReason(result wirev1.ResultCode) string {
	switch result {
	case wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION:
		return CapabilitiesIncompatibleVersionReason
	case wirev1.ResultCode_RESULT_CODE_MISSING_REQUIRED_FEATURE:
		return CapabilitiesMissingRequiredReason
	case wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER:
		return CapabilitiesInvalidParameterReason
	default:
		return CapabilitiesInvalidResultReason
	}
}

func (e *Engine) handleReset(message *wirev1.Control) ([]Outbound, error) {
	if err := e.requireRemoteRequest(message); err != nil {
		return nil, err
	}
	decision := e.state.ObserveResetSequence(message)
	dataSessionID := message.GetResetSequence().GetDataSessionId()
	ackBody := (&wirev1.ResetSequenceAck_builder{DataSessionId: &dataSessionID, Result: &decision.Result}).Build()
	ack := buildControl(0, message.GetMessageId(), message.GetControlEpoch(), ackBody)
	response, err := e.sendResponse(ack)
	if err != nil {
		return nil, err
	}
	return []Outbound{response}, nil
}

func (e *Engine) handleResetAck(message *wirev1.Control) ([]Outbound, error) {
	if err := e.requireResponse(message, requestReset); err != nil {
		return nil, err
	}
	ack := message.GetResetSequenceAck()
	if !validResultCode(ack.GetResult()) {
		e.enterTerminalError(ResetSequenceInvalidResultReason)
		return nil, nil
	}
	result := e.state.ObserveResetSequenceAck(message, e.outstanding.messageID)
	if result == wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION {
		e.outstanding = outstandingRequest{}
		return e.restartAfterResetCollision()
	}
	if result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		e.enterTerminalError(resetSequenceReason(result))
		return nil, nil
	}
	e.outstanding = outstandingRequest{}
	return e.progress()
}

func validResultCode(result wirev1.ResultCode) bool {
	switch result {
	case wirev1.ResultCode_RESULT_CODE_ACCEPTED,
		wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION,
		wirev1.ResultCode_RESULT_CODE_MISSING_REQUIRED_FEATURE,
		wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER,
		wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION:
		return true
	default:
		return false
	}
}

func resetSequenceReason(result wirev1.ResultCode) string {
	if result == wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		return ResetSequenceInvalidParameterReason
	}
	return ResetSequenceRejectedReason
}

func (e *Engine) restartAfterResetCollision() ([]Outbound, error) {
	retry, err := e.state.RestartLocalExchange()
	if err != nil {
		if errors.Is(err, controlstate.ErrLocalExchangeBackoff) {
			return nil, nil
		}
		e.enterTerminalError(ResetSequenceRetryExhaustedReason)
		return nil, nil
	}
	e.pmtu = nil
	e.localEpoch = retry.ControlEpoch
	e.localMessageID = 0
	return nil, nil
}

func (e *Engine) handlePeerMTU(message *wirev1.Control) ([]Outbound, error) {
	if err := e.requireRemoteRequest(message); err != nil {
		return nil, err
	}
	result := e.state.ObservePeerMTU(message)
	innerMTU := message.GetPeerMtu().GetInnerMtu()
	ackBody := (&wirev1.PeerMTUAck_builder{InnerMtu: &innerMTU, Result: &result}).Build()
	ack := buildControl(0, message.GetMessageId(), message.GetControlEpoch(), ackBody)
	response, err := e.sendResponse(ack)
	if err != nil {
		return nil, err
	}
	out := []Outbound{response}
	progressed, err := e.progress()
	return append(out, progressed...), err
}

func (e *Engine) handlePeerMTUAck(message *wirev1.Control) ([]Outbound, error) {
	if err := e.requireResponse(message, requestPeerMTU); err != nil {
		return nil, err
	}
	ack := message.GetPeerMtuAck()
	if !validResultCode(ack.GetResult()) {
		e.enterTerminalError(PeerMTUInvalidResultReason)
		return nil, nil
	}
	result := e.state.ObservePeerMTUAck(message, e.outstanding.messageID)
	if result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		e.enterTerminalError(peerMTUReason(result))
		return nil, nil
	}
	e.outstanding = outstandingRequest{}
	return e.progress()
}

func peerMTUReason(result wirev1.ResultCode) string {
	if result == wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER {
		return PeerMTUInvalidParameterReason
	}
	return PeerMTURejectedReason
}

func (e *Engine) handlePing(message *wirev1.Control) ([]Outbound, error) {
	if err := e.requireRemoteRequest(message); err != nil {
		return nil, err
	}
	sequence := message.GetPing().GetSequence()
	response, err := e.sendResponse(buildControl(
		0,
		message.GetMessageId(),
		message.GetControlEpoch(),
		(&wirev1.Pong_builder{Sequence: &sequence}).Build(),
	))
	if err != nil {
		return nil, err
	}
	return []Outbound{response}, nil
}

func (e *Engine) handlePong(message *wirev1.Control) ([]Outbound, error) {
	if err := e.requireResponse(message, requestPing); err != nil {
		return nil, err
	}
	recovering := e.baseError
	result := e.state.ObservePong(message, e.outstanding.messageID, e.outstanding.ping)
	if result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		return nil, ErrMalformedControl
	}
	e.observeRTT()
	e.outstanding = outstandingRequest{}
	if recovering {
		// Keep ERROR and DATA fail-closed until the follow-up BASE probe is
		// acknowledged. Only that complete recovery sequence proves the minimum
		// carrier can cross the path.
		e.baseError = false
		out, err := e.progress()
		e.baseError = true

		if err != nil {
			return nil, err
		}
		return out, nil
	}
	return e.progress()
}

func (e *Engine) handleMtuProbe(message *wirev1.Control, receivedSize uint32) ([]Outbound, error) {
	if err := e.requireRemoteRequest(message); err != nil {
		return nil, err
	}
	response, err := e.sendResponse(buildControl(
		0,
		message.GetMessageId(),
		message.GetControlEpoch(),
		(&wirev1.MtuProbeAck_builder{ReceivedProbePayloadSize: &receivedSize}).Build(),
	))
	if err != nil {
		return nil, err
	}
	return []Outbound{response}, nil
}

func (e *Engine) handleMtuProbeAck(message *wirev1.Control) ([]Outbound, error) {
	if !e.outstanding.initialized {
		if e.pmtu != nil {
			return nil, nil
		}
		return nil, ErrUnexpectedResponse
	}
	if e.outstanding.kind != requestBaseProbe && e.outstanding.kind != requestPMTUProbe {
		return nil, ErrUnexpectedResponse
	}
	// A timeout advances the search and frees the correlation slot. The old
	// probe may still be in flight on the wire; discard its late ACK rather
	// than failing the whole control bridge. A current probe with a malformed
	// size is still rejected below.
	if message.GetReplyTo() != e.outstanding.messageID || message.GetControlEpoch() != e.localEpoch {
		return nil, nil
	}
	if err := e.requireResponse(message, e.outstanding.kind); err != nil {
		return nil, err
	}
	ack := message.GetMtuProbeAck()
	if ack == nil || ack.GetReceivedProbePayloadSize() != e.outstanding.probeSize {
		return nil, ErrMalformedControl
	}
	before := uint32(0)
	if e.pmtu != nil {
		before = e.pmtu.Confirmed()
	}
	if e.outstanding.kind == requestBaseProbe {
		result := e.state.ObserveBaseProbeAck(message, e.outstanding.messageID)
		if result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
			return nil, ErrMalformedControl
		}
		e.outstanding = outstandingRequest{}
		if err := e.startPMTU(); err != nil {
			return nil, err
		}
		// BASE recovery is complete only after the minimum probe ACK. Clearing
		// ERROR here prevents a delayed or unrelated CONTROL message from
		// reopening DATA prematurely.
		e.clearBaseError()
		if err := e.emitConfirmedChange(before); err != nil {
			return nil, err
		}
		return e.emitPMTUProbe(e.now())
	}
	if e.pmtu == nil || !e.pmtu.Acknowledge(e.outstanding.probeAttempt, ack.GetReceivedProbePayloadSize(), e.now()) {
		return nil, ErrMalformedControl
	}
	e.outstanding = outstandingRequest{}
	if err := e.emitConfirmedChange(before); err != nil {
		return nil, err
	}
	return e.emitPMTUProbe(e.now())
}

func (e *Engine) progress() ([]Outbound, error) {
	if !e.started || e.outstanding.initialized || e.terminalError {
		return nil, nil
	}
	flags := e.state.ReadyFlags()
	requiredFlags := controlstate.FlagLocalCapabilities | controlstate.FlagRemoteCapabilities
	if flags&requiredFlags != requiredFlags {
		return nil, nil
	}
	if flags&controlstate.FlagLocalResetAck == 0 {
		exchange := e.state.LocalExchangeID()
		dataSessionID := uint32(exchange.DataSessionID)
		return e.sendRequest(
			requestReset,
			buildControl(
				0,
				0,
				e.localEpoch,
				(&wirev1.ResetSequence_builder{DataSessionId: &dataSessionID}).Build(),
			),
			0,
			0,
		)
	}
	if flags&controlstate.FlagLocalPeerMTUAck == 0 {
		peerMTU := e.state.LocalPeerMTU()
		return e.sendRequest(requestPeerMTU, buildControl(0, 0, e.localEpoch, &peerMTU), 0, 0)
	}
	if flags&controlstate.FlagRemotePeerMTU == 0 {
		return nil, nil
	}
	if flags&controlstate.FlagPingPong == 0 {
		sequence := e.nextPingSequence
		e.nextPingSequence++
		return e.sendRequest(
			requestPing,
			buildControl(
				0,
				0,
				e.localEpoch,
				(&wirev1.Ping_builder{Sequence: &sequence}).Build(),
			),
			sequence,
			0,
		)
	}
	if flags&controlstate.FlagBaseProbe == 0 {
		return e.sendRequest(requestBaseProbe, buildControl(0, 0, e.localEpoch, wirev1.MtuProbe_builder{}.Build()), 0, e.base)
	}
	if e.pmtu == nil {
		if err := e.startPMTU(); err != nil {
			return nil, err
		}
	}
	return e.emitPMTUProbe(e.now())
}

func (e *Engine) sendRequest(kind requestKind, message *wirev1.Control, ping, probeSize uint32) ([]Outbound, error) {
	messageID, err := nextID(&e.localMessageID)
	if err != nil {
		return nil, err
	}
	message.SetMessageId(messageID)
	frame, err := e.marshal(message, probeSize)
	if err != nil {
		return nil, err
	}
	if kind == requestBaseProbe {
		actual := uint32(len(frame))
		if actual < e.base {
			// A BASE candidate below the configured minimum is never a valid
			// probe. Do not leave a correlation slot armed for an ACK that can
			// never satisfy the BASE gate.
			return nil, ErrUnrepresentableProbe
		}
		probeSize = actual
	}
	e.outstanding = outstandingRequest{
		kind:        kind,
		messageID:   messageID,
		ping:        ping,
		probeSize:   probeSize,
		initialized: true,
		sentAt:      e.now(),
	}
	// DPLPMTUD owns probe retries; every other request is retried by Tick.
	if kind != requestPMTUProbe {
		// Outbound ownership is transferred to the caller. Keep an independent
		// copy for retransmission so a TUN implementation cannot mutate the
		// engine's retry state through the returned slice.
		e.outstanding.frame = cloneBytes(frame)
		e.outstanding.retryDeadline = e.now().Add(e.retryDelay(0))
	}
	return []Outbound{{Frame: frame}}, nil
}

// retryDelay returns capped exponential backoff with full jitter.
func (e *Engine) retryDelay(attempt uint) time.Duration {
	delay := initialRetryDelay
	for i := uint(0); i < attempt && delay < maxRetryDelay; i++ {
		delay *= 2
	}
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	if e.entropy == nil {
		return delay
	}
	random, err := e.entropy.Uint64()
	if err != nil {
		return delay
	}
	jittered := time.Duration(random % uint64(delay))
	if jittered == 0 {
		return time.Nanosecond
	}
	return jittered
}

// retryOutstanding retransmits an unanswered request and re-arms its backoff.
func (e *Engine) retryOutstanding(now time.Time) []Outbound {
	if !e.outstanding.initialized || e.outstanding.frame == nil ||
		now.Before(e.outstanding.retryDeadline) {
		return nil
	}

	e.outstanding.retryAttempt++
	e.outstanding.retryDeadline = now.Add(e.retryDelay(e.outstanding.retryAttempt))
	// The caller owns returned frames. Do not expose the retained retry copy;
	// a queue is allowed to reuse or mutate a frame after EnqueueControl.
	return []Outbound{{Frame: cloneBytes(e.outstanding.frame)}}
}

func (e *Engine) enterBaseError() {
	e.state.ResetPathGates()
	e.outstanding = outstandingRequest{}
	e.baseError = true
	e.baseErrorReason = BaseErrorReason
	e.baseRetryAttempt = 0
	e.baseRetryAt = e.now().Add(e.retryDelay(0))
}

func (e *Engine) enterTerminalError(reason string) {
	e.state.ResetPathGates()
	e.outstanding = outstandingRequest{}
	e.baseError = false
	e.baseErrorReason = ""
	e.baseRetryAt = time.Time{}
	e.baseRetryAttempt = 0
	e.terminalError = true
	e.terminalReason = reason
}

func (e *Engine) clearBaseError() {
	if !e.baseError {
		return
	}
	e.baseError = false
	e.baseErrorReason = ""
	e.baseRetryAt = time.Time{}
	e.baseRetryAttempt = 0
}

func (e *Engine) clearTerminalError() {
	e.terminalError = false
	e.terminalReason = ""
}

func (e *Engine) scheduleBaseRetry(now time.Time) {
	e.baseError = true
	e.baseErrorReason = BaseErrorReason
	e.baseRetryAttempt++
	e.baseRetryAt = now.Add(e.retryDelay(e.baseRetryAttempt))
}

func (e *Engine) tickBaseError(now time.Time) ([]Outbound, error) {
	if e.outstanding.initialized {
		// Recovery requests are kept for the full path timeout. Retrying them
		// with the ordinary short jitter can create duplicate state transitions,
		// while dropping them before the timeout loses valid slow ACKs.
		if now.Before(e.outstanding.sentAt.Add(e.recoveryProbeTimeout())) {
			return nil, nil
		}
		e.outstanding = outstandingRequest{}
		e.state.ResetPathGates()
		e.scheduleBaseRetry(now)
		return nil, nil
	}
	if !e.baseRetryAt.IsZero() && now.Before(e.baseRetryAt) {
		return nil, nil
	}
	// Temporarily open progress so it emits the next request. Keep ERROR
	// observable while that request is in flight and until valid CONTROL clears
	// it.
	e.baseError = false
	var out []Outbound
	var err error
	if e.state.ReadyFlags()&controlstate.FlagLocalCapabilities == 0 {
		out, err = e.sendCapabilitiesHello()
	} else {
		out, err = e.progress()
	}
	e.baseError = true
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		e.scheduleBaseRetry(now)
	}
	return out, nil
}

func (e *Engine) sendPMTUProbe(probe pmtu.Probe) ([]Outbound, error) {
	out, err := e.sendRequest(
		requestPMTUProbe,
		buildControl(0, 0, e.localEpoch, wirev1.MtuProbe_builder{}.Build()),
		0,
		probe.PayloadSize,
	)
	if err != nil {
		return nil, err
	}
	actual := uint32(len(out[0].Frame))
	if actual < e.base {
		e.abortPMTUProbe()
		return nil, ErrUnrepresentableProbe
	}
	if actual != probe.PayloadSize && !e.pmtu.AdjustCurrent(probe.Attempt, actual) {
		e.abortPMTUProbe()
		return nil, ErrUnrepresentableProbe
	}
	e.outstanding.probeSize = actual
	e.outstanding.probeAttempt = probe.Attempt
	return out, nil
}

// abortPMTUProbe releases both sides of the control/pmtu correlation when a
// probe cannot be represented. Leaving either side armed would make the
// single-owner engine appear permanently busy after returning the error.
func (e *Engine) abortPMTUProbe() {
	if e.pmtu != nil {
		_ = e.pmtu.FailCurrent(e.now())
	}
	e.outstanding = outstandingRequest{}
}

func (e *Engine) emitPMTUProbe(now time.Time) ([]Outbound, error) {
	if e.pmtu == nil || e.outstanding.initialized {
		return nil, nil
	}
	probe, ok := e.pmtu.Next(now)
	if !ok {
		return nil, nil
	}
	return e.sendPMTUProbe(probe)
}

func (e *Engine) startPMTU() error {
	if e.pmtu != nil {
		return nil
	}
	ceiling := e.state.NegotiatedCarrierPayload()
	if ceiling == 0 {
		return nil
	}
	search, err := pmtu.New(pmtu.Config{
		Base:                 e.base,
		Ceiling:              ceiling,
		Canonicalize:         e.canonicalizeCarrierPayload,
		ProbeTimeout:         probeTimeout,
		RefreshInterval:      refreshInterval,
		ConfirmationInterval: confirmationInterval,
	})
	if err != nil {
		return err
	}
	if e.srtt > 0 {
		search.ObserveRTT(e.srtt)
	}
	e.pmtu = search
	e.pmtu.Start(e.now())
	return nil
}

func (e *Engine) transportSize(payload uint32) int {
	if e.transportDatagramSize == nil {
		return int(payload)
	}
	return e.transportDatagramSize(payload)
}

func (e *Engine) emitConfirmedChange(before uint32) error {
	if e.pmtu == nil || e.pmtu.Confirmed() == before || e.onConfirmedPayloadChange == nil {
		return nil
	}
	e.onConfirmedPayloadChange(e.pmtu.Confirmed())
	return nil
}

// observeRTT records a Ping/Pong round trip for subsequent probe timeouts. It
// deliberately ignores retries so a delayed response cannot inflate SRTT.
func (e *Engine) observeRTT() {
	if e.outstanding.sentAt.IsZero() || e.outstanding.retryAttempt != 0 {
		return
	}
	sample := e.now().Sub(e.outstanding.sentAt)
	if sample <= 0 {
		return
	}
	if e.srtt == 0 {
		e.srtt = sample
	} else {
		e.srtt += (sample - e.srtt) / 8
	}
	if e.pmtu != nil {
		e.pmtu.ObserveRTT(sample)
	}
}

func (e *Engine) recoveryProbeTimeout() time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if e.srtt <= 0 {
		return probeTimeout
	}
	if e.srtt > maxDuration/4 {
		return maxDuration
	}
	adaptive := 4 * e.srtt
	if adaptive < minimumProbeTimeout {
		return minimumProbeTimeout
	}
	return adaptive
}

func (e *Engine) now() time.Time { return e.clock.Now() }

func (e *Engine) sendResponse(message *wirev1.Control) (Outbound, error) {
	messageID, err := nextID(&e.remoteResponseID)
	if err != nil {
		return Outbound{}, err
	}
	message.SetMessageId(messageID)
	frame, err := e.marshal(message, 0)
	if err != nil {
		return Outbound{}, err
	}
	return Outbound{Frame: frame}, nil
}

func resetReplayKeyFor(message *wirev1.Control) (resetReplayKey, bool) {
	if message == nil {
		return resetReplayKey{}, false
	}
	if message.GetResetSequence() == nil {
		return resetReplayKey{}, false
	}
	return resetReplayKey{epoch: message.GetControlEpoch(), message: message.GetMessageId(), kind: requestReset}, true
}

func (e *Engine) lookupResetReplay(key resetReplayKey) ([]byte, bool) {
	for i := range e.resetReplay {
		entry := &e.resetReplay[i]
		if entry.used && entry.key == key {
			return cloneBytes(entry.frame), true
		}
	}
	return nil, false
}

func (e *Engine) storeResetReplay(key resetReplayKey, frame []byte) {
	if len(frame) == 0 {
		return
	}
	for i := range e.resetReplay {
		entry := &e.resetReplay[i]
		if entry.used && entry.key == key {
			entry.frame = cloneBytes(frame)
			return
		}
	}
	entry := &e.resetReplay[e.resetReplayNext]
	entry.key = key
	entry.frame = cloneBytes(frame)
	entry.used = true
	e.resetReplayNext = (e.resetReplayNext + 1) % len(e.resetReplay)
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (e *Engine) marshal(message *wirev1.Control, targetSize uint32) ([]byte, error) {
	if targetSize != 0 {
		if targetSize > uint32(e.codec.MaxFrameSize()) {
			return nil, corecontrol.ErrFrameTooLarge
		}
		padding := make([]byte, int(targetSize))
		// proto.Size is monotonic in the padding length. Find the largest
		// representable frame at or below targetSize in O(log targetSize),
		// including protobuf length-varint discontinuities.
		lo, hi := 0, len(padding)+1 // hi is exclusive and initially infeasible
		for lo < hi {
			mid := lo + (hi-lo)/2
			message.SetPadding(padding[:mid])
			if corecontrol.HeaderSize+proto.Size(message) <= int(targetSize) {
				lo = mid + 1

				continue
			}
			hi = mid
		}
		best := lo - 1
		if best < 0 {
			return nil, ErrUnrepresentableProbe
		}
		message.SetPadding(padding[:best])
	} else {
		message.ClearPadding()
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, corecontrol.HeaderSize+len(payload))
	if _, err := e.codec.MarshalTo(frame, payload); err != nil {
		return nil, err
	}
	return frame, nil
}

func (e *Engine) requireRemoteRequest(message *wirev1.Control) error {
	if message.GetReplyTo() != 0 || e.remoteEpoch == 0 || message.GetControlEpoch() != e.remoteEpoch {
		return ErrMalformedControl
	}
	return nil
}

func (e *Engine) requireResponse(message *wirev1.Control, kind requestKind) error {
	if !e.started {
		return ErrNotStarted
	}
	if !e.outstanding.initialized ||
		e.outstanding.kind != kind ||
		message.GetReplyTo() != e.outstanding.messageID ||
		message.GetControlEpoch() != e.localEpoch {
		return ErrUnexpectedResponse
	}
	return nil
}

func nextID(value *uint64) (uint64, error) {
	if *value == math.MaxUint64 {
		return 0, ErrMessageIDExhausted
	}

	*value++
	return *value, nil
}
