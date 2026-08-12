package state

import (
	"errors"
	"fmt"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/limits"
	wirev1 "github.com/kurochan/wg-frag-go/proto/wire/v1"
)

const (
	DataProtocolVersion     uint32 = 1
	MinReassemblyLifetimeMs uint32 = 100
	MaxReassemblyLifetimeMs uint32 = 60_000
	// InitialLocalExchangeBackoff is the starting local exchange retry backoff and uses full jitter.
	InitialLocalExchangeBackoff = 200 * time.Millisecond
	MaxLocalExchangeBackoff     = 60 * time.Second
	maxRetiredSessionEntries    = 4096
	maxRetiredEpochEntries      = 1 << 14
	retiredEpochLifetime        = 4 * time.Minute
	// maxCarrierPayload is the IPv6 payload-length field's largest value.
	// Keeping this bound at the codec boundary prevents a negotiated value
	// from later overflowing the on-wire uint16 length field.
	maxCarrierPayload uint32 = 1<<16 - 1
)

var (
	ErrInvalidConfig        = errors.New("control state: invalid config")
	ErrMissingClock         = errors.New("control state: clock is required")
	ErrMissingEntropy       = errors.New("control state: entropy is required")
	ErrEntropyExhausted     = errors.New("control state: failed to generate a non-zero unique value")
	ErrLocalExchangeBackoff = errors.New("control state: local exchange retry is backed off")
)

// Clock supplies monotonic time to rate-limited state transitions.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Entropy supplies random control epochs and data session IDs. Implementations
// must be safe for the single goroutine that owns State.
type Entropy interface {
	Uint64() (uint64, error)
}

// EntropyFunc adapts a function to Entropy.
type EntropyFunc func() (uint64, error)

func (f EntropyFunc) Uint64() (uint64, error) { return f() }

// Config contains local capabilities and injected dependencies.
// MinCarrierPayload is the locally configured BASE and must be at least 613;
// MaxCarrierPayload must fit the 16-bit IPv6 payload-length field.
type Config struct {
	MaxCarrierPayload    uint32
	MinCarrierPayload    uint32
	SupportedFeatureBits uint64
	RequiredFeatureBits  uint64
	ReassemblyLifetimeMs uint32
	LocalPeerMTU         uint32
	StateSyncMinInterval time.Duration
	Clock                Clock
	Entropy              Entropy
}

// Flags represent independently confirmed prerequisites for outbound DATA.
type Flags uint16

// Status is the externally observable CONTROL path state.  The values are
// deliberately stable strings so adapters can expose them without mapping a
// wire enum or introducing another CONTROL message.
type Status string

const (
	StatusStarting       Status = "STARTING"
	StatusBase           Status = "BASE"
	StatusSearching      Status = "SEARCHING"
	StatusSearchComplete Status = "SEARCH_COMPLETE"
	StatusError          Status = "ERROR"
)

const (
	FlagLocalCapabilities Flags = 1 << iota
	FlagRemoteCapabilities
	FlagLocalResetAck
	FlagLocalPeerMTUAck
	FlagRemotePeerMTU
	FlagPingPong
	FlagBaseProbe

	RequiredFlags = FlagLocalCapabilities |
		FlagRemoteCapabilities |
		FlagLocalResetAck |
		FlagLocalPeerMTUAck |
		FlagRemotePeerMTU |
		FlagPingPong |
		FlagBaseProbe
)

// LocalExchange identifies a newly started local send-direction exchange.
type LocalExchange struct {
	ControlEpoch  uint64
	DataSessionID uint16
}

// LocalExchangeRetry is the result of restarting a rejected local exchange.
// The new exchange is installed immediately, while RetryAt is the earliest
// time the owner may send its first Hello. RetryAfter uses full jitter between
// one nanosecond and the exponential cap; the owner may wait longer.
type LocalExchangeRetry struct {
	LocalExchange

	RetryAt    time.Time
	RetryAfter time.Duration
}

// CapabilityDecision is the response to a remote CapabilitiesHello.
type CapabilityDecision struct {
	Result                      wirev1.ResultCode
	SelectedDataProtocolVersion uint32
	SelectedFeatureBits         uint64
	SelectedCarrierPayload      uint32
	StartReverseExchange        bool
}

// ResetDecision describes whether a remote send-direction data session was
// accepted and whether receive-side packet state must be purged.
type ResetDecision struct {
	Result         wirev1.ResultCode
	DataSessionID  uint16
	SessionChanged bool
}

// SessionDecision is a hot-path decision for an authenticated DATA record.
// It contains enough information for the caller to populate a preallocated
// wirev1.StateSyncRequired without allocating.
type SessionDecision struct {
	Accept                bool
	SendStateSyncRequired bool
	Reason                wirev1.StateSyncRequired_Reason
	ObservedSessionID     uint32
}

// PopulateStateSyncRequired writes the decision into dst. It returns false if
// no synchronization message should be sent.
func (d SessionDecision) PopulateStateSyncRequired(dst *wirev1.StateSyncRequired) bool {
	if !d.SendStateSyncRequired || dst == nil {
		return false
	}
	dst.SetReason(d.Reason)
	dst.SetObservedDataSessionId(d.ObservedSessionID)
	return true
}

// State owns capability/session gate state for one peer. It intentionally has
// no mutex: exactly one goroutine must own and mutate it.
type State struct {
	config Config
	flags  Flags

	localEpoch      uint64
	remoteEpoch     uint64
	localSessionID  uint16
	remoteSessionID uint16
	// retiredSessions never evicts an unexpired ID. Its fixed capacity covers
	// the ingress rate limit for the configured reassembly lifetime.
	retiredSessions      *expirySet[uint16]
	localRetiredSessions *expirySet[uint16]
	retiredEpochs        *expirySet[uint64]

	remoteSelectedFeatures     uint64
	remoteMaxCarrierPayload    uint32
	remoteReassemblyLifetimeMs uint32
	remotePeerMTU              uint32

	pendingCapabilitiesAck  bool
	pendingSelectedFeatures uint64

	lastStateSync time.Time
	stateSyncSent bool

	localExchangeRetryAt      time.Time
	localExchangeRetryAttempt uint
}

// New validates local invariants and returns an empty fail-closed State.
func New(config Config) (*State, error) {
	if config.Clock == nil {
		return nil, ErrMissingClock
	}
	if config.Entropy == nil {
		return nil, ErrMissingEntropy
	}
	if config.MinCarrierPayload < limits.DefaultCarrierPayload ||
		config.MaxCarrierPayload < config.MinCarrierPayload ||
		config.MaxCarrierPayload > maxCarrierPayload ||
		config.ReassemblyLifetimeMs < MinReassemblyLifetimeMs ||
		config.ReassemblyLifetimeMs > MaxReassemblyLifetimeMs ||
		config.LocalPeerMTU < limits.MinInnerMTU ||
		config.LocalPeerMTU > limits.MaxInnerMTU ||
		config.RequiredFeatureBits&^config.SupportedFeatureBits != 0 ||
		config.StateSyncMinInterval <= 0 {
		return nil, fmt.Errorf("%w: local capability values are outside v1 bounds", ErrInvalidConfig)
	}
	return &State{
		config:               config,
		retiredSessions:      newExpirySet[uint16](maxRetiredSessionEntries),
		localRetiredSessions: newExpirySet[uint16](maxRetiredSessionEntries),
		retiredEpochs:        newExpirySet[uint64](maxRetiredEpochEntries),
	}, nil
}

// BeginLocalExchange starts a new local send-direction exchange using injected
// entropy. It preserves an already accepted remote Hello/PeerMTU, allowing a
// received Hello to trigger the reverse exchange without discarding it.
func (s *State) BeginLocalExchange() (LocalExchange, error) {
	now := s.config.Clock.Now()
	if !s.localExchangeRetryAt.IsZero() && now.Before(s.localExchangeRetryAt) {
		return LocalExchange{}, ErrLocalExchangeBackoff
	}
	s.pruneRetired(now)
	if s.localSessionID != 0 && !s.localRetiredSessions.contains(s.localSessionID) && s.localRetiredSessions.full() {
		return LocalExchange{}, ErrEntropyExhausted
	}
	epoch, err := s.nextNonZero(s.localEpoch, false)
	if err != nil {
		return LocalExchange{}, err
	}
	session, err := s.nextNonZero(uint64(s.localSessionID), true)
	if err != nil {
		return LocalExchange{}, err
	}

	if s.localSessionID != 0 {
		if !s.retainLocal(s.localSessionID, now.Add(s.localSessionLifetime())) {
			return LocalExchange{}, ErrEntropyExhausted
		}
	}
	s.localEpoch = epoch
	s.localSessionID = uint16(session)
	s.flags &^= FlagLocalCapabilities | FlagLocalResetAck | FlagLocalPeerMTUAck | FlagPingPong | FlagBaseProbe
	s.pendingCapabilitiesAck = false
	s.pendingSelectedFeatures = 0
	return LocalExchange{ControlEpoch: epoch, DataSessionID: uint16(session)}, nil
}

// RestartLocalExchange rotates the local epoch and session after a rejected
// CONTROL exchange. It returns a full-jitter retry deadline so callers do not
// immediately repeat a collision with the same peer state. A call before the
// deadline returns ErrLocalExchangeBackoff and leaves the current exchange
// unchanged. The returned exchange is already installed in State.
func (s *State) RestartLocalExchange() (LocalExchangeRetry, error) {
	now := s.config.Clock.Now()
	if !s.localExchangeRetryAt.IsZero() && now.Before(s.localExchangeRetryAt) {
		return LocalExchangeRetry{
			LocalExchange: s.LocalExchangeID(),
			RetryAt:       s.localExchangeRetryAt,
			RetryAfter:    s.localExchangeRetryAt.Sub(now),
		}, ErrLocalExchangeBackoff
	}

	exchange, err := s.BeginLocalExchange()
	if err != nil {
		return LocalExchangeRetry{}, err
	}
	backoff := s.localExchangeBackoff(s.localExchangeRetryAttempt)
	s.localExchangeRetryAttempt++
	s.localExchangeRetryAt = now.Add(backoff)
	return LocalExchangeRetry{
		LocalExchange: exchange,
		RetryAt:       s.localExchangeRetryAt,
		RetryAfter:    backoff,
	}, nil
}

// LocalExchangeRetryReady reports whether a restarted exchange may send its
// first Hello. It is false while the state-enforced deadline is active.
func (s *State) LocalExchangeRetryReady() bool {
	return s.localExchangeRetryAt.IsZero() || !s.config.Clock.Now().Before(s.localExchangeRetryAt)
}

// LocalExchangeRetryAt returns the deadline installed by the most recent
// RestartLocalExchange call, or the zero time when none is pending.
func (s *State) LocalExchangeRetryAt() time.Time { return s.localExchangeRetryAt }

func (s *State) localExchangeBackoff(attempt uint) time.Duration {
	delay := InitialLocalExchangeBackoff
	for i := uint(0); i < attempt && delay < MaxLocalExchangeBackoff; i++ {
		delay *= 2
	}
	if delay > MaxLocalExchangeBackoff {
		delay = MaxLocalExchangeBackoff
	}
	random, err := s.config.Entropy.Uint64()
	if err != nil {
		return delay
	}
	return time.Duration(random%uint64(delay)) + time.Nanosecond
}

// LocalCapabilities returns the local v1 capability advertisement by value.
func (s *State) LocalCapabilities() wirev1.CapabilitiesHello {
	version := DataProtocolVersion
	fragments := uint32(limits.MaxFragments)
	maxPayload := s.config.MaxCarrierPayload
	supported := s.config.SupportedFeatureBits
	required := s.config.RequiredFeatureBits
	lifetime := s.config.ReassemblyLifetimeMs
	return *wirev1.CapabilitiesHello_builder{
		DataProtocolVersion:  &version,
		MaxFragments:         &fragments,
		MaxCarrierPayload:    &maxPayload,
		SupportedFeatureBits: &supported,
		RequiredFeatureBits:  &required,
		ReassemblyLifetimeMs: &lifetime,
	}.Build()
}

// LocalPeerMTU returns the local receive MTU advertisement by value.
func (s *State) LocalPeerMTU() wirev1.PeerMTU {
	mtu := s.config.LocalPeerMTU
	return *wirev1.PeerMTU_builder{InnerMtu: &mtu}.Build()
}

// ReadyFlags returns the currently satisfied outbound DATA prerequisites.
func (s *State) ReadyFlags() Flags { return s.flags }

// MissingFlags returns the prerequisites that still fail closed.
func (s *State) MissingFlags() Flags { return RequiredFlags &^ s.flags }

// DataSendAllowed reports whether every required v1 gate is satisfied.
func (s *State) DataSendAllowed() bool { return s.flags&RequiredFlags == RequiredFlags }

// ResetPathGates clears the reachability and BASE gates, closing DATA until
// both succeed again. A black hole invalidates what they proved, so continuing
// to send at any size would keep feeding a path that discards it.
func (s *State) ResetPathGates() {
	s.flags &^= FlagPingPong | FlagBaseProbe
}

// LocalExchangeID returns the current local epoch and data session ID.
func (s *State) LocalExchangeID() LocalExchange {
	return LocalExchange{ControlEpoch: s.localEpoch, DataSessionID: s.localSessionID}
}

// IsRemoteEpochRetired reports whether a delayed Hello belongs to a previous
// remote process epoch. Callers may use it to drop the frame before normal
// CONTROL dispatch; ObserveCapabilitiesHello performs the same check.
func (s *State) IsRemoteEpochRetired(epoch uint64) bool {
	if epoch == 0 {
		return false
	}
	now := s.config.Clock.Now()
	s.retiredEpochs.prune(now)
	return s.retiredEpochs.contains(epoch)
}

// RemotePeerMTU returns the validated remote receive MTU, or zero before the
// remote PeerMTU exchange completes.
func (s *State) RemotePeerMTU() uint32 { return s.remotePeerMTU }

// RemoteReassemblyLifetimeMs returns the peer's advertised reassembly
// lifetime, or zero before the remote CapabilitiesHello has been accepted.
func (s *State) RemoteReassemblyLifetimeMs() uint32 { return s.remoteReassemblyLifetimeMs }

// NegotiatedCarrierPayload returns the largest carrier payload accepted by
// both peers. It is zero until the remote CapabilitiesHello has been
// accepted. The value is a ceiling for the local send-direction DPLPMTUD
// search; the active DATA payload may remain lower while a search runs.
func (s *State) NegotiatedCarrierPayload() uint32 {
	if s.remoteMaxCarrierPayload == 0 || s.flags&FlagRemoteCapabilities == 0 {
		return 0
	}
	return min(s.config.MaxCarrierPayload, s.remoteMaxCarrierPayload)
}

// LocalMaxCarrierPayload returns the configured local capability ceiling.
func (s *State) LocalMaxCarrierPayload() uint32 { return s.config.MaxCarrierPayload }

// RemoteDataSessionID returns the currently accepted peer send-direction
// session, or zero until ResetSequence has been accepted. The local
// send-direction session is returned by LocalExchangeID.
func (s *State) RemoteDataSessionID() uint16 { return s.remoteSessionID }

// ObserveCapabilitiesHello validates and records a remote Hello. A new remote
// epoch invalidates acknowledgments and path gates from the previous epoch.
func (s *State) ObserveCapabilitiesHello(control *wirev1.Control) CapabilityDecision {
	decision := CapabilityDecision{Result: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER}
	hello := control.GetCapabilitiesHello()
	if !validRequest(control) || hello == nil || len(control.GetPadding()) != 0 {
		return decision
	}

	decision = ValidateCapabilities(s.config, hello)
	if decision.Result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		return decision
	}

	now := s.config.Clock.Now()
	s.pruneRetired(now)
	startReverseExchange := s.localEpoch == 0
	if s.remoteEpoch != 0 && s.remoteEpoch != control.GetControlEpoch() {
		if s.retiredEpochs.contains(control.GetControlEpoch()) || s.retiredEpochs.full() ||
			(s.remoteSessionID != 0 && !s.retiredSessions.contains(s.remoteSessionID) && s.retiredSessions.full()) {
			return CapabilityDecision{Result: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER}
		}
		if !s.clearRemoteEpoch(now) {
			return CapabilityDecision{Result: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER}
		}
		startReverseExchange = true
	}
	s.remoteEpoch = control.GetControlEpoch()
	s.remoteSelectedFeatures = decision.SelectedFeatureBits
	s.remoteMaxCarrierPayload = hello.GetMaxCarrierPayload()
	s.remoteReassemblyLifetimeMs = hello.GetReassemblyLifetimeMs()
	s.flags |= FlagRemoteCapabilities
	s.reconcileCapabilitiesAck()
	decision.StartReverseExchange = startReverseExchange
	return decision
}

// ObserveCapabilitiesAck validates a reply to the local Hello. It is not
// considered complete until the peer's independently epoch'd Hello is also
// valid and both messages select the same feature set.
func (s *State) ObserveCapabilitiesAck(control *wirev1.Control, expectedReplyTo uint64) wirev1.ResultCode {
	ack := control.GetCapabilitiesAck()
	if ack == nil || len(control.GetPadding()) != 0 || !s.validResponse(control, expectedReplyTo) {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	if ack.GetResult() != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		s.flags &^= FlagLocalCapabilities
		return ack.GetResult()
	}
	if ack.GetSelectedDataProtocolVersion() != DataProtocolVersion ||
		ack.GetSelectedFeatureBits()&^s.config.SupportedFeatureBits != 0 ||
		s.config.RequiredFeatureBits&^ack.GetSelectedFeatureBits() != 0 {
		s.flags &^= FlagLocalCapabilities
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}

	s.pendingCapabilitiesAck = true
	s.pendingSelectedFeatures = ack.GetSelectedFeatureBits()
	s.reconcileCapabilitiesAck()
	if s.flags&FlagRemoteCapabilities != 0 && s.flags&FlagLocalCapabilities == 0 {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

// ObserveResetSequence validates and installs a remote send-direction session.
func (s *State) ObserveResetSequence(control *wirev1.Control) ResetDecision {
	decision := ResetDecision{Result: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER}
	reset := control.GetResetSequence()
	if !s.validRemoteRequest(control) || reset == nil || len(control.GetPadding()) != 0 {
		return decision
	}
	if ValidateDataSessionID(reset.GetDataSessionId()) != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		return decision
	}

	session := uint16(reset.GetDataSessionId())
	now := s.config.Clock.Now()
	s.pruneRetired(now)
	if s.remoteSessionID != 0 && s.remoteSessionID == session {
		return ResetDecision{
			Result:        wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION,
			DataSessionID: session,
		}
	}
	if s.isRetired(session) {
		return ResetDecision{
			Result:        wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION,
			DataSessionID: session,
		}
	}
	if s.remoteSessionID != 0 {
		if !s.retiredSessions.contains(s.remoteSessionID) && s.retiredSessions.full() {
			// Never evict a live reassembly ID just to admit a new session. The
			// sender can retry with another random ID after the lifetime expires.
			return ResetDecision{
				Result:        wirev1.ResultCode_RESULT_CODE_SESSION_COLLISION,
				DataSessionID: session,
			}
		}
	}
	decision = ResetDecision{
		Result:         wirev1.ResultCode_RESULT_CODE_ACCEPTED,
		DataSessionID:  session,
		SessionChanged: s.remoteSessionID != session,
	}
	if s.remoteSessionID != 0 {
		s.retainRetired(s.remoteSessionID, now.Add(time.Duration(s.config.ReassemblyLifetimeMs)*time.Millisecond))
	}
	s.remoteSessionID = session
	return decision
}

// ObserveResetSequenceAck validates a reply for the current local session.
func (s *State) ObserveResetSequenceAck(control *wirev1.Control, expectedReplyTo uint64) wirev1.ResultCode {
	ack := control.GetResetSequenceAck()
	if ack == nil || len(control.GetPadding()) != 0 || !s.validResponse(control, expectedReplyTo) {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	if ack.GetResult() != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		s.flags &^= FlagLocalResetAck
		return ack.GetResult()
	}
	if ValidateDataSessionID(ack.GetDataSessionId()) != wirev1.ResultCode_RESULT_CODE_ACCEPTED ||
		uint16(ack.GetDataSessionId()) != s.localSessionID {
		s.flags &^= FlagLocalResetAck
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	s.flags |= FlagLocalResetAck
	s.localExchangeRetryAt = time.Time{}
	s.localExchangeRetryAttempt = 0
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

// ObservePeerMTU validates and records the remote receive MTU.
func (s *State) ObservePeerMTU(control *wirev1.Control) wirev1.ResultCode {
	peerMTU := control.GetPeerMtu()
	if !s.validRemoteRequest(control) || peerMTU == nil || len(control.GetPadding()) != 0 {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	result := ValidatePeerMTU(peerMTU)
	if result != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		return result
	}
	s.remotePeerMTU = peerMTU.GetInnerMtu()
	s.flags |= FlagRemotePeerMTU
	return result
}

// ObservePeerMTUAck validates a reply to the local receive MTU advertisement.
func (s *State) ObservePeerMTUAck(control *wirev1.Control, expectedReplyTo uint64) wirev1.ResultCode {
	ack := control.GetPeerMtuAck()
	if ack == nil || len(control.GetPadding()) != 0 || !s.validResponse(control, expectedReplyTo) {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	if ack.GetResult() != wirev1.ResultCode_RESULT_CODE_ACCEPTED {
		s.flags &^= FlagLocalPeerMTUAck
		return ack.GetResult()
	}
	if validatePeerMTUValue(ack.GetInnerMtu()) != wirev1.ResultCode_RESULT_CODE_ACCEPTED ||
		ack.GetInnerMtu() != s.config.LocalPeerMTU {
		s.flags &^= FlagLocalPeerMTUAck
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	s.flags |= FlagLocalPeerMTUAck
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

// ObservePong confirms the minimum-size Ping/Pong gate.
func (s *State) ObservePong(
	control *wirev1.Control,
	expectedReplyTo uint64,
	expectedSequence uint32,
) wirev1.ResultCode {
	pong := control.GetPong()
	if pong == nil || len(control.GetPadding()) != 0 ||
		!s.validResponse(control, expectedReplyTo) ||
		pong.GetSequence() != expectedSequence {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	s.flags |= FlagPingPong
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

// ObserveBaseProbeAck confirms the BASE carrier payload gate.
func (s *State) ObserveBaseProbeAck(control *wirev1.Control, expectedReplyTo uint64) wirev1.ResultCode {
	ack := control.GetMtuProbeAck()
	if ack == nil || len(control.GetPadding()) != 0 ||
		!s.validResponse(control, expectedReplyTo) ||
		ack.GetReceivedProbePayloadSize() != s.config.MinCarrierPayload {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	s.flags |= FlagBaseProbe
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

// CheckInboundDataSession makes a zero-allocation hot-path admission decision.
// Unknown/noncurrent sessions are dropped and request a rate-limited state sync.
func (s *State) CheckInboundDataSession(dataSessionID uint16) SessionDecision {
	if dataSessionID != 0 && dataSessionID == s.remoteSessionID {
		return SessionDecision{Accept: true}
	}
	// Session zero is invalid on the wire rather than an unknown valid session.
	// The DATA decoder should reject it before this point; fail closed without
	// emitting another invalid session ID in StateSyncRequired.
	if dataSessionID == 0 {
		return SessionDecision{}
	}

	now := s.config.Clock.Now()
	sendSync := !s.stateSyncSent || !now.Before(s.lastStateSync.Add(s.config.StateSyncMinInterval))
	if sendSync {
		s.lastStateSync = now
		s.stateSyncSent = true
	}
	return SessionDecision{
		SendStateSyncRequired: sendSync,
		Reason:                wirev1.StateSyncRequired_REASON_UNKNOWN_DATA_SESSION,
		ObservedSessionID:     uint32(dataSessionID),
	}
}

// ObserveStateSyncRequired validates a remote resynchronization request for
// the current local DATA session and clears only local outbound readiness. The
// peer's independent inbound session remains valid. The caller should invoke
// BeginLocalExchange and restart with a new Hello.
func (s *State) ObserveStateSyncRequired(control *wirev1.Control) wirev1.ResultCode {
	sync := control.GetStateSyncRequired()
	if sync == nil || len(control.GetPadding()) != 0 || !s.validRemoteRequest(control) ||
		sync.GetReason() != wirev1.StateSyncRequired_REASON_UNKNOWN_DATA_SESSION ||
		ValidateDataSessionID(sync.GetObservedDataSessionId()) != wirev1.ResultCode_RESULT_CODE_ACCEPTED ||
		uint16(sync.GetObservedDataSessionId()) != s.localSessionID {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	s.flags &^= FlagLocalCapabilities | FlagLocalResetAck | FlagLocalPeerMTUAck | FlagPingPong | FlagBaseProbe
	s.pendingCapabilitiesAck = false
	s.pendingSelectedFeatures = 0
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

// ValidateCapabilities applies exact v1 capability and feature rules.
func ValidateCapabilities(local Config, remote *wirev1.CapabilitiesHello) CapabilityDecision {
	decision := CapabilityDecision{Result: wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER}
	if remote == nil {
		return decision
	}
	if remote.GetDataProtocolVersion() != DataProtocolVersion {
		decision.Result = wirev1.ResultCode_RESULT_CODE_INCOMPATIBLE_VERSION
		return decision
	}
	if remote.GetMaxFragments() != uint32(limits.MaxFragments) ||
		remote.GetMaxCarrierPayload() < limits.DefaultCarrierPayload ||
		remote.GetMaxCarrierPayload() < local.MinCarrierPayload ||
		remote.GetMaxCarrierPayload() > maxCarrierPayload ||
		remote.GetReassemblyLifetimeMs() < MinReassemblyLifetimeMs ||
		remote.GetReassemblyLifetimeMs() > MaxReassemblyLifetimeMs {
		return decision
	}
	if local.RequiredFeatureBits&^remote.GetSupportedFeatureBits() != 0 ||
		remote.GetRequiredFeatureBits()&^local.SupportedFeatureBits != 0 {
		decision.Result = wirev1.ResultCode_RESULT_CODE_MISSING_REQUIRED_FEATURE
		return decision
	}
	decision.Result = wirev1.ResultCode_RESULT_CODE_ACCEPTED
	decision.SelectedDataProtocolVersion = DataProtocolVersion
	decision.SelectedFeatureBits = local.SupportedFeatureBits & remote.GetSupportedFeatureBits()
	decision.SelectedCarrierPayload = min(local.MaxCarrierPayload, remote.GetMaxCarrierPayload())
	return decision
}

// ValidatePeerMTU applies the v1 receive MTU range.
func ValidatePeerMTU(peerMTU *wirev1.PeerMTU) wirev1.ResultCode {
	if peerMTU == nil {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	return validatePeerMTUValue(peerMTU.GetInnerMtu())
}

func validatePeerMTUValue(innerMTU uint32) wirev1.ResultCode {
	if innerMTU < uint32(limits.MinInnerMTU) || innerMTU > uint32(limits.MaxInnerMTU) {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

// ValidateDataSessionID applies the 16-bit, non-zero wire range.
func ValidateDataSessionID(dataSessionID uint32) wirev1.ResultCode {
	if dataSessionID == 0 || dataSessionID > 1<<16-1 {
		return wirev1.ResultCode_RESULT_CODE_INVALID_PARAMETER
	}
	return wirev1.ResultCode_RESULT_CODE_ACCEPTED
}

func (s *State) validResponse(control *wirev1.Control, expectedReplyTo uint64) bool {
	// A response echoes the request's epoch. Therefore it must match our local
	// send-direction epoch, not the peer's independent request epoch.
	return control != nil &&
		control.GetMessageId() != 0 &&
		expectedReplyTo != 0 &&
		control.GetReplyTo() == expectedReplyTo &&
		s.localEpoch != 0 &&
		control.GetControlEpoch() == s.localEpoch
}

func (s *State) validRemoteRequest(control *wirev1.Control) bool {
	return validRequest(control) && s.flags&FlagRemoteCapabilities != 0 && control.GetControlEpoch() == s.remoteEpoch
}

func validRequest(control *wirev1.Control) bool {
	return control != nil && control.GetMessageId() != 0 && control.GetReplyTo() == 0 && control.GetControlEpoch() != 0
}

func (s *State) reconcileCapabilitiesAck() {
	s.flags &^= FlagLocalCapabilities
	if !s.pendingCapabilitiesAck || s.flags&FlagRemoteCapabilities == 0 {
		return
	}
	if s.pendingSelectedFeatures == s.remoteSelectedFeatures {
		s.flags |= FlagLocalCapabilities
	}
}

func (s *State) clearRemoteEpoch(now time.Time) bool {
	if s.remoteEpoch != 0 && !s.retiredEpochs.retain(s.remoteEpoch, now.Add(retiredEpochLifetime)) {
		return false
	}
	if s.remoteSessionID != 0 {
		if !s.retainRetired(s.remoteSessionID, now.Add(time.Duration(s.config.ReassemblyLifetimeMs)*time.Millisecond)) {
			return false
		}
	}
	s.flags = 0
	s.remoteSessionID = 0
	s.remotePeerMTU = 0
	s.remoteSelectedFeatures = 0
	s.remoteMaxCarrierPayload = 0
	s.remoteReassemblyLifetimeMs = 0
	s.pendingCapabilitiesAck = false
	s.pendingSelectedFeatures = 0
	return true
}

func (s *State) pruneRetired(now time.Time) {
	s.retiredSessions.prune(now)
	s.localRetiredSessions.prune(now)
	s.retiredEpochs.prune(now)
}

func (s *State) isRetired(session uint16) bool {
	return s.retiredSessions.contains(session)
}

func (s *State) retainRetired(session uint16, expires time.Time) bool {
	if session == 0 {
		return true
	}
	return s.retiredSessions.retain(session, expires)
}

func (s *State) retainLocal(session uint16, expires time.Time) bool {
	if session == 0 {
		return true
	}
	return s.localRetiredSessions.retain(session, expires)
}

func (s *State) localSessionLifetime() time.Duration {
	lifetime := s.config.ReassemblyLifetimeMs
	if s.remoteReassemblyLifetimeMs > lifetime {
		lifetime = s.remoteReassemblyLifetimeMs
	}
	return time.Duration(lifetime) * time.Millisecond
}

func (s *State) nextNonZero(previous uint64, session bool) (uint64, error) {
	for range 16 {
		value, err := s.config.Entropy.Uint64()
		if err != nil {
			return 0, err
		}
		if session {
			value &= 1<<16 - 1
		}
		if value != 0 && value != previous {
			if session && s.localRetiredSessions.contains(uint16(value)) {
				continue
			}
			return value, nil
		}
	}
	return 0, ErrEntropyExhausted
}
