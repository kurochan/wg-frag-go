package pmtu

import (
	"errors"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

var ErrInvalidConfig = errors.New("pmtu: invalid config")

// ConfirmationFailureLimit is the consecutive confirmation timeout threshold.
// One loss must not shrink a working ceiling.
const ConfirmationFailureLimit = 3

// SearchAttemptLimit is the timeout retry count for one candidate.
const SearchAttemptLimit = 3

const minimumProbeTimeout = 100 * time.Millisecond

// Config bounds a single peer direction. Ceiling is the smaller of the local
// and remote advertised maximum carrier payloads. Canonicalize optionally
// maps a logical candidate to the transport's representable candidate; nil
// uses identity. ProbeTimeout is the fallback used until a control RTT sample
// is available; after that, the timeout is max(100ms, 4*SRTT).
// RefreshInterval is normally ten minutes.
type Config struct {
	Base            uint32
	Ceiling         uint32
	Canonicalize    func(uint32) uint32
	ProbeTimeout    time.Duration
	RefreshInterval time.Duration
	// ConfirmationInterval paces probes that re-verify the confirmed size.
	ConfirmationInterval time.Duration
}

// Probe identifies one logical carrier-payload candidate. Framing and padding
// are transport concerns handled by the caller's canonicalization strategy.
type Probe struct {
	Attempt     uint64
	PayloadSize uint32
}

// Outstanding returns the currently transmitted probe, if any. The caller
// may use it to report a synchronous send failure such as EMSGSIZE without
// having to retain any pmtu implementation details.
func (s *State) Outstanding() (Probe, bool) {
	if !s.inFlight {
		return Probe{}, false
	}
	return Probe{Attempt: s.attempt, PayloadSize: s.candidate}, true
}

// AdjustCurrent records the complete CONTROL frame size that was actually
// emitted for the in-flight candidate.  Protobuf length varints can make an
// exact requested size impossible; the control-plane builder then emits the
// greatest representable size below that request and must update PMTUD's
// correlation value before accepting an ACK.
func (s *State) AdjustCurrent(attempt uint64, payloadSize uint32) bool {
	if !s.inFlight || attempt != s.attempt || payloadSize < s.config.Base || payloadSize > s.config.Ceiling {
		return false
	}
	s.candidate = payloadSize
	return true
}

// State owns one direction's DPLPMTUD search. It is single-owner. CONTROL
// message IDs and padding construction remain in the control-plane adapter;
// Attempt is only a local correlation token.
type State struct {
	config       Config
	canonicalize func(uint32) uint32

	confirmed uint32
	low       uint32
	bad       uint32 // first known failing size; zero until one is observed
	candidate uint32

	rounds  [3]uint32
	results int

	attempt     uint64
	inFlight    bool
	pending     bool
	deadline    time.Time
	nextRefresh time.Time

	candidateTries        int
	confirming            bool
	refreshing            bool
	confirmationCandidate uint32
	confirmFailures       int
	nextConfirmation      time.Time
	blackholed            bool
	srtt                  time.Duration
}

// New returns a conservative state. BASE is immediately usable; callers only
// call Start after the CONTROL Ping/Pong and BASE probe gates are confirmed.
func New(config Config) (*State, error) {
	if config.Base < limits.DefaultCarrierPayload || config.Ceiling < config.Base ||
		config.ProbeTimeout < minimumProbeTimeout || config.RefreshInterval <= 0 ||
		config.ConfirmationInterval <= 0 {
		return nil, ErrInvalidConfig
	}
	canonicalize := config.Canonicalize
	if canonicalize == nil {
		canonicalize = identity
	}
	return &State{config: config, canonicalize: canonicalize, confirmed: config.Base}, nil
}

// Confirmed returns the non-fragmenting carrier payload used for DATA. It is
// never reduced below BASE and remains usable while a refresh is in progress.
func (s *State) Confirmed() uint32 { return s.confirmed }

// Searching reports whether a probe is awaiting a result or ready to send.
func (s *State) Searching() bool { return s.pending || s.inFlight }

// Start begins a fresh two-pass search. If the two results disagree, a third
// pass runs and the median is selected. Calling Start while a search runs
// restarts it from BASE; traffic remains on the existing confirmed ceiling.
func (s *State) Start(now time.Time) {
	s.start(now, false)
}

func (s *State) start(now time.Time, refreshing bool) {
	s.results = 0
	s.confirming = false
	s.refreshing = refreshing
	s.confirmationCandidate = 0
	s.confirmFailures = 0
	s.nextConfirmation = time.Time{}
	// There is no exploratory candidate when the negotiated ceiling equals
	// BASE. Keep the state idle and schedule the normal raise refresh instead
	// of recursively opening empty rounds.
	if s.config.Ceiling == s.config.Base {
		s.confirmed = s.config.Base
		s.pending = false
		s.inFlight = false
		s.nextRefresh = now.Add(s.config.RefreshInterval)
		s.nextConfirmation = now.Add(s.config.ConfirmationInterval)
		return
	}

	s.beginRound(now)
}

// RefreshDue starts the periodic non-blocking re-exploration when due. It
// returns true only when it actually changed state.
func (s *State) RefreshDue(now time.Time) bool {
	if s.Searching() || s.nextRefresh.IsZero() || now.Before(s.nextRefresh) {
		return false
	}

	s.start(now, true)
	return true
}

// ConfirmationDue arms a probe when the pacing interval has elapsed.
func (s *State) ConfirmationDue(now time.Time) bool {
	if s.Searching() || s.nextConfirmation.IsZero() || now.Before(s.nextConfirmation) {
		return false
	}
	s.confirming = true
	s.confirmationCandidate = 0
	s.candidate = s.confirmed
	s.candidateTries = 0
	s.pending = true
	return true
}

// Confirming reports whether the outstanding probe is a confirmation.
func (s *State) Confirming() bool { return s.confirming }

// Next returns one unsent probe. It must be called by the CONTROL sender; the
// returned attempt is required when acknowledging or timing out that probe.
func (s *State) Next(now time.Time) (Probe, bool) {
	if !s.pending {
		return Probe{}, false
	}
	s.pending = false
	s.inFlight = true
	s.attempt++
	s.candidateTries++
	s.deadline = now.Add(s.probeTimeout())
	return Probe{Attempt: s.attempt, PayloadSize: s.candidate}, true
}

// Acknowledge records a matching MtuProbeAck. The adapter must verify that
// receivedPayloadSize equals the probe's intended payload before calling it.
func (s *State) Acknowledge(attempt uint64, payloadSize uint32, now time.Time) bool {
	if !s.inFlight || attempt != s.attempt || payloadSize != s.candidate {
		return false
	}
	s.inFlight = false
	if s.confirming {
		s.confirmSuccess(now)
		return true
	}

	s.success(now)
	return true
}

// Fail records a matching timeout or EMSGSIZE for the outstanding probe.
func (s *State) Fail(attempt uint64, now time.Time) bool {
	if !s.inFlight || attempt != s.attempt {
		return false
	}
	s.inFlight = false
	if s.confirming {
		s.confirmFailure(now)
		return true
	}
	// A reported failure is local proof that the size is wrong, so unlike a
	// timeout it needs no repetition.
	s.failure(now, true)
	return true
}

// FailCurrent records a synchronous send failure for the outstanding probe.
// It is equivalent to Fail with the current attempt token and returns false
// when no probe is in flight.
func (s *State) FailCurrent(now time.Time) bool {
	if !s.inFlight {
		return false
	}
	return s.Fail(s.attempt, now)
}

// SoftFailCurrent retries the current probe when a stashed EMSGSIZE cannot be
// attributed to it, instead of treating the candidate as definitively bad.
func (s *State) SoftFailCurrent(now time.Time) bool {
	if !s.inFlight {
		return false
	}
	s.inFlight = false
	if s.confirming {
		s.confirmFailure(now)
		return true
	}

	s.failure(now, false)
	return true
}

// Tick turns an overdue outstanding probe into a failed one.
func (s *State) Tick(now time.Time) bool {
	if !s.inFlight || now.Before(s.deadline) {
		return false
	}
	s.inFlight = false
	if s.confirming {
		s.confirmFailure(now)
		return true
	}

	s.failure(now, false)
	return true
}

// ReportBlackhole handles a DATA-path EMSGSIZE or authenticated black-hole
// signal. It immediately returns DATA to BASE and begins a new search without
// blocking traffic.
func (s *State) ReportBlackhole(now time.Time) {
	s.confirmed = s.config.Base
	s.Start(now)
}

// ObserveRTT feeds a control round-trip sample into the probe timeout.
func (s *State) ObserveRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if s.srtt == 0 {
		s.srtt = sample
		return
	}

	s.srtt += (sample - s.srtt) / 8
}

// probeTimeout uses the configured fallback until Ping/Pong supplies an RTT.
// A known RTT gets a small floor to avoid false failures from scheduling and
// queueing jitter on otherwise short paths.
func (s *State) probeTimeout() time.Duration {
	if s.srtt <= 0 {
		return s.config.ProbeTimeout
	}
	const maxDuration = time.Duration(1<<63 - 1)
	if s.srtt > maxDuration/4 {
		return maxDuration
	}
	adaptive := 4 * s.srtt
	if adaptive < minimumProbeTimeout {
		return minimumProbeTimeout
	}
	return adaptive
}

// TakeBlackhole reports and clears a pending confirmation black-hole event.
func (s *State) TakeBlackhole() bool {
	blackholed := s.blackholed
	s.blackholed = false
	return blackholed
}

// NextRefresh returns the next non-blocking raise-search deadline. A zero
// value means that no search has completed yet.
func (s *State) NextRefresh() time.Time { return s.nextRefresh }

func (s *State) confirmSuccess(now time.Time) {
	if s.confirmationCandidate != 0 {
		s.confirmed = s.confirmationCandidate
		s.confirmationCandidate = 0
		s.refreshing = false
		s.confirming = false
		s.pending = false
		s.confirmFailures = 0
		s.nextRefresh = now.Add(s.config.RefreshInterval)
		s.nextConfirmation = now.Add(s.config.ConfirmationInterval)
		return
	}
	s.confirming = false
	s.pending = false
	s.confirmFailures = 0
	s.nextConfirmation = now.Add(s.config.ConfirmationInterval)
}

func (s *State) confirmFailure(now time.Time) {
	if s.confirmationCandidate != 0 {
		s.confirmationCandidate = 0
		s.refreshing = false
		s.confirming = false
		s.pending = false
		s.confirmFailures = 0
		s.nextRefresh = now.Add(s.config.RefreshInterval)
		s.nextConfirmation = now.Add(s.config.ConfirmationInterval)
		return
	}
	s.confirming = false
	s.pending = false
	s.confirmFailures++
	if s.confirmFailures < ConfirmationFailureLimit {
		s.nextConfirmation = now.Add(s.config.ConfirmationInterval)
		return
	}
	s.confirmed = s.config.Base
	s.blackholed = true
	s.Start(now)
}

func (s *State) beginRound(now time.Time) {
	s.low = s.config.Base
	s.bad = 0
	s.candidateTries = 0
	s.candidate = s.nextCandidate()
	s.inFlight = false
	if s.candidate == 0 {
		s.finishRound(now)
		return
	}
	s.pending = true
}

func (s *State) success(now time.Time) {
	s.low = s.candidate
	s.candidateTries = 0
	s.candidate = s.nextCandidate()
	if s.candidate == 0 {
		s.finishRound(now)
		return
	}
	s.pending = true
}

func (s *State) failure(now time.Time, definitive bool) {
	if !definitive && s.candidateTries < SearchAttemptLimit {
		s.pending = true
		return
	}
	s.bad = s.candidate
	s.candidateTries = 0
	s.candidate = s.nextCandidate()
	if s.candidate == 0 {
		s.finishRound(now)
		return
	}
	s.pending = true
}

func (s *State) nextCandidate() uint32 {
	if s.bad != 0 {
		candidate := s.canonicalCandidate(s.low + (s.bad-s.low)/2)
		if candidate <= s.low || candidate >= s.bad {
			return 0
		}
		return candidate
	}
	if s.low >= s.config.Ceiling {
		return 0
	}
	candidate := s.low * 2
	if s.low > s.config.Ceiling/2 {
		candidate = s.config.Ceiling
	}
	if candidate = s.canonicalCandidate(candidate); candidate <= s.low {
		return 0
	}
	return candidate
}

// canonicalCandidate delegates transport-specific candidate representation
// to the injected strategy. The core search otherwise operates on logical
// carrier payload sizes without assuming a framing or padding scheme.
func (s *State) canonicalCandidate(payload uint32) uint32 {
	candidate := s.canonicalize(payload)
	if candidate < s.config.Base || candidate > s.config.Ceiling {
		return 0
	}
	return candidate
}

func identity(payload uint32) uint32 { return payload }

func (s *State) finishRound(now time.Time) {
	s.pending = false
	s.inFlight = false
	s.rounds[s.results] = s.low
	s.results++
	if s.results == 1 {
		s.beginRound(now)
		return
	}
	if s.results == 2 && s.rounds[0] != s.rounds[1] {
		s.beginRound(now)
		return
	}

	var candidate uint32
	if s.results == 2 {
		candidate = s.rounds[0]
	} else {
		candidate = median(s.rounds[0], s.rounds[1], s.rounds[2])
	}
	if candidate > s.confirmed {
		s.confirmationCandidate = candidate
		s.confirming = true
		s.candidate = candidate
		s.candidateTries = 0
		s.pending = true
		return
	}
	s.refreshing = false
	s.nextRefresh = now.Add(s.config.RefreshInterval)
	s.nextConfirmation = now.Add(s.config.ConfirmationInterval)
}

func median(a, b, c uint32) uint32 {
	if a > b {
		a, b = b, a
	}
	if b > c {
		b = c
	}
	if a > b {
		b = a
	}
	return b
}
