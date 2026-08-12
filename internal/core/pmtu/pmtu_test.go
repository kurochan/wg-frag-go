package pmtu

import (
	"testing"
	"time"
)

func TestSearchConvergesAfterTwoMatchingPasses(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 4_000)
	now := time.Unix(1, 0)
	s.Start(now)
	completeSearch(t, s, &now, 2_733)
	if s.Searching() || s.Confirmed() != alignedPayload(2_733) {
		t.Fatalf("searching=%t confirmed=%d", s.Searching(), s.Confirmed())
	}
	if s.RefreshDue(now.Add(9*time.Minute + 59*time.Second)) {
		t.Fatal("refresh started early")
	}
	if !s.RefreshDue(now.Add(10*time.Minute)) || !s.Searching() {
		t.Fatal("refresh did not restart search")
	}
}

func TestInitialSearchPromotesOnlyAfterConfirmation(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 2_000)
	now := time.Unix(1, 0)
	s.Start(now)

	completeSearchUntilConfirmation(t, s, &now, 800)
	if !s.Confirming() || s.Confirmed() != 613 {
		t.Fatalf("confirming=%t confirmed=%d, want confirmation at BASE", s.Confirming(), s.Confirmed())
	}
	probe, ok := s.Next(now)
	if !ok {
		t.Fatal("missing initial confirmation probe")
	}
	if !s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatal("initial confirmation failed")
	}
	if s.Searching() || s.Confirmed() != alignedPayload(800) {
		t.Fatalf("searching=%t confirmed=%d, want confirmed candidate", s.Searching(), s.Confirmed())
	}
}

func TestInitialConfirmationFailureDoesNotBlackhole(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 2_000)
	now := time.Unix(1, 0)
	s.Start(now)
	completeSearchUntilConfirmation(t, s, &now, 800)
	probe, ok := s.Next(now)
	if !ok || !s.Tick(now.Add(2*time.Second)) {
		t.Fatal("initial confirmation did not time out")
	}
	blackhole := s.TakeBlackhole()
	if s.Confirmed() != 613 || blackhole {
		t.Fatalf("confirmed=%d blackhole=%t, want BASE without black-hole", s.Confirmed(), blackhole)
	}
	if s.Searching() || s.NextRefresh().IsZero() {
		t.Fatalf("searching=%t next_refresh=%v, want idle reschedule", s.Searching(), s.NextRefresh())
	}
	if s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatal("timed-out confirmation was accepted")
	}
}

func TestSearchUsesThirdPassMedianWhenPathChanges(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 4_000)
	now := time.Unix(1, 0)
	s.Start(now)
	completeRound(t, s, &now, 2_000)
	completeRound(t, s, &now, 3_000)
	if !s.Searching() {
		t.Fatal("third pass was not started")
	}
	completeRound(t, s, &now, 2_500)
	if !s.Confirming() || s.Confirmed() != 613 {
		t.Fatalf("confirming=%t confirmed=%d, want confirmation at BASE", s.Confirming(), s.Confirmed())
	}
	probe, ok := s.Next(now)
	if !ok || probe.PayloadSize != alignedPayload(2_500) || !s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatalf("initial confirmation probe = %#v ok=%t, want median candidate", probe, ok)
	}
	if s.Confirmed() != alignedPayload(2_500) || s.Searching() {
		t.Fatalf("confirmed=%d searching=%t", s.Confirmed(), s.Searching())
	}
}

func TestRefreshDoesNotLowerConfirmedSize(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 2_000)
	now := time.Unix(1, 0)
	s.Start(now)
	completeSearch(t, s, &now, 1_400)
	confirmed := s.Confirmed()
	if !s.RefreshDue(s.NextRefresh()) {
		t.Fatal("refresh did not start")
	}
	completeSearch(t, s, &now, 800)
	if got := s.Confirmed(); got != confirmed {
		t.Fatalf("refresh lowered confirmed size from %d to %d", confirmed, got)
	}
}

func TestRefreshRaisesOnlyAfterConfirmation(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 2_000)
	now := time.Unix(1, 0)
	s.Start(now)
	completeSearch(t, s, &now, 800)
	confirmed := s.Confirmed()
	if !s.RefreshDue(s.NextRefresh()) {
		t.Fatal("refresh did not start")
	}
	for s.Searching() && !s.confirming {
		completeRound(t, s, &now, 1_400)
	}
	if !s.confirming || s.Confirmed() != confirmed {
		t.Fatalf("refresh promoted before confirmation: confirming=%t confirmed=%d", s.confirming, s.Confirmed())
	}
	probe, ok := s.Next(now)
	if !ok || !s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatal("refresh confirmation failed")
	}
	if s.Confirmed() <= confirmed {
		t.Fatalf("confirmed=%d, want increase above %d", s.Confirmed(), confirmed)
	}
}

func TestTimeoutAndBlackholeFallBackToBase(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 3_000)
	now := time.Unix(1, 0)
	s.Start(now)
	probe, ok := s.Next(now)
	if !ok {
		t.Fatal("missing first probe")
	}
	if !s.Tick(now.Add(2 * time.Second)) {
		t.Fatal("probe did not timeout")
	}
	if s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatal("timed out probe was accepted")
	}
	completeSearch(t, s, &now, 2_000)
	s.ReportBlackhole(now)
	if s.Confirmed() != 613 || !s.Searching() {
		t.Fatalf("confirmed=%d searching=%t", s.Confirmed(), s.Searching())
	}
}

func TestMismatchedAcknowledgementsAreRejected(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 2_000)
	now := time.Unix(1, 0)
	s.Start(now)
	probe, ok := s.Next(now)
	if !ok {
		t.Fatal("missing probe")
	}
	if s.Acknowledge(probe.Attempt+1, probe.PayloadSize, now) || s.Acknowledge(probe.Attempt, probe.PayloadSize+1, now) {
		t.Fatal("mismatched acknowledgement accepted")
	}
	if !s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatal("matching acknowledgement rejected")
	}
}

func TestAdjustCurrentTracksActualEmittedPayload(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 2_000)
	now := time.Unix(1, 0)
	s.Start(now)
	probe, ok := s.Next(now)
	if !ok {
		t.Fatal("missing probe")
	}
	if !s.AdjustCurrent(probe.Attempt, probe.PayloadSize-1) {
		t.Fatal("AdjustCurrent rejected a valid smaller emitted size")
	}
	if got, ok := s.Outstanding(); !ok || got.PayloadSize != probe.PayloadSize-1 {
		t.Fatalf("outstanding=%#v ok=%t, want actual payload", got, ok)
	}
	if s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatal("ack for requested, un-emitted payload was accepted")
	}
	if !s.Acknowledge(probe.Attempt, probe.PayloadSize-1, now) {
		t.Fatal("ack for actual emitted payload was rejected")
	}
}

func TestCeilingAtBaseDoesNotSearch(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 613)
	now := time.Unix(1, 0)
	s.Start(now)
	if s.Searching() || s.Confirmed() != 613 {
		t.Fatalf("searching=%t confirmed=%d", s.Searching(), s.Confirmed())
	}
	if s.NextRefresh() != now.Add(10*time.Minute) {
		t.Fatalf("next refresh=%v", s.NextRefresh())
	}
}

func TestFailCurrentAndOutstanding(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 2_000)
	now := time.Unix(1, 0)
	s.Start(now)
	probe, ok := s.Next(now)
	if !ok {
		t.Fatal("missing probe")
	}
	if got, ok := s.Outstanding(); !ok || got != probe {
		t.Fatalf("outstanding=%#v ok=%t", got, ok)
	}
	if !s.FailCurrent(now) {
		t.Fatal("FailCurrent rejected outstanding probe")
	}
	if _, ok := s.Outstanding(); ok {
		t.Fatal("timed-out probe remains outstanding")
	}
}

func TestInvalidConfig(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{Base: 612, Ceiling: 613, ProbeTimeout: 2 * time.Second, RefreshInterval: time.Minute, ConfirmationInterval: time.Minute}); err == nil {
		t.Fatal("accepted small base")
	}
	if _, err := New(Config{Base: 613, Ceiling: 613, ProbeTimeout: 99 * time.Millisecond, RefreshInterval: time.Minute, ConfirmationInterval: time.Minute}); err == nil {
		t.Fatal("accepted short timeout")
	}
}

func TestProbeTimeoutUsesRTTMultiplierAndFloor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rtt    time.Duration
		before time.Duration
		at     time.Duration
	}{
		{name: "multiplier", rtt: 50 * time.Millisecond, before: 199 * time.Millisecond, at: 200 * time.Millisecond},
		{name: "floor", rtt: 10 * time.Millisecond, before: 99 * time.Millisecond, at: 100 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustState(t, 613, 2_000)
			now := time.Unix(1, 0)
			s.ObserveRTT(tt.rtt)
			s.Start(now)
			probe, ok := s.Next(now)
			if !ok {
				t.Fatal("missing probe")
			}
			if s.Tick(now.Add(tt.before)) {
				t.Fatalf("probe timed out after %s", tt.before)
			}
			if !s.Tick(now.Add(tt.at)) {
				t.Fatalf("probe did not time out after %s", tt.at)
			}
			if s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
				t.Fatal("timed-out probe was acknowledged")
			}
		})
	}
}

// wgCanonicalize is test-only coverage for the former WireGuard transport
// bucket behavior. Production pmtu defaults to transport-neutral identity.
func wgCanonicalize(payload uint32) uint32 {
	return (payload+40)/16*16 - 40
}

// alignedPayload is the largest carrier payload sharing threshold's outer
// datagram size under the explicit test strategy above.
func alignedPayload(threshold uint32) uint32 {
	return wgCanonicalize(threshold)
}

func mustState(t *testing.T, base, ceiling uint32) *State {
	t.Helper()
	s, err := New(Config{Base: base, Ceiling: ceiling, Canonicalize: wgCanonicalize, ProbeTimeout: 2 * time.Second, RefreshInterval: 10 * time.Minute, ConfirmationInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDefaultCanonicalizationIsIdentity(t *testing.T) {
	t.Parallel()
	s, err := New(Config{Base: 613, Ceiling: 2_000, ProbeTimeout: 2 * time.Second, RefreshInterval: time.Minute, ConfirmationInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	s.Start(time.Unix(0, 0))
	probe, ok := s.Next(time.Unix(0, 0))
	if !ok || probe.PayloadSize != 1_226 {
		t.Fatalf("default candidate = (%d, %t), want identity candidate 1226", probe.PayloadSize, ok)
	}
}

func TestOutOfRangeCanonicalizationStopsSearchSafely(t *testing.T) {
	t.Parallel()

	for _, canonicalize := range []func(uint32) uint32{
		func(uint32) uint32 { return 1 },
		func(uint32) uint32 { return ^uint32(0) },
	} {
		s, err := New(Config{
			Base:                 613,
			Ceiling:              2_000,
			Canonicalize:         canonicalize,
			ProbeTimeout:         2 * time.Second,
			RefreshInterval:      time.Minute,
			ConfirmationInterval: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		s.Start(time.Unix(0, 0))
		if s.Searching() || s.Confirmed() != 613 {
			t.Fatalf("searching=%t confirmed=%d, want stopped at BASE", s.Searching(), s.Confirmed())
		}
	}
}

func completeSearch(t *testing.T, s *State, now *time.Time, threshold uint32) {
	t.Helper()

	for s.Searching() {
		completeRound(t, s, now, threshold)
	}
}

func completeSearchUntilConfirmation(t *testing.T, s *State, now *time.Time, threshold uint32) {
	t.Helper()
	for s.Searching() && !s.Confirming() {
		completeRound(t, s, now, threshold)
	}
}

func completeRound(t *testing.T, s *State, now *time.Time, threshold uint32) {
	t.Helper()
	startResults := s.results

	for s.Searching() && s.results == startResults {
		probe, ok := s.Next(*now)
		if !ok {
			return
		}
		if probe.PayloadSize <= threshold {
			if !s.Acknowledge(probe.Attempt, probe.PayloadSize, *now) {
				t.Fatal("ack failed")
			}
		} else if !s.Fail(probe.Attempt, *now) {
			t.Fatal("failure rejected")
		}
		*now = now.Add(time.Millisecond)
	}
}

func TestConfirmationProbesKeepConfirmedSizeWhilePathIsHealthy(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 1400)
	now := time.Unix(0, 0)
	s.Start(now)
	completeSearch(t, s, &now, 1400)
	confirmed := s.Confirmed()
	if confirmed == 0 {
		t.Fatal("search did not confirm a size")
	}

	for round := 0; round < 3; round++ {
		if s.ConfirmationDue(now) {
			t.Fatal("confirmation fired before its interval elapsed")
		}
		now = now.Add(time.Minute)
		if !s.ConfirmationDue(now) {
			t.Fatal("confirmation did not fire after its interval")
		}
		probe, ok := s.Next(now)
		if !ok || probe.PayloadSize != confirmed {
			t.Fatalf("probe = (%d, %t), want the confirmed size %d", probe.PayloadSize, ok, confirmed)
		}
		if !s.Confirming() {
			t.Fatal("probe was not marked as a confirmation")
		}
		if !s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
			t.Fatal("Acknowledge() rejected the confirmation probe")
		}
		if s.Confirmed() != confirmed {
			t.Fatalf("Confirmed() = %d after a successful confirmation, want %d", s.Confirmed(), confirmed)
		}
	}
}

func TestConfirmationFailuresBelowLimitDoNotShrinkTheCeiling(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 1400)
	now := time.Unix(0, 0)
	s.Start(now)
	completeSearch(t, s, &now, 1400)
	confirmed := s.Confirmed()

	// One isolated loss must never cost a working ceiling.
	for attempt := 0; attempt < ConfirmationFailureLimit-1; attempt++ {
		now = now.Add(time.Minute)
		if !s.ConfirmationDue(now) {
			t.Fatal("confirmation did not fire")
		}
		probe, _ := s.Next(now)
		now = now.Add(3 * time.Second)
		if !s.Tick(now) {
			t.Fatal("Tick() did not time out the confirmation probe")
		}
		_ = probe
		if s.Confirmed() != confirmed {
			t.Fatalf("Confirmed() = %d after %d failures, want %d", s.Confirmed(), attempt+1, confirmed)
		}
	}

	now = now.Add(time.Minute)
	if !s.ConfirmationDue(now) {
		t.Fatal("confirmation did not fire")
	}
	probe, _ := s.Next(now)
	if !s.Acknowledge(probe.Attempt, probe.PayloadSize, now) {
		t.Fatal("Acknowledge() rejected the confirmation probe")
	}
	now = now.Add(time.Minute)
	if !s.ConfirmationDue(now) {
		t.Fatal("confirmation did not fire after the streak was cleared")
	}
	_, _ = s.Next(now)
	now = now.Add(3 * time.Second)
	if !s.Tick(now) || s.Confirmed() != confirmed {
		t.Fatalf("Confirmed() = %d, want the streak to have restarted at %d", s.Confirmed(), confirmed)
	}
}

func TestConsecutiveConfirmationFailuresFallBackToBaseAndResearch(t *testing.T) {
	t.Parallel()
	s := mustState(t, 613, 1400)
	now := time.Unix(0, 0)
	s.Start(now)
	completeSearch(t, s, &now, 1400)
	confirmed := s.Confirmed()
	if confirmed <= 613 {
		t.Fatalf("search confirmed %d, want a size above BASE for this case", confirmed)
	}

	for attempt := 0; attempt < ConfirmationFailureLimit; attempt++ {
		now = now.Add(time.Minute)
		if !s.ConfirmationDue(now) {
			t.Fatalf("confirmation %d did not fire", attempt)
		}
		probe, _ := s.Next(now)
		_ = probe
		now = now.Add(3 * time.Second)
		if !s.Tick(now) {
			t.Fatalf("Tick() did not time out confirmation %d", attempt)
		}
	}
	if s.Confirmed() != 613 {
		t.Fatalf("Confirmed() = %d after %d consecutive failures, want BASE", s.Confirmed(), ConfirmationFailureLimit)
	}
	if !s.Searching() {
		t.Fatal("a black hole did not start a fresh search")
	}

	completeSearch(t, s, &now, 800)
	if got := s.Confirmed(); got > 800 || got < 613 {
		t.Fatalf("Confirmed() = %d after re-searching an 800-byte path", got)
	}
}
