//go:build linux

package main

import (
	"bytes"
	"errors"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQuickFileLockSerializesOperations(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "quick.lock")
	release, err := acquireQuickFileLockFor(path, quickLockOwner{})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := acquireQuickFileLockFor(path, quickLockOwner{}); !errors.Is(err, errQuickLockBusy) {
		t.Fatalf("second lock error = %v, want errQuickLockBusy", err)
	}
}

func TestQuickFileLockUncontendedDoesNotLog(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	retry := quickLockRetry{
		now: func() time.Time { return time.Unix(1, 0) },
		acquire: func(string) (func(), error) {
			return func() {}, nil
		},
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	unlock, err := acquireQuickFileLockWithRetry("/run/wg-frag/.quick.lock", retry)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if logs.Len() != 0 {
		t.Fatalf("uncontended lock log = %q, want empty", logs.String())
	}
}

func TestQuickFileLockRecordsOwner(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "quick.lock")
	want := quickLockOwner{
		AcquisitionID: "acquisition-1",
		PID:           42,
		Operation:     "reload",
		Interface:     "wgf0",
		AcquiredAt:    time.Unix(123, 0).UTC(),
	}
	unlock, err := acquireQuickFileLockFor(path, want)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	got, err := readQuickLockOwner(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("owner = %+v, want %+v", got, want)
	}
}

func TestQuickFileLockRetriesWithCappedBackoff(t *testing.T) {
	t.Parallel()

	now := time.Unix(1, 0)
	attempts := 0
	var waits []time.Duration
	var logs bytes.Buffer
	retry := quickLockRetry{
		ownerTimeout: 10 * time.Second,
		totalTimeout: 10 * time.Second,
		initial:      100 * time.Millisecond,
		maximum:      time.Second,
		now:          func() time.Time { return now },
		sleep: func(delay time.Duration) {
			waits = append(waits, delay)
			now = now.Add(delay)
		},
		jitter: func(delay time.Duration) time.Duration { return delay },
		acquire: func(string) (func(), error) {
			attempts++
			if attempts <= 6 {
				return nil, errQuickLockBusy
			}
			return func() {}, nil
		},
		readOwner: func(string) (quickLockOwner, error) {
			return quickLockOwner{AcquisitionID: "owner-1", PID: 42, Operation: "up", Interface: "wgf0"}, nil
		},
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	unlock, err := acquireQuickFileLockWithRetry("/run/wg-frag/.quick.lock", retry)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, time.Second, time.Second}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits = %v, want %v", waits, want)
		}
	}
	if attempts != 7 {
		t.Fatalf("attempts = %d, want 7", attempts)
	}
	if text := logs.String(); !strings.Contains(text, "waiting for quick lock") ||
		!strings.Contains(text, "quick lock acquired") ||
		!strings.Contains(text, "path=/run/wg-frag/.quick.lock") {
		t.Fatalf("lock logs = %q", text)
	}
}

func TestQuickFileLockRetryTimesOut(t *testing.T) {
	t.Parallel()

	now := time.Unix(1, 0)
	attempts := 0
	var waits []time.Duration
	var logs bytes.Buffer
	retry := quickLockRetry{
		ownerTimeout: 250 * time.Millisecond,
		totalTimeout: 10 * time.Second,
		initial:      100 * time.Millisecond,
		maximum:      time.Second,
		now:          func() time.Time { return now },
		sleep: func(delay time.Duration) {
			waits = append(waits, delay)
			now = now.Add(delay)
		},
		jitter: func(delay time.Duration) time.Duration { return delay },
		acquire: func(string) (func(), error) {
			attempts++
			return nil, errQuickLockBusy
		},
		readOwner: func(string) (quickLockOwner, error) {
			return quickLockOwner{AcquisitionID: "owner-1", PID: 42, Operation: "up", Interface: "wgf0"}, nil
		},
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	_, err := acquireQuickFileLockWithRetry("/run/wg-frag/.quick.lock", retry)
	if !errors.Is(err, errQuickLockBusy) {
		t.Fatalf("error = %v, want errQuickLockBusy", err)
	}
	want := []time.Duration{100 * time.Millisecond, 150 * time.Millisecond}
	if len(waits) != len(want) || waits[0] != want[0] || waits[1] != want[1] {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if text := logs.String(); !strings.Contains(text, "quick lock owner did not change") ||
		!strings.Contains(text, "path=/run/wg-frag/.quick.lock") {
		t.Fatalf("lock logs = %q", text)
	}
}

func TestQuickFileLockOwnerChangesExtendWaitUntilTotalTimeout(t *testing.T) {
	t.Parallel()

	started := time.Unix(1, 0)
	now := started
	owner := 0
	var logs bytes.Buffer
	retry := quickLockRetry{
		ownerTimeout: 250 * time.Millisecond,
		totalTimeout: 700 * time.Millisecond,
		initial:      100 * time.Millisecond,
		maximum:      time.Second,
		now:          func() time.Time { return now },
		sleep: func(delay time.Duration) {
			now = now.Add(delay)
			if now.Sub(started)%(250*time.Millisecond) == 0 {
				owner++
			}
		},
		jitter: func(delay time.Duration) time.Duration { return delay },
		acquire: func(string) (func(), error) {
			return nil, errQuickLockBusy
		},
		readOwner: func(string) (quickLockOwner, error) {
			return quickLockOwner{AcquisitionID: strconv.Itoa(owner), PID: owner + 1}, nil
		},
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	_, err := acquireQuickFileLockWithRetry("/run/wg-frag/.quick.lock", retry)
	if !errors.Is(err, errQuickLockBusy) || !strings.Contains(err.Error(), "total timeout=700ms") {
		t.Fatalf("error = %v, want total timeout", err)
	}
	if now.Sub(started) != 700*time.Millisecond {
		t.Fatalf("waited = %v, want 700ms", now.Sub(started))
	}
	if text := logs.String(); !strings.Contains(text, "quick lock owner changed") ||
		!strings.Contains(text, "quick lock total wait timed out") {
		t.Fatalf("lock logs = %q", text)
	}
}

func TestQuickLockJitterStaysWithinTenPercent(t *testing.T) {
	t.Parallel()

	const delay = 100 * time.Millisecond
	for range 1000 {
		got := jitterQuickLockDelay(delay)
		if got < 90*time.Millisecond || got > 110*time.Millisecond {
			t.Fatalf("jittered delay = %v", got)
		}
	}
}
