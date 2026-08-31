//go:build linux

package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/kurochan/wg-frag-go/internal/platform/runtimedir"
	"golang.org/x/sys/unix"
)

const (
	quickLockOwnerWait = 10 * time.Second
	quickLockTotalWait = 180 * time.Second
	quickLockMinDelay  = 100 * time.Millisecond
	quickLockMaxDelay  = time.Second
)

var errQuickLockBusy = errors.New("wgf quick: another quick operation is already in progress")

type quickLockRetry struct {
	ownerTimeout time.Duration
	totalTimeout time.Duration
	initial      time.Duration
	maximum      time.Duration
	now          func() time.Time
	sleep        func(time.Duration)
	jitter       func(time.Duration) time.Duration
	acquire      func(string) (func(), error)
	readOwner    func(string) (quickLockOwner, error)
	requestOwner quickLockOwner
	logger       *slog.Logger
}

type quickLockOwner struct {
	AcquisitionID string    `json:"acquisition_id"`
	PID           int       `json:"pid"`
	Operation     string    `json:"operation"`
	Interface     string    `json:"interface"`
	AcquiredAt    time.Time `json:"acquired_at"`
}

// The file can outlive its owner, but the kernel releases flock when every
// owning file descriptor closes, including on process exit.
func acquireQuickFileLockFor(path string, owner quickLockOwner) (func(), error) {
	lockFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open quick lock: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errQuickLockBusy
		}
		return nil, fmt.Errorf("acquire quick lock: %w", err)
	}
	if owner.AcquisitionID != "" {
		if owner.AcquiredAt.IsZero() {
			owner.AcquiredAt = time.Now().UTC()
		}
		if err := writeQuickLockOwner(lockFile, owner); err != nil {
			_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
			_ = lockFile.Close()
			return nil, err
		}
	}
	return func() {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		_ = lockFile.Close()
	}, nil
}

func newQuickLockOwner(operation, ifname string) (quickLockOwner, error) {
	var id [16]byte
	if _, err := crand.Read(id[:]); err != nil {
		return quickLockOwner{}, fmt.Errorf("generate quick lock acquisition ID: %w", err)
	}
	return quickLockOwner{
		AcquisitionID: hex.EncodeToString(id[:]),
		PID:           os.Getpid(),
		Operation:     operation,
		Interface:     ifname,
	}, nil
}

func writeQuickLockOwner(lockFile *os.File, owner quickLockOwner) error {
	encoded, err := json.Marshal(owner)
	if err != nil {
		return fmt.Errorf("encode quick lock owner: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := lockFile.Truncate(0); err != nil {
		return fmt.Errorf("truncate quick lock metadata: %w", err)
	}
	if _, err := lockFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek quick lock metadata: %w", err)
	}
	n, err := lockFile.Write(encoded)
	if err != nil {
		return fmt.Errorf("write quick lock metadata: %w", err)
	}
	if n != len(encoded) {
		return fmt.Errorf("write quick lock metadata: %w", io.ErrShortWrite)
	}
	return nil
}

func readQuickLockOwner(path string) (quickLockOwner, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return quickLockOwner{}, err
	}
	var owner quickLockOwner
	if err := json.Unmarshal(encoded, &owner); err != nil {
		return quickLockOwner{}, err
	}
	if owner.AcquisitionID == "" {
		return quickLockOwner{}, errors.New("quick lock metadata has no acquisition ID")
	}
	return owner, nil
}

func jitterQuickLockDelay(delay time.Duration) time.Duration {
	window := delay / 10
	return delay - window + time.Duration(rand.Int64N(int64(2*window)+1))
}

func acquireQuickFileLockWithRetry(path string, retry quickLockRetry) (func(), error) {
	started := retry.now()
	ownerStarted := started
	delay := retry.initial
	waiting := false
	var observedOwner quickLockOwner

	for {
		unlock, err := retry.acquire(path)
		if err == nil {
			if waiting && retry.logger != nil {
				retry.logger.Info(
					"quick lock acquired",
					"path", path,
					"waited", retry.now().Sub(started).Round(time.Millisecond),
					"operation", retry.requestOwner.Operation,
					"interface", retry.requestOwner.Interface,
				)
			}
			return unlock, nil
		}
		if !errors.Is(err, errQuickLockBusy) {
			return nil, err
		}

		now := retry.now()
		owner, ownerErr := retry.readOwner(path)
		if ownerErr != nil {
			owner = observedOwner
		}
		if !waiting {
			waiting = true
			observedOwner = owner
			ownerStarted = now
			retry.logWaiting(path, owner)
		} else if owner.AcquisitionID != "" && owner.AcquisitionID != observedOwner.AcquisitionID {
			retry.logOwnerChange(path, observedOwner, owner)
			observedOwner = owner
			ownerStarted = now
			delay = retry.initial
		}

		totalRemaining := retry.totalTimeout - now.Sub(started)
		if totalRemaining <= 0 {
			if retry.logger != nil {
				retry.logger.Warn("quick lock total wait timed out", "path", path, "timeout", retry.totalTimeout)
			}
			return nil, fmt.Errorf("%w: path=%s total timeout=%s", errQuickLockBusy, path, retry.totalTimeout)
		}
		ownerRemaining := retry.ownerTimeout - now.Sub(ownerStarted)
		if ownerRemaining <= 0 {
			retry.logUnchangedOwner(path, observedOwner)
			return nil, fmt.Errorf(
				"%w: path=%s owner pid=%d operation=%s interface=%s unchanged for %s",
				errQuickLockBusy,
				path,
				observedOwner.PID,
				observedOwner.Operation,
				observedOwner.Interface,
				retry.ownerTimeout,
			)
		}

		retry.sleep(min(retry.jitter(delay), totalRemaining, ownerRemaining))
		if delay < retry.maximum {
			delay = min(delay*2, retry.maximum)
		}
	}
}

func (retry quickLockRetry) logWaiting(path string, owner quickLockOwner) {
	if retry.logger == nil {
		return
	}
	retry.logger.Info(
		"waiting for quick lock",
		"path", path,
		"owner_timeout", retry.ownerTimeout,
		"total_timeout", retry.totalTimeout,
		"owner_pid", owner.PID,
		"owner_operation", owner.Operation,
		"owner_interface", owner.Interface,
	)
}

func (retry quickLockRetry) logOwnerChange(path string, previous, owner quickLockOwner) {
	if retry.logger == nil {
		return
	}
	retry.logger.Info(
		"quick lock owner changed",
		"path", path,
		"previous_owner_pid", previous.PID,
		"owner_pid", owner.PID,
		"owner_operation", owner.Operation,
		"owner_interface", owner.Interface,
	)
}

func (retry quickLockRetry) logUnchangedOwner(path string, owner quickLockOwner) {
	if retry.logger == nil {
		return
	}
	retry.logger.Warn(
		"quick lock owner did not change",
		"path", path,
		"timeout", retry.ownerTimeout,
		"owner_pid", owner.PID,
		"owner_operation", owner.Operation,
		"owner_interface", owner.Interface,
	)
}

func acquireQuickLock(stderr io.Writer, operation, ifname string) (func(), error) {
	if err := os.MkdirAll(runtimedir.Default, 0o700); err != nil {
		return nil, fmt.Errorf("create quick runtime directory: %w", err)
	}
	owner, err := newQuickLockOwner(operation, ifname)
	if err != nil {
		return nil, err
	}
	return acquireQuickFileLockWithRetry(filepath.Join(runtimedir.Default, ".quick.lock"), quickLockRetry{
		ownerTimeout: quickLockOwnerWait,
		totalTimeout: quickLockTotalWait,
		initial:      quickLockMinDelay,
		maximum:      quickLockMaxDelay,
		now:          time.Now,
		sleep:        time.Sleep,
		jitter:       jitterQuickLockDelay,
		acquire: func(path string) (func(), error) {
			return acquireQuickFileLockFor(path, owner)
		},
		readOwner:    readQuickLockOwner,
		requestOwner: owner,
		logger:       newAppLogger(stderr),
	})
}
