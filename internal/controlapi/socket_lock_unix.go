//go:build android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package controlapi

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func acquireSocketLock(path string) (*os.File, func(), error) {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, nil, errors.New("another instance owns or is creating this socket")
		}
		return nil, nil, err
	}
	release := func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}
	return lock, release, nil
}
