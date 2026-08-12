//go:build android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package controlapi

import (
	"errors"
	"syscall"
)

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
