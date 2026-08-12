//go:build !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package controlapi

import "os"

func acquireSocketLock(string) (*os.File, func(), error) {
	return nil, func() {}, nil
}
