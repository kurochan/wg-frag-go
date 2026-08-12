//go:build !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package controlapi

func isConnectionRefused(error) bool { return false }
