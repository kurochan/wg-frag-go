//go:build android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package controlapi

import (
	"fmt"
	"os"
	"syscall"
)

func validateSocketDirectory(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not owner-only (mode %04o)", path, info.Mode().Perm())
	}
	if err := validateSocketDirectoryOwner(path, info); err != nil {
		return err
	}
	return nil
}

func validateSocketDirectoryComponent(path string, info os.FileInfo) error {
	if err := validateSocketDirectoryOwner(path, info); err != nil {
		return err
	}
	stat := info.Sys().(*syscall.Stat_t)
	// A root-owned sticky directory such as /tmp is an acceptable system
	// path component. Other group/other-writable components are not.
	if info.Mode().Perm()&0o022 != 0 && (stat.Uid != 0 || info.Mode()&os.ModeSticky == 0) {
		return fmt.Errorf("%s is writable by group or other (mode %04o)", path, info.Mode().Perm())
	}
	return nil
}

func validateSocketDirectoryOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s has no Unix ownership metadata", path)
	}
	owner := uint64(stat.Uid)
	euid := uint64(os.Geteuid())
	if owner != 0 && owner != euid {
		return fmt.Errorf("%s is not owned by root or effective uid %d", path, euid)
	}
	return nil
}
