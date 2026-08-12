//go:build !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package controlapi

import (
	"fmt"
	"os"
)

// Non-Unix systems do not expose a portable numeric owner in FileInfo.Sys.
// Keep the path/symlink checks common and enforce the portable permission
// subset; platform-specific ACL policy belongs to the host integration.
func validateSocketDirectory(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not owner-only (mode %04o)", path, info.Mode().Perm())
	}
	return nil
}

func validateSocketDirectoryComponent(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o)", path, info.Mode().Perm())
	}
	return nil
}
