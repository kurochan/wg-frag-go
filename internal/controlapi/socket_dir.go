package controlapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// prepareSocketDirectory creates only missing path components and validates
// every existing component before a socket is bound. The final directory may
// not be a symlink; system path aliases such as macOS's /tmp are resolved and
// their target metadata is validated.
func prepareSocketDirectory(path string) error {
	path = filepath.Clean(path)
	if err := ensureSocketDirectoryTree(path, true); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	return validateSocketDirectory(path, info)
}

func ensureSocketDirectoryTree(path string, rejectSymlink bool) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 && rejectSymlink {
			return fmt.Errorf("%s is a symlink", path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			info, err = os.Stat(path)
			if err != nil {
				return fmt.Errorf("inspect symlink %s: %w", path, err)
			}
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", path)
		}
		parent := filepath.Dir(path)
		if parent != path {
			if err := ensureSocketDirectoryTree(parent, false); err != nil {
				return err
			}
		}
		return validateSocketDirectoryComponent(path, info)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return fmt.Errorf("cannot create directory %s", path)
	}
	if err := ensureSocketDirectoryTree(parent, false); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s: %w", path, err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s after create: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return validateSocketDirectoryComponent(path, info)
}
