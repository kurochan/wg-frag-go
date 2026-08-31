//go:build linux || darwin

package tunanchor

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

func openNative(name string, mtu int) (*os.File, string, error) {
	native, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, "", err
	}
	file := native.File()
	if file == nil {
		_ = native.Close()
		return nil, "", fmt.Errorf("tunanchor: TUN %q returned no file", name)
	}
	actualName, err := native.Name()
	if err != nil {
		_ = native.Close()
		return nil, "", err
	}
	anchorFile, err := duplicateFile(file)
	closeErr := native.Close()
	if err != nil {
		return nil, "", err
	}
	if closeErr != nil {
		_ = anchorFile.Close()
		return nil, "", closeErr
	}
	return anchorFile, actualName, nil
}

func duplicateFile(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrInvalidAnchor
	}
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}

func createLease(file *os.File, mtu int) (tun.Device, error) {
	return tun.CreateTUNFromFile(file, mtu)
}
