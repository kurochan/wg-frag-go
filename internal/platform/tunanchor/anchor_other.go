//go:build !linux && !darwin

package tunanchor

import (
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

func openNative(string, int) (*os.File, string, error) {
	return nil, "", ErrUnsupported
}

func duplicateFile(*os.File) (*os.File, error) {
	return nil, ErrUnsupported
}

func createLease(*os.File, int) (tun.Device, error) {
	return nil, ErrUnsupported
}
