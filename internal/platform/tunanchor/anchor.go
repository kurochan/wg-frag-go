// Package tunanchor keeps a native TUN alive while runtime generations use
// independent tun.Device leases made from duplicated file descriptors.
package tunanchor

import (
	"errors"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

var (
	// ErrClosed is returned when a lease is requested after the anchor closed.
	ErrClosed = errors.New("tunanchor: anchor is closed")
	// ErrInvalidAnchor indicates a nil or otherwise unusable anchor.
	ErrInvalidAnchor = errors.New("tunanchor: invalid anchor")
	// ErrUnsupported is returned on platforms without the native TUN lease API.
	ErrUnsupported = errors.New("tunanchor: unsupported platform")
)

type leaseFactory func(*os.File, int) (tun.Device, error)

// Anchor owns the descriptor that keeps a native TUN alive. A runtime
// generation should use Lease and close that lease when it stops. Close the
// Anchor only after all leases have stopped.
type Anchor struct {
	mu       sync.Mutex
	file     *os.File
	name     string
	closed   bool
	closeErr error
	newLease leaseFactory
}

// Open creates a native TUN and retains an anchor descriptor for it. The
// returned name is the actual native name, which may differ from name on
// platforms that allocate interface names dynamically.
func Open(name string, mtu int) (*Anchor, error) {
	file, actualName, err := openNative(name, mtu)
	if err != nil {
		return nil, err
	}
	return newAnchor(file, actualName, createLease), nil
}

func newAnchor(file *os.File, name string, newLease leaseFactory) *Anchor {
	return &Anchor{file: file, name: name, newLease: newLease}
}

// Name returns the native TUN name.
func (a *Anchor) Name() string {
	if a == nil {
		return ""
	}
	return a.name
}

// Lease creates a tun.Device for one runtime generation. Closing the lease
// releases only its duplicated descriptor; the anchor remains alive.
func (a *Anchor) Lease(mtu int) (tun.Device, error) {
	if a == nil {
		return nil, ErrInvalidAnchor
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	if a.file == nil || a.newLease == nil {
		return nil, ErrInvalidAnchor
	}
	file, err := duplicateFile(a.file)
	if err != nil {
		return nil, err
	}
	lease, err := a.newLease(file, mtu)
	if err != nil {
		// CreateTUNFromFile does not consistently take ownership on every
		// error path across supported platforms.
		_ = file.Close()
		return nil, err
	}
	return lease, nil
}

// Close releases the anchor descriptor. It is idempotent and must be called
// after all runtime leases have been closed.
func (a *Anchor) Close() error {
	if a == nil {
		return ErrInvalidAnchor
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return a.closeErr
	}
	a.closed = true
	if a.file == nil {
		a.closeErr = ErrInvalidAnchor
		return a.closeErr
	}
	a.closeErr = a.file.Close()
	return a.closeErr
}
