package wgadapter

import (
	"errors"
	"reflect"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var (
	ErrNilTUN    = errors.New("wgadapter: nil TUN device")
	ErrNilBind   = errors.New("wgadapter: nil conn.Bind")
	ErrNilLogger = errors.New("wgadapter: nil WireGuard logger")
)

// DeviceConfig supplies the two WGF-owned injection points to wireguard-go.
// The caller must provide a fragment-aware tun.Device wrapper and a Bind that
// prohibits outer IP fragmentation. No wireguard-go fork is required.
type DeviceConfig struct {
	TUN    tun.Device
	Bind   conn.Bind
	Logger *device.Logger
}

// New creates one wireguard-go device using the caller-provided TUN and Bind.
func New(config DeviceConfig) (*device.Device, error) {
	if isNil(config.TUN) {
		return nil, ErrNilTUN
	}
	if isNil(config.Bind) {
		return nil, ErrNilBind
	}
	if config.Logger == nil {
		return nil, ErrNilLogger
	}
	return device.NewDevice(config.TUN, config.Bind, config.Logger), nil
}

// isNil also catches typed nil implementations stored in an interface. They
// otherwise pass a direct == nil check and panic inside wireguard-go later.
func isNil(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)

	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
