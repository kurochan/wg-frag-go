//go:build darwin

package daemonruntime

import (
	"errors"
	"log/slog"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/platform/darwin/wgbind"
	"github.com/kurochan/wg-frag-go/internal/platform/tunanchor"
)

// DefaultPlatform returns the macOS TUN and UDP construction hooks.
func DefaultPlatform() Platform {
	return Platform{
		OpenAnchor:       func(name string, mtu int) (TUNAnchor, error) { return tunanchor.Open(name, mtu) },
		TUNName:          func(string) string { return "utun" },
		NativeReadOffset: 4,
		NewBind:          func() Bind { return wgbind.New() },
		ConfigureBind:    configureDarwinBind,
		WarnSocketBuffer: warnDarwinSocketBuffer,
	}
}

func configureDarwinBind(_ Bind, cfg *config.Config) error {
	if cfg != nil && cfg.Interface.UDPBatchSize != config.DefaultUDPBatchSize {
		return errors.New("WGFUDPBatchSize is supported on Linux only")
	}
	return nil
}

func warnDarwinSocketBuffer(bind Bind, logger *slog.Logger) {
	requested, v4, v6 := bind.SocketBufferStatus()
	if requested <= 0 || logger == nil {
		return
	}
	for _, socket := range []struct {
		family string
		value  int
	}{{"IPv4", v4}, {"IPv6", v6}} {
		if socket.value > 0 && socket.value < requested {
			logger.Warn("UDP socket buffer below requested size", "family", socket.family,
				"achieved_bytes", socket.value, "requested_bytes", requested)
		}
	}
}
