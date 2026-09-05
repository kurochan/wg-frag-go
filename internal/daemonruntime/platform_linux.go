//go:build linux

package daemonruntime

import (
	"log/slog"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/platform/linux/wgbind"
	"github.com/kurochan/wg-frag-go/internal/platform/tunanchor"
)

// DefaultPlatform returns the Linux TUN and UDP construction hooks.
func DefaultPlatform() Platform {
	return Platform{
		OpenAnchor:       func(name string, mtu int) (TUNAnchor, error) { return tunanchor.Open(name, mtu) },
		TUNName:          func(name string) string { return name },
		NewBind:          func() Bind { return wgbind.New() },
		ConfigureBind:    configureLinuxBind,
		WarnSocketBuffer: warnLinuxSocketBuffer,
	}
}

func configureLinuxBind(bind Bind, cfg *config.Config) error {
	linuxBind, ok := bind.(*wgbind.Bind)
	if !ok {
		return nil
	}
	if err := linuxBind.SetBatchSize(cfg.Interface.UDPBatchSize); err != nil {
		return err
	}
	linuxBind.SetFwMark(cfg.Interface.FwMark)
	return nil
}

func warnLinuxSocketBuffer(bind Bind, logger *slog.Logger) {
	requested, v4, v6 := bind.SocketBufferStatus()
	if requested <= 0 || logger == nil {
		return
	}
	for _, socket := range []struct {
		family   string
		achieved int
	}{{"IPv4", v4}, {"IPv6", v6}} {
		if socket.achieved == 0 || socket.achieved >= requested {
			continue
		}
		logger.Warn("UDP socket buffer below requested size",
			"family", socket.family,
			"achieved_bytes", socket.achieved,
			"requested_bytes", requested,
			"remediation", "raise net.core.rmem_max/wmem_max or grant CAP_NET_ADMIN")
	}
}
