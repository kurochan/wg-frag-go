//go:build linux

package main

import (
	"io"
	"log/slog"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/platform/linux/wgbind"
	"golang.zx2c4.com/wireguard/tun"
)

func runCommand(args []string, stdout, stderr io.Writer) error {
	return runConfiguredInterface(args, stdout, stderr, runPlatform{
		createTUN: tun.CreateTUN,
		tunName:   func(ifname string) string { return ifname },
		newBind:   func() runtimeBind { return wgbind.New() },
		configureBind: func(bind runtimeBind, cfg *config.Config) error {
			bind.(*wgbind.Bind).SetFwMark(cfg.Interface.FwMark)
			return nil
		},
		warnSocketBuffer: warnSocketBuffer,
	})
}

func warnSocketBuffer(bind runtimeBind, logger *slog.Logger) {
	requested, v4, v6 := bind.SocketBufferStatus()
	if requested <= 0 {
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
