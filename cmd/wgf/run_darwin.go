//go:build darwin

package main

import (
	"io"
	"log/slog"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/platform/darwin/wgbind"
	"golang.zx2c4.com/wireguard/tun"
)

func runCommand(args []string, stdout, stderr io.Writer) error {
	return runConfiguredInterface(args, stdout, stderr, runPlatform{
		createTUN: tun.CreateTUN,
		// macOS allocates utunN names. The configured name remains the WGF
		// interface identity for its control socket and status API.
		tunName:          func(string) string { return "utun" },
		nativeReadOffset: 4,
		newBind:          func() runtimeBind { return wgbind.New() },
		configureBind:    func(runtimeBind, *config.Config) error { return nil },
		warnSocketBuffer: func(bind runtimeBind, logger *slog.Logger) {
			requested, v4, v6 := bind.SocketBufferStatus()
			if requested <= 0 {
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
		},
	})
}
