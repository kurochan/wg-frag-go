package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/kurochan/wg-frag-go/internal/config/syntax"
	"github.com/kurochan/wg-frag-go/internal/quick"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

// renderSavedConfig keeps everything up to the first [Peer] section verbatim
// and regenerates the peer sections from the running daemon.
func renderSavedConfig(source string, status *controlapiv1.GetStatusResponse) (string, error) {
	headEnd := 0

	for line := range strings.Lines(source) {
		if section := syntax.Section(line); section == "Peer" {
			break
		}
		headEnd += len(line)
	}

	var out strings.Builder
	out.Grow(len(source))
	out.WriteString(strings.TrimRight(source[:headEnd], "\n"))
	out.WriteByte('\n')

	for _, peer := range status.GetPeers() {
		out.WriteString("\n[Peer]\nPublicKey = ")
		out.WriteString(peer.GetPublicKey())
		out.WriteByte('\n')
		if endpoint := peer.GetEndpoint(); endpoint != "" {
			out.WriteString("Endpoint = ")
			out.WriteString(endpoint)
			out.WriteByte('\n')
		}
		if allowed := peer.GetAllowedIps(); len(allowed) != 0 {
			out.WriteString("AllowedIPs = ")
			out.WriteString(strings.Join(allowed, ", "))
			out.WriteByte('\n')
		}
		if keepalive := peer.GetPersistentKeepaliveSec(); keepalive != 0 {
			out.WriteString("PersistentKeepalive = ")
			out.WriteString(strconv.FormatUint(uint64(keepalive), 10))
			out.WriteByte('\n')
		}
		if peer.HasPresharedKey() {
			out.WriteString("PresharedKey = ")
			out.WriteString(base64.StdEncoding.EncodeToString(peer.GetPresharedKey()))
			out.WriteByte('\n')
		}
	}
	rendered := out.String()
	// The result must round-trip through the quick parser.
	if _, err := quick.Parse(rendered); err != nil {
		return "", fmt.Errorf("rendered configuration is invalid: %w", err)
	}
	return rendered, nil
}
