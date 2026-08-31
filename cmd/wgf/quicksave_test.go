package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

func TestRenderSavedConfigRegeneratesPeers(t *testing.T) {
	t.Parallel()
	source := `# saved by hand
[Interface]
Address = 10.9.0.2/24
PrivateKey = GGHiF3lJmZSPqQfHelxSTObVh8lGYbBAyTNTdEIsuEc=
ListenPort = 51820
Table = off

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 192.0.2.0/24
`
	key := "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	endpoint := "203.0.113.9:51821"
	keepalive := uint32(25)
	psk := bytes.Repeat([]byte{4}, 32)
	peer := controlapiv1.PeerStatus_builder{
		PublicKey:              &key,
		Endpoint:               &endpoint,
		AllowedIps:             []string{"10.0.0.0/24", "10.1.0.0/24"},
		PersistentKeepaliveSec: &keepalive,
	}.Build()
	peer.SetPresharedKey(psk)
	peer.SetMetricsId("edge-a")
	status := controlapiv1.InterfaceStatus_builder{Peers: []*controlapiv1.PeerStatus{peer}}.Build()

	rendered, err := renderSavedConfig(source, status)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# saved by hand",
		"Table = off",
		"Endpoint = 203.0.113.9:51821",
		"AllowedIPs = 10.0.0.0/24, 10.1.0.0/24",
		"PersistentKeepalive = 25",
		"PresharedKey = " + base64.StdEncoding.EncodeToString(psk),
		"WGFPeerID = edge-a",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config lacks %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "192.0.2.0/24") {
		t.Fatalf("stale peer survived save:\n%s", rendered)
	}
}

func TestRenderSavedConfigRecognizesCommentedPeerHeader(t *testing.T) {
	t.Parallel()
	source := "[Interface]\nPrivateKey = GGHiF3lJmZSPqQfHelxSTObVh8lGYbBAyTNTdEIsuEc=\n\n[ Peer ] # home\nPublicKey = stale\n"
	key := "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	status := controlapiv1.InterfaceStatus_builder{Peers: []*controlapiv1.PeerStatus{
		controlapiv1.PeerStatus_builder{PublicKey: &key}.Build(),
	}}.Build()
	if _, err := renderSavedConfig(source, status); err != nil {
		t.Fatalf("renderSavedConfig() = %v", err)
	}
}
