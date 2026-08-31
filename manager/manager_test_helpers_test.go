//go:build linux || darwin

package manager

import controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"

func testDesiredPeer(publicKey, endpoint string, allowed []string) *controlapiv1.PeerSpec {
	peer := controlapiv1.PeerSpec_builder{}.Build()
	peer.SetPublicKey(publicKey)
	if endpoint != "" {
		peer.SetEndpoint(endpoint)
	}
	if allowed != nil {
		peer.SetAllowedIps(allowed)
	}
	return peer
}

func testApplyResponse(generation uint64) *controlapiv1.ApplyPeersResponse {
	response := controlapiv1.ApplyPeersResponse_builder{}.Build()
	response.SetGeneration(generation)
	return response
}
