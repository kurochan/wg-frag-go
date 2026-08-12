package main

import controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"

func testDesiredPeer(publicKey, endpoint string, allowed []string) *controlapiv1.DesiredPeer {
	peer := controlapiv1.DesiredPeer_builder{}.Build()
	peer.SetPublicKey(publicKey)
	if endpoint != "" {
		peer.SetEndpoint(endpoint)
	}
	if allowed != nil {
		peer.SetAllowedIps(allowed)
	}
	return peer
}

func testPeerStatus(publicKey, endpoint string, allowed []string, dataReady bool) *controlapiv1.PeerStatus {
	peer := controlapiv1.PeerStatus_builder{}.Build()
	peer.SetPublicKey(publicKey)
	if endpoint != "" {
		peer.SetEndpoint(endpoint)
	}
	if allowed != nil {
		peer.SetAllowedIps(allowed)
	}
	if dataReady {
		peer.SetDataReady(true)
	}
	return peer
}

func testStatusResponse(generation uint64, peers []*controlapiv1.PeerStatus) *controlapiv1.GetStatusResponse {
	status := controlapiv1.GetStatusResponse_builder{}.Build()
	status.SetGeneration(generation)
	status.SetPeers(peers)
	return status
}

func testApplyResponse(generation uint64) *controlapiv1.ApplyConfigResponse {
	response := controlapiv1.ApplyConfigResponse_builder{}.Build()
	response.SetGeneration(generation)
	return response
}
