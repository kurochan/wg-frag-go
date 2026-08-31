package main

import (
	"encoding/base64"

	"github.com/kurochan/wg-frag-go/internal/config"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

func controlConfigKey(value byte) config.Key {
	var key config.Key
	for index := range key {
		key[index] = value
	}
	return key
}

func encodedControlConfigKey(value byte) string {
	key := controlConfigKey(value)
	return base64.StdEncoding.EncodeToString(key[:])
}

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

func testStatusResponse(generation uint64, peers []*controlapiv1.PeerStatus) *controlapiv1.InterfaceStatus {
	status := controlapiv1.InterfaceStatus_builder{}.Build()
	status.SetGeneration(generation)
	status.SetPeers(peers)
	return status
}

func testApplyResponse(generation uint64) *controlapiv1.ApplyPeersResponse {
	response := controlapiv1.ApplyPeersResponse_builder{}.Build()
	response.SetGeneration(generation)
	return response
}
