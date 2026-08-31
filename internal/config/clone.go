package config

import "net/netip"

// Clone returns an independent copy of source, including every slice and
// optional secret owned by the configuration. A nil source returns nil.
func Clone(source *Config) *Config {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.Interface.Addresses = append([]netip.Prefix(nil), source.Interface.Addresses...)
	cloned.Interface.MetricsListen.Addresses = append([]string(nil), source.Interface.MetricsListen.Addresses...)
	cloned.Interface.MetricsInclude = append([]string(nil), source.Interface.MetricsInclude...)
	cloned.Interface.MetricsExclude = append([]string(nil), source.Interface.MetricsExclude...)
	cloned.Peers = make([]Peer, len(source.Peers))
	for index, peer := range source.Peers {
		cloned.Peers[index] = peer
		cloned.Peers[index].AllowedIPs = append([]netip.Prefix(nil), peer.AllowedIPs...)
		if peer.PresharedKey != nil {
			key := *peer.PresharedKey
			cloned.Peers[index].PresharedKey = &key
		}
	}
	return &cloned
}
