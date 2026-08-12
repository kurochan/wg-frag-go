package wgadapter

import "testing"

func TestWireGuardPMTURepresentation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		payload   uint32
		canonical uint32
		datagram  int
	}{
		{payload: 613, canonical: 600, datagram: 688},
		{payload: 614, canonical: 600, datagram: 688},
		{payload: 615, canonical: 600, datagram: 688},
		{payload: 616, canonical: 616, datagram: 688},
		{payload: 617, canonical: 616, datagram: 704},
	}
	for _, test := range cases {
		if got := CanonicalCarrierPayload(test.payload); got != test.canonical {
			t.Errorf("CanonicalCarrierPayload(%d) = %d, want %d", test.payload, got, test.canonical)
		}
		if got := WireGuardDatagramSize(test.payload); got != test.datagram {
			t.Errorf("WireGuardDatagramSize(%d) = %d, want %d", test.payload, got, test.datagram)
		}
	}
}
