package core_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/core/carrier"
	"github.com/kurochan/wg-frag-go/internal/core/fragment"
	"github.com/kurochan/wg-frag-go/internal/core/limits"
	"github.com/kurochan/wg-frag-go/internal/core/packetizer"
	"github.com/kurochan/wg-frag-go/internal/core/peerroute"
	"github.com/kurochan/wg-frag-go/internal/core/reassembly"
)

func TestCarrierDataPathRoundTrip(t *testing.T) {
	t.Parallel()
	localKey := testPublicKey(1)
	peerKey := testPublicKey(2)
	localAddress, err := peerroute.DeriveCarrierAddress(localKey)
	if err != nil {
		t.Fatal(err)
	}
	peerAddress, err := peerroute.DeriveCarrierAddress(peerKey)
	if err != nil {
		t.Fatal(err)
	}

	key := reassembly.Key{PeerID: 0, DataSessionID: 1, LaneID: 7, LaneSequence: 42}
	records := []carrier.Record{
		{Header: carrier.Header{FragmentCount: 2, DataSessionID: key.DataSessionID, LaneID: key.LaneID, LaneSequence: key.LaneSequence}, Data: []byte("abc")},
		{Header: carrier.Header{FragmentIndex: 1, FragmentCount: 2, DataSessionID: key.DataSessionID, LaneID: key.LaneID, LaneSequence: key.LaneSequence, Offset: 3}, Data: []byte("def")},
	}
	payload := make([]byte, 2*(carrier.HeaderSize+3))

	offset := 0
	for _, record := range records {
		n, err := carrier.MarshalTo(payload[offset:], record.Header, record.Data)
		if err != nil {
			t.Fatal(err)
		}
		offset += n
	}

	packet := make([]byte, carrier.IPv6HeaderSize+len(payload))
	if _, err := carrier.MarshalEnvelopeTo(packet, peerAddress, localAddress, payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := carrier.ParseEnvelope(packet, peerAddress, localAddress)
	if err != nil {
		t.Fatal(err)
	}

	r, err := reassembly.New(reassembly.Config{
		Slots: 1, MaxPacketSize: 64, MaxPeers: 1, PerPeerSlots: 1, Lifetime: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	var completed reassembly.Packet
	if err := carrier.Parse(envelope.Payload, func(record carrier.Record) error {
		result, err := r.Accept(time.Unix(100, 0), key, record)
		if err != nil {
			return err
		}
		if result.Status == reassembly.StatusCompleted {
			completed = result.Packet
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(completed.Data, []byte("abcdef")) {
		t.Fatalf("completed data = %q", completed.Data)
	}
	if err := r.Release(completed.Handle); err != nil {
		t.Fatal(err)
	}
}

type payloadCollector struct{ payloads [][]byte }

func (c *payloadCollector) EmitCarrier(payload []byte) error {
	c.payloads = append(c.payloads, append([]byte(nil), payload...))
	return nil
}

// TestPackedMultiPacketRoundTrip fixes the essential product behavior that a
// carrier may contain fragments from different inner packets. Every carrier
// crosses the hidden IPv6 envelope before all records enter reassembly.
func TestPackedMultiPacketRoundTrip(t *testing.T) {
	t.Parallel()
	localAddress, err := peerroute.DeriveCarrierAddress(testPublicKey(10))
	if err != nil {
		t.Fatal(err)
	}
	peerAddress, err := peerroute.DeriveCarrierAddress(testPublicKey(20))
	if err != nil {
		t.Fatal(err)
	}

	collector := &payloadCollector{}
	var tx packetizer.Packetizer
	if err := tx.Init(make([]byte, limits.DefaultCarrierPayload), packetizer.Config{
		CarrierPayload: limits.DefaultCarrierPayload,
		MinPack:        limits.DefaultMinPackData,
	}, collector); err != nil {
		t.Fatal(err)
	}
	first := bytes.Repeat([]byte{0xa1}, 700)
	second := bytes.Repeat([]byte{0xb2}, 1500)
	if err := tx.Add(first, fragment.Metadata{DataSessionID: 3, LaneID: 4, LaneSequence: 100}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Add(second, fragment.Metadata{DataSessionID: 3, LaneID: 4, LaneSequence: 101}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(collector.payloads) < 2 {
		t.Fatalf("carrier count = %d, want packed multi-carrier output", len(collector.payloads))
	}

	rx, err := reassembly.New(reassembly.Config{
		Slots: 4, MaxPacketSize: limits.MaxInnerMTU, MaxPeers: 1, PerPeerSlots: 4, Lifetime: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	completed := make(map[uint32][]byte)
	for _, payload := range collector.payloads {
		outer := make([]byte, carrier.IPv6HeaderSize+len(payload))
		if _, err := carrier.MarshalEnvelopeTo(outer, peerAddress, localAddress, payload); err != nil {
			t.Fatal(err)
		}
		envelope, err := carrier.ParseEnvelope(outer, peerAddress, localAddress)
		if err != nil {
			t.Fatal(err)
		}
		if err := carrier.Parse(envelope.Payload, func(record carrier.Record) error {
			key := reassembly.Key{
				PeerID:        0,
				DataSessionID: record.Header.DataSessionID,
				LaneID:        record.Header.LaneID,
				LaneSequence:  record.Header.LaneSequence,
			}
			result, err := rx.Accept(time.Unix(200, 0), key, record)
			if err != nil {
				return err
			}
			if result.Status == reassembly.StatusCompleted {
				completed[key.LaneSequence] = append([]byte(nil), result.Packet.Data...)
				return rx.Release(result.Packet.Handle)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(completed[100], first) || !bytes.Equal(completed[101], second) {
		t.Fatalf("completed packets: first=%d second=%d", len(completed[100]), len(completed[101]))
	}
}

func testPublicKey(seed byte) []byte {
	key := make([]byte, peerroute.PublicKeySize)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}
