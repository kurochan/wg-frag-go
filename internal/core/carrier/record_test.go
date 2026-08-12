package carrier

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestMarshalTo(t *testing.T) {
	t.Parallel()
	header := Header{
		FragmentIndex: 1,
		FragmentCount: 3,
		LaneID:        0x56,
		DataSessionID: 0x1234,
		LaneSequence:  0x789abcde,
		Offset:        0x0102,
	}
	data := []byte{0xaa, 0xbb, 0xcc}
	want := []byte{
		0x00, 0x0f,
		0x12,
		0x56,
		0x12, 0x34,
		0x78, 0x9a, 0xbc, 0xde,
		0x01, 0x02,
		0xaa, 0xbb, 0xcc,
	}

	dst := make([]byte, len(want))
	n, err := MarshalTo(dst, header, data)
	if err != nil {
		t.Fatalf("MarshalTo() error = %v", err)
	}
	if n != len(want) {
		t.Fatalf("MarshalTo() n = %d, want %d", n, len(want))
	}
	if !bytes.Equal(dst, want) {
		t.Fatalf("MarshalTo() = %x, want %x", dst, want)
	}
}

func TestMarshalToRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	valid := Header{FragmentCount: 1, DataSessionID: 1}
	tests := []struct {
		name   string
		dst    []byte
		header Header
		data   []byte
		want   error
	}{
		{name: "short destination", dst: make([]byte, HeaderSize), header: valid, data: []byte{1}, want: io.ErrShortBuffer},
		{name: "empty data", dst: make([]byte, HeaderSize), header: valid, want: ErrInvalidRecordLength},
		{name: "zero fragment count", dst: make([]byte, 32), header: Header{DataSessionID: 1}, data: []byte{1}, want: ErrInvalidFragment},
		{name: "too many fragments", dst: make([]byte, 32), header: Header{FragmentCount: 17, DataSessionID: 1}, data: []byte{1}, want: ErrInvalidFragment},
		{name: "index equals count", dst: make([]byte, 32), header: Header{FragmentIndex: 2, FragmentCount: 2, DataSessionID: 1}, data: []byte{1}, want: ErrInvalidFragment},
		{name: "zero session", dst: make([]byte, 32), header: Header{FragmentCount: 1}, data: []byte{1}, want: ErrInvalidDataSessionID},
		{name: "range overflow", dst: make([]byte, 32), header: Header{FragmentCount: 1, DataSessionID: 1, Offset: maxUint16}, data: []byte{1}, want: ErrInvalidRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := MarshalTo(tt.dst, tt.header, tt.data); !errors.Is(err, tt.want) {
				t.Fatalf("MarshalTo() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDecodeRecord(t *testing.T) {
	t.Parallel()
	firstHeader := Header{FragmentCount: 2, LaneID: 3, DataSessionID: 7, LaneSequence: 99}
	secondHeader := Header{FragmentIndex: 1, FragmentCount: 2, LaneID: 3, DataSessionID: 7, LaneSequence: 99, Offset: 2}
	payload := make([]byte, 2*(HeaderSize+2))
	n, err := MarshalTo(payload, firstHeader, []byte{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalTo(payload[n:], secondHeader, []byte{3, 4}); err != nil {
		t.Fatal(err)
	}

	var got []Record
	if err := Parse(payload, func(record Record) error {
		got = append(got, record)
		return nil
	}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Parse() records = %d, want 2", len(got))
	}
	if got[0].Header != firstHeader || !bytes.Equal(got[0].Data, []byte{1, 2}) {
		t.Fatalf("first record = %#v", got[0])
	}
	if got[1].Header != secondHeader || !bytes.Equal(got[1].Data, []byte{3, 4}) {
		t.Fatalf("second record = %#v", got[1])
	}

	payload[HeaderSize] = 9
	if got[0].Data[0] != 9 {
		t.Fatal("decoded data does not alias payload")
	}
}

func TestParseRejectsMalformedPayload(t *testing.T) {
	t.Parallel()
	validHeader := Header{FragmentCount: 1, DataSessionID: 1}
	valid := make([]byte, HeaderSize+1)
	if _, err := MarshalTo(valid, validHeader, []byte{1}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{name: "empty", payload: nil, want: ErrHeaderTooShort},
		{name: "short header", payload: make([]byte, HeaderSize-1), want: ErrHeaderTooShort},
		{name: "header only length", payload: append([]byte(nil), valid...), want: ErrInvalidRecordLength},
		{name: "truncated record", payload: append([]byte(nil), valid...), want: ErrRecordTruncated},
		{name: "zero session", payload: append([]byte(nil), valid...), want: ErrInvalidDataSessionID},
		{name: "index out of range", payload: append([]byte(nil), valid...), want: ErrInvalidFragment},
		{name: "byte range overflow", payload: append([]byte(nil), valid...), want: ErrInvalidRange},
		{name: "trailing bytes", payload: append(append([]byte(nil), valid...), 1, 2), want: ErrHeaderTooShort},
	}

	tests[2].payload[0], tests[2].payload[1] = 0, HeaderSize
	tests[3].payload[0], tests[3].payload[1] = 0, HeaderSize+2
	tests[4].payload[4], tests[4].payload[5] = 0, 0
	tests[5].payload[2] = 0x10
	tests[6].payload[10], tests[6].payload[11] = 0xff, 0xff

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Parse(tt.payload, nil); !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParsePropagatesVisitorError(t *testing.T) {
	t.Parallel()
	payload := make([]byte, HeaderSize+1)
	if _, err := MarshalTo(payload, Header{FragmentCount: 1, DataSessionID: 1}, []byte{1}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("stop")
	if err := Parse(payload, func(Record) error { return want }); !errors.Is(err, want) {
		t.Fatalf("Parse() error = %v, want %v", err, want)
	}
}

func FuzzParseRoundTrip(f *testing.F) {
	seed := make([]byte, HeaderSize+3)
	_, _ = MarshalTo(seed, Header{FragmentIndex: 1, FragmentCount: 2, LaneID: 2, DataSessionID: 1, LaneSequence: 3, Offset: 4}, []byte{5, 6, 7})
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0, 13})

	f.Fuzz(func(t *testing.T, payload []byte) {
		var records []Record
		if err := Parse(payload, func(record Record) error {
			records = append(records, record)
			return nil
		}); err != nil {
			return
		}

		encoded := make([]byte, len(payload))
		offset := 0
		for _, record := range records {
			n, err := MarshalTo(encoded[offset:], record.Header, record.Data)
			if err != nil {
				t.Fatalf("MarshalTo(decoded record): %v", err)
			}
			offset += n
		}
		if offset != len(payload) || !bytes.Equal(encoded, payload) {
			t.Fatalf("round trip mismatch: got %x, want %x", encoded[:offset], payload)
		}
	})
}
