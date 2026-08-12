package control

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewCodec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		max  int
		want error
	}{
		{name: "negative", max: -1, want: ErrInvalidMaxFrameSize},
		{name: "zero", max: 0, want: ErrInvalidMaxFrameSize},
		{name: "header only", max: HeaderSize, want: ErrInvalidMaxFrameSize},
		{name: "minimum", max: HeaderSize + 1},
		{name: "padded probe", max: 65_448},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec, err := NewCodec(tt.max)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewCodec(%d) error = %v, want %v", tt.max, err, tt.want)
			}
			if err == nil && codec.MaxFrameSize() != tt.max {
				t.Fatalf("MaxFrameSize() = %d, want %d", codec.MaxFrameSize(), tt.max)
			}
		})
	}
}

func TestCodecRoundTrip(t *testing.T) {
	t.Parallel()
	codec := mustCodec(t, 64)
	payload := []byte{0x08, 0x96, 0x01, 0x7a, 0x00}
	frame := make([]byte, HeaderSize+len(payload))

	n, err := codec.MarshalTo(frame, payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(frame) {
		t.Fatalf("MarshalTo() n = %d, want %d", n, len(frame))
	}

	want := append([]byte{0, 0, ProtocolVersion}, payload...)
	if !bytes.Equal(frame, want) {
		t.Fatalf("MarshalTo() = %x, want %x", frame, want)
	}

	got, err := codec.Parse(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Parse() = %x, want %x", got, payload)
	}
	frame[HeaderSize] ^= 0xff
	if got[0] != frame[HeaderSize] {
		t.Fatal("Parse() payload does not alias frame")
	}
}

func TestMarshalToRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	codec := mustCodec(t, 8)
	tests := []struct {
		name    string
		dst     []byte
		payload []byte
		want    error
	}{
		{name: "empty payload", dst: make([]byte, 8), want: ErrEmptyPayload},
		{name: "frame too large", dst: make([]byte, 9), payload: make([]byte, 6), want: ErrFrameTooLarge},
		{name: "short destination", dst: make([]byte, 7), payload: make([]byte, 5), want: ErrShortBuffer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := codec.MarshalTo(tt.dst, tt.payload); !errors.Is(err, tt.want) {
				t.Fatalf("MarshalTo() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestMarshalToSupportsOverlappingPayload(t *testing.T) {
	t.Parallel()
	codec := mustCodec(t, 16)
	buffer := []byte{0x08, 0x01, 0x10, 0x02, 0, 0, 0, 0}
	wantPayload := append([]byte(nil), buffer[:4]...)
	n, err := codec.MarshalTo(buffer, buffer[:4])
	if err != nil {
		t.Fatal(err)
	}

	want := append([]byte{0, 0, ProtocolVersion}, wantPayload...)
	if !bytes.Equal(buffer[:n], want) {
		t.Fatalf("MarshalTo(overlap) = %x, want %x", buffer[:n], want)
	}
}

func TestParseRejectsMalformedFrames(t *testing.T) {
	t.Parallel()
	codec := mustCodec(t, 8)
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{name: "empty", frame: nil, want: ErrFrameTooShort},
		{name: "one byte", frame: []byte{0}, want: ErrFrameTooShort},
		{name: "marker only", frame: []byte{0, 0}, want: ErrFrameTooShort},
		{name: "DATA marker", frame: []byte{0, 12, ProtocolVersion, 1}, want: ErrInvalidMarker},
		{name: "old version", frame: []byte{0, 0, 0, 1}, want: ErrUnsupportedVersion},
		{name: "future version", frame: []byte{0, 0, 2, 1}, want: ErrUnsupportedVersion},
		{name: "empty protobuf", frame: []byte{0, 0, ProtocolVersion}, want: ErrEmptyPayload},
		{name: "frame too large", frame: []byte{0, 0, ProtocolVersion, 1, 2, 3, 4, 5, 6}, want: ErrFrameTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := codec.Parse(tt.frame); !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParsePreservesEntireOpaquePayload(t *testing.T) {
	t.Parallel()
	codec := mustCodec(t, 16)
	frame := []byte{0, 0, ProtocolVersion, 0x08, 0x01, 0xaa, 0xbb}
	got, err := codec.Parse(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, frame[HeaderSize:]) {
		t.Fatalf("Parse() = %x, want complete payload %x", got, frame[HeaderSize:])
	}
}

func TestZeroValueCodecIsRejected(t *testing.T) {
	t.Parallel()
	var codec Codec
	if _, err := codec.Parse([]byte{0, 0, ProtocolVersion, 1}); !errors.Is(err, ErrInvalidMaxFrameSize) {
		t.Fatalf("Parse() error = %v, want ErrInvalidMaxFrameSize", err)
	}
	if _, err := codec.MarshalTo(make([]byte, 4), []byte{1}); !errors.Is(err, ErrInvalidMaxFrameSize) {
		t.Fatalf("MarshalTo() error = %v, want ErrInvalidMaxFrameSize", err)
	}
}

func FuzzCodecParseRoundTrip(f *testing.F) {
	codec, err := NewCodec(613)
	if err != nil {
		f.Fatal(err)
	}
	valid := []byte{0, 0, ProtocolVersion, 0x08, 0x01}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0, 12, 1, 1})
	f.Add(make([]byte, 614))

	f.Fuzz(func(t *testing.T, frame []byte) {
		payload, err := codec.Parse(frame)
		if err != nil {
			return
		}
		encoded := make([]byte, len(frame))
		n, err := codec.MarshalTo(encoded, payload)
		if err != nil {
			t.Fatalf("MarshalTo(parsed frame): %v", err)
		}
		if n != len(frame) || !bytes.Equal(encoded[:n], frame) {
			t.Fatalf("round trip mismatch: got %x, want %x", encoded[:n], frame)
		}
	})
}

var (
	allocationPayloadSink []byte
	allocationSizeSink    int
	allocationErrorSink   error
)

func TestCodecDoesNotAllocate(t *testing.T) {
	codec := mustCodec(t, 613)
	payload := make([]byte, 610)
	frame := make([]byte, 613)

	marshalAllocs := testing.AllocsPerRun(1000, func() {
		allocationSizeSink, allocationErrorSink = codec.MarshalTo(frame, payload)
	})
	if allocationErrorSink != nil {
		t.Fatal(allocationErrorSink)
	}
	if allocationSizeSink != len(frame) {
		t.Fatalf("MarshalTo() n = %d, want %d", allocationSizeSink, len(frame))
	}
	if marshalAllocs != 0 {
		t.Fatalf("MarshalTo() allocations = %v, want 0", marshalAllocs)
	}

	parseAllocs := testing.AllocsPerRun(1000, func() {
		allocationPayloadSink, allocationErrorSink = codec.Parse(frame)
	})
	if allocationErrorSink != nil {
		t.Fatal(allocationErrorSink)
	}
	if len(allocationPayloadSink) != len(payload) {
		t.Fatalf("Parse() payload length = %d, want %d", len(allocationPayloadSink), len(payload))
	}
	if parseAllocs != 0 {
		t.Fatalf("Parse() allocations = %v, want 0", parseAllocs)
	}
}

func mustCodec(t *testing.T, maxFrameSize int) Codec {
	t.Helper()
	codec, err := NewCodec(maxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}
