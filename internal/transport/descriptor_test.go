package transport

import (
	"bytes"
	"testing"
)

func TestDescriptorBytesValidatesBorrowedLength(t *testing.T) {
	t.Parallel()
	payload := []byte{1, 2, 3}

	tests := []struct {
		name   string
		length int
		want   []byte
	}{
		{name: "empty", length: 0, want: []byte{}},
		{name: "partial", length: 2, want: []byte{1, 2}},
		{name: "full", length: len(payload), want: payload},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, descriptor := range []interface{ Bytes() []byte }{
				TXDescriptor{Payload: payload, Length: test.length},
				RXDescriptor{Payload: payload, Length: test.length},
			} {
				if got := descriptor.Bytes(); !bytes.Equal(got, test.want) {
					t.Fatalf("Bytes() = %v, want %v", got, test.want)
				}
			}
		})
	}
	for _, length := range []int{-1, len(payload) + 1} {
		for _, descriptor := range []interface{ Bytes() []byte }{
			TXDescriptor{Payload: payload, Length: length},
			RXDescriptor{Payload: payload, Length: length},
		} {
			if got := descriptor.Bytes(); got != nil {
				t.Fatalf("Bytes(length=%d) = %v, want nil", length, got)
			}
		}
	}
}
