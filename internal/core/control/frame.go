package control

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// HeaderSize is the fixed CONTROL frame header size in bytes.
	HeaderSize = 3
	// Marker distinguishes a CONTROL frame from DATA records.
	Marker uint16 = 0
	// ProtocolVersion is the only CONTROL framing version accepted by v1.
	ProtocolVersion uint8 = 1
)

var (
	// ErrInvalidMaxFrameSize reports a codec limit too small to hold a valid
	// CONTROL frame, including at least one protobuf payload byte.
	ErrInvalidMaxFrameSize = errors.New("control: invalid maximum frame size")
	// ErrFrameTooShort reports an input shorter than the fixed frame header.
	ErrFrameTooShort = errors.New("control: frame header too short")
	// ErrInvalidMarker reports a payload that is not a CONTROL frame.
	ErrInvalidMarker = errors.New("control: invalid marker")
	// ErrUnsupportedVersion reports a CONTROL framing version other than v1.
	ErrUnsupportedVersion = errors.New("control: unsupported protocol version")
	// ErrEmptyPayload reports a frame with no protobuf payload.
	ErrEmptyPayload = errors.New("control: empty protobuf payload")
	// ErrFrameTooLarge reports a frame exceeding the configured carrier
	// payload limit.
	ErrFrameTooLarge = errors.New("control: frame exceeds maximum size")
	// ErrShortBuffer is returned by MarshalTo when dst cannot hold the frame.
	ErrShortBuffer = io.ErrShortBuffer
)

// Codec validates and encodes v1 CONTROL frames. MaxFrameSize includes the
// fixed CONTROL header and is normally the maximum carrier payload accepted
// by the peer/path. A Codec must be constructed with NewCodec.
//
// Codec only frames opaque protobuf bytes. Protobuf validation, padding rules,
// request correlation, and state transitions belong to higher layers.
type Codec struct {
	maxFrameSize int
}

// NewCodec returns a v1 CONTROL frame codec. maxFrameSize includes HeaderSize
// and must leave room for at least one protobuf payload byte. Limits large
// enough for padded MTU probes are valid.
func NewCodec(maxFrameSize int) (Codec, error) {
	if maxFrameSize < HeaderSize+1 {
		return Codec{}, ErrInvalidMaxFrameSize
	}
	return Codec{maxFrameSize: maxFrameSize}, nil
}

// MaxFrameSize returns the configured maximum complete CONTROL frame size.
func (c Codec) MaxFrameSize() int {
	return c.maxFrameSize
}

// MarshalTo writes one complete v1 CONTROL frame to dst and returns its size.
// protobufPayload must contain a complete, non-empty protobuf message. The
// method does not allocate. The payload may alias dst; copy semantics are the
// same as the built-in copy function.
func (c Codec) MarshalTo(dst, protobufPayload []byte) (int, error) {
	if len(protobufPayload) == 0 {
		return 0, ErrEmptyPayload
	}
	if c.maxFrameSize < HeaderSize+1 {
		return 0, ErrInvalidMaxFrameSize
	}
	if len(protobufPayload) > c.maxFrameSize-HeaderSize {
		return 0, ErrFrameTooLarge
	}

	frameSize := HeaderSize + len(protobufPayload)
	if len(dst) < frameSize {
		return 0, ErrShortBuffer
	}

	// Copy first so payload may safely overlap the beginning of dst.
	copy(dst[HeaderSize:frameSize], protobufPayload)
	binary.BigEndian.PutUint16(dst[0:2], Marker)
	dst[2] = ProtocolVersion
	return frameSize, nil
}

// Parse strictly validates one complete v1 CONTROL carrier payload. The
// returned protobuf payload aliases frame and remains valid only while frame
// is unchanged. Parse does not allocate or interpret protobuf bytes.
func (c Codec) Parse(frame []byte) ([]byte, error) {
	if len(frame) < HeaderSize {
		return nil, ErrFrameTooShort
	}
	if binary.BigEndian.Uint16(frame[0:2]) != Marker {
		return nil, ErrInvalidMarker
	}
	if frame[2] != ProtocolVersion {
		return nil, ErrUnsupportedVersion
	}
	if c.maxFrameSize < HeaderSize+1 {
		return nil, ErrInvalidMaxFrameSize
	}
	if len(frame) > c.maxFrameSize {
		return nil, ErrFrameTooLarge
	}
	if len(frame) == HeaderSize {
		return nil, ErrEmptyPayload
	}
	return frame[HeaderSize:], nil
}
