package carrier

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// HeaderSize is the encoded DATA record header size in bytes.
	HeaderSize    = 12
	minRecordSize = HeaderSize + 1
	maxUint16     = 1<<16 - 1
)

var (
	// ErrHeaderTooShort and the related errors are stable sentinels for drop accounting.
	ErrHeaderTooShort       = errors.New("carrier: record header too short")
	ErrRecordTruncated      = errors.New("carrier: record length exceeds payload")
	ErrInvalidRecordLength  = errors.New("carrier: invalid record length")
	ErrInvalidFragment      = errors.New("carrier: invalid fragment index or count")
	ErrInvalidDataSessionID = errors.New("carrier: data session ID must be non-zero")
	ErrInvalidRange         = errors.New("carrier: fragment byte range is invalid")
)

// Header contains the fixed fields of a DATA record. FragmentIndex is
// zero-based and FragmentCount is in the range 1..16.
type Header struct {
	FragmentIndex uint8
	FragmentCount uint8
	LaneID        uint8
	DataSessionID uint16
	LaneSequence  uint32
	Offset        uint16
}

// Record is a decoded DATA record. Data aliases the input carrier payload.
type Record struct {
	Header Header
	Data   []byte
}

// MarshalTo encodes one DATA record into dst and returns the number of bytes
// written. The record length is derived from data and includes HeaderSize.
// MarshalTo does not allocate.
func MarshalTo(dst []byte, header Header, data []byte) (int, error) {
	if err := validate(header, len(data)); err != nil {
		return 0, err
	}

	recordLen := HeaderSize + len(data)
	if len(dst) < recordLen {
		return 0, io.ErrShortBuffer
	}

	binary.BigEndian.PutUint16(dst[0:2], uint16(recordLen))
	dst[2] = header.FragmentIndex<<4 | (header.FragmentCount - 1)
	dst[3] = header.LaneID
	binary.BigEndian.PutUint16(dst[4:6], header.DataSessionID)
	binary.BigEndian.PutUint32(dst[6:10], header.LaneSequence)
	binary.BigEndian.PutUint16(dst[10:12], header.Offset)
	copy(dst[HeaderSize:recordLen], data)
	return recordLen, nil
}

// DecodeRecord decodes the first DATA record in src. It returns a zero-copy
// Record and the number of bytes consumed; trailing bytes are left for the
// caller. Use Parse to validate an entire carrier payload.
func DecodeRecord(src []byte) (Record, int, error) {
	if len(src) < HeaderSize {
		return Record{}, 0, ErrHeaderTooShort
	}

	recordLen := int(binary.BigEndian.Uint16(src[0:2]))
	if recordLen < minRecordSize {
		return Record{}, 0, ErrInvalidRecordLength
	}
	if recordLen > len(src) {
		return Record{}, 0, ErrRecordTruncated
	}

	fragment := src[2]
	header := Header{
		FragmentIndex: fragment >> 4,
		FragmentCount: fragment&0x0f + 1,
		LaneID:        src[3],
		DataSessionID: binary.BigEndian.Uint16(src[4:6]),
		LaneSequence:  binary.BigEndian.Uint32(src[6:10]),
		Offset:        binary.BigEndian.Uint16(src[10:12]),
	}
	data := src[HeaderSize:recordLen]
	if err := validate(header, len(data)); err != nil {
		return Record{}, 0, err
	}

	return Record{Header: header, Data: data}, recordLen, nil
}

// Parse strictly decodes every DATA record in payload. It rejects an empty
// payload and any trailing partial record. visit may be nil for validation
// only. Record.Data aliases payload and is only valid while payload remains
// unchanged.
func Parse(payload []byte, visit func(Record) error) error {
	if len(payload) == 0 {
		return ErrHeaderTooShort
	}

	for len(payload) > 0 {
		record, consumed, err := DecodeRecord(payload)
		if err != nil {
			return err
		}
		if visit != nil {
			if err := visit(record); err != nil {
				return err
			}
		}
		payload = payload[consumed:]
	}
	return nil
}

func validate(header Header, dataLen int) error {
	if header.FragmentCount < 1 || header.FragmentCount > 16 || header.FragmentIndex >= header.FragmentCount {
		return ErrInvalidFragment
	}
	if header.DataSessionID == 0 {
		return ErrInvalidDataSessionID
	}
	if dataLen < 1 || dataLen > maxUint16-HeaderSize {
		return ErrInvalidRecordLength
	}
	if int(header.Offset)+dataLen > maxUint16 {
		return ErrInvalidRange
	}
	return nil
}
