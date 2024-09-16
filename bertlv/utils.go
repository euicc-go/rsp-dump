package bertlv

import (
	"encoding/binary"
	"github.com/pkg/errors"
)

func marshalLength(n int) []byte {
	switch {
	case n < 128:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func unmarshalLength(data []byte) (value, n int, err error) {
	if len(data) == 0 {
		err = errors.New("missing length")
		return
	}
	if data[0] < 128 {
		n, value = 1, int(data[0])
	} else if data[0] == 0x81 {
		n, value = 2, int(data[1])
	} else if data[0] == 0x82 {
		n, value = 3, int(binary.BigEndian.Uint16(data[1:3]))
	} else {
		err = errors.New("if length is greater than 127, first byte must indicate encoding of length")
	}
	if len(data)-min(n, 1) < 0 {
		err = errors.Errorf("indicated length encoding with %d bytes, but following byte are missing", n)
	}
	return
}
