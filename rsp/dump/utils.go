package dump

import (
	"encoding/asn1"
	"encoding/binary"
	
	"github.com/euicc-go/bertlv"
)

func variant(b []byte) uint64 {
	dst := make([]byte, 8)
	copy(dst[8-len(b):], b)
	return binary.BigEndian.Uint64(dst)
}

func toBits(tlv *bertlv.TLV, definitions ...string) (features []string) {
	bits := &asn1.BitString{
		Bytes:     tlv.Value[1:],
		BitLength: (len(tlv.Value)-1)*8 - int(tlv.Value[0]),
	}
	for index := 0; index < min(bits.BitLength, len(definitions)); index++ {
		if bits.At(index) == 1 {
			features = append(features, definitions[index])
		}
	}
	return
}
