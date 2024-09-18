package dump

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"github.com/euicc-go/bertlv"
	"os/exec"
	"strings"
)

var (
	certOpts     = []string{"ext_parse"}
	certNameOpts = []string{"sep_multiline", "space_eq", "lname", "utf8"}
)

func parseCertificate(data []byte) (output []byte) {
	cmd := exec.Command(
		"openssl", "x509",
		"-inform", "DER",
		"-text",
		"-certopt", strings.Join(certOpts, ","),
		"-nameopt", strings.Join(certNameOpts, ","),
	)
	cmd.Stdin = bytes.NewReader(data)
	if output, _ = cmd.Output(); output == nil {
		output = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: data,
		})
	}
	return output
}

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
