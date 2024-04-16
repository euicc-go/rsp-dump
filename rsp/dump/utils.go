package dump

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"os/exec"
)

func parseCertificate(data []byte) (output []byte) {
	cmd := exec.Command("openssl", "x509", "-inform", "DER", "-text")
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
