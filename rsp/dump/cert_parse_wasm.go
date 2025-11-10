//go:build wasm

package dump

import (
	"encoding/pem"
)

func ParseCertificate(data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: data,
	})
}
