//go:build !wasm

package utils

import (
	"bytes"
	"encoding/pem"
	"os/exec"
	"strings"
)

var certOpts = []string{"ext_parse"}
var certNameOpts = []string{"sep_multiline", "space_eq", "lname", "utf8"}

func ParseCertificate(data []byte) []byte {
	cmd := exec.Command(
		"openssl", "x509",
		"-inform", "DER",
		"-text",
		"-certopt", strings.Join(certOpts, ","),
		"-nameopt", strings.Join(certNameOpts, ","),
	)
	cmd.Stdin = bytes.NewReader(data)
	output, err := cmd.Output()
	if err != nil || output == nil {
		output = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: data,
		})
	}
	return output
}
