package dump

import (
	"bytes"
	"os/exec"
)

func parseCertificate(data []byte) ([]byte, error) {
	cmd := exec.Command("openssl", "x509", "-inform", "DER", "-text")
	cmd.Stdin = bytes.NewReader(data)
	return cmd.Output()
}
