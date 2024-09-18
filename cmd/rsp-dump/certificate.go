package main

import (
	"crypto/tls"
	_ "embed"
)

//go:embed certificate/CERT_S_SM_DP_TLS_NIST.pem
var testCICert []byte

//go:embed certificate/SK_S_SM_DP_TLS_NIST.pem
var testCISK []byte

var TestCI, _ = tls.X509KeyPair(testCICert, testCISK)
