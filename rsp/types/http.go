package types

import . "github.com/CursedHardware/go-rsp-dump/bertlv"

type GeneralResponse struct {
	Header Header `json:"header"`
}

type InitAuthenRequest struct {
	Challenge []byte `json:"euiccChallenge"`
	Address   string `json:"smdpAddress"`
	Info1     *TLV   `json:"euiccInfo1"`
}

type InitAuthenResponse struct {
	Header        Header `json:"header"`
	TransactionId string `json:"transactionId"`
	Signed1       *TLV   `json:"serverSigned1"`
	Signature1    *TLV   `json:"serverSignature1"`
	UsedIssuer    *TLV   `json:"euiccCiPKIdToBeUsed"`
	Certificate   *TLV   `json:"serverCertificate"`
}

type AuthenClientRequest struct {
	TransactionId string `json:"transactionId"`
	Response      *TLV   `json:"authenticateServerResponse"`
}
