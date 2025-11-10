package main

import (
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
)

func NewJSON(report *dump.Report) (string, error) {
	var eid, issuer string

	if data, _ := report.EUICCCertificate.MarshalBinary(); data != nil {
		if parsed, _ := x509.ParseCertificate(data); parsed != nil {
			eid = parsed.Subject.SerialNumber
		}
	}

	if data, _ := report.EUMCertificate.MarshalBinary(); data != nil {
		if parsed, _ := x509.ParseCertificate(data); parsed != nil {
			issuer = hex.EncodeToString(parsed.AuthorityKeyId)
		}
	}

	data := struct {
		EID          string           `json:"eid"`
		UsedIssuer   string           `json:"used_issuer"`
		FreeNVRAM    float64          `json:"free_nvram_kb"`
		EUICCInfo2   *dump.EUICCInfo2 `json:"euicc_info2"`
		Certificates struct {
			EUICC string `json:"euicc,omitempty"`
			EUM   string `json:"eum,omitempty"`
		} `json:"certificates"`
	}{
		EID:        eid,
		UsedIssuer: issuer,
		FreeNVRAM:  float64(report.EUICCInfo2.ExtCardResource.FreeNVRAM) / 1024,
		EUICCInfo2: &report.EUICCInfo2,
	}

	if euiccData, _ := report.EUICCCertificate.MarshalBinary(); euiccData != nil {
		data.Certificates.EUICC = string(dump.ParseCertificate(euiccData))
	}

	if eumData, _ := report.EUMCertificate.MarshalBinary(); eumData != nil {
		data.Certificates.EUM = string(dump.ParseCertificate(eumData))
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}
