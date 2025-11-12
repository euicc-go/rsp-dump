package utils

import (
	"crypto/x509"
	_ "embed"
	"encoding/hex"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
)

func NewJSONStruct(report *dump.Report) (*JSONReport, error) {
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

	result := &JSONReport{
		EID:        eid,
		UsedIssuer: issuer,
		FreeNVRAM:  float64(report.EUICCInfo2.ExtCardResource.FreeNVRAM) / 1024,
		EUICCInfo2: &report.EUICCInfo2,
	}

	if euiccData, _ := report.EUICCCertificate.MarshalBinary(); euiccData != nil {
		result.Certificates.EUICC = string(ParseCertificate(euiccData))
	}

	if eumData, _ := report.EUMCertificate.MarshalBinary(); eumData != nil {
		result.Certificates.EUM = string(ParseCertificate(eumData))
	}

	return result, nil
}
