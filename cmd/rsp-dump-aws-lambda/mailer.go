package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"

	"gopkg.in/mail.v2"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
)

//go:embed mail-tpl.gohtml
var mailTemplate string

func NewMailMessage(report *dump.Report, issuerDomain string) *mail.Message {
	message := mail.NewMessage()
	if info2, _ := json.MarshalIndent(&report.EUICCInfo2, "", "  "); info2 != nil {
		message.AttachReader("EUICCInfo2.json", bytes.NewReader(info2), mail.SetHeader(map[string][]string{
			"Content-Type": {"text/plain"},
		}))
	}
	var eid, issuer string
	if data, _ := report.EUICCCertificate.MarshalBinary(); data != nil {
		opensslParsed := dump.ParseCertificate(data)
		filename := fmt.Sprintf("EUICC-%02x.pem", sha1.Sum(data))
		if parsed, _ := x509.ParseCertificate(data); parsed != nil {
			eid = parsed.Subject.SerialNumber
			filename = fmt.Sprintf("EUICC-%s-%02x.pem", eid[0:8], parsed.AuthorityKeyId[0:3])
		}
		message.AttachReader(filename, bytes.NewReader(opensslParsed), mail.SetHeader(map[string][]string{
			"Content-Type": {"text/plain"},
		}))
	}
	if data, _ := report.EUMCertificate.MarshalBinary(); data != nil {
		opensslParsed := dump.ParseCertificate(data)
		filename := fmt.Sprintf("EUM-%02x.pem", sha1.Sum(data))
		if parsed, _ := x509.ParseCertificate(data); parsed != nil {
			issuer = hex.EncodeToString(parsed.AuthorityKeyId)
			filename = fmt.Sprintf("EUM-%s-%02x.pem", issuer[0:6], parsed.SubjectKeyId[0:3])
		}
		message.AttachReader(filename, bytes.NewReader(opensslParsed), mail.SetHeader(map[string][]string{
			"Content-Type": {"text/plain"},
		}))
	}
	subject := "RSP Dump Report"
	if len(eid) == 32 && len(issuer) == 40 {
		subject = fmt.Sprintf("%s (%s)", eid[0:16], issuer[0:6])
	}
	message.SetHeader("Subject", subject)
	message.SetBodyWriter("text/html", func(w io.Writer) error {
		tpl, err := template.New(eid).Parse(mailTemplate)
		if err != nil {
			return err
		}
		data := new(struct {
			Subject    string
			EID        string
			UsedIssuer string
			IssuerHost string
			FreeNVRAM  float64
			*dump.Report
		})
		data.Subject = subject
		data.EID = eid
		data.UsedIssuer = issuer
		data.IssuerHost = issuerDomain
		data.FreeNVRAM = float64(report.EUICCInfo2.ExtCardResource.FreeNVRAM) / 1024
		data.Report = report
		return tpl.Execute(w, data)
	})
	return message
}
