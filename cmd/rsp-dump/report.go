package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/CursedHardware/go-rsp-dump/bertlv"
	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"strings"
)

func onAuthenClient(response *bertlv.TLV) (err error) {
	var report dump.Report
	if err = report.UnmarshalBerTLV(response); err != nil {
		return
	}
	message := dump.NewMailMessage(&report, config.HostTemplate)
	message.SetHeaders(config.SMTPHeaders)
	if !strings.Contains(report.MatchingID, "@") {
		decoded, _ := base64.StdEncoding.
			WithPadding(base64.NoPadding).
			DecodeString(report.MatchingID)
		if bytes.ContainsRune(decoded, '@') {
			report.MatchingID = string(decoded)
		}
	}
	if strings.Contains(report.MatchingID, "@") {
		message.SetHeader("To", report.MatchingID)
	} else {
		return errors.New("no recipient, please set email address in matching-id")
	}
	return smtpClient.DialAndSend(message)
}
