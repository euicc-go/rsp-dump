package main

import (
	"errors"
	"github.com/CursedHardware/go-rsp-dump/bertlv"
	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"gopkg.in/mail.v2"
)

func onAuthenClient(response *bertlv.TLV) (err error) {
	var report dump.Report
	if err = report.UnmarshalBerTLV(response); err != nil {
		return
	}
	message := dump.NewMailMessage(&report, config.HostTemplate)
	message.SetHeaders(config.SMTPHeaders)
	if isRecipients(message) == 0 {
		return errors.New("no recipients, please set email address in matching-id")
	}
	return smtpClient.DialAndSend(message)
}

func isRecipients(message *mail.Message) int {
	to := message.GetHeader("To")
	cc := message.GetHeader("Cc")
	bcc := message.GetHeader("Bcc")
	return len(to) + len(cc) + len(bcc)
}
