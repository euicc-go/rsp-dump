package main

import (
	"github.com/CursedHardware/go-rsp-dump/bertlv"
	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
)

func onAuthenClient(response *bertlv.TLV) (err error) {
	var report dump.Report
	if err = report.UnmarshalBerTLV(response); err != nil {
		return
	}
	message := dump.NewMailMessage(&report, config.HostTemplate)
	message.SetHeaders(config.SMTPHeaders)
	return smtpClient.DialAndSend(message)
}
