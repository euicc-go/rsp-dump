package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"github.com/CursedHardware/go-rsp-dump/rsp/types"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/euicc-go/bertlv"
	"gopkg.in/mail.v2"
)

var config = Configuration{
	Homepage:    "https://septs.blog/posts/rsp-dump/",
	HostPattern: regexp.MustCompile(`^(?P<issuer>[a-f0-9]{6,40})\.rsp\.`),
	SMTPPort:    587,
	SMTPHeaders: make(map[string][]string),
}

var smtpClient *mail.Dialer

func init() {
	if fp, err := os.Open("rsp-config.json"); err != nil {
		log.Fatalln(err)
	} else if err = json.NewDecoder(fp).Decode(&config); err != nil {
		log.Fatalln(err)
	}
	if _, ok := config.SMTPHeaders["From"]; !ok {
		config.SMTPHeaders["From"] = []string{config.SMTPUsername}
	}
	smtpClient = mail.NewDialer(config.SMTPHost, int(config.SMTPPort), config.SMTPUsername, config.SMTPPassword)
	smtpClient.StartTLSPolicy = mail.MandatoryStartTLS
}

func main() {
	log.SetFlags(0)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	handler := &dump.Handler{
		Homepage:       config.Homepage,
		Client:         http.DefaultClient,
		OnInitAuthen:   onInitAuthen,
		OnAuthenClient: onAuthenClient,
	}
	lambda.Start(httpadapter.New(handler).ProxyWithContext)
}

func mustRSPRegistry() (issuers map[string][]string) {
	fp, err := os.Open("rsp-registry.json")
	if err != nil {
		panic(err)
	}
	if err = json.NewDecoder(fp).Decode(&issuers); err != nil {
		panic(err)
	}
	return
}

func onInitAuthen(svn *bertlv.TLV, r *types.InitAuthenRequest) error {
	registry := mustRSPRegistry()

	if issuer, hostTmp, errTmp := dump.FindIssuerFromHost(r.Address, config.HostPattern, registry); errTmp == nil {
		r.Info1 = dump.NewInfo1(issuer, svn, r.Info1.Tag)
		r.Address = hostTmp
	} else if issuer, hostTmp, errTmp := dump.FindIssuerFromIssuers(dump.GetIssuersFromInfo1(r.Info1), registry); errTmp == nil {
		r.Info1 = dump.NewInfo1(issuer, svn, r.Info1.Tag)
		r.Address = hostTmp
	} else {
		return dump.ErrNotFound
	}
	return nil
}
