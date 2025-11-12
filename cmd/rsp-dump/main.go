package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"gopkg.in/mail.v2"
)

var smtpClient *mail.Dialer

var config = Configuration{
	Listen:      "localhost:33000",
	Homepage:    "https://septs.blog/posts/rsp-dump/",
	HostPattern: regexp.MustCompile(`^(?P<issuer>[a-f0-9]{6,40})\.rsp\.`),
	LogFile:     "rsp-report.log",
	SMTPPort:    587,
	SMTPHeaders: make(map[string][]string),
}

func init() {
	var configFile string
	flag.StringVar(&configFile, "config-file", "rsp-config.json", "Configuration file path")
	flag.Parse()
	if fp, err := os.Open(configFile); err != nil {
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
	log.Println("Starting")
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	handler := &dump.Handler{
		Homepage:       config.Homepage,
		Client:         http.DefaultClient,
		GetIssuerHost:  getIssuerHost,
		HostPattern:    config.HostPattern,
		OnAuthenClient: onAuthenClient,
	}
	if logFile, err := os.OpenFile(config.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666); err == nil {
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	}
	log.Println("Started,", strconv.Quote(config.Listen))
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		log.Panicln(err)
	}
	defer listener.Close()
	tlsConfig := &tls.Config{
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{TestCI},
	}
	if config.CertFile != "" && config.KeyFile != "" {
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			log.Panicln(err)
		}
	}
	listener = tls.NewListener(listener, tlsConfig)
	if err = http.Serve(listener, handler); err != nil {
		log.Panicln(err)
	}
}

func getIssuerHost(keyId string) (string, error) {
	var issuers map[string][]string
	fp, err := os.Open("rsp-registry.json")
	if err != nil {
		panic(err)
	}
	if err = json.NewDecoder(fp).Decode(&issuers); err != nil {
		panic(err)
	}
	if hosts, ok := issuers[keyId]; ok && len(hosts) > 0 {
		return hosts[rand.IntN(len(hosts))], nil
	}
	return "", fmt.Errorf("issuer not found: %s", keyId)
}
