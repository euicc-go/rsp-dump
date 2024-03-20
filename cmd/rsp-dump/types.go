package main

import (
	"regexp"
)

type Configuration struct {
	Listen       string              `json:"listen"`
	Homepage     string              `json:"homepage_url"`
	HostPattern  *regexp.Regexp      `json:"host_pattern"`
	HostTemplate string              `json:"host_template"`
	CertFile     string              `json:"cert_file"`
	KeyFile      string              `json:"key_file"`
	LogFile      string              `json:"log_file"`
	SMTPHost     string              `json:"smtp_host"`
	SMTPPort     uint16              `json:"smtp_port"`
	SMTPUsername string              `json:"smtp_username"`
	SMTPPassword string              `json:"smtp_password"`
	SMTPHeaders  map[string][]string `json:"smtp_headers"`
}
