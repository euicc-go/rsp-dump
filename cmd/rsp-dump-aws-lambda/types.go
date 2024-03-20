package main

import (
	"regexp"
)

type Configuration struct {
	Homepage     string              `json:"homepage_url"`
	HostPattern  *regexp.Regexp      `json:"host_pattern"`
	HostTemplate string              `json:"host_template"`
	SMTPHost     string              `json:"smtp_host"`
	SMTPPort     uint16              `json:"smtp_port"`
	SMTPUsername string              `json:"smtp_username"`
	SMTPPassword string              `json:"smtp_password"`
	SMTPHeaders  map[string][]string `json:"smtp_headers"`
}
