package main

import (
	"regexp"
)

type Configuration struct {
	Homepage     string
	HostPattern  *regexp.Regexp
	registryData string
	KVNamespace  string
}
