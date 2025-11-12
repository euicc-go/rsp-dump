package main

import (
	"regexp"
)

type Configuration struct {
	Homepage     string
	HostPattern  *regexp.Regexp
	RegistryData string
	KVNamespace  string
	SMDP        string
}
