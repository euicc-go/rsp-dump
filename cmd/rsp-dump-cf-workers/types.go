package main

import (
	"regexp"
)

type Registry map[string][]string

type Configuration struct {
	Homepage    string
	HostPattern *regexp.Regexp
	Registry    Registry
	KVNamespace string
	SMDP        string
	KeyID       []byte
}
