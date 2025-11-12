//go:build js

package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strings"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare"
	"github.com/syumai/workers/cloudflare/fetch"
)

//go:embed rsp-registry.json
var RegistryData string

var config = Configuration{
	Homepage:     getenv("HOMEPAGE", "https://septs.blog/posts/rsp-dump/", parseString),
	HostPattern:  getenv("HOST_PATTERN", regexp.MustCompile(`^(?P<issuer>[a-f0-9]{6,40})\.rsp\.`), parseRegexp),
	RegistryData: getenv("RSP_REGISTRY", RegistryData, parseString),
	KVNamespace:  getenv("KV_NAMESPACE", "rsp-dump", parseString),
	SMDP:         getenv("SMDP", "null", parseString),
}

func getenv[T any](key string, defaultValue T, parser func(string) (T, error)) T {
	val := cloudflare.Getenv(key)
	val = strings.TrimSpace(val)
	valLower := strings.ToLower(val)

	if val == "" || valLower == "undefined" || valLower == "null" || valLower == "<undefined>" {
		return defaultValue
	}

	parsed, err := parser(val)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func parseString(s string) (string, error) {
	return s, nil
}

func parseRegexp(s string) (*regexp.Regexp, error) {
	return regexp.Compile(s)
}

func main() {
	handler := &dump.Handler{
		Homepage:       config.Homepage,
		Client:         fetch.NewClient().HTTPClient(fetch.RedirectModeFollow),
		GetIssuerHost:  getIssuerHost,
		HostPattern:    config.HostPattern,
		OnAuthenClient: onAuthenClient,
	}

	workers.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle KV routes
		if strings.HasPrefix(r.URL.Path, "/kv") {
			handleKVRoute(w, r)
			return
		}

		handler.ServeHTTP(w, r)
	}))
}

func getIssuerHost(keyId string) (string, error) {
	var issuers map[string][]string
	if config.SMDP != "null" {
		return config.SMDP, nil
	}
	if err := json.Unmarshal([]byte(config.RegistryData), &issuers); err != nil {
		panic(err)
	}
	if hosts, ok := issuers[keyId]; ok && len(hosts) > 0 {
		return hosts[rand.IntN(len(hosts))], nil
	}
	return "", fmt.Errorf("issuer not found: %s", keyId)
}
