package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare"
	"github.com/syumai/workers/cloudflare/fetch"
)

//go:embed rsp-registry.json
var registryData string

var config = Configuration{
	Homepage:     getenv("HOMEPAGE", "https://septs.blog/posts/rsp-dump/", parseString),
	HostPattern:  getenv("HOST_PATTERN", regexp.MustCompile(`^(?P<issuer>[a-f0-9]{6,40})\.rsp\.`), parseRegexp),
	registryData: getenv("RSP_REGISTRY", registryData, parseString),
	KVNamespace:  getenv("KV_NAMESPACE", "rsp-dump", parseString),
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
		Issuers:        mustRSPRegistry(),
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

func mustRSPRegistry() (issuers map[string][]string) {
	if err := json.Unmarshal([]byte(config.registryData), &issuers); err != nil {
		panic(err)
	}
	return
}
