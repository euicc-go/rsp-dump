//go:build js

package main

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/CursedHardware/go-rsp-dump/rsp/dump"
	"github.com/CursedHardware/go-rsp-dump/rsp/types"
	"github.com/euicc-go/bertlv"
	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare"
	"github.com/syumai/workers/cloudflare/fetch"
)

//go:embed rsp-registry.json
var RawRegistry string

var config = Configuration{
	Homepage:    getenv("HOMEPAGE", "https://github.com/euicc-go/rsp-dump/blob/main/docs/cf-worker-readme.md", parseString),
	HostPattern: getenv("HOST_PATTERN", regexp.MustCompile(`^(?P<issuer>[a-f0-9]{6,40})\.rsp\.`), parseRegexp),
	Registry:    getenv("RSP_REGISTRY", func() Registry { r, _ := parseRegistry(RawRegistry); return r }(), parseRegistry),
	KVNamespace: getenv("KV_NAMESPACE", "rsp-dump", parseString),
	SMDP:        getenv("SMDP", "null", parseString),
	KeyID:       getenv("KEY_ID", nil, parseHEX),
}

func parseHEX(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func parseRegistry(s string) (Registry, error) {
	var registry Registry
	err := json.Unmarshal([]byte(s), &registry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registry JSON: %v", err)
	}
	return registry, nil
}

func getenv[T any](key string, defaultValue T, parser func(string) (T, error)) T {
	val := cloudflare.Getenv(key)
	val = strings.TrimSpace(val)

	if val == "" || strings.ToLower(val) == "undefined" || strings.ToLower(val) == "null" || strings.ToLower(val) == "<undefined>" {
		return defaultValue
	}

	if parsed, err := parser(val); err == nil {
		return parsed
	}
	return defaultValue
}

func parseRegexp(s string) (*regexp.Regexp, error) {
	return regexp.Compile(s)
}

func parseString(s string) (string, error) {
	return s, nil
}

func main() {
	handler := &dump.Handler{
		Homepage:       config.Homepage,
		Client:         fetch.NewClient().HTTPClient(fetch.RedirectModeFollow),
		OnInitAuthen:   onInitAuthen,
		OnAuthenClient: onAuthenClient,
	}

	workers.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/kv") {
			handleKVRoute(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	}))
}

func onInitAuthen(svn *bertlv.TLV, r *types.InitAuthenRequest) error {
	if config.SMDP != "null" {
		if config.KeyID != nil {
			r.Info1 = dump.NewInfo1(config.KeyID, svn, r.Info1.Tag)
		}
		r.Address = config.SMDP
	} else if issuer, hostTmp, errTmp := dump.FindIssuerFromHost(r.Address, config.HostPattern, config.Registry); errTmp == nil {
		r.Info1 = dump.NewInfo1(issuer, svn, r.Info1.Tag)
		r.Address = hostTmp
	} else if issuer, hostTmp, errTmp := dump.FindIssuerFromIssuers(dump.GetIssuersFromInfo1(r.Info1), config.Registry); errTmp == nil {
		r.Info1 = dump.NewInfo1(issuer, svn, r.Info1.Tag)
		r.Address = hostTmp
	} else {
		return dump.ErrNotFound
	}
	return nil
}
