package utils

import "github.com/CursedHardware/go-rsp-dump/rsp/dump"

type JSONReport struct {
	EID          string           `json:"eid"`
	UsedIssuer   string           `json:"used_issuer"`
	FreeNVRAM    float64          `json:"free_nvram_kb"`
	EUICCInfo2   *dump.EUICCInfo2 `json:"euicc_info2"`
	Certificates struct {
		EUICC string `json:"euicc,omitempty"`
		EUM   string `json:"eum,omitempty"`
	} `json:"certificates"`
}
