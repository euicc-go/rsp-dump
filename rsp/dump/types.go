package dump

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	. "github.com/CursedHardware/go-rsp-dump/bertlv"
	"strings"
)

type Report struct {
	MatchingID       string
	ServerAddress    string
	EUICCInfo2       EUICCInfo2
	EUICCCertificate *TLV
	EUMCertificate   *TLV
}

func (r *Report) UnmarshalBerTLV(response *TLV) (err error) {
	var report Report
	euiccSigned1 := response.At(0) // eUICCSigned1
	report.ServerAddress = string(euiccSigned1.First(Tag{0x83}).Value)
	euiccInfo2 := euiccSigned1.First(Tag{0xBF, 0x22})       // eUICCSigned1 -> eUICCInfo2
	matchingId := euiccSigned1.Select(Tag{0xA0}, Tag{0x80}) // eUICCSigned1 -> ctxParams1 -> MatchingID
	report.EUICCCertificate = response.At(2)                // eUICC Certificate
	report.EUMCertificate = response.At(3)                  // EUM Certificate
	if err = report.EUICCInfo2.UnmarshalBerTLV(euiccInfo2); err != nil {
		return
	}
	if matchingId != nil {
		report.MatchingID = string(matchingId.Value)
	}
	*r = report
	return nil
}

type EUICCInfo2 struct {
	ProfileVersion              Version     `json:"profile_version,omitempty"`
	SVN                         Version     `json:"sgp22_version_supported,omitempty"`
	FirmwareVersion             Version     `json:"euicc_firmware_version,omitempty"`
	FreeNVRAM                   uint32      `json:"free_nvram,omitempty"`
	UICCCapability              []string    `json:"uicc_capability,omitempty"`
	TS102241Version             Version     `json:"ts102241_version,omitempty"`
	GlobalPlatformVersion       Version     `json:"gp_version,omitempty"`
	RSPCapability               []string    `json:"rsp_capability,omitempty"`
	IssuerVerification          []HexString `json:"issuer_for_verification,omitempty"`
	IssuerSigning               []HexString `json:"issuer_for_signing,omitempty"`
	Category                    string      `json:"category,omitempty"`
	ForbiddenProfilePolicyRules []string    `json:"forbidden_profile_policy_rules,omitempty"`
	SASAccreditationNumber      string      `json:"sas_accreditation_number,omitempty"`
	CertificationDataObject     *CertData   `json:"certification_data_object,omitempty"`
}

func (e *EUICCInfo2) UnmarshalBerTLV(tlv *TLV) (err error) {
	info := EUICCInfo2{
		ProfileVersion:         Version(tlv.First(Tag{0x81}).Value),
		SVN:                    Version(tlv.First(Tag{0x82}).Value),
		FirmwareVersion:        Version(tlv.First(Tag{0x83}).Value),
		Category:               "Other",
		SASAccreditationNumber: strings.TrimSpace(string(tlv.First(Tag{0x0C}).Value)),
	}
	if resource := tlv.First(Tag{0x84}); resource != nil {
		// ExtCardResource
		for i := 0; i < len(resource.Value); {
			tag := resource.Value[i]
			length := int(resource.Value[i+1])
			value := resource.Value[i+2 : i+length+2]
			if tag == 0x82 {
				info.FreeNVRAM = binary.BigEndian.Uint32(value)
				break
			}
			i += length + 2
		}
	}
	info.UICCCapability = tlv.First(Tag{0x85}).BitString(
		"Contactless Support", "USIM Support", "ISIM Support", "CSIM Support",
		"DeviceInfo Extensibility Support",
		"AkaMilenage", "AkaCave", "AkaTuak128", "AkaTuak256",
		"RFU1", "RFU2",
		"GBA Authentication USIM", "GBA Authentication ISIM", "MBMS Authentication USIM",
		"EAP Client", "JavaCard", "MultOS",
		"Multiple USIM Support", "Multiple ISIM Support", "Multiple CSIM Support",
		"Ber TLV File Support", "DF Link Support",
		"CAT TP", "GET IDENTITY", "profile-a-x25519", "profile-b-p256", "SUCICalculatorAPI",
	)
	if version := tlv.First(Tag{0x86}); version != nil {
		info.TS102241Version = Version(version.Value)
	}
	if version := tlv.First(Tag{0x87}); version != nil {
		info.GlobalPlatformVersion = Version(version.Value)
	}
	info.RSPCapability = tlv.First(Tag{0x88}).BitString(
		"additionalProfile",
		"crlSupport",
		"rpmSupport",
		"testProfileSupport",
		"deviceInfoExtensibilitySupport",
	)
	for _, child := range tlv.First(Tag{0xA9}).Children {
		info.IssuerVerification = append(info.IssuerVerification, child.Value)
	}
	for _, child := range tlv.First(Tag{0xAA}).Children {
		info.IssuerSigning = append(info.IssuerSigning, child.Value)
	}
	if category := tlv.First(Tag{0x8B}); category != nil {
		categories := []string{"Other", "Basic eUICC", "Medium eUICC", "Contactless eUICC"}
		info.Category = categories[category.Value[0]]
	}
	if ppr := tlv.First(Tag{0x99}); ppr != nil {
		info.ForbiddenProfilePolicyRules = ppr.BitString(
			"pprUpdateControl",
			"ppr1",
			"ppr2",
		)
	}
	if certData := tlv.First(Tag{0xAC}); certData != nil {
		info.CertificationDataObject = &CertData{
			PlatformLabel:    strings.TrimSpace(string(certData.First(Tag{0x80}).Value)),
			DiscoveryBaseURL: strings.TrimSpace(string(certData.First(Tag{0x81}).Value)),
		}
	}
	*e = info
	return nil
}

type Version [3]byte

func (v Version) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}

type HexString []byte

func (h *HexString) UnmarshalJSON(data []byte) (err error) {
	var value string
	if err = json.Unmarshal(data, &value); err != nil {
		return
	}
	*h, err = hex.DecodeString(value)
	return
}

func (h *HexString) MarshalJSON() (dst []byte, _ error) {
	return json.Marshal(h.String())
}

func (h *HexString) String() string {
	return hex.EncodeToString(*h)
}

type CertData struct {
	PlatformLabel    string `json:"platform_label,omitempty"`
	DiscoveryBaseURL string `json:"discovery_base_url,omitempty"`
}
