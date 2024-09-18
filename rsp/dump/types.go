package dump

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	. "github.com/euicc-go/bertlv"
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
	ProfileVersion              Version         `json:"profileVersion,omitempty"`
	SVN                         Version         `json:"svn,omitempty"`
	FirmwareVersion             Version         `json:"euiccFirmwareVer,omitempty"`
	ExtCardResource             ExtCardResource `json:"extCardResource,omitempty"`
	UICCCapability              []string        `json:"uiccCapability,omitempty"`
	TS102241Version             Version         `json:"ts102241Version,omitempty"`
	GlobalPlatformVersion       Version         `json:"globalplatformVersion,omitempty"`
	RSPCapability               []string        `json:"rspCapability,omitempty"`
	IssuerVerification          []HexString     `json:"euiccCiPKIdListForVerification,omitempty"`
	IssuerSigning               []HexString     `json:"euiccCiPKIdListForSigning,omitempty"`
	Category                    string          `json:"euiccCategory,omitempty"`
	ForbiddenProfilePolicyRules []string        `json:"forbiddenProfilePolicyRules,omitempty"`
	ProtectionProfileVersion    Version         `json:"ppVersion,omitempty"`
	SASAccreditationNumber      string          `json:"sasAccreditationNumber,omitempty"`
	CertificationDataObject     *CertData       `json:"certificationDataObject,omitempty"`
	TreProperties               []string        `json:"treProperties,omitempty"`
	TreProductReference         string          `json:"treProductReference,omitempty"`
	ProfilePackageVersions      []Version       `json:"additionalEuiccProfilePackageVersions,omitempty"`
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
		data, _ := resource.MarshalBinary()
		data[0] = 0x30
		if err = resource.UnmarshalBinary(data); err != nil {
			return
		}
		info.ExtCardResource = ExtCardResource{
			InstallApps: variant(resource.First(Tag{0x81}).Value),
			FreeNVRAM:   variant(resource.First(Tag{0x82}).Value),
			FreeRAM:     variant(resource.First(Tag{0x83}).Value),
		}
	}
	info.UICCCapability = toBits(tlv.First(Tag{0x85}),
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
	info.RSPCapability = toBits(tlv.First(Tag{0x88}),
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
		info.ForbiddenProfilePolicyRules = toBits(ppr, "pprUpdateControl", "ppr1", "ppr2")
	}
	if ppVersion := tlv.First(Tag{0x04}); ppVersion != nil {
		info.ProtectionProfileVersion = Version(ppVersion.Value)
	}
	if certData := tlv.First(Tag{0xAC}); certData != nil {
		info.CertificationDataObject = &CertData{
			PlatformLabel:    strings.TrimSpace(string(certData.First(Tag{0x80}).Value)),
			DiscoveryBaseURL: strings.TrimSpace(string(certData.First(Tag{0x81}).Value)),
		}
	}
	if properties := tlv.First(Tag{0xAD}); properties != nil {
		info.TreProperties = toBits(tlv, "isDiscrete", "isIntegrated", "usesRemoteMemory")
	}
	if reference := tlv.First(Tag{0xAE}); reference != nil {
		info.TreProductReference = strings.TrimSpace(string(reference.Value))
	}
	if versions := tlv.First(Tag{0xAF}); versions != nil {
		info.ProfilePackageVersions = make([]Version, len(versions.Children))
		for index, version := range versions.Children {
			info.ProfilePackageVersions[index] = Version(version.Value)
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

type ExtCardResource struct {
	InstallApps uint64 `json:"installApps,omitempty"`
	FreeNVRAM   uint64 `json:"freeNVRAM,omitempty"`
	FreeRAM     uint64 `json:"freeRAM,omitempty"`
}

type CertData struct {
	PlatformLabel    string `json:"platformLabel,omitempty"`
	DiscoveryBaseURL string `json:"discoveryBaseURL,omitempty"`
}
