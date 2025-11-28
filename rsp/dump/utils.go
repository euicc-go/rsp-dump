package dump

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"regexp"
	"strings"

	. "github.com/euicc-go/bertlv"
)

func variant(b []byte) uint64 {
	dst := make([]byte, 8)
	copy(dst[8-len(b):], b)
	return binary.BigEndian.Uint64(dst)
}

func toBits(tlv *TLV, definitions ...string) (features []string) {
	bits := &asn1.BitString{
		Bytes:     tlv.Value[1:],
		BitLength: (len(tlv.Value)-1)*8 - int(tlv.Value[0]),
	}
	for index := 0; index < min(bits.BitLength, len(definitions)); index++ {
		if bits.At(index) == 1 {
			features = append(features, definitions[index])
		}
	}
	return
}

func GetIssuersFromInfo1(info1 *TLV) []*TLV {
	if tag := info1.First(Tag{0xAA}); tag != nil {
		return tag.Children
	}
	return nil
}

func GetSVNFromInfo1(info1 *TLV) *TLV {
	return info1.First(Tag{0x82})
}

func NewInfo1(issuer []byte, svn *TLV, tag Tag) *TLV {
	return NewChildren(
		tag,
		svn,
		NewChildren(Tag{0xA9}, NewValue(Tag{0x04}, issuer)),
		NewChildren(Tag{0xAA}, NewValue(Tag{0x04}, issuer)),
	)
}

func FindIssuerFromHost(smdp string, hostPattern *regexp.Regexp, registry map[string][]string) (issuer []byte, host string, err error) {
	err = ErrNotFound

	if hostPattern == nil {
		return
	}

	index := hostPattern.SubexpIndex("issuer")
	matches := hostPattern.FindStringSubmatch(smdp)
	if index == -1 || matches == nil {
		return
	}

	prefix := strings.ToLower(matches[index])
	for keyId, hosts := range registry {
		if strings.HasPrefix(keyId, prefix) && len(hosts) > 0 {
			if issuer, err = hex.DecodeString(keyId); err != nil {
				return
			}
			host = hosts[rand.IntN(len(hosts))]
			err = nil
			return
		}
	}

	return
}

func FindIssuerFromIssuers(issuers []*TLV, registry map[string][]string) (issuer []byte, host string, err error) {
	for _, child := range issuers {
		keyId := hex.EncodeToString(child.Value)
		if hosts := registry[keyId]; len(hosts) > 0 {
			issuer = child.Value
			host = hosts[rand.IntN(len(hosts))]
			return issuer, host, nil
		}
	}
	return nil, "", ErrNotFound
}
