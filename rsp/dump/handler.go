package dump

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	. "github.com/CursedHardware/go-rsp-dump/rsp/types"
	. "github.com/euicc-go/bertlv"
	"github.com/pkg/errors"
)

type Handler struct {
	Homepage       string
	Client         *http.Client
	GetIssuerHost  func(string) (string, error)
	HostPattern    *regexp.Regexp
	OnAuthenClient func(*TLV, *http.Client) error
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case !strings.HasPrefix(r.URL.Path, "/gsma/rsp2"):
		if h.Homepage != "" {
			http.Redirect(w, r, h.Homepage, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}
		return
	case r.Method != http.MethodPost:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	var err error
	encoder := json.NewEncoder(w)
	decoder := json.NewDecoder(r.Body)
	switch strings.TrimPrefix(r.URL.Path, "/gsma/rsp2") {
	case "/asn1":
		var request *TLV
		if _, err = request.ReadFrom(r.Body); err == nil {
			_, _ = h.handleASN1(request).WriteTo(w)
		}
	case "/es9plus/initiateAuthentication":
		var request InitAuthenRequest
		var response *InitAuthenResponse
		if err = decoder.Decode(&request); err != nil {
			goto errorHandling
		}
		if response, err = h.handleInitAuthen(&request); err == nil {
			_ = encoder.Encode(response)
		}
	case "/es9plus/authenticateClient":
		var request AuthenClientRequest
		var response *GeneralResponse
		if err = decoder.Decode(&request); err != nil {
			goto errorHandling
		}
		if response, err = h.handleAuthenClient(&request); err == nil {
			_ = encoder.Encode(response)
		}
	}
errorHandling:
	if err != nil {
		var _err *Error
		if !errors.As(err, &_err) {
			_err = &Error{Status: Failed, SubjectCode: "1.1", ReasonCode: "1.1", Message: err.Error()}
		}
		_ = encoder.Encode(_err)
	}
}

func (h *Handler) handleInitAuthen(r *InitAuthenRequest) (resp *InitAuthenResponse, err error) {
	u := &url.URL{Scheme: "https", Path: "/gsma/rsp2/es9plus/initiateAuthentication"}
	var issuer []byte
	if issuer, u.Host, err = h.findHost(r); err != nil {
		return
	}
	svn := r.Info1.First(Tag{0x82})
	r.Info1 = NewChildren(
		r.Info1.Tag,
		svn,
		NewChildren(Tag{0xA9}, NewValue(Tag{0x04}, issuer)),
		NewChildren(Tag{0xAA}, NewValue(Tag{0x04}, issuer)),
	)
	r.Address = u.Host
	body, _ := json.Marshal(r)
	request, _ := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	request.Header.Set("User-Agent", "gsma-rsp-lpad")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Admin-Protocol", fmt.Sprintf("gsma/rsp/v%d.%d.%d", svn.Value[0], svn.Value[1], svn.Value[2]))
	response, err := h.Client.Do(request)
	if err != nil {
		return
	}
	resp = new(InitAuthenResponse)
	if err = json.NewDecoder(response.Body).Decode(resp); err != nil {
		return
	}
	if resp.UsedIssuer == nil || !bytes.Equal(issuer, resp.UsedIssuer.Value) {
		err = fmt.Errorf("InitiateAuthenticationResponse: issuer is mismatch (%s)", r.Address)
		return
	}
	log.Println(
		"ES9+.InitiateAuthenticationResponse",
		"TransactionId:", resp.TransactionId,
		"Host:", u.Host,
		"Issuer:", hex.EncodeToString(issuer),
	)
	return
}

func (h *Handler) handleAuthenClient(r *AuthenClientRequest) (_ *GeneralResponse, err error) {
	if data, _ := r.Response.MarshalBinary(); len(data) > 0 {
		log.Println(
			"ES9+.AuthenticateClientRequest",
			"TransactionId:", r.TransactionId,
			"Response:", base64.StdEncoding.EncodeToString(data),
		)
	}
	switch response := r.Response.At(0); response.Tag[0] {
	case 0xA0: // AuthenticateResponseOk
		if err = h.OnAuthenClient(response, h.Client); err == nil {
			err = errors.New("AuthenticateResponseOk: extract information finished")
		}
	case 0xA1: // AuthenticateResponseError
		errorCodes := map[byte]string{
			1: "invalidCertificate",
			2: "invalidSignature",
			3: "unsupportedCurve",
			4: "noSessionContext",
			5: "invalidOid",
			6: "euiccChallengeMismatch",
			7: "ciPKUnknown",
		}
		errorCode := response.First(Tag{0x02}).Value[0]
		err = fmt.Errorf("AuthenticateResponseError: undefinedError (%d)", errorCode)
		if errorMessage, ok := errorCodes[errorCode]; ok {
			err = fmt.Errorf("AuthenticateResponseError: %s (%d)", errorMessage, errorCode)
		}
	default:
		err = errors.New("ES10b#AuthenticateServer: An unknown error occurred")
	}
	return
}

func (h *Handler) handleASN1(request *TLV) *TLV {
	if r := request.First(Tag{0xBF, 0x39}); r != nil {
		authen, err := h.handleInitAuthen(&InitAuthenRequest{
			Challenge: r.First(Tag{0x81}).Value,
			Address:   string(r.First(Tag{0x83}).Value),
			Info1:     r.First(Tag{0xBF, 0x20}),
		})
		if err != nil {
			return nil
		}
		transactionId, err := hex.DecodeString(authen.TransactionId)
		if err != nil {
			return nil
		}
		return NewChildren(Tag{0xBF, 0x39}, NewChildren(
			Tag{0xA0},
			NewValue(Tag{0x80}, transactionId),
			authen.Signed1,
			authen.Signature1,
			authen.UsedIssuer,
			authen.Certificate,
		))
	}
	if r := request.First(Tag{0xBF, 0x3B}); r != nil {
		_, _ = h.handleAuthenClient(&AuthenClientRequest{
			TransactionId: hex.EncodeToString(r.First(Tag{0x80}).Value),
			Response:      r.First(Tag{0xBF, 0x38}),
		})
	}
	return nil
}

func (h *Handler) findHost(r *InitAuthenRequest) (issuer []byte, host string, err error) {
	if h.HostPattern == nil {
		return h.findBestMatchHost(r)
	}
	index := h.HostPattern.SubexpIndex("issuer")
	matches := h.HostPattern.FindStringSubmatch(r.Address)
	if index == -1 || matches == nil {
		return h.findBestMatchHost(r)
	}
	return h.findSpecificHost(strings.ToLower(matches[index]))
}

func (h *Handler) findBestMatchHost(r *InitAuthenRequest) (issuer []byte, host string, err error) {
	err = errNotFound
	for _, child := range r.Info1.First(Tag{0xAA}).Children {
		keyId := hex.EncodeToString(child.Value)
		if _host, e := h.GetIssuerHost(keyId); e == nil {
			issuer = child.Value
			err = nil
			host = _host
			return
		}
	}
	return
}

func (h *Handler) findSpecificHost(prefix string) (issuer []byte, host string, err error) {
	err = errNotFound
	if len(prefix) == 0 {
		return
	}
	if _host, e := h.GetIssuerHost(prefix); e == nil {
		issuer, _ = hex.DecodeString(prefix)
		host = _host
		err = nil
		return
	}
	return
}
