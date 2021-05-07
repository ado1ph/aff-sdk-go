package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// Authorization Authorization
	Authorization = "Authorization"
	// AuthVersion 授权版本
	AuthVersion = "bce-auth-v1"
	// JoinSigncanonicalHeaders sign关联符号
	JoinSigncanonicalHeaders = "\n"
	// JoinSignHeaders 分隔符
	JoinSignHeaders = ";"
	// DefaultExpireSeconds 默认过期时间
	DefaultExpireSeconds = 1800

	// Get Get
	Get httpMethod = "GET"
	// Put Put
	Put httpMethod = "PUT"
	// Post Post
	Post httpMethod = "POST"
	// Delete Delete
	Delete httpMethod = "DELETE"
	// Head Head
	Head httpMethod = "HEAD"
)

type (
	// Auth Auth
	Auth struct {
		AK         string
		SK         string
		Expire     int
		Header     map[string]string
		Path       string
		Param      interface{}
		QueryParam map[string]string
		Time       string
	}

	httpMethod string
)

// String 2String
func (h httpMethod) String() string {
	return string(h)
}

// NewAuth set ak,sk
func NewAuth(ak, sk string) *Auth {
	a := new(Auth)
	a.AK = ak
	a.SK = sk
	a.Expire = DefaultExpireSeconds
	return a
}

// Sign generate the authorization string
func (a *Auth) Sign(method httpMethod) string {
	canonicalHeader, signHeader := a.getCanonicalHeaders()
	// bce-auth-v1/{accessKeyId}/{timestamp}/{expirationPeriodInSeconds }/{signedHeaders}/{signature}
	return a.buildAuthStringPrefix() + "/" + signHeader + "/" +
		a.buildSignature(a.buildCanonicalRequest(canonicalHeader, method), a.buildSigningKey(a.buildAuthStringPrefix()))
}

// buildAuthStringPrefix sign step 1
func (a *Auth) buildAuthStringPrefix() string {
	// "bce-auth-v1/{accessKeyId}/{timestamp}/{expirationPeriodInSeconds}"
	var utc string
	if len(a.Time) == 0 {
		utc = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	} else {
		utc = a.Time
	}
	return fmt.Sprintf("bce-auth-v1/%s/%s/%d", a.AK, utc, a.Expire)
}

// buildCanonicalRequest sign step 2
func (a *Auth) buildCanonicalRequest(canonicalHeader string, method httpMethod) string {
	// HTTP Method + "\n" + CanonicalURI + "\n" + CanonicalQueryString + "\n" + CanonicalHeaders
	newMethod := strings.ToTitle(method.String())
	return newMethod + JoinSigncanonicalHeaders + uriEncode(a.Path) + JoinSigncanonicalHeaders + a.getCanonicalQueryString(a.QueryParam) + JoinSigncanonicalHeaders + canonicalHeader
}

// buildSigningKey sign step 3
func (a *Auth) buildSigningKey(authStringPrefix string) string {
	return hmacSha256(authStringPrefix, a.SK)
}

// buildSignature sign step 4
func (a *Auth) buildSignature(canonicalRequest string, secret string) string {
	return hmacSha256(canonicalRequest, secret)
}

func (a *Auth) getCanonicalQueryString(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	result := make([]string, 0, len(params))
	for k, v := range params {
		if strings.ToLower(k) == strings.ToLower(Authorization) {
			continue
		}

		item := ""
		if len(v) == 0 {
			item = fmt.Sprintf("%s=", uriEncode(k))
		} else {
			item = fmt.Sprintf("%s=%s", uriEncode(k), uriEncode(v))
		}
		result = append(result, item)
	}
	sort.Strings(result)
	return strings.Join(result, "&")
}

func (a *Auth) getCanonicalHeaders() (string, string) {
	if len(a.Header) == 0 {
		return "", ""
	}
	canonicalHeaders := make([]string, 0, len(a.Header))
	signHeaders := make([]string, 0, len(a.Header))
	for k, v := range a.Header {
		headKey := strings.ToLower(k)

		headVal := strings.TrimSpace(v)
		encoded := uriEncode(headKey) + ":" + uriEncode(headVal)
		canonicalHeaders = append(canonicalHeaders, encoded)
		signHeaders = append(signHeaders, headKey)
	}

	sort.Strings(canonicalHeaders)
	sort.Strings(signHeaders)
	return strings.Join(canonicalHeaders, JoinSigncanonicalHeaders), strings.Join(signHeaders, JoinSignHeaders)
}

func uriEncode(str string) string {
	return strings.Replace(str, "%2F", "/", -1)
}

func hmacSha256(data string, secret string) string {
	p := hmac.New(sha256.New, []byte(secret))
	p.Write([]byte(data))
	return hex.EncodeToString(p.Sum(nil))
}
