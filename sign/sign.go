package sign

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// AuthorizationHeader represents the Authentication HTTP Header.
	AuthorizationHeader = "Authorization"
	// AuthorizationHeaderScheme is the Authentication scheme.
	AuthorizationHeaderScheme = "HHMAC"
	// AuthorizationHeaderHash is the authentication
	// parameter for the hash.
	AuthorizationHeaderHash = "hash"
	// AuthorizationHeaderTimestamp is the authentication
	// parameter for the timestamp.
	AuthorizationHeaderTimestamp = "time"
	// AuthorizationHeaderPublicKey is the authentication
	// parameter for the public key.
	AuthorizationHeaderPublicKey = "key"

	// TimeFormat represents the format of timestamp
	TimeFormat = "20060102150405"
)

var (
	ErrAuthorizationParameterInvalid = errors.New("Authorization header invalid")
	ErrMissingAuthorizationHeader    = errors.New("Missing Authorization Header")
	ErrNonHMACScheme                 = errors.New("Non HHMAC authorization")

	ErrAuthorizationParameterNotFound = errors.New("Autorization parameter not found")
)

// HashFunc represents a hash function.
type HashFunc func() hash.Hash

// AuthorizationParameters represents the header
// contained within a request.
type AuthorizationParameters struct {
	Hash      string
	Date      time.Time
	PublicKey string
}

// NewAuthorizationParametersFromString returns new parameter from string
func NewAuthorizationParametersFromString(str string) (*AuthorizationParameters, error) {
	authorization := strings.TrimSpace(str)

	if !strings.HasPrefix(authorization, AuthorizationHeaderScheme+" ") {
		return nil, ErrNonHMACScheme
	}

	parametersRaw := authorization[len(AuthorizationHeaderScheme)+1:]
	parameters := strings.Split(parametersRaw, ",")

	paramsMap := map[string]string{}

	for _, param := range parameters {
		param := strings.TrimSpace(param)
		k, v := keyValueFromString(param)
		paramsMap[k] = v
	}

	signParam, signCondition := paramsMap[AuthorizationHeaderHash]
	dateParam, dateCondition := paramsMap[AuthorizationHeaderTimestamp]
	keyParam, keyCondition := paramsMap[AuthorizationHeaderPublicKey]

	if !signCondition || !dateCondition || !keyCondition {
		return nil, ErrAuthorizationParameterInvalid
	}

	date, err := time.Parse(TimeFormat, dateParam)

	if err != nil {
		fmt.Println("Err:", err)
		return nil, ErrAuthorizationParameterInvalid
	}

	authorizationParams := &AuthorizationParameters{
		Hash:      signParam,
		Date:      date,
		PublicKey: keyParam,
	}
	return authorizationParams, nil

}

func keyValueFromString(str string) (string, string) {
	n := strings.Index(str, "=")
	if n < 0 {
		return "", ""
	}

	return str[0:n], str[n+1:]
}

// Valid tells whether parameters are valid or not.
func (p *AuthorizationParameters) Valid() bool {
	return p.Hash != "" && len(p.PublicKey) > 0
}

// ReadParameters reads the parameters from
// an HTTP request.
func ReadParameters(r *http.Request) (*AuthorizationParameters, error) {

	authorization := r.Header.Get(AuthorizationHeader)

	if authorization == "" {
		return nil, ErrMissingAuthorizationHeader
	}

	return NewAuthorizationParametersFromString(authorization)
}

// Hash returns the hash of
// an HTTP request with the given key.
func Hash(r *http.Request, date time.Time, public, secret []byte, fn HashFunc) []byte {

	queryCharacteristic := QueryCharacteristic(r)
	dateString := date.UTC().Format(TimeFormat)
	publicKey := string(public)

	args := []string{queryCharacteristic, dateString, publicKey}
	signatureRaw := strings.Join(args, "_")

	mac := hmac.New(fn, secret)
	mac.Write([]byte(signatureRaw))
	return mac.Sum(nil)
}

// QueryCharacteristic returns the
// characteristic of the URL.
func QueryCharacteristic(r *http.Request) string {

	args := []string{strings.ToLower(r.Method), r.Host}

	args = append(args, strings.Split(r.URL.Path, "/")...)

	for key, arg := range r.URL.Query() {
		args = append(args, fmt.Sprintf("%s_%s", key, arg[0]))
	}

	args = filterNonEmpty(args)
	sort.Strings(args)
	return strings.Join(args, "_")
}

func filterNonEmpty(elements []string) []string {

	final := []string{}
	for _, element := range elements {
		if element != "" {
			final = append(final, element)
		}
	}
	return final
}
