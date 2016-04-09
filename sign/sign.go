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
	PublicKey []byte
}

// NewAuthorizationParametersFromString returns new parameter from string
func NewAuthorizationParametersFromString(str string) (*AuthorizationParameters, error) {
	authorization := strings.TrimSpace(str)

	if !strings.HasPrefix(authorization, AuthorizationHeaderScheme+" ") {
		return nil, ErrNonHMACScheme
	}

	// parametersRaw := strings.TrimSpace(authorization[len(AuthorizationHeader)+1:])
	// parameters := strings.Split(parametersRaw, ",")

	return nil, nil

}

func parameterFromKeyString(str, key string) string {
	var v, k string
	_, err := fmt.Sscanf(str, "%s=%s", &k, &v)

	if err != nil || k != key {
		return ""
	}
	return v
}

// Valid tells whether parameters are valid or not.
func (p *AuthorizationParameters) Valid() bool {
	return p.Hash != "" && len(p.PublicKey) > 0
}

func ReadParameters(r *http.Request) (*AuthorizationParameters, error) {

	authorization := r.Header.Get(AuthorizationHeader)

	if authorization == "" {
		return nil, ErrMissingAuthorizationHeader
	}

	return nil, nil
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
