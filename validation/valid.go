package validation

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"github.com/yageek/hhmac/sign"
	"net/http"
	"time"
)

var (
	ErrHashInvalid  = errors.New("Invalid Hash")
	ErrTokenExpires = errors.New("Token expires")
)

// SecretProvider helps to retrieve
// informations about the user.
type SecretProvider interface {
	GetSecret(identifier string) ([]byte, error)
	GetScopes(identifier string) ([]string, error)
}

// Validator validates request
type Validator struct {
	tokenMinTime   time.Duration
	tokenMaxTime   time.Duration
	secretProvider SecretProvider
	hash           sign.HashFunc
}

// NewValidator returns a new validator
func NewValidator(min, max time.Duration, provider SecretProvider, fn sign.HashFunc) *Validator {
	return &Validator{min, max, provider, fn}
}

// ValidateRequest validate the requests
func (v *Validator) ValidateRequest(r *http.Request) error {

	params, err := sign.ReadParameters(r)

	if err != nil {
		return err
	}

	publicKey := params.PublicKey
	secret, err := v.secretProvider.GetSecret(publicKey)

	if err != nil {
		return err
	}

	date := params.Date
	expectedSign := params.Hash

	sign := sign.Hash(r, date, []byte(publicKey), secret, v.hash)

	if !hmac.Equal([]byte(expectedSign), sign) {
		return ErrHashInvalid
	}

	// Valid time
	now := time.Now()
	max := now.Add(v.tokenMaxTime)
	min := now.Add(-v.tokenMinTime)

	if date.Sub(min) < 0 || max.Sub(date) < 0 {
		return ErrTokenExpires
	}

	return nil
}

// HashRequest hash the requests with
// the given parameters.
// Ex: Authorization: FIRE-TOKEN apikey="0PN5J17HBGZHT7JJ3X82", hash="frJIUN8DYpKDtOLCwo//yllqDzg="
// See http://stackoverflow.com/questions/7802116/custom-http-authorization-header
func (v *Validator) HashRequest(r *http.Request, date time.Time, public []byte, identifier string) error {

	secret, err := v.secretProvider.GetSecret(identifier)

	if err != nil {
		return err
	}

	timeStampParam := fmt.Sprintf("%s=%s", sign.AuthorizationHeaderTimestamp, date.Format(sign.TimeFormat))
	publicKeyParam := fmt.Sprintf("%s=%s", sign.AuthorizationHeaderPublicKey, string(public))

	hash := sign.Hash(r, date, public, secret, v.hash)
	signatureParam := fmt.Sprintf("%s=%s", sign.AuthorizationHeaderHash, string(hash))

	authorizationHeader := fmt.Sprintf("%s %s, %s, %s", sign.AuthorizationHeaderScheme, timeStampParam, publicKeyParam, signatureParam)

	r.Header.Set(sign.AuthorizationHeader, authorizationHeader)

	return nil
}
