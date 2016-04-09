package validation

import (
	"fmt"
	"github.com/yageek/hhmac/sign"
	"net/http"
	"time"
)

// SecretProvider helps to retrieve
// informations about the user.
type SecretProvider interface {
	GetSecret(identifier string) ([]byte, error)
	GetScopes(identifier string) ([]string, error)
}

// Validator validates request
type Validator struct {
	tokenValidTime time.Duration
	secretProvider SecretProvider
	hash           sign.HashFunc
}

// NewValidator returns a new validator
func NewValidator(last time.Duration, provider SecretProvider, fn sign.HashFunc) *Validator {
	return &Validator{last, provider, fn}
}

// ValidateRequest validate the requests
func (v *Validator) ValidateRequest(r *http.Request) error {

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
