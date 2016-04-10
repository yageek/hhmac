package validation

import (
	"errors"
	"fmt"
	"github.com/yageek/hhmac/sign"

	"net/http"
	"time"
)

var (
	// ErrHashInvalid is returned when hash is
	// considered invalid.
	ErrHashInvalid = errors.New("Invalid Hash")
	// ErrTokenExpires is returned when token time
	// is considerd invalid.
	ErrTokenExpires = errors.New("Token expires")
	// ErrSecretNotFound tells that no secret has been found.
	ErrSecretNotFound = errors.New("Secret not found")
	// ErrInvalidScopes tells the user has no access
	ErrInvalidScopes = errors.New("No valid scopes found")
)

// SecretProvider helps to retrieve
// informations about the user.
type SecretProvider interface {
	GetSecret(identifier string) (string, error)
	GetScopes(identifier string) ([]string, error)
}

// Validator validates request
type Validator struct {
	tokenTime      time.Duration
	secretProvider SecretProvider
	hash           sign.HashFunc
}

// NewValidator returns a new validator
func NewValidator(validTime time.Duration, provider SecretProvider, fn sign.HashFunc) *Validator {
	return &Validator{validTime, provider, fn}
}

// ValidateRequest validate the requests
func (v *Validator) ValidateRequest(r *http.Request, scopes []string) error {

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

	sign := sign.Hash(r, date, publicKey, secret, v.hash)

	if sign != expectedSign {
		return ErrHashInvalid
	}

	// Valid scopes
	if len(scopes) > 0 {
		err := v.validScopes(publicKey, scopes)

		if err != nil {
			return err
		}
	}

	// Valid time
	now := time.Now()
	delta := now.Sub(date).Seconds()
	acceptedDelta := v.tokenTime.Seconds()

	if delta > acceptedDelta || delta < -acceptedDelta {
		return ErrTokenExpires
	}

	return nil
}

func (v *Validator) validScopes(identifier string, scopes []string) error {
	// Valid scopes
	userScopes, err := v.secretProvider.GetScopes(identifier)
	if err != nil {
		return err
	}

	for _, wantedScope := range scopes {
		validCurrentScope := false

		for _, userScope := range userScopes {
			if userScope == wantedScope {
				validCurrentScope = true
				break
			}
		}

		if !validCurrentScope {
			return ErrInvalidScopes
		}
	}
	return nil
}

// HashRequest hash the requests with
// the given parameters.
// Ex: Authorization: FIRE-TOKEN apikey="0PN5J17HBGZHT7JJ3X82", hash="frJIUN8DYpKDtOLCwo//yllqDzg="
// See http://stackoverflow.com/questions/7802116/custom-http-authorization-header
func (v *Validator) HashRequest(r *http.Request, date time.Time, public string, identifier string) error {

	secret, err := v.secretProvider.GetSecret(identifier)

	if err != nil {
		return err
	}

	timeStampParam := fmt.Sprintf("%s=%d", sign.AuthorizationHeaderTimestamp, date.UnixNano())
	publicKeyParam := fmt.Sprintf("%s=%s", sign.AuthorizationHeaderPublicKey, string(public))

	hash := sign.Hash(r, date, public, secret, v.hash)
	signatureParam := fmt.Sprintf("%s=%s", sign.AuthorizationHeaderHash, string(hash))

	authorizationHeader := fmt.Sprintf("%s %s, %s, %s", sign.AuthorizationHeaderScheme, timeStampParam, publicKeyParam, signatureParam)

	r.Header.Set(sign.AuthorizationHeader, authorizationHeader)

	return nil
}
