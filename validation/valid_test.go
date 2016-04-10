package validation

import (
	"crypto"
	"net/http"
	"testing"
	"time"
)

type MockProvider struct {
}

func (m *MockProvider) GetSecret(identifier string) (string, error) {
	return "MYSECRET", nil
}

func (m *MockProvider) GetScopes(identifier string) ([]string, error) {
	return []string{"scope1", "scope2"}, nil
}

func TestHashUnhash(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.com/test/path?obj=1", nil)
	date := time.Now()
	public := "42"

	v := NewValidator(30*time.Second, &MockProvider{}, crypto.SHA256.New)

	v.HashRequest(r, date, public, "whatever")

	if err := v.ValidateRequest(r, []string{}); err != nil {
		t.Error("Should not failed:", err)
	}

	v.HashRequest(r, date.Add(29*time.Second), public, "whatever")

	if err := v.ValidateRequest(r, []string{}); err != nil {
		t.Error("Should not failed:", err)

	}

	v.HashRequest(r, date.Add(31*time.Second), public, "whatever")

	if err := v.ValidateRequest(r, []string{}); err == nil {
		t.Error("Should failed")

	}

	v.HashRequest(r, date.Add(20*time.Second), public, "whatever")

	if err := v.ValidateRequest(r, []string{}); err != nil {
		t.Error("Should not failed:", err)

	}
	v.HashRequest(r, date.Add(61*time.Second), public, "whatever")

	if err := v.ValidateRequest(r, []string{}); err == nil {
		t.Error("Should failed")
	}
}

func TestScopesValidation(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.com/test/path?obj=1", nil)
	date := time.Now()
	public := "42"

	v := NewValidator(30*time.Second, &MockProvider{}, crypto.SHA256.New)

	v.HashRequest(r, date.Add(20*time.Second), public, "whatever")

	if err := v.ValidateRequest(r, []string{"scope1"}); err != nil {
		t.Error("Should not failed")
	}

	if err := v.ValidateRequest(r, []string{"scope1", "scope2"}); err != nil {
		t.Error("Should not failed")
	}

	if err := v.ValidateRequest(r, []string{"some scope"}); err == nil {
		t.Error("Should failed")
	}
}
