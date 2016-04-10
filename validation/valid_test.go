package validation

import (
	"crypto"
	"net/http"
	"testing"
	"time"
)

type MockProvider struct {
}

func (m *MockProvider) GetSecret(identifier string) ([]byte, error) {
	return []byte("MYSECRET"), nil
}

func (m *MockProvider) GetScopes(identifier string) ([]string, error) {
	return []string{}, nil
}

func TestHashUnhash(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.com/test/path?obj=1", nil)
	date := time.Now().UTC()
	public := []byte("42")

	v := NewValidator(30*time.Second, 60*time.Second, &MockProvider{}, crypto.SHA256.New)

	v.HashRequest(r, date, public, "whatever")

	if err := v.ValidateRequest(r); err != nil {
		t.Error("Should not failed:", err)
	}

	v.HashRequest(r, date.Add(29*time.Second), public, "whatever")

	if err := v.ValidateRequest(r); err != nil {
		t.Error("Should not failed:", err)

	}

	v.HashRequest(r, date.Add(31*time.Second), public, "whatever")

	if err := v.ValidateRequest(r); err == nil {
		t.Error("Should failed")

	}

	v.HashRequest(r, date.Add(59*time.Second), public, "whatever")

	if err := v.ValidateRequest(r); err != nil {
		t.Error("Should not failed:", err)

	}
	v.HashRequest(r, date.Add(61*time.Second), public, "whatever")

	if err := v.ValidateRequest(r); err == nil {
		t.Error("Should failed")
	}

}
