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
	// 20091110230000
	date := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	public := []byte("42")

	//8618c5198d8ef93206a7b1724feaa83743c858153cac2a1edc987321a7fb5c7f

	v := NewValidator(time.Duration(3600), &MockProvider{}, crypto.SHA256.New)

	err := v.HashRequest(r, date, public, "whatever")
	if err != nil {
		t.Error("Should not fail")
		t.Fail()
	}

	err = v.ValidateRequest(r)
	if err == nil {
		t.Error("Should failed")

	}

}
