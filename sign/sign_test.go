package sign

import (
	"crypto"
	"net/http"
	"testing"
	"time"
)

func TestNonEmpty(t *testing.T) {
	a := []string{"", "nonEmpty", "", "nonEmpty"}
	final := filterNonEmpty(a)

	if len(final) != 2 {
		t.Error("Length of final should be 2")
		t.FailNow()
	}

	for _, elem := range final {
		if elem != "nonEmpty" {
			t.Error("Unexpected value")
			break
		}
	}
}
func TestGetCharacteristics(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.com", nil)

	ch := QueryCharacteristic(r)

	if ch != ("example.com_get") {
		t.Errorf("Unexpected characteristics: %s\n", ch)
	}
}

func TestGetCmptsCharacteristics(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://example.com/test/path?obj=1", nil)

	ch := QueryCharacteristic(r)

	if ch != ("example.com_get_obj_1_path_test") {
		t.Errorf("Unexpected characteristics: %s\n", ch)
	}
}

func TestHash(t *testing.T) {

	//example.com_get_obj_1_path_test
	r, _ := http.NewRequest("GET", "https://example.com/test/path?obj=1", nil)

	// 20091110230000
	date := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	secret := "MYSECRET"
	public := "42"

	hash := Hash(r, date, public, secret, crypto.SHA256.New)

	expected := "7175a8fbdbadb54e8a20d4187f8b62a71d0d9db9c43e6b45925eadeecfb9d99d"

	if hash != expected {
		t.Error("Unexpected hash:", hash)
	}
}

func TestParameterKey(t *testing.T) {

	str1 := "key=value"

	key, value := keyValueFromString(str1)

	if key != "key" && value != "value" {
		t.Error("Unexpected key value")
	}
}

func TestAuthorizationParameters(t *testing.T) {
	str := "HHMAC hash=123456, time=1460277361, key=32"

	params, err := NewAuthorizationParametersFromString(str)

	if err != nil {
		t.Error("Should not failed to parse parameters:", err)
		t.FailNow()
	}

	f := time.Unix(0, 55)
	if params.Hash != "123456" && params.PublicKey != "32" && params.Date.Second() != f.Second() {
		t.Error("Params should match")
	}
}
