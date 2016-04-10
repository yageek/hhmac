package sign

import (
	"crypto"
	"crypto/hmac"
	"encoding/hex"
	"net/http"
	"testing"
	"time"
)

func TestNonEmpty(t *testing.T) {
	a := []string{"", "nonEmpty", "", "nonEmpty"}
	final := filterNonEmpty(a)

	if len(final) != 2 {
		t.Error("Length of final should be 2")
		t.Fail()
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
	secret := []byte("MYSECRET")
	public := []byte("42")

	hash := Hash(r, date, public, secret, crypto.SHA256.New)

	expected, _ := hex.DecodeString("8618c5198d8ef93206a7b1724feaa83743c858153cac2a1edc987321a7fb5c7f")

	if !hmac.Equal(expected, hash) {
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