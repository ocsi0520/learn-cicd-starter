package auth

import (
	"net/http"
	"strings"
	"testing"
)

func checkErrorFound(t *testing.T, str string, err error) {
	if str != "" {
		t.Fatal("It should have sent empty string")
	}
	if err == nil {
		t.Fatal("It should have sent an error")
	}
}

func checkMalformed(t *testing.T, str string, err error) {
	checkErrorFound(t, str, err)
	if !strings.Contains(err.Error(), "malformed") {
		t.Error("It should say malformed in error message")
	}
}

func TestGetAPIKeyWithoutAuthHeader(t *testing.T) {
	aHeader := make(http.Header)
	str, err := GetAPIKey(aHeader)

	checkErrorFound(t, str, err)
	if !strings.Contains(err.Error(), "no auth") {
		t.Error("It should say no auth found in error message")
	}
}

func TestGetAPIKeyWithNonApiKey(t *testing.T) {
	aHeader := make(http.Header)
	aHeader.Add("Authorization", "Bearer asd")
	str, err := GetAPIKey(aHeader)
	checkMalformed(t, str, err)
}

func TestGetAPIKeyWithFewerWords(t *testing.T) {
	aHeader := make(http.Header)
	aHeader.Add("Authorization", "ApiKey")
	str, err := GetAPIKey(aHeader)
	checkMalformed(t, str, err)
}

// actually this is incorrect, by the code it should allow more tokens than 2
// from the second we just simply ignore them
func TestGetAPIKeyWithMoreWords(t *testing.T) {
	aHeader := make(http.Header)
	aHeader.Add("Authorization", "ApiKey asdasd asdasd")
	str, err := GetAPIKey(aHeader)
	checkMalformed(t, str, err)
}

func TestGetAPIKeyWithWellFormedHeader(t *testing.T) {
	aHeader := make(http.Header)
	aHeader.Add("Authorization", "ApiKey asdasd")
	str, err := GetAPIKey(aHeader)
	if err != nil {
		t.Fatal("It should not return an error")
	}
	if str != "asdasd" {
		t.Fatal("It should have extracted token properly")
	}
}
